#!/bin/sh
# Compare unsigned builds of committed HEAD in different source/build directories.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/oscam-repro.XXXXXX")
cleanup() {
	result=$?
	if [ -n "${REPRO_LOG_DIR:-}" ]; then
		mkdir -p "$REPRO_LOG_DIR"
		cp "$work_dir"/*.log "$REPRO_LOG_DIR/" 2>/dev/null || true
	fi
	if [ "$result" -ne 0 ]; then
		for log in "$work_dir"/*.log; do
			[ -f "$log" ] || continue
			echo "--- $log" >&2
			tail -n 20 "$log" >&2
		done
	fi
	if [ "$result" -ne 0 ] || [ "${REPRO_KEEP:-0}" = 1 ]; then
		echo "Reproducibility check artifacts: $work_dir"
	else
		rm -rf "$work_dir"
	fi
	exit "$result"
}
trap cleanup 0
trap 'exit 1' 1 2 3 15

first=$work_dir/source-one
second=$work_dir/different/nested/source-two
mkdir -p "$(dirname "$second")"
git clone --quiet --shared "$repo" "$first"
git clone --quiet --shared "$repo" "$second"
git -C "$first" config core.abbrev 4
git -C "$second" config core.abbrev 12
commit=$(git -C "$repo" rev-parse HEAD | cut -c1-8)
for source in "$first" "$second"; do
	[ "$("$source/config.sh" --oscam-commit)" = "$commit" ]
	"$source/config.sh" --disable WITH_SIGNING WEBIF_WIKI > /dev/null
done

export LC_ALL=C
# Leading zeros also exercise the normalization of C integer definitions.
export SOURCE_DATE_EPOCH=0001700000000
[ "$("$first/config.sh" --oscam-epoch)" = 1700000000 ]
[ "$(TZ=Pacific/Honolulu "$first/config.sh" --oscam-build-date)" = '14.11.2023 22:13:20' ]
[ "$("$first/config.sh" --oscam-epoch 0000)" = 0 ]
make -s -C "$first" SOURCE_DATE_EPOCH=0008 \
	--eval='metadata-check:;@test "$(BUILD_EPOCH)" = 8' metadata-check
for epoch in invalid -1 999999999999999999999999; do
	if SOURCE_DATE_EPOCH=$epoch "$first/config.sh" --oscam-build-date > "$work_dir/invalid-date.log" 2>&1; then
		echo "Invalid source epoch was accepted: $epoch" >&2
		exit 1
	fi
	if make -s -C "$first" SOURCE_DATE_EPOCH="$epoch" -n help > "$work_dir/invalid-make.log" 2>&1; then
		echo "Make accepted invalid source epoch: $epoch" >&2
		exit 1
	fi
	if SOURCE_DATE_EPOCH=$epoch cmake -S "$first" -B "$work_dir/invalid-cmake" > "$work_dir/invalid-cmake.log" 2>&1; then
		echo "CMake accepted invalid source epoch: $epoch" >&2
		exit 1
	fi
done

# Exercise real signing providers: deterministic ECDSA when available, the
# compatibility fallback, and deterministic RSA on providers without nonce-type.
printf '%s' 'reproducibility signing check' > "$work_dir/hash"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$work_dir/ec.key" > "$work_dir/signing.log" 2>&1
"$first/devtools/sign-digest.sh" openssl "$work_dir/ec.key" "$work_dir/ec.sig" "$work_dir/hash" 0 >> "$work_dir/signing.log" 2>&1
openssl pkey -in "$work_dir/ec.key" -pubout -out "$work_dir/ec.pub" >> "$work_dir/signing.log" 2>&1
openssl dgst -sha256 -verify "$work_dir/ec.pub" -signature "$work_dir/ec.sig" "$work_dir/hash" >> "$work_dir/signing.log" 2>&1
ecdsa_deterministic=0
if openssl dgst -sha256 -sigopt nonce-type:1 -sign "$work_dir/ec.key" -out "$work_dir/probe.sig" "$work_dir/hash" >> "$work_dir/signing.log" 2>&1; then
	ecdsa_deterministic=1
	"$first/devtools/sign-digest.sh" openssl "$work_dir/ec.key" "$work_dir/ec-strict.sig" "$work_dir/hash" 1 >> "$work_dir/signing.log" 2>&1
	cmp "$work_dir/probe.sig" "$work_dir/ec-strict.sig"
elif "$first/devtools/sign-digest.sh" openssl "$work_dir/ec.key" "$work_dir/ec-strict.sig" "$work_dir/hash" 1 >> "$work_dir/signing.log" 2>&1; then
	echo 'Randomized ECDSA signing was accepted in strict mode' >&2
	exit 1
fi
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work_dir/rsa.key" >> "$work_dir/signing.log" 2>&1
"$first/devtools/sign-digest.sh" openssl "$work_dir/rsa.key" "$work_dir/rsa.sig" "$work_dir/hash" 1 >> "$work_dir/signing.log" 2>&1

build_pair() {
	source=$1
	name=$2
	zone=$3
	export TZ=$zone
	echo "Building $name in $source (TZ=$TZ)"
	make -C "$source" -j"${REPRO_JOBS:-2}" BUILD_DIR="$work_dir/make-$name" \
		OSCAM_BIN="$work_dir/oscam-make-$name" > "$work_dir/make-$name.log" 2>&1
	cmake -S "$source" -B "$work_dir/cmake-$name" -DCMAKE_BUILD_TYPE=Debug \
		-DWITH_SIGNING=0 > "$work_dir/cmake-$name.log" 2>&1
	cmake --build "$work_dir/cmake-$name" -- -j"${REPRO_JOBS:-2}" >> "$work_dir/cmake-$name.log" 2>&1
}
build_pair "$first" one UTC
build_pair "$second" two Pacific/Honolulu
cmp "$work_dir/oscam-make-one" "$work_dir/oscam-make-two"
cmp "$work_dir/oscam-make-one.debug" "$work_dir/oscam-make-two.debug"
cmp "$work_dir/cmake-one/oscam" "$work_dir/cmake-two/oscam"
echo 'Make stripped/debug and CMake debug binaries are byte-identical.'

# Enabling signing must select its crypto dependencies. Changing the signing
# policy must re-sign an existing binary even without a C source change.
"$first/config.sh" --enable WITH_SIGNING > /dev/null
make -C "$first" -j"${REPRO_JOBS:-2}" BUILD_DIR="$work_dir/make-signed" \
	OSCAM_BIN="$work_dir/oscam-signed" REQUIRE_DETERMINISTIC_SIGNING=0 > "$work_dir/make-signed.log" 2>&1
if make -C "$first" -j"${REPRO_JOBS:-2}" BUILD_DIR="$work_dir/make-signed" \
	OSCAM_BIN="$work_dir/oscam-signed" REQUIRE_DETERMINISTIC_SIGNING=1 > "$work_dir/make-strict.log" 2>&1; then
	[ "$ecdsa_deterministic" = 1 ]
else
	[ "$ecdsa_deterministic" = 0 ]
	grep -q 'Cannot produce deterministic signatures' "$work_dir/make-strict.log"
fi
cmake -S "$first" -B "$work_dir/cmake-signed" -DWITH_SIGNING=1 \
	-DREQUIRE_DETERMINISTIC_SIGNING=OFF > "$work_dir/cmake-signed.log" 2>&1
cmake --build "$work_dir/cmake-signed" -- -j"${REPRO_JOBS:-2}" >> "$work_dir/cmake-signed.log" 2>&1
cmake -S "$first" -B "$work_dir/cmake-signed" -DWITH_SIGNING=1 \
	-DREQUIRE_DETERMINISTIC_SIGNING=ON > "$work_dir/cmake-strict.log" 2>&1
if cmake --build "$work_dir/cmake-signed" -- -j"${REPRO_JOBS:-2}" >> "$work_dir/cmake-strict.log" 2>&1; then
	[ "$ecdsa_deterministic" = 1 ]
else
	[ "$ecdsa_deterministic" = 0 ]
	grep -q 'Cannot produce deterministic signatures' "$work_dir/cmake-strict.log"
fi
echo 'Make and CMake signing policies are enforced on incremental builds.'

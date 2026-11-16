#!/bin/sh
# Sign the binary hash, preferring RFC 6979 where the OpenSSL provider supports it.
set -eu

if [ "$#" -ne 5 ]; then
	echo "Usage: $0 openssl private-key signature hash-file require-deterministic(0|1)" >&2
	exit 1
fi
openssl=$1
key=$2
signature=$3
input=$4
case "$5" in
	0|1) ;;
	*) echo "require-deterministic must be 0 or 1" >&2; exit 1 ;;
esac

if "$openssl" dgst -sha256 -sigopt nonce-type:1 -sign "$key" -out "$signature" "$input" 2>/dev/null; then
	exit 0
fi

"$openssl" dgst -sha256 -sign "$key" -out "$signature" "$input"
if [ "$5" = 0 ]; then
	echo "NOTICE: signing without deterministic nonce support; signatures may differ between builds. Use REQUIRE_DETERMINISTIC_SIGNING=1 to reject this fallback." >&2
	exit 0
fi

# RSA PKCS#1 v1.5 is deterministic without a nonce option. Compare fallback
# signatures instead of assuming every unsupported key/provider is randomized.
check_sig=$(mktemp "${TMPDIR:-/tmp}/oscam-sign.XXXXXX")
trap 'rm -f "$check_sig"' 0
trap 'exit 1' 1 2 3 15
"$openssl" dgst -sha256 -sign "$key" -out "$check_sig" "$input"
if ! cmp -s "$signature" "$check_sig"; then
	rm -f "$signature"
	echo "Cannot produce deterministic signatures with this OpenSSL key/provider" >&2
	exit 1
fi

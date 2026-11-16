# Reproducible builds

Make and CMake embed a UTC source timestamp instead of the current wall-clock
time. They use `SOURCE_DATE_EPOCH` when supplied, otherwise the most recent Git
commit's committer timestamp. Without Git metadata or an explicit epoch, they
use zero (1970-01-01) and skip the startup clock check. Set an epoch explicitly
when building a source archive.

```sh
SOURCE_DATE_EPOCH=1700000000 make
SOURCE_DATE_EPOCH=1700000000 cmake -S . -B build-cmake
cmake --build build-cmake
```

Make also accepts `make SOURCE_DATE_EPOCH=1700000000`. Leading zeros are
normalized before generating C definitions. Negative, nonnumeric, and
host-unrepresentable dates fail the build configuration. The build log shows
the current compilation time separately; the executable contains only the
source timestamp. The eight-character Git commit identifier is independent of
Git abbreviation settings.

Builds must use the same source, configuration, compiler, linker, libraries,
and optional packer versions. Source and build paths in debug information and
`__FILE__` are normalized with supported compiler prefix-map options. Compilers
that cannot normalize these paths remain usable, with warnings about the
remaining directory dependence. Path-independent debug builds require a
compiler that supports both debug and macro path mapping.

## Signing

Signed builds must also reuse the same certificate and private key; automatically
generating a new certificate changes the binary. ECDSA signatures use RFC 6979
when the OpenSSL provider supports `nonce-type:1`. Older providers fall back to
ordinary signing and print a notice that signatures may vary.

To reject randomized signatures, enable strict signing:

```sh
make REQUIRE_DETERMINISTIC_SIGNING=1
cmake -S . -B build-cmake -DREQUIRE_DETERMINISTIC_SIGNING=ON
```

This setting applies when signing is enabled. Deterministic fallback algorithms,
such as RSA PKCS#1 v1.5, are accepted after comparing two signatures. If signing
fails, the build fails instead of appending an invalid signature.

## Regression check

Run `devtools/check_reproducible_builds.sh` after committing changes. It builds
committed HEAD in two separate source and external build directories, varies
timezones and Git abbreviation settings, and compares Make stripped/debug and
CMake debug executables. Signing and wiki embedding are disabled in these
comparison builds. Separate signing builds check compatibility and strict mode,
including policy changes without source changes. Epoch validation is also tested.

The script requires Git, Make, CMake 3.13+, a native C compiler, and OpenSSL
with its development headers and libraries. Set
`REPRO_JOBS` to control build parallelism (default 2), `REPRO_KEEP=1` to retain
successful artifacts, or `REPRO_LOG_DIR` to copy logs to a chosen directory.

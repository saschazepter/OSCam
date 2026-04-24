/**
 * \file tf-psa-crypto-config.h
 * \brief OSCam's TF-PSA-Crypto user configuration (mbedTLS 4.x)
 *
 * Platform and crypto-level overrides.  Included via
 * -DTF_PSA_CRYPTO_USER_CONFIG_FILE before the default crypto_config.h
 * is processed.
 *
 * Granularity follows oscam's own WITH_LIB_* feature matrix that
 * config.sh derives from the enabled modules/readers — we only
 * enable a PSA algorithm when the corresponding WITH_LIB_* is set.
 * config.sh additionally force-enables those libs under WITH_SSL,
 * so TLS builds automatically get MD5/SHA1/SHA256/AES/BIGNUM too.
 *
 * Everything else (RSA, ECC, HMAC, GCM, TLS KDFs, extra SHA sizes,
 * …) is gated on WITH_SSL because TLS is the only consumer.
 */

#ifndef OSCAM_TF_PSA_CRYPTO_CONFIG_H
#define OSCAM_TF_PSA_CRYPTO_CONFIG_H

#include <stddef.h>
#include "config.h"

/* ============================================================================
 *  Custom platform function prototypes
 * ========================================================================== */
#if !defined(OSCAM_MBEDTLS_PLATFORM_DECLS)
#define OSCAM_MBEDTLS_PLATFORM_DECLS
void *oscam_mbedtls_calloc(size_t n, size_t size);
void  oscam_mbedtls_free(void *ptr);
int   oscam_mbedtls_printf(const char *fmt, ...);
int   oscam_mbedtls_snprintf(char *buf, size_t buflen, const char *fmt, ...);
#endif

/* ============================================================================
 *  Platform / system support
 * ========================================================================== */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS

#define MBEDTLS_PLATFORM_CALLOC_MACRO(n,sz) oscam_mbedtls_calloc((n),(sz))
#define MBEDTLS_PLATFORM_FREE_MACRO(p)      oscam_mbedtls_free((p))
#define MBEDTLS_PLATFORM_PRINTF_MACRO(...)  oscam_mbedtls_printf(__VA_ARGS__)
#define MBEDTLS_PLATFORM_SNPRINTF_MACRO(...) oscam_mbedtls_snprintf(__VA_ARGS__)
#define MBEDTLS_PLATFORM_FPRINTF_MACRO      fprintf

/* --- Time support --- */
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE

#undef MBEDTLS_PLATFORM_TIME_ALT
#undef MBEDTLS_PLATFORM_GMTIME_R_ALT

/* ============================================================================
 *  Entropy / RNG (mbedTLS 4.x: PSA provides entropy, no HARDWARE_ALT)
 * ========================================================================== */
#define MBEDTLS_CTR_DRBG_C

/* On Linux kernels < 3.17 (typical on STBs such as DM900, kernel 3.14)
 * getrandom() returns ENOSYS and mbedTLS falls back to
 * MBEDTLS_PLATFORM_DEV_RANDOM (default /dev/random, blocks forever
 * on embedded boards with no HW entropy source). Route the fallback
 * to /dev/urandom: non-blocking and cryptographically sound after
 * the kernel has seeded its CSPRNG. */
#define MBEDTLS_PLATFORM_DEV_RANDOM "/dev/urandom"

/* ============================================================================
 *  Bignum
 *
 *  oscam-crypto-mbedtls.c uses mbedtls_mpi_* directly via
 *  <mbedtls/private/bignum.h> because PSA has no equivalent public API.
 *  In tf-psa-crypto 1.0+ the bignum module is a private implementation
 *  detail and MBEDTLS_BIGNUM_C was removed — the symbols are always
 *  linked in, there is nothing to toggle here.
 * ========================================================================== */

/* ============================================================================
 *  PSA crypto: activate the builtin whitelist mechanism
 * ========================================================================== */
#define MBEDTLS_PSA_CRYPTO_CONFIG

/* Note: in tf-psa-crypto 4.x only PSA_WANT_* is user-settable.
 * MBEDTLS_PSA_BUILTIN_* is derived internally and is explicitly
 * rejected by tf_psa_crypto_config_check_user.h if defined here. */

/* ----- Hash primitives, individually gated ----- */
#ifdef WITH_LIB_MD5
#define PSA_WANT_ALG_MD5                1
#endif

#ifdef WITH_LIB_SHA1
#define PSA_WANT_ALG_SHA_1              1
#endif

#ifdef WITH_LIB_SHA256
#define PSA_WANT_ALG_SHA_256            1
#endif

/* ----- Symmetric cipher (AES ECB + CBC) ----- */
#ifdef WITH_LIB_AES
#define PSA_WANT_KEY_TYPE_AES                   1
#define PSA_WANT_ALG_ECB_NO_PADDING             1
#define PSA_WANT_ALG_CBC_NO_PADDING             1
#endif

/* ============================================================================
 *  SSL/TLS profile — adds RSA, ECC, ECDH(E), ECDSA, extra SHA sizes,
 *  HMAC, GCM, TLS 1.2 KDFs
 *
 *  Note: config.sh already forces WITH_LIB_MD5, WITH_LIB_SHA1,
 *  WITH_LIB_SHA256, WITH_LIB_AES and WITH_LIB_BIGNUM on whenever
 *  WITH_SSL is set, so the core hash/cipher/bignum gates above
 *  are guaranteed active here.
 * ========================================================================== */
#ifdef WITH_SSL

/* Additional hashes used by TLS 1.2 cipher-suites / X.509 signatures */
#define PSA_WANT_ALG_SHA_224                1
#define PSA_WANT_ALG_SHA_384                1
#define PSA_WANT_ALG_SHA_512                1

/* MAC for TLS */
#define PSA_WANT_ALG_HMAC                   1

/* AEAD / GCM for modern TLS 1.2 suites */
#define PSA_WANT_ALG_GCM                    1

/* RSA (key exchange, PKCS#1 v1.5 and PSS for signatures) */
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC    1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT   1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE 1
#define PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY        1
#define PSA_WANT_ALG_RSA_PKCS1V15_CRYPT         1
#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN          1
#define PSA_WANT_ALG_RSA_PSS                    1
#define PSA_WANT_ALG_RSA_OAEP                   1

/* ECC curves and algorithms (ECDHE-ECDSA / ECDHE-RSA) */
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC    1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE 1
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY        1
#define PSA_WANT_ALG_ECDH                       1
#define PSA_WANT_ALG_ECDSA                      1
#define PSA_WANT_ALG_DETERMINISTIC_ECDSA        1
#define PSA_WANT_ECC_SECP_R1_256                1
#define PSA_WANT_ECC_SECP_R1_384                1
#define PSA_WANT_ECC_SECP_R1_521                1
#define PSA_WANT_ECC_MONTGOMERY_255             1

/* Key derivation used by TLS 1.2 */
#define PSA_WANT_ALG_TLS12_PRF                  1
#define PSA_WANT_ALG_TLS12_PSK_TO_MS            1

#endif /* WITH_SSL */

/* ============================================================================
 *  Disable features not needed by OSCam
 * ========================================================================== */
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_DEBUG_C
//#define MBEDTLS_DEBUG_C

/* ============================================================================
 *  Toolchain workarounds
 *
 *  aesce.c (ARMv8-A AES Crypto Extensions accelerator) declares GCC 6.0
 *  as its minimum, but the ghash NEON crypto intrinsics it uses —
 *  vreinterpretq_u8_p128, vget_low_p64, vreinterpretq_p64_u8,
 *  vmull_high_p64 — were only added to arm_neon.h in GCC 7. Building
 *  with GCC 6.x on aarch64 (e.g. OE "pyro" 2017 toolchains) therefore
 *  fails with "implicit declaration of function 'vreinterpretq_u8_p128'"
 *  even though mbedtls' own check passes. Fall back to the generic AES
 *  implementation on those toolchains.
 * ========================================================================== */
#if defined(__GNUC__) && !defined(__clang__) && (__GNUC__ < 7)
#undef MBEDTLS_AESCE_C
#endif

#endif /* OSCAM_TF_PSA_CRYPTO_CONFIG_H */

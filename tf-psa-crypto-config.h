/**
 * \file tf-psa-crypto-config.h
 * \brief OSCam's TF-PSA-Crypto user configuration (mbedTLS 4.x)
 *
 * Platform and crypto-level overrides.  Included via
 * -DTF_PSA_CRYPTO_USER_CONFIG_FILE before the default crypto_config.h
 * is processed.
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

/* MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS is no longer set globally.
 * Hashes and AES use the PSA Crypto API; only oscam-crypto-mbedtls.c
 * still needs private access (for bignum) and defines the macro locally. */

/* ============================================================================
 *  Entropy / RNG (mbedTLS 4.x: PSA provides entropy, no HARDWARE_ALT)
 * ========================================================================== */
#define MBEDTLS_CTR_DRBG_C

/* ============================================================================
 *  Disable features not needed by OSCam
 * ========================================================================== */
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_DEBUG_C
//#define MBEDTLS_DEBUG_C

#endif /* OSCAM_TF_PSA_CRYPTO_CONFIG_H */

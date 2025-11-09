/**
 * \file mbedtls-config.h
 * \brief OSCam’s configuration for mbedTLS (glibc-free)
 */

#ifndef MBEDTLS_USER_CONFIG_H
#define MBEDTLS_USER_CONFIG_H

#include <stddef.h>
#include "config.h"

/* OSCam custom MbedTLS platform function prototypes */
#if !defined(OSCAM_MBEDTLS_PLATFORM_DECLS)
#define OSCAM_MBEDTLS_PLATFORM_DECLS
void *oscam_mbedtls_calloc(size_t n, size_t size);
void  oscam_mbedtls_free(void *ptr);
int   oscam_mbedtls_printf(const char *fmt, ...);
int   oscam_mbedtls_snprintf(char *buf, size_t buflen, const char *fmt, ...);
#endif

/* ============================================================================
 *  Disable PSA and default templates
 * ========================================================================== */
#define MBEDTLS_CONFIG_NO_ENTROPY_DISABLED
#define MBEDTLS_CONFIG_NO_DEFAULT_ENTROPY_SOURCES_DISABLED
#define MBEDTLS_CONFIG_PSA_DISABLED

#undef MBEDTLS_PSA_CRYPTO_C
#undef MBEDTLS_USE_PSA_CRYPTO
#undef MBEDTLS_PSA_CRYPTO_CONFIG
#undef MBEDTLS_PSA_CRYPTO_DRIVERS
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_PSA_CRYPTO_SE_C
#undef MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS
#undef MBEDTLS_PSA_CRYPTO_ACCELERATION_SUPPORT

/* ============================================================================
 *  Platform / system support
 * ========================================================================== */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS   /* no malloc/printf/time from libc */

// Tell Mbed TLS which functions to use:
#define MBEDTLS_PLATFORM_CALLOC_MACRO(n,sz) oscam_mbedtls_calloc((n),(sz))
#define MBEDTLS_PLATFORM_FREE_MACRO(p)      oscam_mbedtls_free((p))
#define MBEDTLS_PLATFORM_PRINTF_MACRO(...)  oscam_mbedtls_printf(__VA_ARGS__)
#define MBEDTLS_PLATFORM_SNPRINTF_MACRO(...) oscam_mbedtls_snprintf(__VA_ARGS__)
#define MBEDTLS_PLATFORM_FPRINTF_MACRO    fprintf

/* --- Time support for X.509 validity checks --- */
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE

/* Do NOT use ALT time hooks — our mbedtls_platform.c already defines gmtime_r */
#undef MBEDTLS_PLATFORM_TIME_ALT
#undef MBEDTLS_PLATFORM_GMTIME_R_ALT
#undef MBEDTLS_DEBUG_C
//#define MBEDTLS_DEBUG_C

/* ============================================================================
 *  Entropy / RNG
 * ========================================================================== */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_MD_CAN_SHA256
#define MBEDTLS_ENTROPY_HARDWARE_ALT        /* provide mbedtls_hardware_poll() */

/* ============================================================================
 *  Hash / Message Digest
 * ========================================================================== */
#define MBEDTLS_DES_C
#define MBEDTLS_MD_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_MD5_C

/* ============================================================================
 *  Ciphers
 * ========================================================================== */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_CIPHER_PADDING_PKCS7
#define MBEDTLS_GCM_C

/* ============================================================================
 *  ASN.1 / Utilities
 * ========================================================================== */
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_ERROR_C
#define MBEDTLS_VERSION_C

/* ============================================================================
 *  Public-key algorithms
 * ========================================================================== */
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_PKCS5_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_PK_RSA_ALT_SUPPORT
#define MBEDTLS_PK_CAN_ECDSA_SIGN

/* ============================================================================
 *  X.509 certificates
 * ========================================================================== */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CRT_WRITE_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_PEM_WRITE_C
#define MBEDTLS_X509_CREATE_C

/* ============================================================================
 *  TLS / SSL (TLS 1.2 + 1.3 only)
 * ========================================================================== */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#undef  MBEDTLS_SSL_PROTO_TLS1_3
#undef  MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
#undef  MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
#define MBEDTLS_SSL_MAX_CONTENT_LEN 4096
#define MBEDTLS_SSL_TICKET_C
#define MBEDTLS_SSL_CONTEXT_SERIALIZATION

/* Key-exchange methods */
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_CAN_ECDH

/* ============================================================================
 *  Optional features disabled for glibc-free builds
 * ========================================================================== */
#undef MBEDTLS_CCM_C
#undef MBEDTLS_LMS_C
#undef MBEDTLS_CMAC_C
#undef MBEDTLS_NIST_KW_C

#undef MBEDTLS_SELF_TEST   /* remove printf usage in self-tests */

/* =======================================================
 *  Disable unused features when building without WITH_SSL
 * ======================================================= */
#ifndef WITH_SSL
#undef MBEDTLS_SSL_CLI_C
#undef MBEDTLS_SSL_SRV_C
#undef MBEDTLS_SSL_TLS_C
#undef MBEDTLS_SSL_PROTO_TLS1_2
#undef MBEDTLS_SSL_PROTO_TLS1_3
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
#undef MBEDTLS_SSL_SERVER_NAME_INDICATION
#undef MBEDTLS_PKCS7_C
#undef MBEDTLS_X509_CSR_PARSE_C
#undef MBEDTLS_X509_USE_C
#undef MBEDTLS_X509_CRL_PARSE_C
#undef MBEDTLS_X509_CRT_PARSE_C
#undef MBEDTLS_PEM_PARSE_C
#undef MBEDTLS_X509_CRT_WRITE_C
#undef MBEDTLS_PEM_WRITE_C
#endif

#if !defined(WITH_LIB_AES) && !defined(WITH_SSL)
#undef MBEDTLS_AES_C
#endif
#if !defined(WITH_LIB_AES) && !defined(WITH_SSL)
#undef MBEDTLS_CIPHER_C
#endif
#if !defined(WITH_LIB_DES) && !defined(WITH_LIB_MDC2) && !defined(WITH_SSL)
#undef MBEDTLS_DES_C
#endif
#if !defined(WITH_LIB_MD5) && !defined(WITH_SSL)
#undef MBEDTLS_MD5_C
#endif
#if !defined(WITH_LIB_SHA1) && !defined(WITH_SSL)
#undef MBEDTLS_SHA1_C
#endif
#if !defined(WITH_LIB_SHA256) && !defined(WITH_SSL)
#undef MBEDTLS_SHA256_C
#undef MBEDTLS_SHA512_C
#endif
#if !defined(WITH_LIB_BIGNUM) && !defined(WITH_SSL)
#undef MBEDTLS_BIGNUM_C
#endif

#endif /* MBEDTLS_USER_CONFIG_H */

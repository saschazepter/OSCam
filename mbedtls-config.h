/**
 * \file mbedtls-config.h
 * \brief Minimal working configuration for mbedTLS 3.6.5 (TLS 1.2, no PSA)
 */

#ifndef MBEDTLS_USER_CONFIG_H
#define MBEDTLS_USER_CONFIG_H

/* ============================================================================
 *  Disable PSA and default templates
 * ========================================================================== */
#define MBEDTLS_CONFIG_NO_ENTROPY_DISABLED
#define MBEDTLS_CONFIG_NO_DEFAULT_ENTROPY_SOURCES_DISABLED
#define MBEDTLS_CONFIG_PSA_DISABLED

#undef MBEDTLS_PSA_CRYPTO_C
#undef MBEDTLS_USE_PSA_CRYPTO
#undef MBEDTLS_PSA_CRYPTO_CONFIG

/* ============================================================================
 *  Platform / system support
 * ========================================================================== */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_TIMING_C

/* ============================================================================
 *  Entropy / RNG
 * ========================================================================== */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_MD_CAN_SHA256
#define MBEDTLS_CTR_DRBG_C
/* Do NOT define MBEDTLS_NO_PLATFORM_ENTROPY or MBEDTLS_TEST_NULL_ENTROPY */
#define MBEDTLS_ENTROPY_HARDWARE_ALT   /* optional hook if you want your own source */

/* ============================================================================
 *  Hash / Message Digest
 * ========================================================================== */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_MD5_C

/* ============================================================================
 *  Ciphers
 * ========================================================================== */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_CIPHER_PADDING_PKCS7

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
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C

/* ============================================================================
 *  X.509 certificates
 * ========================================================================== */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_PEM_PARSE_C

/* ============================================================================
 *  TLS / SSL (TLS 1.2 only)
 * ========================================================================== */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
#define MBEDTLS_SSL_MAX_CONTENT_LEN 4096

/* Key-exchange methods */
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_CAN_ECDH
#define MBEDTLS_RSA_C
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_PK_CAN_ECDSA_SIGN

/* ============================================================================
 *  Force-disable PSA, CCM/GCM, TLS 1.3 and other extras
 * ========================================================================== */
#undef MBEDTLS_PSA_CRYPTO_C
#undef MBEDTLS_PSA_CRYPTO_DRIVERS
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_PSA_CRYPTO_SE_C
#undef MBEDTLS_USE_PSA_CRYPTO
#undef MBEDTLS_PSA_CRYPTO_CONFIG
#undef MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS
#undef MBEDTLS_PSA_CRYPTO_ACCELERATION_SUPPORT

#undef MBEDTLS_CCM_C
#undef MBEDTLS_GCM_C
#undef MBEDTLS_LMS_C

#undef MBEDTLS_SSL_PROTO_TLS1_3
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
#undef MBEDTLS_SSL_TICKET_C
#undef MBEDTLS_SSL_CONTEXT_SERIALIZATION

/* ============================================================================
 *  Disable unused features when building without SSL
 * ========================================================================== */
#ifndef WITH_SSL
#undef MBEDTLS_SSL_CLI_C
#undef MBEDTLS_SSL_SRV_C
#undef MBEDTLS_SSL_TLS_C
#undef MBEDTLS_SSL_PROTO_TLS1_2
#undef MBEDTLS_SSL_SERVER_NAME_INDICATION
#undef MBEDTLS_PKCS7_C
#undef MBEDTLS_X509_CSR_PARSE_C
#undef MBEDTLS_X509_USE_C
#undef MBEDTLS_X509_CRL_PARSE_C
#undef MBEDTLS_X509_CRT_PARSE_C
#undef MBEDTLS_PEM_PARSE_C
#endif

/* ============================================================================
 *  Misc / self-test
 * ========================================================================== */
#define MBEDTLS_SELF_TEST

#endif /* MBEDTLS_USER_CONFIG_H */

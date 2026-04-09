/**
 * \file mbedtls-config.h
 * \brief OSCam's mbedTLS user configuration (SSL/TLS/X.509 layer)
 *
 * Crypto and platform settings are in tf-psa-crypto-config.h
 * (included via TF_PSA_CRYPTO_USER_CONFIG_FILE).
 */

#ifndef MBEDTLS_USER_CONFIG_H
#define MBEDTLS_USER_CONFIG_H

/* ============================================================================
 *  ASN.1 / Utilities
 * ========================================================================== */
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_ERROR_C
#define MBEDTLS_VERSION_C

/* ============================================================================
 *  Public-key (non-internal options only)
 * ========================================================================== */
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_PKCS5_C

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
 *  TLS / SSL (TLS 1.2 only)
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

/* Key-exchange methods (TLS 1.2) */
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

#endif /* MBEDTLS_USER_CONFIG_H */

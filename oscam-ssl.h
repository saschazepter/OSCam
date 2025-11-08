#ifndef OSCAM_SSL_H
#define OSCAM_SSL_H

#ifdef WITH_SSL

#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include <mbedtls/ssl_ticket.h>
#include "mbedtls/net_sockets.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"

/* ---------------------------------------------------------------------
 * Status codes
 * ------------------------------------------------------------------ */
enum {
	OSCAM_SSL_OK = 0,
	OSCAM_SSL_ERR = -1,
	OSCAM_SSL_PARAM = -2,
	OSCAM_SSL_WANT_READ = -3,
	OSCAM_SSL_WANT_WRITE = -4,
	OSCAM_SSL_HANDSHAKE_FAIL = -5,
	OSCAM_SSL_CERT_FAIL = -6
};

/* ---------------------------------------------------------------------
 * Opaque handles
 * ------------------------------------------------------------------ */
typedef struct oscam_ssl_conf_s oscam_ssl_conf_t;
typedef struct oscam_ssl_s	  oscam_ssl_t;

/* ---------------------------------------------------------------------
 * Configuration structure
 * ------------------------------------------------------------------ */
struct oscam_ssl_conf_s {
	mbedtls_ssl_config       ssl_conf;
	mbedtls_x509_crt         ca_chain;
	mbedtls_x509_crt         own_cert;
	mbedtls_pk_context       own_key;
	mbedtls_entropy_context  entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
};

/* ---------------------------------------------------------------------
 * SSL connection structure
 * ------------------------------------------------------------------ */
struct oscam_ssl_s {
	mbedtls_ssl_context ssl;
	mbedtls_net_context net;
};

/* ------------------------------------------------------------------
 * Unified SSL/TLS configuration modes
 * ------------------------------------------------------------------ */
typedef enum {
	OSCAM_SSL_MODE_DEFAULT = 0,   /* TLS 1.2–1.3, mixed ciphers (safe baseline) */
	OSCAM_SSL_MODE_STRICT,        /* TLS ≥ 1.2, AEAD-only (modern clients) */
	OSCAM_SSL_MODE_LEGACY         /* TLS 1.2 only, adds CBC (old browsers) */
} oscam_ssl_mode_t;

/* ---------------------------------------------------------------------
 * Global initialization
 * ------------------------------------------------------------------ */
int  oscam_ssl_global_init(void);
void oscam_ssl_global_free(void);

/* ---------------------------------------------------------------------
 * Configuration management
 * ------------------------------------------------------------------ */
oscam_ssl_conf_t *oscam_ssl_conf_build(oscam_ssl_mode_t mode);
void oscam_ssl_conf_free(oscam_ssl_conf_t *conf);
int  oscam_ssl_conf_set_min_tls12(oscam_ssl_conf_t *conf);
int  oscam_ssl_conf_load_ca(oscam_ssl_conf_t *conf, const char *ca_pem_path);
int oscam_ssl_conf_use_own_cert_pem(oscam_ssl_conf_t *conf,
									const char *pem_path,
									const char *key_pass);

/* ---------------------------------------------------------------------
 * SSL context / connection
 * ------------------------------------------------------------------ */
oscam_ssl_t *oscam_ssl_new(oscam_ssl_conf_t *conf, int fd);
void oscam_ssl_free(oscam_ssl_t *ssl);
int  oscam_ssl_handshake(oscam_ssl_t *ssl);
int oscam_ssl_handshake_blocking(oscam_ssl_t *ssl, int fd, int timeout_ms);
int oscam_ssl_accept(oscam_ssl_t *ssl, int fd, int timeout_ms);
int  oscam_ssl_read(oscam_ssl_t *ssl, void *buf, size_t len);
int oscam_ssl_write(oscam_ssl_t *ssl, const unsigned char *buf, size_t len);
int oscam_ssl_pending(oscam_ssl_t *ssl);
int oscam_ssl_get_fd(oscam_ssl_t *ssl);
void oscam_ssl_close_notify(oscam_ssl_t *ssl);
const char *oscam_ssl_version(void);
/* ---------------------------------------------------------------------
 * Utilities
 * ------------------------------------------------------------------ */
int oscam_ssl_get_peer_cn(oscam_ssl_t *ssl, char *out, size_t outlen);
int oscam_ssl_random(void *buf, size_t len);
int oscam_ssl_get_error(oscam_ssl_t *ssl, int ret);
void oscam_ssl_conf_strict_ciphers(oscam_ssl_conf_t *conf);
void oscam_ssl_conf_enable_legacy_compat(oscam_ssl_conf_t *conf);
int oscam_ssl_generate_selfsigned(const char *path);
void oscam_ssl_strerror(int err, char *buf, size_t len);


/* --- Abstracted types --- */
typedef struct {
	mbedtls_x509_crt crt;
} oscam_x509_crt;

typedef struct {
	mbedtls_pk_context pk;
} oscam_pk_context;

// ---- Certificate Handling ----
int oscam_ssl_cert_parse(oscam_x509_crt  *crt, const unsigned char *buf, size_t buflen);
int oscam_ssl_cert_parse_file(oscam_x509_crt  *crt, const char *path);
int oscam_ssl_cert_verify(oscam_x509_crt  *crt, oscam_x509_crt  *trust);
void oscam_ssl_cert_free(oscam_x509_crt  *crt);
void oscam_ssl_cert_init(oscam_x509_crt  *crt);
oscam_x509_crt *oscam_ssl_cert_get_next(oscam_x509_crt *crt);
const oscam_pk_context *oscam_ssl_cert_get_pubkey(const oscam_x509_crt *crt);
int oscam_ssl_cert_dn_gets(char *buf, size_t size, const void *dn);
void oscam_ssl_cert_serial_gets(const oscam_x509_crt *crt, char *buf, size_t len);
const void *oscam_ssl_cert_get_subject(const oscam_x509_crt *crt);

// ---- Public Key Handling ----
int oscam_ssl_pk_clone(oscam_pk_context *dst, const oscam_pk_context *src);
void oscam_ssl_pk_free(oscam_pk_context *pk);
int oscam_ssl_pk_verify(oscam_pk_context *pk, const unsigned char *hash, size_t hash_len,
						const unsigned char *sig, size_t sig_len);
int oscam_ssl_pk_get_type(const oscam_pk_context *pk);


// ---- Hashing ----
int oscam_ssl_sha1(const unsigned char *data, size_t len, unsigned char *out);
int oscam_ssl_sha256(const unsigned char *data, size_t len, unsigned char *out);
int oscam_ssl_sha256_stream(const unsigned char *data1, size_t len1,
							const unsigned char *data2, size_t len2,
							unsigned char *out);
#endif /* WITH_SSL */
#endif /* OSCAM_SSL_H */

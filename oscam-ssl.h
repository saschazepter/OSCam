#ifndef OSCAM_SSL_H
#define OSCAM_SSL_H

#ifdef WITH_SSL

#ifdef WITH_MBEDTLS
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_ticket.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#endif /* WITH_MBEDTLS */

#ifdef WITH_OPENSSL
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#endif /* WITH_OPENSSL */

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

#define OSCAM_SSL_CERT_YEARS 2

#define OSCAM_PK_RSA   0
#define OSCAM_PK_EC    1
#define OSCAM_PK_NONE -1

/* ---------------------------------------------------------------------
 * Opaque handles
 * ------------------------------------------------------------------ */
typedef struct oscam_ssl_conf_s   oscam_ssl_conf_t;
typedef struct oscam_ssl_s        oscam_ssl_t;
typedef struct oscam_x509_crt_s   oscam_x509_crt;
typedef struct oscam_pk_context_s oscam_pk_context;

/* Small alloc helpers for opaque types */
oscam_x509_crt  *oscam_ssl_cert_new(void);
void             oscam_ssl_cert_delete(oscam_x509_crt *crt);

oscam_pk_context *oscam_ssl_pk_new(void);
void              oscam_ssl_pk_delete(oscam_pk_context *pk);

/* Unified SSL/TLS modes */
typedef enum {
	OSCAM_SSL_MODE_DEFAULT = 0,
	OSCAM_SSL_MODE_STRICT,
	OSCAM_SSL_MODE_LEGACY
} oscam_ssl_mode_t;

/* Validity times */
typedef struct {
	int year, mon, day, hour, min, sec;
} oscam_cert_time_t;

/* ---------------------------------------------------------------------
 * Public API — shared for both backends
 * ------------------------------------------------------------------ */
int  oscam_ssl_global_init(void);
void oscam_ssl_global_free(void);

oscam_ssl_conf_t *oscam_ssl_conf_build(oscam_ssl_mode_t mode);
void oscam_ssl_conf_free(oscam_ssl_conf_t *conf);
int  oscam_ssl_conf_set_min_tls12(oscam_ssl_conf_t *conf);
int  oscam_ssl_conf_load_ca(oscam_ssl_conf_t *conf, const char *ca_pem_path);
int  oscam_ssl_conf_use_own_cert_pem(oscam_ssl_conf_t *conf, const char *pem_path, const char *key_pass);

oscam_ssl_t *oscam_ssl_new(oscam_ssl_conf_t *conf, int fd);
void oscam_ssl_free(oscam_ssl_t *ssl);
int  oscam_ssl_handshake(oscam_ssl_t *ssl);
int  oscam_ssl_handshake_blocking(oscam_ssl_t *ssl, int fd, int timeout_ms);
int  oscam_ssl_accept(oscam_ssl_t *ssl, int fd, int timeout_ms);
int  oscam_ssl_read(oscam_ssl_t *ssl, void *buf, size_t len);
int  oscam_ssl_write(oscam_ssl_t *ssl, const unsigned char *buf, size_t len);
int  oscam_ssl_pending(oscam_ssl_t *ssl);
int  oscam_ssl_get_fd(oscam_ssl_t *ssl);
void oscam_ssl_close_notify(oscam_ssl_t *ssl);
const char *oscam_ssl_version(void);

int oscam_ssl_get_peer_cn(oscam_ssl_t *ssl, char *out, size_t outlen);
int oscam_ssl_random(void *buf, size_t len);
int oscam_ssl_get_error(oscam_ssl_t *ssl, int ret);
int oscam_ssl_generate_selfsigned(const char *path);
void oscam_ssl_strerror(int err, char *buf, size_t len);

/* ------------------- X.509 certificate interface ------------------- */
void oscam_ssl_cert_init(oscam_x509_crt *crt);
void oscam_ssl_cert_free(oscam_x509_crt *crt);
int oscam_ssl_cert_parse(oscam_x509_crt *crt, const unsigned char *buf, size_t len);
int oscam_ssl_cert_parse_file(oscam_x509_crt *crt, const char *path);
int oscam_ssl_cert_verify(oscam_x509_crt *crt, oscam_x509_crt *trust);
void oscam_ssl_cert_raw(const oscam_x509_crt *crt, const unsigned char **buf, size_t *len);
void oscam_ssl_cert_get_validity(const oscam_x509_crt *crt, oscam_cert_time_t *from, oscam_cert_time_t *to);
int  oscam_ssl_cert_get_version(const oscam_x509_crt *crt);
const void *oscam_ssl_cert_get_issuer(const oscam_x509_crt *crt);

oscam_x509_crt *oscam_ssl_cert_get_next(oscam_x509_crt *crt);
const void *oscam_ssl_cert_get_subject(const oscam_x509_crt *crt);
int oscam_ssl_cert_dn_gets(char *buf, size_t size, const void *dn);
void oscam_ssl_cert_serial_gets(const oscam_x509_crt *crt, char *buf, size_t len);
const oscam_pk_context *oscam_ssl_cert_get_pubkey(const oscam_x509_crt *crt);
int oscam_ssl_pk_get_bitlen(const oscam_pk_context *pk);
int oscam_ssl_pk_get_bits(const oscam_pk_context *pk);

/* ------------------- public key interface --------------------------- */
int oscam_ssl_pk_clone(oscam_pk_context *dst, const oscam_pk_context *src);
void oscam_ssl_pk_free(oscam_pk_context *pk);
int oscam_ssl_pk_verify(oscam_pk_context *pk, const unsigned char *hash, size_t hash_len, const unsigned char *sig, size_t sig_len);
int oscam_ssl_pk_get_type(const oscam_pk_context *pk);

#endif /* WITH_SSL */
#endif /* OSCAM_SSL_H */

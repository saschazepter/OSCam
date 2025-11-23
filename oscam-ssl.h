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
#include <openssl/x509v3.h>

#ifdef WITH_OPENSSL_DLOPEN

/* --- function pointer types for SSL-centric symbols --- */

/* Methods */
typedef const SSL_METHOD *(*oscam_SSLv23_server_method_f)(void);
typedef const SSL_METHOD *(*oscam_TLS_server_method_f)(void);
typedef const SSL_METHOD *(*oscam_TLS_method_f)(void);

/* Legacy global init helpers (< 1.1.0) */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
typedef int  (*oscam_SSL_library_init_f)(void);
typedef void (*oscam_SSL_load_error_strings_f)(void);
typedef void (*oscam_OpenSSL_add_all_algorithms_f)(void);
#endif

/* SSL_CTX API */
typedef SSL_CTX *(*oscam_SSL_CTX_new_f)(const SSL_METHOD *meth);
typedef void     (*oscam_SSL_CTX_free_f)(SSL_CTX *ctx);
typedef long     (*oscam_SSL_CTX_set_options_f)(SSL_CTX *ctx, long opts);
typedef void     (*oscam_SSL_CTX_set_verify_f)(SSL_CTX *ctx, int mode,
						int (*cb)(int, X509_STORE_CTX *));
typedef int      (*oscam_SSL_CTX_load_verify_locations_f)(SSL_CTX *ctx,
						const char *cafile,
						const char *capath);
typedef int      (*oscam_SSL_CTX_use_certificate_chain_file_f)(SSL_CTX *ctx,
						const char *file);
typedef int      (*oscam_SSL_CTX_use_certificate_file_f)(SSL_CTX *ctx,
						const char *file, int type);
typedef int      (*oscam_SSL_CTX_use_PrivateKey_file_f)(SSL_CTX *ctx,
						const char *file, int type);
typedef int      (*oscam_SSL_CTX_check_private_key_f)(const SSL_CTX *ctx);
typedef int      (*oscam_SSL_CTX_set_min_proto_version_f)(SSL_CTX *ctx,
						int version);
typedef int      (*oscam_SSL_CTX_set_cipher_list_f)(SSL_CTX *ctx,
						const char *list);
typedef void     (*oscam_SSL_CTX_set_default_passwd_cb_userdata_f)(SSL_CTX *ctx,
						void *u);

/* SSL connection API */
typedef SSL *(*oscam_SSL_new_f)(SSL_CTX *ctx);
typedef void (*oscam_SSL_free_f)(SSL *ssl);
typedef int  (*oscam_SSL_set_fd_f)(SSL *ssl, int fd);
typedef int  (*oscam_SSL_do_handshake_f)(SSL *ssl);
typedef int  (*oscam_SSL_accept_f)(SSL *ssl);
typedef int  (*oscam_SSL_connect_f)(SSL *ssl);
typedef int  (*oscam_SSL_read_f)(SSL *ssl, void *buf, int num);
typedef int  (*oscam_SSL_write_f)(SSL *ssl, const void *buf, int num);
typedef int  (*oscam_SSL_shutdown_f)(SSL *ssl);
typedef int  (*oscam_SSL_get_error_f)(const SSL *ssl, int ret);
typedef int  (*oscam_SSL_pending_f)(const SSL *ssl);
typedef long (*oscam_SSL_get_verify_result_f)(const SSL *ssl);

/* Version / error helpers */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
typedef void (*oscam_CRYPTO_cleanup_all_ex_data_f)(void);
typedef int  (*oscam_CRYPTO_add_f)(volatile int *pointer, int amount, int type);
typedef const char *(*oscam_SSLeay_version_f)(int type);
#else
typedef const char *(*oscam_OpenSSL_version_f)(int type);
#endif

typedef unsigned long (*oscam_ERR_get_error_f)(void);
typedef void (*oscam_ERR_error_string_n_f)(unsigned long e, char *buf,
						size_t len);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
typedef void (*oscam_ERR_free_strings_f)(void);
#endif

/* EVP_PKEY / keygen */
typedef EVP_PKEY *(*oscam_X509_get_pubkey_f)(X509 *x);
typedef EVP_PKEY *(*oscam_EVP_PKEY_new_f)(void);
typedef void      (*oscam_EVP_PKEY_free_f)(EVP_PKEY *pkey);
typedef void      (*oscam_EVP_PKEY_CTX_free_f)(EVP_PKEY_CTX *ctx);

typedef EVP_PKEY_CTX *(*oscam_EVP_PKEY_CTX_new_id_f)(int id, void *engine /* ENGINE* or NULL */);
typedef int           (*oscam_EVP_PKEY_keygen_init_f)(EVP_PKEY_CTX *ctx);
typedef int           (*oscam_EVP_PKEY_CTX_set_rsa_keygen_bits_f)(EVP_PKEY_CTX *ctx, int bits);
typedef int           (*oscam_EVP_PKEY_keygen_f)(EVP_PKEY_CTX *ctx, EVP_PKEY **pkey);

typedef EVP_PKEY_CTX *(*oscam_EVP_PKEY_CTX_new_f)(EVP_PKEY *pkey, void *engine);
typedef int           (*oscam_EVP_PKEY_verify_init_f)(EVP_PKEY_CTX *ctx);
typedef int           (*oscam_EVP_PKEY_CTX_set_signature_md_f)(EVP_PKEY_CTX *ctx, const EVP_MD *md);
typedef int           (*oscam_EVP_PKEY_verify_f)(EVP_PKEY_CTX *ctx,
                                                 const unsigned char *sig, size_t siglen,
                                                 const unsigned char *tbs, size_t tbslen);

typedef int (*oscam_EVP_PKEY_bits_f)(const EVP_PKEY *pkey);
typedef EVP_PKEY *(*oscam_EVP_PKEY_dup_f)(EVP_PKEY *pkey);
typedef int (*oscam_EVP_PKEY_base_id_f)(const EVP_PKEY *pkey);
typedef int (*oscam_EVP_PKEY_type_f)(int type);
typedef RSA *(*oscam_EVP_PKEY_get1_RSA_f)(EVP_PKEY *pkey);
typedef EC_KEY *(*oscam_EVP_PKEY_get1_EC_KEY_f)(EVP_PKEY *pkey);

/* RSA / ECDSA */
typedef int (*oscam_RSA_verify_f)(int type,
                                  const unsigned char *m, unsigned int m_length,
                                  const unsigned char *sigbuf, unsigned int siglen,
                                  RSA *rsa);
typedef void (*oscam_RSA_free_f)(RSA *rsa);

typedef int (*oscam_ECDSA_verify_f)(int type,
                                    const unsigned char *dgst, int dgst_len,
                                    const unsigned char *sig, int sig_len,
                                    EC_KEY *eckey);
typedef void (*oscam_EC_KEY_free_f)(EC_KEY *key);

/* X509 and X509 NAME / serial / version */
typedef X509 *(*oscam_X509_new_f)(void);
typedef void  (*oscam_X509_free_f)(X509 *x);
typedef int   (*oscam_X509_set_version_f)(X509 *x, long version);
typedef ASN1_INTEGER *(*oscam_X509_get_serialNumber_f)(X509 *x);
typedef int   (*oscam_X509_set_pubkey_f)(X509 *x, EVP_PKEY *pkey);

/* OpenSSL >= 1.1.0 (mutable getters) */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
typedef ASN1_TIME *(*oscam_X509_getm_notBefore_f)(X509 *x);
typedef ASN1_TIME *(*oscam_X509_getm_notAfter_f)(X509 *x);
typedef int (*oscam_ASN1_TIME_to_tm_f)(const ASN1_TIME *t, struct tm *tm);
#else
/* OpenSSL < 1.1.0 */
typedef ASN1_TIME *(*oscam_X509_get_notBefore_f)(X509 *x);
typedef ASN1_TIME *(*oscam_X509_get_notAfter_f)(X509 *x);
#endif
typedef ASN1_TIME *(*oscam_X509_gmtime_adj_f)(ASN1_TIME *s, long adj);

typedef X509_NAME *(*oscam_X509_NAME_new_f)(void);
typedef void       (*oscam_X509_NAME_free_f)(X509_NAME *a);
typedef int        (*oscam_X509_NAME_add_entry_by_txt_f)(
                        X509_NAME *name, const char *field, int type,
                        const unsigned char *bytes, int len, int loc, int set);
typedef int        (*oscam_X509_set_subject_name_f)(X509 *x, X509_NAME *name);
typedef int        (*oscam_X509_set_issuer_name_f)(X509 *x, X509_NAME *name);
typedef X509_NAME *(*oscam_X509_get_subject_name_f)(const X509 *x);
typedef X509_NAME *(*oscam_X509_get_issuer_name_f)(const X509 *x);
typedef int        (*oscam_X509_get_version_f)(const X509 *x);
typedef int        (*oscam_X509_NAME_print_ex_f)(BIO *bio, X509_NAME *nm, int indent, unsigned long flags);

typedef BIGNUM    *(*oscam_ASN1_INTEGER_to_BN_f)(const ASN1_INTEGER *ai, BIGNUM *bn);
typedef char      *(*oscam_BN_bn2hex_f)(const BIGNUM *a);
typedef ASN1_INTEGER *(*oscam_BN_to_ASN1_INTEGER_f)(const BIGNUM *bn, ASN1_INTEGER *ai);

/* X509 V3 / extensions / SAN / stacks */
typedef void     (*oscam_X509V3_set_ctx_f)(X509V3_CTX *ctx,
                                       X509 *issuer, X509 *subject,
                                       X509 *req, X509_CRL *crl, int flags);
typedef X509_EXTENSION *(*oscam_X509V3_EXT_conf_nid_f)(LHASH_OF(CONF_VALUE) *conf,
                                                       X509V3_CTX *ctx, int nid,
                                                       const char *value);
typedef int (*oscam_X509_add_ext_f)(X509 *x, X509_EXTENSION *ex, int loc);
typedef void (*oscam_X509_EXTENSION_free_f)(X509_EXTENSION *ex);
typedef X509_EXTENSION *(*oscam_X509V3_EXT_i2d_f)(int nid, int crit, void *value);

typedef _STACK *(*oscam_OPENSSL_sk_new_null_f)(void);
typedef int     (*oscam_OPENSSL_sk_push_f)(_STACK *st, void *data);
typedef void    (*oscam_OPENSSL_sk_pop_free_f)(_STACK *st, void (*func)(void *));

typedef GENERAL_NAME *(*oscam_GENERAL_NAME_new_f)(void);
typedef void          (*oscam_GENERAL_NAME_free_f)(GENERAL_NAME *a);
typedef void          (*oscam_GENERAL_NAME_set0_value_f)(GENERAL_NAME *a, int type, void *value);

typedef ASN1_IA5STRING *(*oscam_ASN1_IA5STRING_new_f)(void);
typedef ASN1_OCTET_STRING *(*oscam_ASN1_OCTET_STRING_new_f)(void);
typedef int (*oscam_ASN1_OCTET_STRING_set_f)(ASN1_OCTET_STRING *str,
                                             const unsigned char *data, int len);
typedef int (*oscam_ASN1_STRING_set_f)(ASN1_STRING *str, const void *data, int len);

/* BIO / PEM / misc */
typedef BIO *(*oscam_BIO_new_f)(const BIO_METHOD *type);
typedef BIO *(*oscam_BIO_new_mem_buf_f)(void *buf, int len);
typedef BIO *(*oscam_BIO_new_file_f)(const char *filename, const char *mode);
typedef const BIO_METHOD *(*oscam_BIO_s_mem_f)(void);
typedef int  (*oscam_BIO_free_f)(BIO *a);
typedef int  (*oscam_BIO_read_f)(BIO *b, void *data, int len);
typedef long (*oscam_BIO_ctrl_f)(BIO *b, int cmd, long larg, void *parg);
typedef long (*oscam_BIO_get_mem_data_f)(BIO *b, char **pp);

typedef X509 *(*oscam_PEM_read_bio_X509_f)(BIO *bp, X509 **x,
                                           pem_password_cb *cb, void *u);
typedef int   (*oscam_PEM_write_X509_f)(FILE *fp, X509 *x);
typedef int   (*oscam_PEM_write_PrivateKey_f)(FILE *fp, EVP_PKEY *x,
                                              const EVP_CIPHER *enc,
                                              unsigned char *kstr, int klen,
                                              pem_password_cb *cb, void *u);

typedef X509 *(*oscam_d2i_X509_bio_f)(BIO *bp, X509 **x);

typedef int (*oscam_ASN1_TIME_print_f)(BIO *bp, const ASN1_TIME *tm);
typedef int (*oscam_i2d_X509_f)(X509 *x, unsigned char **out);

/* Random */
typedef int (*oscam_RAND_bytes_f)(unsigned char *buf, int num);

/* X509 store / verify */
typedef X509_STORE *(*oscam_X509_STORE_new_f)(void);
typedef void        (*oscam_X509_STORE_free_f)(X509_STORE *v);
typedef int         (*oscam_X509_STORE_add_cert_f)(X509_STORE *ctx, X509 *x);
typedef X509_STORE_CTX *(*oscam_X509_STORE_CTX_new_f)(void);
typedef void           (*oscam_X509_STORE_CTX_free_f)(X509_STORE_CTX *ctx);
typedef int            (*oscam_X509_STORE_CTX_init_f)(X509_STORE_CTX *ctx,
                                                      X509_STORE *store,
                                                      X509 *x,
                                                      STACK_OF(X509) *chain);
typedef int (*oscam_X509_verify_cert_f)(X509_STORE_CTX *ctx);
typedef X509 *(*oscam_SSL_get_peer_certificate_f)(const SSL *s);

/* subject/issuer name utilities */
typedef int          (*oscam_X509_NAME_get_index_by_NID_f)(X509_NAME *name, int nid, int lastpos);
typedef X509_NAME_ENTRY *(*oscam_X509_NAME_get_entry_f)(X509_NAME *name, int loc);
typedef ASN1_STRING *(*oscam_X509_NAME_ENTRY_get_data_f)(X509_NAME_ENTRY *ne);
typedef int          (*oscam_ASN1_STRING_to_UTF8_f)(unsigned char **out, const ASN1_STRING *in);

/* OPENSSL_free */
typedef void (*oscam_OPENSSL_free_f)(void *addr);

/* X509 sign */
typedef int (*oscam_X509_sign_f)(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);

extern oscam_BIO_get_mem_data_f oscam_BIO_get_mem_data;

#endif /* WITH_OPENSSL_DLOPEN */

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
	OSCAM_SSL_CERT_FAIL = -6,
	OSCAM_SSL_FATAL = -7   /* loader / binding failures */
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
int  oscam_ssl_cert_parse(oscam_x509_crt *crt, const unsigned char *buf, size_t len);
int  oscam_ssl_cert_parse_file(oscam_x509_crt *crt, const char *path);
int  oscam_ssl_cert_verify(oscam_x509_crt *crt, oscam_x509_crt *trust);
void oscam_ssl_cert_raw(const oscam_x509_crt *crt, const unsigned char **buf, size_t *len);
void oscam_ssl_cert_get_validity(const oscam_x509_crt *crt, oscam_cert_time_t *from, oscam_cert_time_t *to);
int  oscam_ssl_cert_get_version(const oscam_x509_crt *crt);
const void *oscam_ssl_cert_get_issuer(const oscam_x509_crt *crt);

oscam_x509_crt *oscam_ssl_cert_get_next(oscam_x509_crt *crt);
const void *oscam_ssl_cert_get_subject(const oscam_x509_crt *crt);
int  oscam_ssl_cert_dn_gets(char *buf, size_t size, const void *dn);
void oscam_ssl_cert_serial_gets(const oscam_x509_crt *crt, char *buf, size_t len);
const oscam_pk_context *oscam_ssl_cert_get_pubkey(const oscam_x509_crt *crt);
int  oscam_ssl_pk_get_bitlen(const oscam_pk_context *pk);
int  oscam_ssl_pk_get_bits(const oscam_pk_context *pk);

/* ------------------- public key interface --------------------------- */
int  oscam_ssl_pk_clone(oscam_pk_context *dst, const oscam_pk_context *src);
void oscam_ssl_pk_free(oscam_pk_context *pk);
int  oscam_ssl_pk_verify(oscam_pk_context *pk, const unsigned char *hash, size_t hash_len, const unsigned char *sig, size_t sig_len);
int  oscam_ssl_pk_get_type(const oscam_pk_context *pk);

#endif /* WITH_SSL */
#endif /* OSCAM_SSL_H */

#ifndef OSCAM_SSL_H
#define OSCAM_SSL_H

#ifdef WITH_SSL

#include <stddef.h>
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

/* ---------------------------------------------------------------------
 * Opaque handles
 * ------------------------------------------------------------------ */
typedef struct oscam_ssl_conf_s oscam_ssl_conf_t;
typedef struct oscam_ssl_s      oscam_ssl_t;

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

/* ---------------------------------------------------------------------
 * Global initialization
 * ------------------------------------------------------------------ */
int  oscam_ssl_global_init(void);
void oscam_ssl_global_free(void);

/* ---------------------------------------------------------------------
 * Configuration management
 * ------------------------------------------------------------------ */
oscam_ssl_conf_t *oscam_ssl_conf_new(void);
void oscam_ssl_conf_free(oscam_ssl_conf_t *conf);
int  oscam_ssl_conf_set_min_tls12(oscam_ssl_conf_t *conf);
int  oscam_ssl_conf_load_ca(oscam_ssl_conf_t *conf, const char *ca_pem_path);
int  oscam_ssl_conf_load_own_cert(oscam_ssl_conf_t *conf,
                                  const char *cert_pem_path,
                                  const char *key_pem_path,
                                  const char *key_pass);

/* ---------------------------------------------------------------------
 * SSL context / connection
 * ------------------------------------------------------------------ */
oscam_ssl_t *oscam_ssl_new(oscam_ssl_conf_t *conf, int fd);
void oscam_ssl_free(oscam_ssl_t *ssl);
int  oscam_ssl_handshake(oscam_ssl_t *ssl);
int  oscam_ssl_read(oscam_ssl_t *ssl, void *buf, size_t len);
int  oscam_ssl_write(oscam_ssl_t *ssl, const void *buf, size_t len);
void oscam_ssl_close_notify(oscam_ssl_t *ssl);

/* ---------------------------------------------------------------------
 * Utilities
 * ------------------------------------------------------------------ */
int oscam_ssl_get_peer_cn(oscam_ssl_t *ssl, char *out, size_t outlen);
int oscam_ssl_random(void *buf, size_t len);

#endif /* WITH_SSL */
#endif /* OSCAM_SSL_H */

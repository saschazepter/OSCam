#include "globals.h"
#include "oscam-ssl.h"

#ifdef WITH_SSL

/* mbedTLS */
#include "mbedtls/platform.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/error.h"
#include "mbedtls/version.h"
#include "mbedtls/oid.h"

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
 * Global RNG state
 * ------------------------------------------------------------------ */
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;
static int g_init_ref = 0;

/* ---------------------------------------------------------------------
 * BIO wrappers
 * ------------------------------------------------------------------ */
static int bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    int fd = (int)(intptr_t)ctx;
    ssize_t r = send(fd, buf, len, 0);
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return (int)r;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    int fd = (int)(intptr_t)ctx;
    ssize_t r = recv(fd, buf, len, 0);
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return MBEDTLS_ERR_SSL_WANT_READ;
        return MBEDTLS_ERR_NET_RECV_FAILED;
    }
    if (r == 0)
        return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY; /* EOF */
    return (int)r;
}

static int map_tls_err(int ret)
{
    if (ret == MBEDTLS_ERR_SSL_WANT_READ)
        return OSCAM_SSL_WANT_READ;
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        return OSCAM_SSL_WANT_WRITE;
    return OSCAM_SSL_ERR;
}

/* ---------------------------------------------------------------------
 * Global init / free
 * ------------------------------------------------------------------ */
int oscam_ssl_global_init(void)
{
    if (g_init_ref++ > 0)
        return OSCAM_SSL_OK;

    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_drbg);

    const char *pers = "oscam-mbedtls";
    int ret = mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
                                    (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        g_init_ref = 0;
        mbedtls_ctr_drbg_free(&g_drbg);
        mbedtls_entropy_free(&g_entropy);
        return OSCAM_SSL_ERR;
    }
    return OSCAM_SSL_OK;
}

void oscam_ssl_global_free(void)
{
    if (g_init_ref == 0)
        return;
    if (--g_init_ref == 0) {
        mbedtls_ctr_drbg_free(&g_drbg);
        mbedtls_entropy_free(&g_entropy);
    }
}

/* ---------------------------------------------------------------------
 * Configuration object
 * ------------------------------------------------------------------ */
oscam_ssl_conf_t *oscam_ssl_conf_new(void)
{
    oscam_ssl_conf_t *conf = calloc(1, sizeof(*conf));
    if (!conf)
        return NULL;

    mbedtls_ssl_config_init(&conf->ssl_conf);
    mbedtls_x509_crt_init(&conf->ca_chain);
    mbedtls_x509_crt_init(&conf->own_cert);
    mbedtls_pk_init(&conf->own_key);
    mbedtls_entropy_init(&conf->entropy);
    mbedtls_ctr_drbg_init(&conf->ctr_drbg);

    const char *pers = "oscam_ssl_conf";
    if (mbedtls_ctr_drbg_seed(&conf->ctr_drbg, mbedtls_entropy_func, &conf->entropy,
                              (const unsigned char *)pers, strlen(pers)) != 0) {
        oscam_ssl_conf_free(conf);
        return NULL;
    }

    if (mbedtls_ssl_config_defaults(&conf->ssl_conf,
                                    MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        oscam_ssl_conf_free(conf);
        return NULL;
    }

    mbedtls_ssl_conf_rng(&conf->ssl_conf, mbedtls_ctr_drbg_random, &conf->ctr_drbg);
    mbedtls_ssl_conf_authmode(&conf->ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

    return conf;
}

void oscam_ssl_conf_free(oscam_ssl_conf_t *conf)
{
    if (!conf)
        return;
    mbedtls_pk_free(&conf->own_key);
    mbedtls_x509_crt_free(&conf->own_cert);
    mbedtls_x509_crt_free(&conf->ca_chain);
    mbedtls_ssl_config_free(&conf->ssl_conf);
    mbedtls_ctr_drbg_free(&conf->ctr_drbg);
    mbedtls_entropy_free(&conf->entropy);
    free(conf);
}

int oscam_ssl_conf_set_min_tls12(oscam_ssl_conf_t *conf)
{
    if (!conf)
        return OSCAM_SSL_PARAM;
    mbedtls_ssl_conf_min_version(&conf->ssl_conf,
                                 MBEDTLS_SSL_MAJOR_VERSION_3,
                                 MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_max_version(&conf->ssl_conf,
                                 MBEDTLS_SSL_MAJOR_VERSION_3,
                                 MBEDTLS_SSL_MINOR_VERSION_3);
    return OSCAM_SSL_OK;
}

int oscam_ssl_conf_load_own_cert(oscam_ssl_conf_t *conf,
                                 const char *cert_pem_path,
                                 const char *key_pem_path,
                                 const char *key_pass)
{
    if (!conf || !cert_pem_path || !key_pem_path)
        return OSCAM_SSL_PARAM;

    if (mbedtls_x509_crt_parse_file(&conf->own_cert, cert_pem_path) != 0)
        return OSCAM_SSL_CERT_FAIL;

    if (mbedtls_pk_parse_keyfile(&conf->own_key, key_pem_path, key_pass,
                                 mbedtls_ctr_drbg_random, &conf->ctr_drbg) != 0)
        return OSCAM_SSL_CERT_FAIL;

    if (mbedtls_ssl_conf_own_cert(&conf->ssl_conf,
                                  &conf->own_cert, &conf->own_key) != 0)
        return OSCAM_SSL_CERT_FAIL;

    return OSCAM_SSL_OK;
}

int oscam_ssl_conf_load_ca(oscam_ssl_conf_t *conf, const char *ca_pem_path)
{
    if (!conf)
        return OSCAM_SSL_PARAM;
    if (!ca_pem_path) {
        mbedtls_ssl_conf_authmode(&conf->ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
        return OSCAM_SSL_OK;
    }

    if (mbedtls_x509_crt_parse_file(&conf->ca_chain, ca_pem_path) != 0)
        return OSCAM_SSL_CERT_FAIL;

    mbedtls_ssl_conf_ca_chain(&conf->ssl_conf, &conf->ca_chain, NULL);
    mbedtls_ssl_conf_authmode(&conf->ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    return OSCAM_SSL_OK;
}

/* ---------------------------------------------------------------------
 * SSL context
 * ------------------------------------------------------------------ */
oscam_ssl_t *oscam_ssl_new(oscam_ssl_conf_t *conf, int fd)
{
    if (!conf)
        return NULL;

    oscam_ssl_t *ssl = calloc(1, sizeof(*ssl));
    if (!ssl)
        return NULL;

    mbedtls_ssl_init(&ssl->ssl);
    mbedtls_net_init(&ssl->net);
    ssl->net.fd = fd;

    if (mbedtls_ssl_setup(&ssl->ssl, &conf->ssl_conf) != 0) {
        oscam_ssl_free(ssl);
        return NULL;
    }

    mbedtls_ssl_set_bio(&ssl->ssl, (void *)(intptr_t)fd, bio_send, bio_recv, NULL);
    return ssl;
}

void oscam_ssl_free(oscam_ssl_t *ssl)
{
    if (!ssl)
        return;
    mbedtls_ssl_free(&ssl->ssl);
    mbedtls_net_free(&ssl->net);
    free(ssl);
}

/* ---------------------------------------------------------------------
 * Handshake / I/O
 * ------------------------------------------------------------------ */
int oscam_ssl_handshake(oscam_ssl_t *ssl)
{
    if (!ssl)
        return OSCAM_SSL_PARAM;

    int ret;
    while ((ret = mbedtls_ssl_handshake(&ssl->ssl)) != 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ)
            return OSCAM_SSL_WANT_READ;
        if (ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            return OSCAM_SSL_WANT_WRITE;
        return OSCAM_SSL_HANDSHAKE_FAIL;
    }
    return OSCAM_SSL_OK;
}

int oscam_ssl_read(oscam_ssl_t *ssl, void *buf, size_t len)
{
    if (!ssl || !buf)
        return OSCAM_SSL_PARAM;
    int ret = mbedtls_ssl_read(&ssl->ssl, buf, len);
    if (ret >= 0)
        return ret;
    return map_tls_err(ret);
}

int oscam_ssl_write(oscam_ssl_t *ssl, const void *buf, size_t len)
{
    if (!ssl || !buf)
        return OSCAM_SSL_PARAM;
    int ret = mbedtls_ssl_write(&ssl->ssl, buf, len);
    if (ret >= 0)
        return ret;
    return map_tls_err(ret);
}

void oscam_ssl_close_notify(oscam_ssl_t *ssl)
{
    if (!ssl)
        return;
    for (int i = 0; i < 2; ++i) {
        int ret = mbedtls_ssl_close_notify(&ssl->ssl);
        if (ret == 0)
            break;
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            break;
    }
}

/* ---------------------------------------------------------------------
 * Peer info / RNG
 * ------------------------------------------------------------------ */
int oscam_ssl_get_peer_cn(oscam_ssl_t *ssl, char *out, size_t outlen)
{
    if (!ssl || !out || outlen == 0)
        return OSCAM_SSL_PARAM;

    const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&ssl->ssl);
    if (!peer)
        return OSCAM_SSL_ERR;

    const mbedtls_x509_name *name = &peer->subject;
    while (name) {
        if (name->oid.len == MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN) &&
            memcmp(name->oid.p, MBEDTLS_OID_AT_CN, name->oid.len) == 0) {
            size_t n = name->val.len < outlen - 1 ? name->val.len : outlen - 1;
            memcpy(out, name->val.p, n);
            out[n] = '\0';
            return OSCAM_SSL_OK;
        }
        name = name->next;
    }

    if (outlen)
        out[0] = '\0';
    return OSCAM_SSL_ERR;
}

int oscam_ssl_random(void *buf, size_t len)
{
    if (!buf)
        return OSCAM_SSL_PARAM;
    int ret = mbedtls_ctr_drbg_random(&g_drbg, (unsigned char *)buf, len);
    return ret == 0 ? OSCAM_SSL_OK : OSCAM_SSL_ERR;
}

#endif /* WITH_SSL */

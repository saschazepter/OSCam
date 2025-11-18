#define MODULE_LOG_PREFIX "ssl-openssl"

#include "globals.h"
#include "oscam-time.h"
#include "oscam-string.h"
#include "oscam-ssl.h"

#ifdef WITH_SSL

/* ============================================================
 * BACKEND SELECTOR
 * ============================================================ */
#ifdef WITH_OPENSSL
/* ========================= OPENSSL BACKEND ========================== */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/opensslv.h>

/* Some very old OpenSSL releases (0.9.8 / 1.0.0) don't define these.
 * Define them as 0 so SSL_CTX_set_options() still compiles. */
#ifndef SSL_OP_NO_TLSv1_1
#define SSL_OP_NO_TLSv1_1 0
#endif
#ifndef SSL_OP_NO_TLSv1_2
#define SSL_OP_NO_TLSv1_2 0
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* --------------------------------------------------------------------
 * OpenSSL 1.0.2 compatibility: ASN1_TIME_to_tm()
 *
 * OpenSSL < 1.1.0 does not provide ASN1_TIME_to_tm, so we emulate it
 * using ASN1_TIME_print() + sscanf. Format is typically:
 *   "MMM DD HH:MM:SS YYYY GMT"
 * which is stable enough for our "display validity" use-case.
 * ------------------------------------------------------------------ */
static int ASN1_TIME_to_tm(const ASN1_TIME *t, struct tm *tm)
{
	if (!t || !tm)
		return 0;

	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio)
		return 0;

	if (ASN1_TIME_print(bio, t) <= 0) {
		BIO_free(bio);
		return 0;
	}

	char buf[64];
	int len = BIO_read(bio, buf, sizeof(buf) - 1);
	BIO_free(bio);

	if (len <= 0)
		return 0;

	buf[len] = '\0';

	/* Expected format: "MMM DD HH:MM:SS YYYY GMT" */
	char mon_str[4] = {0};
	int day = 0, year = 0;
	int hour = 0, min = 0, sec = 0;

	if (sscanf(buf, "%3s %d %d:%d:%d %d",
			   mon_str, &day, &hour, &min, &sec, &year) != 6)
		return 0;

	static const char *months = "JanFebMarAprMayJunJulAugSepOctNovDec";
	char *m = strstr(months, mon_str);
	int mon = 0;
	if (m)
		mon = (int)((m - months) / 3);

	memset(tm, 0, sizeof(*tm));
	tm->tm_year = year - 1900;
	tm->tm_mon  = mon;
	tm->tm_mday = day;
	tm->tm_hour = hour;
	tm->tm_min  = min;
	tm->tm_sec  = sec;

	return 1;
}
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

/* Opaque structs defined here (match header typedefs) */
struct oscam_ssl_conf_s {
	SSL_CTX  *ctx;
	X509     *ca_chain;
	X509     *own_cert;
	EVP_PKEY *own_key;
};

struct oscam_ssl_s {
	SSL *ssl;
	int fd;
};

struct oscam_x509_crt_s {
	X509 *crt;
};

struct oscam_pk_context_s {
	EVP_PKEY *pk;
};

/* --- Opaque alloc helpers --- */

oscam_x509_crt *oscam_ssl_cert_new(void)
{
	oscam_x509_crt *crt = calloc(1, sizeof(*crt));
	if (crt)
		oscam_ssl_cert_init(crt);
	return crt;
}

void oscam_ssl_cert_delete(oscam_x509_crt *crt)
{
	if (!crt) return;
	oscam_ssl_cert_free(crt);
	free(crt);
}

oscam_pk_context *oscam_ssl_pk_new(void)
{
	oscam_pk_context *pk = calloc(1, sizeof(*pk));
	return pk;
}

void oscam_ssl_pk_delete(oscam_pk_context *pk)
{
	if (!pk) return;
	oscam_ssl_pk_free(pk);
	free(pk);
}

/* ============================================================
 * OpenSSL Backend Implementation
 * ============================================================ */

int oscam_ssl_global_init(void)
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	return OSCAM_SSL_OK;
}

void oscam_ssl_global_free(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
#endif
}

int oscam_ssl_random(void *buf, size_t len)
{
	if (!buf) return OSCAM_SSL_PARAM;
	return RAND_bytes(buf, len) == 1 ? OSCAM_SSL_OK : OSCAM_SSL_ERR;
}

/* SSL Config object */
oscam_ssl_conf_t *oscam_ssl_conf_build(oscam_ssl_mode_t mode)
{
	oscam_ssl_conf_t *conf = calloc(1, sizeof(*conf));
	if (!conf) return NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	conf->ctx = SSL_CTX_new(SSLv23_server_method());
#else
	conf->ctx = SSL_CTX_new(TLS_server_method());
#endif
	if (!conf->ctx) { free(conf); return NULL; }

/* Enable ECDHE key exchange support */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L && OPENSSL_VERSION_NUMBER < 0x10100000L
	/* OpenSSL 1.0.2: has SSL_CTX_set_ecdh_auto() */
	SSL_CTX_set_ecdh_auto(conf->ctx, 1);
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	/* OpenSSL 1.1.0+ and 3.x: use explicit groups */
	SSL_CTX_set1_groups_list(conf->ctx, "P-256:P-384");
#else
	/* OpenSSL 0.9.8 – 1.0.1: either no ECDHE or configured elsewhere */
	/* nothing */
#endif

#ifdef SSL_CTX_set_min_proto_version
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_CTX_set_options(conf->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
#else
	SSL_CTX_set_min_proto_version(conf->ctx, TLS1_2_VERSION);
#endif
#else
	SSL_CTX_set_options(conf->ctx,
		SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
		SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
#endif

	switch (mode)
	{
		case OSCAM_SSL_MODE_STRICT:
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
			SSL_CTX_set_cipher_list(conf->ctx,
				"TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:"
				"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256");
#else
			SSL_CTX_set_cipher_list(conf->ctx,
				"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
				"DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA");
#endif
			break;

		case OSCAM_SSL_MODE_LEGACY:
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
			SSL_CTX_set_cipher_list(conf->ctx,
				"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
				"AES256-SHA:AES128-SHA");
#else
			SSL_CTX_set_cipher_list(conf->ctx,
				"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
				"AES256-SHA:AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA");
#endif
			break;

		default:
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
			SSL_CTX_set_cipher_list(conf->ctx,
				"TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:"
				"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
				"AES256-SHA:AES128-SHA");
#else
			SSL_CTX_set_cipher_list(conf->ctx,
				"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
				"AES256-SHA:AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA");
#endif
	}

	SSL_CTX_set_verify(conf->ctx, SSL_VERIFY_NONE, NULL);
	return conf;
}

void oscam_ssl_conf_free(oscam_ssl_conf_t *conf)
{
	if (!conf) return;
	if (conf->ctx)      SSL_CTX_free(conf->ctx);
	if (conf->own_key)  EVP_PKEY_free(conf->own_key);
	if (conf->own_cert) X509_free(conf->own_cert);
	if (conf->ca_chain) X509_free(conf->ca_chain);
	free(conf);
}

int oscam_ssl_conf_set_min_tls12(oscam_ssl_conf_t *conf)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_CTX_set_options(conf->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
#else
	SSL_CTX_set_min_proto_version(conf->ctx, TLS1_2_VERSION);
#endif
	return OSCAM_SSL_OK;
}

/* CA load and cert/key load mirror mbedTLS behavior */
int oscam_ssl_conf_load_ca(oscam_ssl_conf_t *conf, const char *ca_pem_path)
{
	if (!conf) return OSCAM_SSL_PARAM;

	if (!ca_pem_path) {
		SSL_CTX_set_verify(conf->ctx, SSL_VERIFY_NONE, NULL);
		return OSCAM_SSL_OK;
	}

	if (!SSL_CTX_load_verify_locations(conf->ctx, ca_pem_path, NULL))
		return OSCAM_SSL_CERT_FAIL;

	SSL_CTX_set_verify(conf->ctx, SSL_VERIFY_PEER, NULL);
	return OSCAM_SSL_OK;
}

int oscam_ssl_conf_use_own_cert_pem(oscam_ssl_conf_t *conf,
									const char *pem_path,
									const char *key_pass)
{
	if (!conf || !pem_path) return OSCAM_SSL_PARAM;

	if (key_pass)
		SSL_CTX_set_default_passwd_cb_userdata(conf->ctx, (void*)key_pass);

	if (!SSL_CTX_use_certificate_chain_file(conf->ctx, pem_path))
		return OSCAM_SSL_CERT_FAIL;

	if (!SSL_CTX_use_PrivateKey_file(conf->ctx, pem_path, SSL_FILETYPE_PEM))
		return OSCAM_SSL_CERT_FAIL;

	if (!SSL_CTX_check_private_key(conf->ctx))
		return OSCAM_SSL_CERT_FAIL;

	return OSCAM_SSL_OK;
}

/* SSL connection */
oscam_ssl_t *oscam_ssl_new(oscam_ssl_conf_t *conf, int fd)
{
	oscam_ssl_t *ssl = calloc(1, sizeof(*ssl));
	if (!ssl) return NULL;

	ssl->ssl = SSL_new(conf->ctx);
	ssl->fd = fd;
	SSL_set_fd(ssl->ssl, fd);

	int ret = SSL_accept(ssl->ssl);
	if (ret <= 0) {
		SSL_free(ssl->ssl);
		free(ssl);
		return NULL;
	}

	return ssl;
}

int oscam_ssl_handshake(oscam_ssl_t *ssl)
{
	int ret = SSL_do_handshake(ssl->ssl);
	if (ret == 1) return OSCAM_SSL_OK;

	int e = SSL_get_error(ssl->ssl, ret);
	return (e == SSL_ERROR_WANT_READ)  ? OSCAM_SSL_WANT_READ :
		   (e == SSL_ERROR_WANT_WRITE) ? OSCAM_SSL_WANT_WRITE :
										OSCAM_SSL_HANDSHAKE_FAIL;
}

int oscam_ssl_handshake_blocking(oscam_ssl_t *ssl, int fd, int timeout)
{
	(void)fd;
	(void)timeout;

	return oscam_ssl_handshake(ssl);
}

int oscam_ssl_accept(oscam_ssl_t *ssl, int fd, int timeout)
{
	(void)fd;
	(void)timeout;

	return oscam_ssl_handshake(ssl);
}

/* IO */
int oscam_ssl_read(oscam_ssl_t *ssl, void *buf, size_t len)
{
	int ret = SSL_read(ssl->ssl, buf, len);
	if (ret >= 0) return ret;
	return OSCAM_SSL_ERR;
}

int oscam_ssl_write(oscam_ssl_t *ssl, const unsigned char *buf, size_t len)
{
	size_t done = 0;
	while (done < len) {
		int r = SSL_write(ssl->ssl, buf + done, len - done);
		if (r <= 0) return OSCAM_SSL_ERR;
		done += r;
	}
	return done;
}

void oscam_ssl_close_notify(oscam_ssl_t *ssl)
{
	SSL_shutdown(ssl->ssl);
}

void oscam_ssl_free(oscam_ssl_t *ssl)
{
	if (!ssl) return;
	SSL_free(ssl->ssl);
	free(ssl);
}

/* Peer info */
int oscam_ssl_get_peer_cn(oscam_ssl_t *ssl, char *out, size_t outlen)
{
	X509 *peer = SSL_get_peer_certificate(ssl->ssl);
	if (!peer) return OSCAM_SSL_ERR;

	X509_NAME *subj = X509_get_subject_name(peer);
	int idx = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
	if (idx < 0) { X509_free(peer); return OSCAM_SSL_ERR; }

	X509_NAME_ENTRY *e = X509_NAME_get_entry(subj, idx);
	ASN1_STRING     *cn = X509_NAME_ENTRY_get_data(e);
	unsigned char *utf8 = NULL;

	int len = ASN1_STRING_to_UTF8(&utf8, cn);
	if (len <= 0 || (size_t)len >= outlen) {
		X509_free(peer);
		return OSCAM_SSL_ERR;
	}

	memcpy(out, utf8, len);
	out[len] = '\0';
	OPENSSL_free(utf8);
	X509_free(peer);
	return OSCAM_SSL_OK;
}

const char *oscam_ssl_version(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	return OpenSSL_version(OPENSSL_VERSION);
#else
	return SSLeay_version(SSLEAY_VERSION);
#endif
}

/* basic error mapping */
int oscam_ssl_get_error(oscam_ssl_t *ssl, int ret)
{
	(void)ssl;
	(void)ret;

	return OSCAM_SSL_ERR;
}

void oscam_ssl_strerror(int err, char *buf, size_t len)
{
	ERR_error_string_n(err, buf, len);
}

/* x509 */
int oscam_ssl_cert_parse(oscam_x509_crt *crt, const unsigned char *buf, size_t len)
{
	BIO *bio = BIO_new_mem_buf(buf, len);
	if (!bio) return OSCAM_SSL_ERR;

	crt->crt = PEM_read_bio_X509(bio, NULL, 0, NULL);
	if (!crt->crt) {
		BIO_reset(bio);
		crt->crt = d2i_X509_bio(bio, NULL);  // try DER
	}

	BIO_free(bio);
	return crt->crt ? OSCAM_SSL_OK : OSCAM_SSL_CERT_FAIL;
}

int oscam_ssl_cert_parse_file(oscam_x509_crt *crt, const char *path)
{
	FILE *f = fopen(path, "rb");
	if (!f) return OSCAM_SSL_CERT_FAIL;
	crt->crt = PEM_read_X509(f, NULL, NULL, NULL);
	fclose(f);
	return crt->crt ? OSCAM_SSL_OK : OSCAM_SSL_CERT_FAIL;
}

void oscam_ssl_cert_init(oscam_x509_crt *crt)
{
	crt->crt = NULL;
}

void oscam_ssl_cert_free(oscam_x509_crt *crt)
{
	if (crt->crt) X509_free(crt->crt);
	crt->crt = NULL;
}

int oscam_ssl_cert_verify(oscam_x509_crt *crt, oscam_x509_crt *trust)
{
	X509_STORE *st = X509_STORE_new();
	X509_STORE_add_cert(st, trust->crt);
	X509_STORE_CTX *ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(ctx, st, crt->crt, NULL);
	int ret = X509_verify_cert(ctx);
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(st);
	return ret == 1 ? OSCAM_SSL_OK : OSCAM_SSL_CERT_FAIL;
}

oscam_x509_crt *oscam_ssl_cert_get_next(oscam_x509_crt *crt)
{
	(void)crt;
	/* OpenSSL does NOT chain X509 objects internally (unlike mbedTLS). */
	return NULL;
}

const void *oscam_ssl_cert_get_subject(const oscam_x509_crt *crt)
{
	if (!crt || !crt->crt) return NULL;
	return X509_get_subject_name(crt->crt);
}

const void *oscam_ssl_cert_get_issuer(const oscam_x509_crt *crt)
{
	if (!crt || !crt->crt) return NULL;
	return (const void *)X509_get_issuer_name(crt->crt);
}

int oscam_ssl_cert_dn_gets(char *buf, size_t size, const void *dn)
{
	if (!buf || size == 0 || !dn)
		return OSCAM_SSL_ERR;

	buf[0] = '\0';

	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio)
		return OSCAM_SSL_ERR;

	/* OpenSSL 0.9.8 – 3.x compatible print */
	if (X509_NAME_print_ex(bio, (X509_NAME *)dn, 0, XN_FLAG_RFC2253) < 0)
	{
		BIO_free(bio);
		return OSCAM_SSL_ERR;
	}

	char *ptr = NULL;
	long len = BIO_get_mem_data(bio, &ptr);

	if (len > 0) {
		size_t copy = (len < (long)size - 1) ? (size_t)len : size - 1;
		memcpy(buf, ptr, copy);
		buf[copy] = '\0';
	}

	BIO_free(bio);
	return OSCAM_SSL_OK;
}

void oscam_ssl_cert_serial_gets(const oscam_x509_crt *crt, char *buf, size_t len)
{
	if (!crt || !crt->crt || !buf || !len) return;
	ASN1_INTEGER *serial = X509_get_serialNumber(crt->crt);
	BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
	char *hex = BN_bn2hex(bn);
	cs_strncpy(buf, hex, len);
	OPENSSL_free(hex);
	BN_free(bn);
}


int oscam_ssl_cert_get_version(const oscam_x509_crt *crt)
{
	if (!crt || !crt->crt) return -1;
	/* X509 version is 0-based; convert to human numbering */
	long ver = X509_get_version(crt->crt);
	return (int)ver + 1;
}

void oscam_ssl_cert_raw(const oscam_x509_crt *crt,
						const unsigned char **buf, size_t *len)
{
	if (!crt || !crt->crt) {
		if (buf) *buf = NULL;
		if (len) *len = 0;
		return;
	}

	/* We need to re-encode DER (OpenSSL stores ASN.1 internally) */
	int l = i2d_X509(crt->crt, NULL);
	if (l <= 0) {
		*buf = NULL;
		*len = 0;
		return;
	}

	unsigned char *tmp = malloc(l);
	unsigned char *p = tmp;
	l = i2d_X509(crt->crt, &p);

	*buf = tmp;
	*len = (size_t)l;
}

/* ----------------- VALIDITY INFO ----------------- */
void oscam_ssl_cert_get_validity(const oscam_x509_crt *crt, oscam_cert_time_t *from, oscam_cert_time_t *to)
{
	if (!crt || !crt->crt || !from || !to)
		return;

	const ASN1_TIME *nb = X509_get_notBefore(crt->crt);
	const ASN1_TIME *na = X509_get_notAfter(crt->crt);

	struct tm tm_from, tm_to;
	memset(&tm_from, 0, sizeof(tm_from));
	memset(&tm_to,   0, sizeof(tm_to));

	/* Convert ASN1_TIME → struct tm */
	ASN1_TIME_to_tm(nb, &tm_from);
	ASN1_TIME_to_tm(na, &tm_to);

	/* Fill our simple struct */
	from->year = tm_from.tm_year + 1900;
	from->mon  = tm_from.tm_mon  + 1;
	from->day  = tm_from.tm_mday;
	from->hour = tm_from.tm_hour;
	from->min  = tm_from.tm_min;
	from->sec  = tm_from.tm_sec;

	to->year = tm_to.tm_year + 1900;
	to->mon  = tm_to.tm_mon  + 1;
	to->day  = tm_to.tm_mday;
	to->hour = tm_to.tm_hour;
	to->min  = tm_to.tm_min;
	to->sec  = tm_to.tm_sec;
}

int oscam_ssl_pk_get_bits(const oscam_pk_context *pk)
{
	if (!pk || !pk->pk) return 0;
	return EVP_PKEY_bits(pk->pk);
}

/* ----------------- KEY LENGTH ----------------- */
int oscam_ssl_pk_get_bitlen(const oscam_pk_context *pk)
{
	if (!pk || !pk->pk) return 0;
	return EVP_PKEY_bits(pk->pk);
}

const oscam_pk_context *oscam_ssl_cert_get_pubkey(const oscam_x509_crt *crt)
{
	if (!crt || !crt->crt) return NULL;
	EVP_PKEY *pk = X509_get_pubkey(crt->crt);
	if (!pk) return NULL;

	oscam_pk_context *wrap = calloc(1, sizeof(*wrap));
	wrap->pk = pk;
	return wrap;
}

void oscam_ssl_pk_free(oscam_pk_context *pk)
{
	if (!pk) return;
	EVP_PKEY_free(pk->pk);
}

int oscam_ssl_pk_clone(oscam_pk_context *dst, const oscam_pk_context *src)
{
	if (!dst || !src || !src->pk)
		return OSCAM_SSL_PARAM;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	CRYPTO_add(&((EVP_PKEY *)src->pk)->references, 1, CRYPTO_LOCK_EVP_PKEY);
	dst->pk = src->pk;
#else
	dst->pk = EVP_PKEY_dup(src->pk);
#endif
	return dst->pk ? OSCAM_SSL_OK : OSCAM_SSL_ERR;
}

int oscam_ssl_pk_get_type(const oscam_pk_context *pk)
{
	if (!pk || !pk->pk)
		return OSCAM_PK_NONE;

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	/* OpenSSL 1.0.0+ has EVP_PKEY_base_id() */
	int t = EVP_PKEY_base_id(pk->pk);

	switch (t)
	{
		case EVP_PKEY_RSA: return OSCAM_PK_RSA;
		case EVP_PKEY_EC : return OSCAM_PK_EC;
		default:           return OSCAM_PK_NONE;
	}
#else
	/* OpenSSL 0.9.8: no EVP_PKEY_base_id(), probe the type */
	RSA *rsa = EVP_PKEY_get1_RSA(pk->pk);
	if (rsa) {
		RSA_free(rsa);
		return OSCAM_PK_RSA;
	}
# ifdef EVP_PKEY_EC
	EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pk->pk);
	if (ec) {
		EC_KEY_free(ec);
		return OSCAM_PK_EC;
	}
# endif
	return OSCAM_PK_NONE;
#endif
}

int oscam_ssl_pk_verify(oscam_pk_context *pk,
						const unsigned char *hash, size_t hash_len,
						const unsigned char *sig,  size_t sig_len)
{
	if (!pk || !pk->pk || !hash || !sig)
		return -1;

	EVP_PKEY *pkey = pk->pk;

	/* ================================================================
	 * Modern EVP_PKEY path (OpenSSL >= 1.0.2)
	 *   - used on 1.0.2, 1.1.x and 3.x+
	 *   - treats `hash` as already-digested SHA-256
	 * ================================================================ */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L

	const EVP_MD *md = EVP_sha256();
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx)
		return -1;

	int ok  = 1;
	int ret = -1;

	/* Initialize verification context */
	if (ok) ok = (EVP_PKEY_verify_init(ctx) > 0);

	/* Configure signature to use SHA256 digest (but DO NOT hash `hash` again) */
	if (ok && md) ok = (EVP_PKEY_CTX_set_signature_md(ctx, md) > 0);

	/* EVP_PKEY_verify() takes the precomputed digest directly */
	if (ok)
		ret = EVP_PKEY_verify(ctx, sig, sig_len, hash, hash_len);

	EVP_PKEY_CTX_free(ctx);
	return (ret == 1) ? 0 : -1;

#else /* OPENSSL_VERSION_NUMBER < 0x10002000L */

/* ================================================================
 * Legacy path: OpenSSL 0.9.8 – 1.0.1
 *   - RSA_verify / ECDSA_verify expect precomputed digest
 * ================================================================ */

	/* Try RSA first */
	RSA *rsa = EVP_PKEY_get1_RSA(pkey);
	if (rsa) {
		int ok = RSA_verify(NID_sha256,
							hash, (unsigned int)hash_len,
							sig,  (unsigned int)sig_len,
							rsa);
		RSA_free(rsa);
		return ok == 1 ? 0 : -1;
	}

# ifdef EVP_PKEY_EC
	/* Then EC */
	EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(pkey);
	if (eckey) {
		int ok = ECDSA_verify(0,
							  hash, (int)hash_len,
							  sig,  (int)sig_len,
							  eckey);
		EC_KEY_free(eckey);
		return ok == 1 ? 0 : -1;
	}
# endif

	return -1;

#endif /* version split */
}

int oscam_ssl_generate_selfsigned(const char *path)
{
	int ret = OSCAM_SSL_ERR;
	EVP_PKEY *pkey = NULL;
	X509 *crt = NULL;
	FILE *f = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_PKEY_CTX *kctx = NULL;
#else
	RSA *rsa = NULL;
#endif

	struct utsname un;
	const char *cn;
	char subject[256];
	time_t now = time(NULL);
	struct tm start_tm, end_tm;

	if (!path || !*path)
		return OSCAM_SSL_ERR;

	/* ---- Create empty PKEY ---- */
	pkey = EVP_PKEY_new();
	if (!pkey)
		goto cleanup;

	/* ===============================================
	 * KEY GENERATION
	 * =============================================== */

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

	/* ---- OpenSSL 3.x (modern API only) ---- */
	kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!kctx) goto cleanup;

	if (EVP_PKEY_keygen_init(kctx) <= 0) goto cleanup;
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 4096) <= 0) goto cleanup;
	if (EVP_PKEY_keygen(kctx, &pkey) <= 0) goto cleanup;

	EVP_PKEY_CTX_free(kctx);
	kctx = NULL;

#else

	/* ---- Legacy OpenSSL (<3.0) ---- */
	BIGNUM *e = BN_new();
	if (!e) goto cleanup;

	if (!BN_set_word(e, RSA_F4)) { BN_free(e); goto cleanup; }

	rsa = RSA_new();
	if (!rsa) { BN_free(e); goto cleanup; }

	if (!RSA_generate_key_ex(rsa, 4096, e, NULL)) {
		BN_free(e);
		goto cleanup;
	}
	BN_free(e);

	if (!EVP_PKEY_assign_RSA(pkey, rsa))
		goto cleanup;

	rsa = NULL; /* transferred */
#endif

	/* ===============================================
	 * CERTIFICATE BUILD
	 * =============================================== */

	crt = X509_new();
	if (!crt) goto cleanup;

	X509_set_version(crt, 2);

	/* Serial random */
	{
		unsigned char serial_bytes[16];
		ASN1_INTEGER *serial = X509_get_serialNumber(crt);
		BIGNUM *bn;

		if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1)
			goto cleanup;
		bn = BN_bin2bn(serial_bytes, sizeof(serial_bytes), NULL);
		if (!bn || !BN_to_ASN1_INTEGER(bn, serial)) {
			BN_free(bn);
			goto cleanup;
		}
		BN_free(bn);
	}

	/* Validity */
	gmtime_r(&now, &start_tm);
	end_tm = start_tm;
	end_tm.tm_year += OSCAM_SSL_CERT_YEARS;

	if (!X509_gmtime_adj(X509_get_notBefore(crt), 0)) goto cleanup;
	if (!X509_gmtime_adj(X509_get_notAfter(crt),
						 (long)3600 * 24 * 365 * OSCAM_SSL_CERT_YEARS))
		goto cleanup;

	if (!X509_set_pubkey(crt, pkey))
		goto cleanup;

	/* Subject CN */
	if (uname(&un) == 0 && un.nodename[0])
		cn = un.nodename;
	else
		cn = "localhost";

	snprintf(subject, sizeof(subject),
			 "CN=%s,O=OSCam AutoCert,OU=Private WebIf Certificate", cn);

	X509_NAME *name = X509_NAME_new();
	if (!name) goto cleanup;

	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
							   (const unsigned char*)cn, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
							   (unsigned char*)"OSCam AutoCert", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,
							   (unsigned char*)"Private WebIf Certificate", -1, -1, 0);

	X509_set_subject_name(crt, name);
	X509_set_issuer_name(crt, name);
	X509_NAME_free(name);

	/* Extensions */
	{
		X509V3_CTX ctx;
		X509V3_set_ctx_nodb(&ctx);
		X509V3_set_ctx(&ctx, crt, crt, NULL, NULL, 0);

		X509_EXTENSION *ext;

		ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE");
		if (ext) { X509_add_ext(crt, ext, -1); X509_EXTENSION_free(ext); }

		ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage,
								  "digitalSignature,keyEncipherment");
		if (ext) { X509_add_ext(crt, ext, -1); X509_EXTENSION_free(ext); }

		ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_netscape_cert_type, "server");
		if (ext) { X509_add_ext(crt, ext, -1); X509_EXTENSION_free(ext); }
	}

	/* SAN */
	{
		GENERAL_NAMES *gens = sk_GENERAL_NAME_new_null();
		GENERAL_NAME *gn;
		X509_EXTENSION *ext;

		/* DNS: CN */
		gn = GENERAL_NAME_new();
		ASN1_IA5STRING *dns1 = ASN1_IA5STRING_new();
		ASN1_STRING_set(dns1, cn, strlen(cn));
		GENERAL_NAME_set0_value(gn, GEN_DNS, dns1);
		sk_GENERAL_NAME_push(gens, gn);

		/* DNS: CN.local */
		char buf[256];
		snprintf(buf, sizeof(buf), "%s.local", cn);
		gn = GENERAL_NAME_new();
		ASN1_IA5STRING *dns2 = ASN1_IA5STRING_new();
		ASN1_STRING_set(dns2, buf, strlen(buf));
		GENERAL_NAME_set0_value(gn, GEN_DNS, dns2);
		sk_GENERAL_NAME_push(gens, gn);

		/* IPv4 127.0.0.1 */
		gn = GENERAL_NAME_new();
		{
			unsigned char ip4[4] = {127,0,0,1};
			ASN1_OCTET_STRING *ip = ASN1_OCTET_STRING_new();
			ASN1_OCTET_STRING_set(ip, ip4, 4);
			GENERAL_NAME_set0_value(gn, GEN_IPADD, ip);
			sk_GENERAL_NAME_push(gens, gn);
		}

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
		/* IPv6 ::1 */
		gn = GENERAL_NAME_new();
		{
			unsigned char ip6[16] = {0};
			ip6[15] = 1;
			ASN1_OCTET_STRING *ipx = ASN1_OCTET_STRING_new();
			ASN1_OCTET_STRING_set(ipx, ip6, 16);
			GENERAL_NAME_set0_value(gn, GEN_IPADD, ipx);
			sk_GENERAL_NAME_push(gens, gn);
		}
#else
		cs_log("SSL: IPv6 SAN skipped (OpenSSL < 1.0.2)");
#endif

		ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, gens);
		if (ext) {
			X509_add_ext(crt, ext, -1);
			X509_EXTENSION_free(ext);
		}
		sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
	}

	/* Sign cert */
	if (!X509_sign(crt, pkey, EVP_sha256())) {
		if (!X509_sign(crt, pkey, EVP_sha1()))
			goto cleanup;
	}

	/* Write PEM (cert + key) */
	f = fopen(path, "wb");
	if (!f) goto cleanup;

	if (!PEM_write_X509(f, crt))
		goto cleanup;
	if (!PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL))
		goto cleanup;

	ret = OSCAM_SSL_OK;

cleanup:
	if (crt) X509_free(crt);
	if (pkey) EVP_PKEY_free(pkey);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (kctx) EVP_PKEY_CTX_free(kctx);
#else
	if (rsa) RSA_free(rsa);
#endif

	if (f) fclose(f);
	return ret;
}

int oscam_ssl_get_fd(oscam_ssl_t *ssl)
{
	return ssl ? ssl->fd : -1;
}

int oscam_ssl_pending(oscam_ssl_t *ssl)
{
	if (!ssl || !ssl->ssl) return 0;
	return SSL_pending(ssl->ssl);
}

#endif /* WITH_OPENSSL */

#endif /* WITH_SSL */

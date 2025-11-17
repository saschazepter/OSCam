#define MODULE_LOG_PREFIX "ssl"

#include "globals.h"
#include "oscam-time.h"
#include "oscam-string.h"
#include "oscam-ssl.h"

#ifdef WITH_SSL

#define OSCAM_SSL_CERT_YEARS 2

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
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	/* OpenSSL 1.0.2 and older */
	SSL_CTX_set_ecdh_auto(conf->ctx, 1);
#else
	/* OpenSSL 1.1.0+ and 3.x */
	SSL_CTX_set1_groups_list(conf->ctx, "P-256:P-384");
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

/* hashing */
int oscam_ssl_sha1(const unsigned char *data, size_t len, unsigned char *out)
{
	unsigned int ol = 0;
	return EVP_Digest(data, len, out, &ol, EVP_sha1(), NULL) == 1 ? 0 : -1;
}

int oscam_ssl_sha256(const unsigned char *data, size_t len, unsigned char *out)
{
	unsigned int ol = 0;
	return EVP_Digest(data, len, out, &ol, EVP_sha256(), NULL) == 1 ? 0 : -1;
}

int oscam_ssl_sha256_stream(const unsigned char *data1, size_t len1,
							const unsigned char *data2, size_t len2,
							unsigned char *out)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
#else
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
#endif
	unsigned int ol = 0;
	if (!ctx) return -1;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
		(data1 && len1 && EVP_DigestUpdate(ctx, data1, len1) != 1) ||
		(data2 && len2 && EVP_DigestUpdate(ctx, data2, len2) != 1) ||
		EVP_DigestFinal_ex(ctx, out, &ol) != 1) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		EVP_MD_CTX_destroy(ctx);
#else
		EVP_MD_CTX_free(ctx);
#endif
		return -1;
	}
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX_destroy(ctx);
#else
	EVP_MD_CTX_free(ctx);
#endif
	return 0;
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
	if (!pk || !pk->pk) return OSCAM_PK_NONE;

	int t = EVP_PKEY_base_id(pk->pk);

	switch (t)
	{
		case EVP_PKEY_RSA: return OSCAM_PK_RSA;
		case EVP_PKEY_EC : return OSCAM_PK_EC;
		default: return OSCAM_PK_NONE;
	}
}

int oscam_ssl_pk_verify(oscam_pk_context *pk, const unsigned char *hash, size_t hash_len, const unsigned char *sig,  size_t sig_len)
{
	if (!pk || !pk->pk || !hash || !sig)
		return OSCAM_SSL_ERR;

	int type = EVP_PKEY_base_id(pk->pk);

	/* ECDSA: use digest directly, like mbedtls_pk_verify */
	if (type == EVP_PKEY_EC)
	{
		EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(pk->pk);
		if (!eckey)
			return OSCAM_SSL_ERR;

		/* ECDSA_verify() takes 'dgst' = already-hashed message */
		int ok = ECDSA_verify(0, hash, (int)hash_len,
							  sig, (int)sig_len, eckey);
		EC_KEY_free(eckey);
		return (ok == 1) ? OSCAM_SSL_OK : OSCAM_SSL_ERR;
	}

	/* RSA: also verify on precomputed digest */
	if (type == EVP_PKEY_RSA)
	{
		RSA *rsa = EVP_PKEY_get1_RSA(pk->pk);
		if (!rsa)
			return OSCAM_SSL_ERR;

		/* NID_sha256: the digest algorithm that produced 'hash' */
		int ok = RSA_verify(NID_sha256,
							hash, (unsigned int)hash_len,
							sig,  (unsigned int)sig_len,
							rsa);
		RSA_free(rsa);
		return (ok == 1) ? OSCAM_SSL_OK : OSCAM_SSL_ERR;
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	/* Fallback for other key types – still treat 'hash' as digest */
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pk->pk, NULL);
	if (!ctx)
		return OSCAM_SSL_ERR;

	int ret = EVP_PKEY_verify_init(ctx);
	if (ret == 1)
		ret = EVP_PKEY_verify(ctx, sig, sig_len, hash, hash_len);

	EVP_PKEY_CTX_free(ctx);
	return (ret == 1) ? OSCAM_SSL_OK : OSCAM_SSL_ERR;
#else
	return OSCAM_SSL_ERR;
#endif
}

int oscam_ssl_generate_selfsigned(const char *path)
{
	int ret = OSCAM_SSL_ERR;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *kctx = NULL;
	X509 *crt = NULL;
	FILE *f = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000L
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

	if (!PEM_write_X509(f, crt)) { fclose(f); goto cleanup; }
	if (!PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL)) {
		fclose(f);
		goto cleanup;
	}

	fclose(f);
	ret = OSCAM_SSL_OK;

cleanup:
	if (f) fclose(f);
	if (crt) X509_free(crt);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (rsa) RSA_free(rsa);
#endif
	if (pkey) EVP_PKEY_free(pkey);
	if (kctx) EVP_PKEY_CTX_free(kctx);

	return ret;
}

#else /* WITH_OPENSSL -------------------------------------------------- */
/* ========================= MBEDTLS BACKEND ========================== */

#if defined(MBEDTLS_DEBUG_C)
#include "mbedtls/debug.h"
#endif

#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/version.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/rsa.h"

/* Opaque structs defined here (match header typedefs) */

struct oscam_ssl_conf_s {
	mbedtls_ssl_config       ssl_conf;
	mbedtls_x509_crt         ca_chain;
	mbedtls_x509_crt         own_cert;
	mbedtls_pk_context       own_key;
	mbedtls_entropy_context  entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
};

struct oscam_ssl_s {
	mbedtls_ssl_context ssl;
	mbedtls_net_context net;
};

struct oscam_x509_crt_s {
	mbedtls_x509_crt crt;
};

struct oscam_pk_context_s {
	mbedtls_pk_context pk;
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
	if (pk)
		mbedtls_pk_init(&pk->pk);
	return pk;
}

void oscam_ssl_pk_delete(oscam_pk_context *pk)
{
	if (!pk) return;
	oscam_ssl_pk_free(pk);
	free(pk);
}

/* ---------------------------------------------------------------------
 * Global RNG state
 * ------------------------------------------------------------------ */
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_drbg;
static int g_init_ref = 0;

/* ---------------------------------------------------------------------
 * HELPERS
 * ------------------------------------------------------------------ */
static int map_tls_err(int ret)
{
	if (ret == MBEDTLS_ERR_SSL_WANT_READ)
		return OSCAM_SSL_WANT_READ;
	if (ret == MBEDTLS_ERR_SSL_WANT_WRITE)
		return OSCAM_SSL_WANT_WRITE;
	return OSCAM_SSL_ERR;
}

static int san_write_dns(unsigned char **p, unsigned char *start, const char *name)
{
	int ret;
	const unsigned char *s = (const unsigned char *) name;
	size_t nlen = strlen(name);

	/* Write IA5 string bytes, then wrap with context tag [2] */
	MBEDTLS_ASN1_CHK_ADD(ret, mbedtls_asn1_write_raw_buffer(p, start, s, nlen));
	MBEDTLS_ASN1_CHK_ADD(ret, mbedtls_asn1_write_len(p, start, nlen));
	MBEDTLS_ASN1_CHK_ADD(ret, mbedtls_asn1_write_tag(p, start,
						 MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2));
	return 0;
}

static int san_write_ip(unsigned char **p, unsigned char *start,
						const unsigned char *ip, size_t iplen)
{
	int ret;
	/* GeneralName iPAddress is OCTET STRING with context tag [7] (primitive) */
	MBEDTLS_ASN1_CHK_ADD(ret, mbedtls_asn1_write_raw_buffer(p, start, ip, iplen));
	MBEDTLS_ASN1_CHK_ADD(ret, mbedtls_asn1_write_len(p, start, iplen));
	MBEDTLS_ASN1_CHK_ADD(ret, mbedtls_asn1_write_tag(p, start,
						 MBEDTLS_ASN1_CONTEXT_SPECIFIC | 7));
	return 0;
}

/* Build SubjectAltName DER and attach it as non-critical extension */
static int write_san_ext_and_attach(mbedtls_x509write_cert *crt, const char *cn)
{
	unsigned char buf[512];
	unsigned char *p = buf + sizeof(buf);
	unsigned char *const start = p;
	int ret;

	/* Values to add (reverse order, since we write backwards) */
	static const unsigned char ip6[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
	static const unsigned char ip4[4]  = { 127,0,0,1 };
	char cn_local[128];
	snprintf(cn_local, sizeof(cn_local), "%s.local", cn);

	/* IP: ::1 */
	MBEDTLS_ASN1_CHK_ADD(ret, san_write_ip(&p, buf, ip6, sizeof(ip6)));
	/* IP: 127.0.0.1 */
	MBEDTLS_ASN1_CHK_ADD(ret, san_write_ip(&p, buf, ip4, sizeof(ip4)));
	/* DNS: <cn>.local */
	MBEDTLS_ASN1_CHK_ADD(ret, san_write_dns(&p, buf, cn_local));
	/* DNS: <cn> */
	MBEDTLS_ASN1_CHK_ADD(ret, san_write_dns(&p, buf, cn));

	/* Wrap as SEQUENCE OF GeneralName */
	size_t gn_len = (size_t)(start - p);
	MBEDTLS_ASN1_CHK_ADD(ret, mbedtls_asn1_write_len(&p, buf, gn_len));
	MBEDTLS_ASN1_CHK_ADD(ret, mbedtls_asn1_write_tag(&p, buf,
						 MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	/* Attach SAN extension (OID 2.5.29.17) */
	return mbedtls_x509write_crt_set_extension(
		crt, MBEDTLS_OID_SUBJECT_ALT_NAME,
		MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),
		0 /* non-critical */, p, (size_t)(start - p));
}

/* classify peer-abort alerts we want to silence in logs */
static inline int is_benign_handshake_abort(int ret)
{
	return ret == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE /* -0x7780 */
		|| ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY   /* -0x7880 */
		|| ret == MBEDTLS_ERR_SSL_CONN_EOF;           /* -0x6100 */
}

#if defined(MBEDTLS_DEBUG_C)
static void oscam_ssl_debug(void *ctx, int level, const char *file, int line, const char *str)
{
	(void)ctx;  // suppress unused warning
	const char *lvl = "DBG";
	if (level == 1) lvl = "ERR";
	else if (level == 2) lvl = "WARN";
	else if (level == 3) lvl = "INFO";
	else if (level == 4) lvl = "DBG";

	cs_log("[mbedtls %s] %s:%d: %s", lvl, file, line, str);
}

static const char *grp_name(mbedtls_ecp_group_id id)
{
#if defined(MBEDTLS_ECP_C)
	switch (id) {
		case MBEDTLS_ECP_DP_SECP256R1: return "secp256r1";
		case MBEDTLS_ECP_DP_SECP384R1: return "secp384r1";
		case MBEDTLS_ECP_DP_SECP521R1: return "secp521r1";
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
		case MBEDTLS_ECP_DP_CURVE25519: return "x25519";
#endif
		default: return "unknown";
	}
#else
	return "n/a";
#endif
}

static inline mbedtls_ecp_group_id get_group_id_from_pk(const mbedtls_pk_context *pk)
{
#if defined(MBEDTLS_PK_HAVE_ECC)
	const mbedtls_ecp_keypair *ec = mbedtls_pk_ec(*pk);
	if (ec == NULL)
		return MBEDTLS_ECP_DP_NONE;
	return ec->grp.id;
#else
	(void) pk;
	return MBEDTLS_ECP_DP_NONE;
#endif
}

static void warn_if_ec_curve_not_advertised(const mbedtls_x509_crt *crt,
											const mbedtls_pk_context *key,
											const uint16_t *adv_groups)
{
#if defined(MBEDTLS_ECP_C)
	if (!crt || !key || !adv_groups) return;
	if (!(mbedtls_pk_get_type(key) == MBEDTLS_PK_ECKEY ||
		  mbedtls_pk_get_type(key) == MBEDTLS_PK_ECDSA))
		return;

	uint16_t need = 0;
	switch (get_group_id_from_pk(key)) {
		case MBEDTLS_ECP_DP_SECP256R1: need = MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1; break;
		case MBEDTLS_ECP_DP_SECP384R1: need = MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1; break;
		case MBEDTLS_ECP_DP_SECP521R1: need = MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1; break;
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
		case MBEDTLS_ECP_DP_CURVE25519: need = MBEDTLS_SSL_IANA_TLS_GROUP_X25519; break;
#endif
		default: return;
	}

	for (const uint16_t *g = adv_groups; g && *g; g++) {
		if (*g == need) return;
	}
	cs_log("SSL: WARNING: server key curve (%s) not in advertised groups; some clients will fail",
		   grp_name(get_group_id_from_pk	(key)));
#else
	(void)crt; (void)key; (void)adv_groups;
#endif
}

static const char *pk_type_name(mbedtls_pk_type_t t)
{
	switch (t) {
		case MBEDTLS_PK_RSA:   return "RSA";
		case MBEDTLS_PK_ECKEY: return "ECDSA";
		case MBEDTLS_PK_ECDSA: return "ECDSA";
		default:               return "UNKNOWN";
	}
}
#endif

/* ---------------------------------------------------------------------
 * Global init / free
 * ------------------------------------------------------------------ */
extern int mbedtls_hardware_poll( void *data, unsigned char *output, size_t len, size_t *olen );

int oscam_ssl_global_init(void)
{
	if (g_init_ref++ > 0)
		return OSCAM_SSL_OK;

	mbedtls_platform_setup(NULL);
	mbedtls_entropy_init(&g_entropy);
	mbedtls_ctr_drbg_init(&g_drbg);

	/* ADD THIS: register a strong source */
	mbedtls_entropy_add_source(&g_entropy,
								mbedtls_hardware_poll, /* or your poll fn */
								NULL,
								32, /* minimum bytes the source can return */
								MBEDTLS_ENTROPY_SOURCE_STRONG);

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
		/* Free global MbedTLS contexts */
		mbedtls_ctr_drbg_free(&g_drbg);
		mbedtls_entropy_free(&g_entropy);

		/* Deinitialize custom platform layer (static allocator, hooks, etc.) */
		mbedtls_platform_teardown(NULL);

		/* defensive cleanup to ensure contexts aren’t reused */
		memset(&g_drbg, 0, sizeof(g_drbg));
		memset(&g_entropy, 0, sizeof(g_entropy));
	}
}

/* ---------------------------------------------------------------------
 * Configuration object
 * ------------------------------------------------------------------ */
oscam_ssl_conf_t *oscam_ssl_conf_build(oscam_ssl_mode_t mode)
{
	oscam_ssl_conf_t *conf = calloc(1, sizeof(*conf));
	if (!conf)
		return NULL;

	/* ---- Initialize base contexts ---- */
	mbedtls_ssl_config_init(&conf->ssl_conf);
	mbedtls_x509_crt_init(&conf->ca_chain);
	mbedtls_x509_crt_init(&conf->own_cert);
	mbedtls_pk_init(&conf->own_key);
	mbedtls_entropy_init(&conf->entropy);
	mbedtls_ctr_drbg_init(&conf->ctr_drbg);

	mbedtls_entropy_add_source(&conf->entropy,
								mbedtls_hardware_poll, /* or your poll fn */
								NULL,
								32,
								MBEDTLS_ENTROPY_SOURCE_STRONG);

	const char *pers = "oscam_webif_conf";
	if (mbedtls_ctr_drbg_seed(&conf->ctr_drbg, mbedtls_entropy_func, &conf->entropy,
								(const unsigned char *)pers, strlen(pers)) != 0) {
		oscam_ssl_conf_free(conf);
		return NULL;
	}

	mbedtls_ssl_conf_rng(&conf->ssl_conf, mbedtls_ctr_drbg_random, &conf->ctr_drbg);

	/* ---- Configure as SERVER ---- */
	if (mbedtls_ssl_config_defaults(&conf->ssl_conf,
									MBEDTLS_SSL_IS_SERVER,
									MBEDTLS_SSL_TRANSPORT_STREAM,
									MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
		oscam_ssl_conf_free(conf);
		return NULL;
	}

#if defined(MBEDTLS_DEBUG_C)
	mbedtls_ssl_conf_dbg(&conf->ssl_conf, oscam_ssl_debug, NULL);
	mbedtls_debug_set_threshold(4);  // 0 = off, 1..4 = increasing verbosity
#endif

	/* ---- Common defaults ---- */
	mbedtls_ssl_conf_rng(&conf->ssl_conf, mbedtls_ctr_drbg_random, &conf->ctr_drbg);
	mbedtls_ssl_conf_authmode(&conf->ssl_conf, MBEDTLS_SSL_VERIFY_NONE);

	/* Default TLS version range */
	int min_minor = MBEDTLS_SSL_MINOR_VERSION_3;  /* TLS 1.2 */
	int max_minor = MBEDTLS_SSL_MINOR_VERSION_4;  /* TLS 1.3 */

	/* Cipher suite selection */
	const int *suites = NULL;
	static const int suites_default[] = {
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		0
	};
	static const int suites_strict[] = {
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
		MBEDTLS_TLS1_3_AES_256_GCM_SHA384,
		MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
#endif
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		0
	};
	static const int suites_legacy[] = {
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA,
		MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA,
		0
	};

	switch (mode) {
		case OSCAM_SSL_MODE_STRICT:
			min_minor = MBEDTLS_SSL_MINOR_VERSION_3;
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
			max_minor = MBEDTLS_SSL_MINOR_VERSION_4;
#else
			/* Fallback to strong TLS 1.2 only if TLS 1.3 is disabled */
			max_minor = MBEDTLS_SSL_MINOR_VERSION_3;
#endif
			suites = suites_strict;
			break;
		case OSCAM_SSL_MODE_LEGACY:
			suites = suites_legacy;
			max_minor = MBEDTLS_SSL_MINOR_VERSION_3;  /* lock to TLS 1.2 */
			break;
		default:
			suites = suites_default;
			break;
	}

	/* Apply version limits and cipher suites */
	mbedtls_ssl_conf_min_version(&conf->ssl_conf, MBEDTLS_SSL_MAJOR_VERSION_3, min_minor);
	mbedtls_ssl_conf_max_version(&conf->ssl_conf, MBEDTLS_SSL_MAJOR_VERSION_3, max_minor);
	mbedtls_ssl_conf_ciphersuites(&conf->ssl_conf, suites);

	/* Supported groups (curve list) */
	static const uint16_t groups_all[] = {
#if defined(MBEDTLS_ECP_C) && defined(MBEDTLS_ECP_HAVE_X25519)
		MBEDTLS_SSL_IANA_TLS_GROUP_X25519,
#endif
		MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1,
		MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1,
		MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1,
		0
	};
	static const uint16_t groups_legacy[] = {
		MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1,
		0
	};

	const uint16_t *grp_list = (mode == OSCAM_SSL_MODE_LEGACY) ? groups_legacy : groups_all;
	mbedtls_ssl_conf_groups(&conf->ssl_conf, grp_list);
#if defined(MBEDTLS_DEBUG_C)
	warn_if_ec_curve_not_advertised(&conf->own_cert, &conf->own_key, grp_list);
#endif

#if defined(MBEDTLS_SSL_TICKET_C)
	static mbedtls_ssl_ticket_context ticket_ctx;
	mbedtls_ssl_ticket_init(&ticket_ctx);
	if (mbedtls_ssl_ticket_setup(&ticket_ctx, mbedtls_ctr_drbg_random,
								 &conf->ctr_drbg, MBEDTLS_CIPHER_AES_256_GCM, 86400) == 0) {
		mbedtls_ssl_conf_session_tickets_cb(&conf->ssl_conf,
											mbedtls_ssl_ticket_write,
											mbedtls_ssl_ticket_parse,
											&ticket_ctx);
	}
#endif

#if defined(MBEDTLS_DEBUG_C)
if (mbedtls_pk_can_do(&conf->own_key, MBEDTLS_PK_ECDSA))
	cs_log("SSL: loaded ECDSA key (%zu bits, curve %s)",
		mbedtls_pk_get_bitlen(&conf->own_key),
		mbedtls_pk_get_name(&conf->own_key));
else if (mbedtls_pk_can_do(&conf->own_key, MBEDTLS_PK_RSA))
	cs_log("SSL: loaded RSA key (%zu bits)", mbedtls_pk_get_bitlen(&conf->own_key));
else
	cs_log("SSL: loaded unknown key type");
#endif

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

int oscam_ssl_conf_use_own_cert_pem(oscam_ssl_conf_t *conf,
									const char *pem_path,
									const char *key_pass)
{
	if (!conf || !pem_path) return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;

	// Clear any previous
	mbedtls_x509_crt_free(&conf->own_cert);
	mbedtls_pk_free(&conf->own_key);
	mbedtls_x509_crt_init(&conf->own_cert);
	mbedtls_pk_init(&conf->own_key);

	// 1) Parse certificate chain (all certs in file)
	int ret = mbedtls_x509_crt_parse_file(&conf->own_cert, pem_path);
	if (ret != 0) {
		char e[128]; mbedtls_strerror(ret, e, sizeof(e));
		cs_log("SSL: failed to parse certificate(s) from %s (%s)", pem_path, e);
		return ret;
	}

	// 2) Parse private key (same file). MbedTLS will locate the key PEM block.
	ret = mbedtls_pk_parse_keyfile(&conf->own_key, pem_path,
								   key_pass ? key_pass : NULL,
								   mbedtls_ctr_drbg_random, &conf->ctr_drbg);
	if (ret != 0) {
		char e[128]; mbedtls_strerror(ret, e, sizeof(e));
		cs_log("SSL: failed to parse private key from %s (%s)", pem_path, e);
		return ret;
	}

#if defined(MBEDTLS_DEBUG_C)
mbedtls_pk_type_t kt = mbedtls_pk_get_type(&conf->own_key);
if (kt == MBEDTLS_PK_ECKEY || kt == MBEDTLS_PK_ECDSA) {
#if defined(MBEDTLS_ECP_C)
	cs_log("SSL: loaded key type=%s curve=%s",
		   pk_type_name(kt), grp_name(get_group_id_from_pk(&conf->own_key)));
#else
	cs_log("SSL: loaded key type=%s", pk_type_name(kt));
#endif
} else {
	cs_log("SSL: loaded key type=%s", pk_type_name(kt));
}
#endif

	// 3) Validate key matches leaf cert
	if (!mbedtls_pk_can_do(&conf->own_key, MBEDTLS_PK_RSA) &&
		!mbedtls_pk_can_do(&conf->own_key, MBEDTLS_PK_ECDSA)) {
		cs_log("SSL: private key algorithm not supported (RSA/ECDSA required)");
		return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
	}

	if (mbedtls_pk_get_bitlen(&conf->own_key) == 0) {
		cs_log("SSL: private key has zero bit-length (invalid)");
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
	}

	// 4) Bind to the SSL config
	ret = mbedtls_ssl_conf_own_cert(&conf->ssl_conf, &conf->own_cert, &conf->own_key);
	if (ret != 0) {
		char e[128]; mbedtls_strerror(ret, e, sizeof(e));
		cs_log("SSL: mbedtls_ssl_conf_own_cert() failed (%s)", e);
		return ret;
	}

	return 0;
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
/* ---- internal: poll helper for WANT_READ/WRITE ---- */
static int wait_on_fd_rw(int fd, int want_write, int timeout_ms)
{
	struct timeval tv;
	fd_set rfds, wfds;

	tv.tv_sec  = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);

	if (want_write)
		FD_SET(fd, &wfds);
	else
		FD_SET(fd, &rfds);

	int n = select(fd + 1, want_write ? NULL : &rfds, want_write ? &wfds : NULL, NULL, &tv);
	if (n > 0)  return 0;          /* ready */
	if (n == 0) return -2;         /* timeout */
	return -1;                     /* error */
}

/* ---- internal: drive mbedTLS handshake to completion with a timeout ---- */
static int handshake_blocking_impl(mbedtls_ssl_context *ssl, int fd, int timeout_ms)
{
	const int slice_ms = 50; /* short wait slices so we remain responsive */
	int elapsed = 0;

	for (;;)
	{
		int ret = mbedtls_ssl_handshake(ssl);
		if (ret == 0)
			return 0;

		if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			int want_write = (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
			int w = wait_on_fd_rw(fd, want_write, slice_ms);
			if (w == -1) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
			if (w == -2) {
				elapsed += slice_ms;
				if (elapsed >= timeout_ms)
					return MBEDTLS_ERR_SSL_TIMEOUT;
			}
			continue;
		}

		/* fatal */
		return ret;
	}
}

/* Public: blocking accept/handshake (optional explicit call) */
int oscam_ssl_accept(oscam_ssl_t *ssl, int fd, int timeout_ms)
{
	if (!ssl) return OSCAM_SSL_PARAM;
	int r = handshake_blocking_impl(&ssl->ssl, fd, timeout_ms);
	if (r == 0)            return OSCAM_SSL_OK;
	if (r == MBEDTLS_ERR_SSL_TIMEOUT)
		return OSCAM_SSL_HANDSHAKE_FAIL;
	return OSCAM_SSL_HANDSHAKE_FAIL;
}

/* Alias (same behavior), handy name if you prefer */
int oscam_ssl_handshake_blocking(oscam_ssl_t *ssl, int fd, int timeout_ms)
{
	return oscam_ssl_accept(ssl, fd, timeout_ms);
}

/* ---- create SSL and COMPLETE the TLS handshake here ---- */
oscam_ssl_t *oscam_ssl_new(oscam_ssl_conf_t *conf, int fd)
{
	if (!conf) return NULL;

	oscam_ssl_t *ssl = calloc(1, sizeof(*ssl));
	if (!ssl) return NULL;

	mbedtls_ssl_init(&ssl->ssl);
	mbedtls_net_init(&ssl->net);
	ssl->net.fd = fd;

	int ret = mbedtls_ssl_setup(&ssl->ssl, &conf->ssl_conf);
	if (ret != 0) {
		char e[128]; mbedtls_strerror(ret, e, sizeof(e));
		cs_log("SSL: mbedtls_ssl_setup() failed (%d: %s)", ret, e);
		mbedtls_ssl_free(&ssl->ssl);
		free(ssl);
		return NULL;
	}

	/* BIO / IO */
	mbedtls_ssl_set_bio(&ssl->ssl, &ssl->net, mbedtls_net_send, mbedtls_net_recv, NULL);

	/* Handshake with WANT_READ/WRITE drive + short timeout slices */
	const int slice_ms = 50;
	const int max_ms   = 10000; /* 10s cap */
	int elapsed = 0;

	for (;;) {
		ret = mbedtls_ssl_handshake(&ssl->ssl);
		if (ret == 0)
			break; /* handshake done */

		if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			int want_write = (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
			int w = wait_on_fd_rw(fd, want_write, slice_ms);
			if (w == -1) { ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR; break; }
			if (w == -2) {
				elapsed += slice_ms;
				if (elapsed >= max_ms) { ret = MBEDTLS_ERR_SSL_TIMEOUT; break; }
			}
			continue;
		}

		/* fatal return from mbedTLS */
		break;
	}

	if (ret != 0) {
		if (!is_benign_handshake_abort(ret)) {
			char e[128];
			mbedtls_strerror(ret, e, sizeof(e));
			cs_log("SSL: handshake failed (%d: %s)", ret, e);

			/* Fatal error — clean up completely */
			mbedtls_ssl_free(&ssl->ssl);
			free(ssl);
			return NULL;
		} else {
			/* Benign abort — client closed early */
			cs_debug_mask(D_CLIENT, "SSL: benign peer abort during handshake (ret=%d)", ret);
			mbedtls_ssl_free(&ssl->ssl);
			ssl->net.fd = -1;  /* mark as invalid for caller */
			return ssl;
		}
	}

	return ssl;
}

/* Keep a non-blocking variant if anything elsewhere calls it explicitly */
int oscam_ssl_handshake(oscam_ssl_t *ssl)
{
	if (!ssl) return OSCAM_SSL_PARAM;

	int ret = mbedtls_ssl_handshake(&ssl->ssl);
	if (ret == 0) return OSCAM_SSL_OK;
	if (ret == MBEDTLS_ERR_SSL_WANT_READ)
		return OSCAM_SSL_WANT_READ;
	if (ret == MBEDTLS_ERR_SSL_WANT_WRITE)
		return OSCAM_SSL_WANT_WRITE;
	return OSCAM_SSL_HANDSHAKE_FAIL;
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

int oscam_ssl_write(oscam_ssl_t *ssl, const unsigned char *buf, size_t len)
{
	size_t total = 0;
	while (total < len)
	{
		int ret = mbedtls_ssl_write(&ssl->ssl, buf + total, len - total);
		if (ret > 0)
			total += ret;
		else if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
			continue;
		else
			return ret;
	}
	return (int)total;
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

void oscam_ssl_free(oscam_ssl_t *ssl)
{
	if (!ssl)
		return;
	mbedtls_ssl_free(&ssl->ssl);
	mbedtls_net_free(&ssl->net);
	free(ssl);
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

const char *oscam_ssl_version(void)
{
	return MBEDTLS_VERSION_STRING_FULL;
}

int oscam_ssl_get_error(oscam_ssl_t *ssl, int ret)
{
	(void)ssl;
	if (ret == OSCAM_SSL_WANT_READ)
		return OSCAM_SSL_WANT_READ;
	if (ret == OSCAM_SSL_WANT_WRITE)
		return OSCAM_SSL_WANT_WRITE;
	return OSCAM_SSL_ERR;
}

int oscam_ssl_generate_selfsigned(const char *path)
{
	int ret;
	mbedtls_pk_context key;
	mbedtls_x509write_cert crt;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	unsigned char cert_buf[4096];
	unsigned char key_buf[8192];  // larger buffer for 4096-bit RSA PEM
	const char *pers = "oscam_selfsign_rsa";
	FILE *f = NULL;
	char not_before[16], not_after[16];
	time_t now = time(NULL);
	struct tm start_tm, end_tm;
	struct utsname buffer;

	mbedtls_pk_init(&key);
	mbedtls_x509write_crt_init(&crt);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_entropy_add_source(&entropy, mbedtls_hardware_poll, NULL, 32, MBEDTLS_ENTROPY_SOURCE_STRONG);

	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0)
		goto cleanup;

	/* ---- Generate RSA 4096-bit key ---- */
	if ((ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0)
		goto cleanup;

	{
		mbedtls_rsa_context *rsa = mbedtls_pk_rsa(key);
		/* public exponent = 65537 */
		if ((ret = mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, 4096, 65537)) != 0)
			goto cleanup;
	}

	/* ---- CN = system nodename (hostname) ---- */
	const char *cn = !uname(&buffer) ? buffer.nodename : "localhost";
	size_t cn_len = MIN(strlen(cn), 63);

	char subject_name[128];
	snprintf(subject_name, sizeof(subject_name),
				"CN=%.*s,O=OSCam AutoCert,OU=Private Webif Certificate",
				(int)cn_len, cn);

	/* ---- Configure certificate metadata ---- */
	mbedtls_x509write_crt_set_subject_key(&crt, &key);
	mbedtls_x509write_crt_set_issuer_key(&crt, &key);
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_subject_name(&crt, subject_name);
	mbedtls_x509write_crt_set_issuer_name(&crt, subject_name);

	/* ---- X.509 V3: SubjectAltName with CN, CN.local, 127.0.0.1, ::1 ---- */
	ret = write_san_ext_and_attach(&crt, cn);
	if (ret != 0) {
		cs_log("SSL: failed to set SAN (%d)", ret);
		goto cleanup;
	}

	/* ---- Validity (2 years) ---- */
	gmtime_r(&now, &start_tm);
	end_tm = start_tm;
	end_tm.tm_year += OSCAM_SSL_CERT_YEARS;
	strftime(not_before, sizeof(not_before), "%Y%m%d%H%M%S", &start_tm);
	strftime(not_after, sizeof(not_after), "%Y%m%d%H%M%S", &end_tm);
	mbedtls_x509write_crt_set_validity(&crt, not_before, not_after);

	/* ---- Serial number (random 128-bit) ---- */
	mbedtls_mpi serial;
	mbedtls_mpi_init(&serial);
	unsigned char serial_bytes[16];
	mbedtls_ctr_drbg_random(&ctr_drbg, serial_bytes, sizeof(serial_bytes));
	mbedtls_mpi_read_binary(&serial, serial_bytes, sizeof(serial_bytes));
	mbedtls_x509write_crt_set_serial(&crt, &serial);
	mbedtls_mpi_free(&serial);

	/* ---- Basic constraints & key usage ---- */
	mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
	mbedtls_x509write_crt_set_key_usage(&crt,
		MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
		MBEDTLS_X509_KU_KEY_ENCIPHERMENT);
	mbedtls_x509write_crt_set_ns_cert_type(&crt,
		MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER);

	/* ---- Write certificate to PEM ---- */
	ret = mbedtls_x509write_crt_pem(&crt, cert_buf, sizeof(cert_buf),
	                                mbedtls_ctr_drbg_random, &ctr_drbg);
	if (ret < 0)
		goto cleanup;

	/* ---- Write private key to PEM ---- */
	ret = mbedtls_pk_write_key_pem(&key, key_buf, sizeof(key_buf));
	if (ret != 0)
		goto cleanup;

	/* ---- Save both into the same file (single PEM) ---- */
	f = fopen(path, "wb");
	if (!f) {
		ret = -1;
		goto cleanup;
	}
	fwrite(cert_buf, 1, strlen((char *)cert_buf), f);
	fwrite(key_buf, 1, strlen((char *)key_buf), f);
	fclose(f);
	f = NULL;

	cs_log("SSL: generated new RSA-4096 self-signed certificate for CN=%s", cn);
	ret = 0;

cleanup:
	if (ret != 0)
		cs_log("SSL: self-signed certificate generation failed (%d)", ret);

	if (f) fclose(f);
	mbedtls_pk_free(&key);
	mbedtls_x509write_crt_free(&crt);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return ret;
}

void oscam_ssl_strerror(int err, char *buf, size_t len)
{
	mbedtls_strerror(err, buf, len);
}

// ---- Certificate Handling ----
void oscam_ssl_cert_init(oscam_x509_crt *crt)
{
	mbedtls_x509_crt_init(&crt->crt);
}

void oscam_ssl_cert_free(oscam_x509_crt *crt)
{
	mbedtls_x509_crt_free(&crt->crt);
}

int oscam_ssl_cert_parse(oscam_x509_crt *crt, const unsigned char *buf, size_t len)
{
	return mbedtls_x509_crt_parse(&crt->crt, buf, len);
}

int oscam_ssl_cert_parse_file(oscam_x509_crt *crt, const char *path)
{
	return mbedtls_x509_crt_parse_file(&crt->crt, path);
}

int oscam_ssl_cert_verify(oscam_x509_crt *crt, oscam_x509_crt *trust)
{
	uint32_t flags = 0;
	return mbedtls_x509_crt_verify(&crt->crt, &trust->crt, NULL, NULL, &flags, NULL, NULL);
}

oscam_x509_crt *oscam_ssl_cert_get_next(oscam_x509_crt *crt)
{
	if (!crt || !crt->crt.next)
		return NULL;
	return (oscam_x509_crt *) crt->crt.next;
}

void oscam_ssl_cert_raw(const oscam_x509_crt *crt, const unsigned char **buf, size_t *len)
{
	if (!crt || !buf || !len) {
		if (buf) *buf = NULL;
		if (len) *len = 0;
		return;
	}

	*buf = crt->crt.raw.p;
	*len = crt->crt.raw.len;
}

/* ----------------- VALIDITY INFO ----------------- */
void oscam_ssl_cert_get_validity(const oscam_x509_crt *crt,
								 oscam_cert_time_t *from,
								 oscam_cert_time_t *to)
{
	if (!crt) return;

	from->year = crt->crt.valid_from.year;
	from->mon  = crt->crt.valid_from.mon;
	from->day  = crt->crt.valid_from.day;
	from->hour = crt->crt.valid_from.hour;
	from->min  = crt->crt.valid_from.min;
	from->sec  = crt->crt.valid_from.sec;

	to->year = crt->crt.valid_to.year;
	to->mon  = crt->crt.valid_to.mon;
	to->day  = crt->crt.valid_to.day;
	to->hour = crt->crt.valid_to.hour;
	to->min  = crt->crt.valid_to.min;
	to->sec  = crt->crt.valid_to.sec;
}

int oscam_ssl_pk_get_bits(const oscam_pk_context *pk)
{
	if (!pk) return 0;
	return (int) mbedtls_pk_get_bitlen(&pk->pk);
}

/* ----------------- KEY LENGTH ----------------- */
int oscam_ssl_pk_get_bitlen(const oscam_pk_context *pk)
{
	if (!pk) return 0;
	return (int)mbedtls_pk_get_bitlen(&pk->pk);
}

const oscam_pk_context *oscam_ssl_cert_get_pubkey(const oscam_x509_crt *crt)
{
	return (const oscam_pk_context *)&crt->crt.pk;
}

int oscam_ssl_cert_dn_gets(char *buf, size_t size, const void *name)
{
	if (!name || !buf || size == 0)
		return OSCAM_SSL_ERR;

	buf[0] = '\0';

	int ret = mbedtls_x509_dn_gets(buf, size, (const mbedtls_x509_name *)name);
	if (ret < 0)
		return OSCAM_SSL_ERR;

	return OSCAM_SSL_OK;
}

void oscam_ssl_cert_serial_gets(const oscam_x509_crt *crt, char *buf, size_t len)
{
	mbedtls_x509_serial_gets(buf, len, &crt->crt.serial);
}

int oscam_ssl_cert_get_version(const oscam_x509_crt *crt)
{
	if (!crt)
		return -1;
	return crt->crt.version;
}

const void *oscam_ssl_cert_get_subject(const oscam_x509_crt *crt)
{
	if (!crt)
		return NULL;
	return (const void *)&crt->crt.subject;
}

const void *oscam_ssl_cert_get_issuer(const oscam_x509_crt *crt)
{
	if (!crt)
		return NULL;
	return (const void *)&crt->crt.issuer;
}

// ---- Public Key ----
int oscam_ssl_pk_clone(oscam_pk_context *dst, const oscam_pk_context *src)
{
	if (!dst || !src)
		return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

	const mbedtls_pk_type_t type = mbedtls_pk_get_type(&src->pk);
	const mbedtls_pk_info_t *info = mbedtls_pk_info_from_type(type);
	if (!info)
		return MBEDTLS_ERR_PK_TYPE_MISMATCH;

	mbedtls_pk_init(&dst->pk);

	int ret = mbedtls_pk_setup(&dst->pk, info);
	if (ret != 0)
		return ret;

	switch (type)
	{
#if defined(MBEDTLS_RSA_C)
	case MBEDTLS_PK_RSA:
		ret = mbedtls_rsa_copy(mbedtls_pk_rsa(dst->pk), mbedtls_pk_rsa(src->pk));
		break;
#endif

#if defined(MBEDTLS_ECP_C)
	case MBEDTLS_PK_ECKEY:
	case MBEDTLS_PK_ECKEY_DH:
	case MBEDTLS_PK_ECDSA:
	{
		const mbedtls_ecp_keypair *src_ec = mbedtls_pk_ec(src->pk);
		mbedtls_ecp_keypair *dst_ec = mbedtls_pk_ec(dst->pk);

		if (!src_ec || !dst_ec)
			return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

		mbedtls_ecp_keypair_init(dst_ec);

		ret = mbedtls_ecp_group_copy(&dst_ec->MBEDTLS_PRIVATE(grp),
									 &src_ec->MBEDTLS_PRIVATE(grp));
		if (ret == 0)
			ret = mbedtls_ecp_copy(&dst_ec->MBEDTLS_PRIVATE(Q),
								   &src_ec->MBEDTLS_PRIVATE(Q));
		break;
	}
#endif

#if defined(MBEDTLS_PK_PARSE_C)
	default:
	{
		/* Fallback: clone via DER public key serialization */
		unsigned char buf[512];
		ret = mbedtls_pk_write_pubkey_der(&src->pk, buf, sizeof(buf));
		if (ret > 0)
			ret = mbedtls_pk_parse_public_key(&dst->pk,
											  buf + sizeof(buf) - ret, ret);
		else
			ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
		break;
	}
#else
	default:
		ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
		break;
#endif
	}

	return ret;
}

void oscam_ssl_pk_free(oscam_pk_context *pk)
{
	mbedtls_pk_free(&pk->pk);
}

int oscam_ssl_pk_verify(oscam_pk_context *pk,
						const unsigned char *hash, size_t hash_len,
						const unsigned char *sig,  size_t sig_len)
{
	return mbedtls_pk_verify(&pk->pk, MBEDTLS_MD_SHA256, hash, hash_len, sig, sig_len);
}

int oscam_ssl_pk_get_type(const oscam_pk_context *pk)
{
	if (!pk)
		return OSCAM_PK_NONE;

	mbedtls_pk_type_t t = mbedtls_pk_get_type(&pk->pk);

	switch (t)
	{
		case MBEDTLS_PK_RSA:
			return OSCAM_PK_RSA;

		case MBEDTLS_PK_ECKEY:
		case MBEDTLS_PK_ECDSA:
			return OSCAM_PK_EC;

		default:
			return OSCAM_PK_NONE;
	}
}

// ---- Hashing ----
int oscam_ssl_sha1(const unsigned char *data, size_t len, unsigned char *out)
{
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data, len);
	SHA1_Final(out, &ctx);
	return 0;
}

int oscam_ssl_sha256(const unsigned char *data, size_t len, unsigned char *out)
{
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, data, len);
	SHA256_Final(out, &ctx);
	SHA256_Free(&ctx);
	return 0;
}

int oscam_ssl_sha256_stream(const unsigned char *data1, size_t len1,
							const unsigned char *data2, size_t len2,
							unsigned char *out)
{
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	if (data1 && len1) SHA256_Update(&ctx, data1, len1);
	if (data2 && len2) SHA256_Update(&ctx, data2, len2);
	SHA256_Final(out, &ctx);
	SHA256_Free(&ctx);
	return 0;
}

#endif /* WITH_OPENSSL */

int oscam_ssl_get_fd(oscam_ssl_t *ssl)
{
#ifdef WITH_OPENSSL
	return ssl ? ssl->fd : -1;
#else
	return ssl ? ssl->net.fd : -1;
#endif
}

int oscam_ssl_pending(oscam_ssl_t *ssl)
{
#ifdef WITH_OPENSSL
	if (!ssl || !ssl->ssl) return 0;
	return SSL_pending(ssl->ssl);
#else
	if (!ssl) return 0;
	return mbedtls_ssl_get_bytes_avail(&ssl->ssl);
#endif
}

#endif /* WITH_SSL */

#include "globals.h"
#include "oscam-time.h"
#include "oscam-ssl.h"

#ifdef WITH_SSL

/* mbedTLS */
#include "mbedtls/platform.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/error.h"
#include "mbedtls/version.h"
#include "mbedtls/oid.h"

#define OSCAM_SSL_CERT_YEARS 2

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

int oscam_ssl_pending(oscam_ssl_t *ssl) {
	return mbedtls_ssl_get_bytes_avail(&ssl->ssl);
}

int oscam_ssl_get_fd(oscam_ssl_t *ssl) {
	return ssl ? ssl->net.fd : -1;
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

const char *oscam_ssl_version(void)
{
	static char version_str[64];
	snprintf(version_str, sizeof(version_str),
			 "MbedTLS %s (TLS %d.%d%s)",
			 MBEDTLS_VERSION_STRING,
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
			 1, 3, ""
#elif defined(MBEDTLS_SSL_PROTO_TLS1_2)
			 1, 2, ""
#else
			 1, 1, " or older"
#endif
	);
	return version_str;
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

void oscam_ssl_conf_strict_ciphers(oscam_ssl_conf_t *conf)
{
	if (!conf)
		return;

#if defined(MBEDTLS_SSL_CONF_CIPHERSUITES) || defined(MBEDTLS_SSL_TLS_C)
	static const int strong_ciphers[] = {
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
		MBEDTLS_TLS1_3_AES_256_GCM_SHA384,
		MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
#endif
#if defined(MBEDTLS_ECDSA_C)
		MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
#endif
		0
	};

	mbedtls_ssl_conf_ciphersuites(&conf->ssl_conf, strong_ciphers);

	// Enforce minimum TLS 1.2 for security
#if defined(MBEDTLS_SSL_CONF_MIN_MAJOR_VER) && defined(MBEDTLS_SSL_CONF_MIN_MINOR_VER)
	mbedtls_ssl_conf_min_version(&conf->ssl_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
#endif

#else
	(void)conf; // fallback for builds without configurable ciphers
#endif
}

/* Create a minimal self-signed certificate */
int oscam_ssl_generate_selfsigned(const char *path)
{
	int ret;
	mbedtls_pk_context key;
	mbedtls_x509write_cert crt;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	unsigned char output_buf[4096];
	const char *pers = "oscam_selfsign_ec";
	FILE *f = NULL;
	char not_before[16], not_after[16];
	time_t now = time(NULL);
	struct tm start_tm, end_tm;

	mbedtls_pk_init(&key);
	mbedtls_x509write_crt_init(&crt);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
									 (const unsigned char *)pers, strlen(pers))) != 0)
		goto cleanup;

	// Use ECDSA key
	if ((ret = mbedtls_pk_setup(&key,
			mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0)
		goto cleanup;

	if ((ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
			mbedtls_pk_ec(key),
			mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
		goto cleanup;

	// Configure certificate metadata
	mbedtls_x509write_crt_set_subject_key(&crt, &key);
	mbedtls_x509write_crt_set_issuer_key(&crt, &key);
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);

	mbedtls_x509write_crt_set_subject_name(&crt, "CN=OSCam,O=OSCam WebIf,C=XX");
	mbedtls_x509write_crt_set_issuer_name(&crt,  "CN=OSCam,O=OSCam WebIf,C=XX");

	// validity: 2 years
	// Convert current time
	gmtime_r(&now, &start_tm);

	// Validity: OSCAM_SSL_CERT_YEARS
	end_tm = start_tm;
	end_tm.tm_year += OSCAM_SSL_CERT_YEARS;

	// Format: "YYYYMMDDhhmmss" as required by mbedTLS
	strftime(not_before, sizeof(not_before), "%Y%m%d%H%M%S", &start_tm);
	strftime(not_after, sizeof(not_after), "%Y%m%d%H%M%S", &end_tm);

	mbedtls_x509write_crt_set_validity(&crt, not_before, not_after);

	// Serial number (optional but good practice)
	mbedtls_mpi serial_mpi;
	mbedtls_mpi_init(&serial_mpi);
	unsigned char serial_bytes[16];
	mbedtls_ctr_drbg_random(&ctr_drbg, serial_bytes, sizeof(serial_bytes));
	mbedtls_mpi_read_binary(&serial_mpi, serial_bytes, sizeof(serial_bytes));
	mbedtls_x509write_crt_set_serial(&crt, &serial_mpi);
	mbedtls_mpi_free(&serial_mpi);

	// Basic constraints & key usage
	mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
	mbedtls_x509write_crt_set_key_usage(&crt,
		MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_ENCIPHERMENT);
	mbedtls_x509write_crt_set_ns_cert_type(&crt,
		MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER);

	if ((ret = mbedtls_x509write_crt_pem(&crt, output_buf, sizeof(output_buf),
										 mbedtls_ctr_drbg_random, &ctr_drbg)) < 0)
		goto cleanup;

	f = fopen(path, "wb");
	if (!f) {
		ret = -1;
		goto cleanup;
	}
	fwrite(output_buf, 1, strlen((char *)output_buf), f);
	fclose(f);

	ret = 0;

cleanup:
	if (ret != 0)
		cs_log("SSL: ECDSA self-signed certificate generation failed (%d)", ret);

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

const oscam_pk_context *oscam_ssl_cert_get_pubkey(const oscam_x509_crt *crt)
{
	return (const oscam_pk_context *)&crt->crt.pk;
}

int oscam_ssl_cert_dn_gets(char *buf, size_t size, const void *dn)
{
	return mbedtls_x509_dn_gets(buf, size, (const mbedtls_x509_name *)dn);
}

void oscam_ssl_cert_serial_gets(const oscam_x509_crt *crt, char *buf, size_t len)
{
	mbedtls_x509_serial_gets(buf, len, &crt->crt.serial);
}

const void *oscam_ssl_cert_get_subject(const oscam_x509_crt *crt)
{
	return &crt->crt.subject;
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
	return mbedtls_pk_get_type(&pk->pk);
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
	mbedtls_sha256_context ctx;
	mbedtls_sha256_init(&ctx);
	mbedtls_sha256_starts(&ctx, 0);
	mbedtls_sha256_update(&ctx, data, len);
	mbedtls_sha256_finish(&ctx, out);
	mbedtls_sha256_free(&ctx);
	return 0;
}

int oscam_ssl_sha256_stream(const unsigned char *data1, size_t len1,
							const unsigned char *data2, size_t len2,
							unsigned char *out)
{
	mbedtls_sha256_context ctx;
	mbedtls_sha256_init(&ctx);
	mbedtls_sha256_starts(&ctx, 0);
	if (data1 && len1) mbedtls_sha256_update(&ctx, data1, len1);
	if (data2 && len2) mbedtls_sha256_update(&ctx, data2, len2);
	mbedtls_sha256_finish(&ctx, out);
	mbedtls_sha256_free(&ctx);
	return 0;
}

#endif /* WITH_SSL */

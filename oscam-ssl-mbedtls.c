#define MODULE_LOG_PREFIX "ssl"

#include "globals.h"
#include "oscam-time.h"
#include "oscam-string.h"
#include "oscam-ssl.h"

#ifdef WITH_SSL

/* ============================================================
 * BACKEND SELECTOR
 * ============================================================ */
#ifdef WITH_MBEDTLS
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

int oscam_ssl_get_fd(oscam_ssl_t *ssl)
{
	return ssl ? ssl->net.fd : -1;
}

int oscam_ssl_pending(oscam_ssl_t *ssl)
{
	if (!ssl) return 0;
	return mbedtls_ssl_get_bytes_avail(&ssl->ssl);
}

#endif /* WITH_MBEDTLS */
#endif /* WITH_SSL */

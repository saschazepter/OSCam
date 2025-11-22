#define MODULE_LOG_PREFIX "crypto"

#include "globals.h"
#include "oscam-crypto.h"
#include "oscam-string.h"

#ifdef WITH_OPENSSL
/* ===========================================================
 * OpenSSL backend
 * =========================================================== */
#include <openssl/rand.h>
#include <openssl/err.h>

#ifdef WITH_OPENSSL_DLOPEN

#include <dlfcn.h>

/* ----------------------------------------------------------------------
 * Global dlopen state
 * ---------------------------------------------------------------------- */
static void       *g_oscam_libcrypto    = NULL;
static void       *g_oscam_libssl       = NULL;
static int         g_oscam_crypto_tried = 0;
static int         g_oscam_ssl_tried    = 0;
static const char *g_oscam_crypto_used  = NULL;
static const char *g_oscam_ssl_used     = NULL;

/* Reasonably common SONAMEs, tried in order when caller passes NULL */
static const char *g_oscam_crypto_sonames[] = {
	"libcrypto.so.3",
	"libcrypto.so.1.1",
	"libcrypto.so.1.0.2",
	"libcrypto.so.1.0.0",
	"libcrypto.so.0.9.8",
	"libcrypto.so",
	NULL
};

static const char *g_oscam_ssl_sonames[] = {
	"libssl.so.3",
	"libssl.so.1.1",
	"libssl.so.1.0.2",
	"libssl.so.1.0.0",
	"libssl.so.0.9.8",
	"libssl.so",
	NULL
};

/* ----------------------------------------------------------------------
 * Function pointer storage (matches externs in oscam-crypto.h)
 * ---------------------------------------------------------------------- */

/* ===== EVP digest function pointers ===== */
DECLARE_OSSL_PTR(EVP_md5,                    oscam_EVP_md5_f);
DECLARE_OSSL_PTR(EVP_sha1,                   oscam_EVP_sha1_f);
DECLARE_OSSL_PTR(EVP_sha256,                 oscam_EVP_sha256_f);

DECLARE_OSSL_PTR(EVP_MD_CTX_new,             oscam_EVP_MD_CTX_new_f);
DECLARE_OSSL_PTR(EVP_MD_CTX_free,            oscam_EVP_MD_CTX_free_f);
DECLARE_OSSL_PTR(EVP_DigestInit_ex,          oscam_EVP_DigestInit_ex_f);
DECLARE_OSSL_PTR(EVP_DigestUpdate,           oscam_EVP_DigestUpdate_f);
DECLARE_OSSL_PTR(EVP_DigestFinal_ex,         oscam_EVP_DigestFinal_ex_f);
DECLARE_OSSL_PTR(EVP_Digest,                 oscam_EVP_Digest_f);

/* ===== EVP cipher getters ===== */
DECLARE_OSSL_PTR(EVP_aes_128_ecb,            oscam_EVP_aes_128_ecb_f);
DECLARE_OSSL_PTR(EVP_aes_192_ecb,            oscam_EVP_aes_192_ecb_f);
DECLARE_OSSL_PTR(EVP_aes_256_ecb,            oscam_EVP_aes_256_ecb_f);
DECLARE_OSSL_PTR(EVP_aes_128_cbc,            oscam_EVP_aes_128_cbc_f);
DECLARE_OSSL_PTR(EVP_aes_192_cbc,            oscam_EVP_aes_192_cbc_f);
DECLARE_OSSL_PTR(EVP_aes_256_cbc,            oscam_EVP_aes_256_cbc_f);

/* ===== EVP cipher context & operations ===== */
DECLARE_OSSL_PTR(EVP_CIPHER_CTX_new,         oscam_EVP_CIPHER_CTX_new_f);
DECLARE_OSSL_PTR(EVP_CIPHER_CTX_free,        oscam_EVP_CIPHER_CTX_free_f);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
DECLARE_OSSL_PTR(EVP_CIPHER_CTX_cleanup,     oscam_EVP_CIPHER_CTX_cleanup_f);
DECLARE_OSSL_PTR(EVP_CIPHER_CTX_init,        oscam_EVP_CIPHER_CTX_init_f);
#endif
DECLARE_OSSL_PTR(EVP_CIPHER_CTX_set_padding, oscam_EVP_CIPHER_CTX_set_padding_f);

DECLARE_OSSL_PTR(EVP_CipherInit_ex,          oscam_EVP_CipherInit_ex_f);
DECLARE_OSSL_PTR(EVP_CipherUpdate,           oscam_EVP_CipherUpdate_f);

DECLARE_OSSL_PTR(EVP_EncryptInit_ex,         oscam_EVP_EncryptInit_ex_f);
DECLARE_OSSL_PTR(EVP_EncryptUpdate,          oscam_EVP_EncryptUpdate_f);
DECLARE_OSSL_PTR(EVP_DecryptInit_ex,         oscam_EVP_DecryptInit_ex_f);
DECLARE_OSSL_PTR(EVP_DecryptUpdate,          oscam_EVP_DecryptUpdate_f);

/* ===== DES (only when enabled) ===== */
#if defined(WITH_SSL) || defined(WITH_LIB_MDC2) || defined(WITH_LIB_DES)
DECLARE_OSSL_PTR(DES_set_key_unchecked,      oscam_DES_set_key_unchecked_f);
DECLARE_OSSL_PTR(DES_ecb_encrypt,            oscam_DES_ecb_encrypt_f);
DECLARE_OSSL_PTR(DES_ecb3_encrypt,           oscam_DES_ecb3_encrypt_f);
#endif

/* ===== BIGNUM (only when enabled) ===== */
#if defined(WITH_LIB_BIGNUM)
DECLARE_OSSL_PTR(BN_CTX_new,                 oscam_BN_CTX_new_f);
DECLARE_OSSL_PTR(BN_CTX_free,                oscam_BN_CTX_free_f);
DECLARE_OSSL_PTR(BN_CTX_start,               oscam_BN_CTX_start_f);
DECLARE_OSSL_PTR(BN_CTX_end,                 oscam_BN_CTX_end_f);
DECLARE_OSSL_PTR(BN_CTX_get,                 oscam_BN_CTX_get_f);

DECLARE_OSSL_PTR(BN_new,                     oscam_BN_new_f);
DECLARE_OSSL_PTR(BN_free,                    oscam_BN_free_f);

DECLARE_OSSL_PTR(BN_bin2bn,                  oscam_BN_bin2bn_f);
DECLARE_OSSL_PTR(BN_bn2bin,                  oscam_BN_bn2bin_f);

DECLARE_OSSL_PTR(BN_mod_exp,                 oscam_BN_mod_exp_f);
DECLARE_OSSL_PTR(BN_num_bits,                oscam_BN_num_bits_f);
DECLARE_OSSL_PTR(BN_mul,                     oscam_BN_mul_f);
DECLARE_OSSL_PTR(BN_add_word,                oscam_BN_add_word_f);
DECLARE_OSSL_PTR(BN_sub_word,                oscam_BN_sub_word_f);
DECLARE_OSSL_PTR(BN_mod_inverse,             oscam_BN_mod_inverse_f);
#endif

/* ----------------------------------------------------------------------
 * Helper: dlopen with fallback list
 * ---------------------------------------------------------------------- */
static void *oscam_ossl_try_open(const char *explicit_name, const char *const *fallbacks)
{
	void *h = NULL;

	if (explicit_name)
	{
		cs_log_dbg(D_TRACE, "OpenSSL: trying %s", explicit_name);
		h = dlopen(explicit_name, RTLD_NOW | RTLD_LOCAL);
		if (!h)
			cs_log("OpenSSL: dlopen(\"%s\") failed: %s", explicit_name, dlerror());
		else
			cs_log_dbg(D_TRACE, "OpenSSL: using %s", explicit_name);
		return h;
	}

	for (const char *const *p = fallbacks; *p; ++p)
	{
		cs_log_dbg(D_TRACE, "OpenSSL: trying %s", *p);
		h = dlopen(*p, RTLD_NOW | RTLD_LOCAL);
		if (h)
		{
			cs_log_dbg(D_TRACE, "OpenSSL: using %s", *p);
			if (fallbacks == g_oscam_crypto_sonames)
				g_oscam_crypto_used = *p;
			else if (fallbacks == g_oscam_ssl_sonames)
				g_oscam_ssl_used = *p;

			return h;
		}
	}

	cs_log("OpenSSL: No usable shared object found!");
	return NULL;
}

/* ----------------------------------------------------------------------
 * Resolve individual symbols
 * ---------------------------------------------------------------------- */
static void oscam_ossl_resolve_crypto_symbols(void)
{
#define RESOLVE_OSSL_CRYPTO_FN(type, var, sym) do {                     \
	if (g_oscam_libcrypto) {                                     \
		var = (type) dlsym(g_oscam_libcrypto, (sym));            \
		if (!(var))                                              \
			cs_debug_mask(D_TRACE,                               \
				"OpenSSL: dlsym(\"%s\") failed: %s",             \
				(sym), dlerror());                               \
	}                                                            \
} while (0)

	if (!g_oscam_libcrypto)
		return;

	/* --- EVP digests --- */
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_md5_f,                    oscam_EVP_md5,                    "EVP_md5");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_sha1_f,                   oscam_EVP_sha1,                   "EVP_sha1");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_sha256_f,                 oscam_EVP_sha256,                 "EVP_sha256");

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_MD_CTX_new_f,             oscam_EVP_MD_CTX_new,             "EVP_MD_CTX_new");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_MD_CTX_free_f,            oscam_EVP_MD_CTX_free,            "EVP_MD_CTX_free");
#else
	/* OpenSSL < 1.1.0 uses EVP_MD_CTX_create/destroy */
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_MD_CTX_new_f,             oscam_EVP_MD_CTX_new,             "EVP_MD_CTX_create");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_MD_CTX_free_f,            oscam_EVP_MD_CTX_free,            "EVP_MD_CTX_destroy");
#endif

	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_DigestInit_ex_f,          oscam_EVP_DigestInit_ex,          "EVP_DigestInit_ex");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_DigestUpdate_f,           oscam_EVP_DigestUpdate,           "EVP_DigestUpdate");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_DigestFinal_ex_f,         oscam_EVP_DigestFinal_ex,         "EVP_DigestFinal_ex");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_Digest_f,                 oscam_EVP_Digest,                 "EVP_Digest");

	/* --- EVP ciphers --- */
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_aes_128_ecb_f,            oscam_EVP_aes_128_ecb,            "EVP_aes_128_ecb");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_aes_192_ecb_f,            oscam_EVP_aes_192_ecb,            "EVP_aes_192_ecb");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_aes_256_ecb_f,            oscam_EVP_aes_256_ecb,            "EVP_aes_256_ecb");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_aes_128_cbc_f,            oscam_EVP_aes_128_cbc,            "EVP_aes_128_cbc");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_aes_192_cbc_f,            oscam_EVP_aes_192_cbc,            "EVP_aes_192_cbc");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_aes_256_cbc_f,            oscam_EVP_aes_256_cbc,            "EVP_aes_256_cbc");

	/* --- EVP cipher ctx / operations --- */
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_CIPHER_CTX_new_f,         oscam_EVP_CIPHER_CTX_new,         "EVP_CIPHER_CTX_new");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_CIPHER_CTX_free_f,        oscam_EVP_CIPHER_CTX_free,        "EVP_CIPHER_CTX_free");
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_CIPHER_CTX_cleanup_f,     oscam_EVP_CIPHER_CTX_cleanup,     "EVP_CIPHER_CTX_cleanup");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_CIPHER_CTX_init_f,        oscam_EVP_CIPHER_CTX_init,        "EVP_CIPHER_CTX_init");
#endif
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_CIPHER_CTX_set_padding_f, oscam_EVP_CIPHER_CTX_set_padding, "EVP_CIPHER_CTX_set_padding");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_CipherInit_ex_f,          oscam_EVP_CipherInit_ex,          "EVP_CipherInit_ex");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_CipherUpdate_f,           oscam_EVP_CipherUpdate,           "EVP_CipherUpdate");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_EncryptInit_ex_f,         oscam_EVP_EncryptInit_ex,         "EVP_EncryptInit_ex");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_EncryptUpdate_f,          oscam_EVP_EncryptUpdate,          "EVP_EncryptUpdate");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_DecryptInit_ex_f,         oscam_EVP_DecryptInit_ex,         "EVP_DecryptInit_ex");
	RESOLVE_OSSL_CRYPTO_FN(oscam_EVP_DecryptUpdate_f,          oscam_EVP_DecryptUpdate,          "EVP_DecryptUpdate");

#if defined(WITH_SSL) || defined(WITH_LIB_MDC2) || defined(WITH_LIB_DES)
	/* --- DES --- */
	RESOLVE_OSSL_CRYPTO_FN(oscam_DES_set_key_unchecked_f,         oscam_DES_set_key_unchecked,      "DES_set_key_unchecked");
	RESOLVE_OSSL_CRYPTO_FN(oscam_DES_ecb_encrypt_f,               oscam_DES_ecb_encrypt,            "DES_ecb_encrypt");
	RESOLVE_OSSL_CRYPTO_FN(oscam_DES_ecb3_encrypt_f,              oscam_DES_ecb3_encrypt,           "DES_ecb3_encrypt");
#endif

#if defined(WITH_LIB_BIGNUM) && defined(WITH_OPENSSL)
	/* --- BIGNUM --- */
	RESOLVE_OSSL_CRYPTO_FN(oscam_BN_CTX_new_f,                     oscam_BN_CTX_new,                  "BN_CTX_new");
	RESOLVE_OSSL_CRYPTO_FN(oscam_BN_CTX_free_f,                    oscam_BN_CTX_free,                 "BN_CTX_free");
	RESOLVE_OSSL_CRYPTO_FN(oscam_BN_CTX_start_f,                   oscam_BN_CTX_start,                "BN_CTX_start");
	RESOLVE_OSSL_CRYPTO_FN(oscam_BN_CTX_end_f,                     oscam_BN_CTX_end,                  "BN_CTX_end");
	RESOLVE_OSSL_CRYPTO_FN(oscam_BN_CTX_get_f,                     oscam_BN_CTX_get,                  "BN_CTX_get");

	RESOLVE_OSSL_CRYPTO_FN(oscam_BN_new_f,                         oscam_BN_new,                      "BN_new");
	RESOLVE_OSSL_CRYPTO_FN(oscam_BN_free_f,                        oscam_BN_free,                     "BN_free");

	RESOLVE_OSSL_CRYPTO_FN(oscam_BN_bin2bn_f,                      oscam_BN_bin2bn,                   "BN_bin2bn");
	RESOLVE_OSSL_CRYPTO_FN(oscam_BN_bn2bin_f,                      oscam_BN_bn2bin,                   "BN_bn2bin");

	RESOLVE_OSSL_CRYPTO_FN(oscam_BN_mod_exp_f,                     oscam_BN_mod_exp,                  "BN_mod_exp");
	RESOLVE_OSSL_CRYPTO_FN(oscam_BN_num_bits_f,                    oscam_BN_num_bits,                 "BN_num_bits");
	RESOLVE_OSSL_CRYPTO_FN(oscam_BN_mul_f,                         oscam_BN_mul,                      "BN_mul");
	RESOLVE_OSSL_CRYPTO_FN(oscam_BN_add_word_f,                    oscam_BN_add_word,                 "BN_add_word");
	RESOLVE_OSSL_CRYPTO_FN(oscam_BN_sub_word_f,                    oscam_BN_sub_word,                 "BN_sub_word");
	RESOLVE_OSSL_CRYPTO_FN(oscam_BN_mod_inverse_f,                 oscam_BN_mod_inverse,              "BN_mod_inverse");
#endif
}

/* ----------------------------------------------------------------------
 * Public loader API
 * ---------------------------------------------------------------------- */

/*
 * Try to load libcrypto (always) and optionally libssl.
 *  need_ssl = 0 -> only libcrypto is required
 *  need_ssl = 1 -> both libcrypto and libssl must succeed
 *
 * Returns:
 *   0 on complete failure,
 *   1 if only libcrypto is available,
 *   2 if both libcrypto and libssl are available.
 */
int oscam_ossl_load(int need_ssl)
{
	if (g_oscam_libcrypto || g_oscam_libssl) {
		/* already loaded; report current state */
		return (g_oscam_libcrypto ? 1 : 0) + (g_oscam_libssl ? 1 : 0);
	}

	if (!g_oscam_crypto_tried) {
		g_oscam_crypto_tried = 1;
		g_oscam_libcrypto = oscam_ossl_try_open(NULL, g_oscam_crypto_sonames);
		if (g_oscam_libcrypto)
			oscam_ossl_resolve_crypto_symbols();
	}

	if (!g_oscam_libcrypto)
		return 0;

	if (need_ssl && !g_oscam_ssl_tried) {
		g_oscam_ssl_tried = 1;
		g_oscam_libssl = oscam_ossl_try_open(NULL, g_oscam_ssl_sonames);
	}

	if (need_ssl && !g_oscam_libssl)
		return 1; /* crypto ok, ssl missing */

	return (g_oscam_libcrypto ? 1 : 0) + (g_oscam_libssl ? 1 : 0);
}

void oscam_ossl_unload(void)
{
	if (g_oscam_libssl)
	{
		dlclose(g_oscam_libssl);
		g_oscam_libssl = NULL;
	}

	if (g_oscam_libcrypto)
	{
		dlclose(g_oscam_libcrypto);
		g_oscam_libcrypto = NULL;
	}

	g_oscam_crypto_used = NULL;
	g_oscam_ssl_used    = NULL;

	/* ===== EVP digest ===== */
	RESET_OSSL_PTR(EVP_md5);
	RESET_OSSL_PTR(EVP_sha1);
	RESET_OSSL_PTR(EVP_sha256);

	RESET_OSSL_PTR(EVP_MD_CTX_new);
	RESET_OSSL_PTR(EVP_MD_CTX_free);
	RESET_OSSL_PTR(EVP_DigestInit_ex);
	RESET_OSSL_PTR(EVP_DigestUpdate);
	RESET_OSSL_PTR(EVP_DigestFinal_ex);
	RESET_OSSL_PTR(EVP_Digest);

	/* ===== EVP cipher getters ===== */
	RESET_OSSL_PTR(EVP_aes_128_ecb);
	RESET_OSSL_PTR(EVP_aes_192_ecb);
	RESET_OSSL_PTR(EVP_aes_256_ecb);
	RESET_OSSL_PTR(EVP_aes_128_cbc);
	RESET_OSSL_PTR(EVP_aes_192_cbc);
	RESET_OSSL_PTR(EVP_aes_256_cbc);

	/* ===== EVP cipher ctx + ops ===== */
	RESET_OSSL_PTR(EVP_CIPHER_CTX_new);
	RESET_OSSL_PTR(EVP_CIPHER_CTX_free);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	RESET_OSSL_PTR(EVP_CIPHER_CTX_cleanup);
	RESET_OSSL_PTR(EVP_CIPHER_CTX_init);
#endif
	RESET_OSSL_PTR(EVP_CIPHER_CTX_set_padding);

	RESET_OSSL_PTR(EVP_CipherInit_ex);
	RESET_OSSL_PTR(EVP_CipherUpdate);
	RESET_OSSL_PTR(EVP_EncryptInit_ex);
	RESET_OSSL_PTR(EVP_EncryptUpdate);
	RESET_OSSL_PTR(EVP_DecryptInit_ex);
	RESET_OSSL_PTR(EVP_DecryptUpdate);

#if defined(WITH_SSL) || defined(WITH_LIB_DES)
	RESET_OSSL_PTR(DES_set_key_unchecked);
	RESET_OSSL_PTR(DES_ecb_encrypt);
	RESET_OSSL_PTR(DES_ecb3_encrypt);
#endif

#if defined(WITH_LIB_BIGNUM)
	RESET_OSSL_PTR(BN_CTX_new);
	RESET_OSSL_PTR(BN_CTX_free);
	RESET_OSSL_PTR(BN_CTX_start);
	RESET_OSSL_PTR(BN_CTX_end);
	RESET_OSSL_PTR(BN_CTX_get);

	RESET_OSSL_PTR(BN_new);
	RESET_OSSL_PTR(BN_free);

	RESET_OSSL_PTR(BN_bin2bn);
	RESET_OSSL_PTR(BN_bn2bin);

	RESET_OSSL_PTR(BN_mod_exp);
	RESET_OSSL_PTR(BN_num_bits);
	RESET_OSSL_PTR(BN_mul);
	RESET_OSSL_PTR(BN_add_word);
	RESET_OSSL_PTR(BN_sub_word);
	RESET_OSSL_PTR(BN_mod_inverse);
#endif
}

/* Small helpers for callers */
int oscam_ossl_have_crypto(void)           { return g_oscam_libcrypto != NULL; }
int oscam_ossl_have_ssl(void)              { return g_oscam_libssl    != NULL; }
const char *oscam_ossl_crypto_soname(void) { return g_oscam_crypto_used; }
const char *oscam_ossl_ssl_soname(void)    { return g_oscam_ssl_used; }

/*
 * Generic symbol resolver.
 *  from_ssl = 0 -> search libcrypto
 *  from_ssl = 1 -> search libssl first, then libcrypto as fallback
 *
 * This is kept for completeness, but the main API uses typed function
 * pointers (oscam_EVP_*, oscam_BN_*, etc.).
 */
void *oscam_ossl_sym(int from_ssl, const char *name)
{
	if (!name)
		return NULL;

	void *h = NULL;
	if (from_ssl && g_oscam_libssl)
	{
		h = dlsym(g_oscam_libssl, name);
		if (h)
			return h;
	}

	if (g_oscam_libcrypto)
	{
		h = dlsym(g_oscam_libcrypto, name);
		if (!h)
			cs_debug_mask(D_TRACE, "OpenSSL: dlsym(\"%s\") failed: %s", name, dlerror());
	}
	return h;
}

/*
 * Public: "is OpenSSL crypto usable?"
 *  - triggers lazy load on first call
 *  - used by all shim wrappers in the header
 */
int oscam_ossl_crypto_available(void)
{
	if (!g_oscam_libcrypto) {
		oscam_ossl_load(0);  /* crypto-only */
	}
	return (g_oscam_libcrypto != NULL);
}

void oscam_crypto_init_dlopen(void)
{
	if (!g_oscam_crypto_tried) {
		g_oscam_crypto_tried = 1;
		g_oscam_libcrypto = oscam_ossl_try_open(NULL, g_oscam_crypto_sonames);
		if (g_oscam_libcrypto)
			oscam_ossl_resolve_crypto_symbols();
	}
}

#endif /* WITH_OPENSSL_DLOPEN */

/* EVP_MD_CTX_create/free were renamed in 1.1.0 */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#ifndef EVP_MD_CTX_create
#define EVP_MD_CTX_create EVP_MD_CTX_new
#endif
#ifndef EVP_MD_CTX_destroy
#define EVP_MD_CTX_destroy EVP_MD_CTX_free
#endif
#endif

/*
 * For OpenSSL < 1.1.0 the library does not provide EVP_CIPHER_CTX_new/free.
 * We provide our own simple wrappers. These are used regardless of dlopen
 * or not, but they do *not* call OPENSSL_malloc/free (no ABI dependency).
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
EVP_CIPHER_CTX *oscam_EVP_CIPHER_CTX_new(void)
{
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)malloc(sizeof(EVP_CIPHER_CTX));
	if (!ctx)
		return NULL;
	EVP_CIPHER_CTX_init(ctx);
	return ctx;
}

void oscam_EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)
{
	if (!ctx)
		return;
	EVP_CIPHER_CTX_cleanup(ctx);
	free(ctx);
}

/* Older OpenSSL headers may not define EVP_MD_CTX_new/free, but OSCam's
 * dlopen shim resolves them (to create/destroy), so we do not need extra
 * compatibility here.
 */
#endif /* < 1.1.0 */

/* ----------------------------------------------------------------------
 * Unified hash helper
 * ---------------------------------------------------------------------- */
int oscam_hash(oscam_hash_alg alg,
               const unsigned char *d1, size_t l1,
               const unsigned char *d2, size_t l2,
               unsigned char *out)
{
	if (!out)
		return -1;

	const EVP_MD *md = NULL;

	switch (alg) {
	case OSCAM_HASH_SHA1:
#ifdef WITH_LIB_SHA1
		md = EVP_sha1();
		break;
#else
		return -1;
#endif

	case OSCAM_HASH_SHA256:
#ifdef WITH_LIB_SHA256
		md = EVP_sha256();
		break;
#else
		return -1;
#endif

	default:
		return -1;
	}

	if (!md)
		return -1;

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx)
		return -1;

	int ok = 1;
	if (ok) ok = (EVP_DigestInit_ex(ctx, md, NULL) == 1);
	if (ok && d1 && l1) ok = (EVP_DigestUpdate(ctx, d1, l1) == 1);
	if (ok && d2 && l2) ok = (EVP_DigestUpdate(ctx, d2, l2) == 1);

	unsigned int outlen = 0;
	if (ok) ok = (EVP_DigestFinal_ex(ctx, out, &outlen) == 1);

	EVP_MD_CTX_free(ctx);
	return ok ? 0 : -1;
}

/* ----------------------------------------------------------------------
 * MD5
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_MD5
static const char *__md5__magic = "$1$";

/* Internal 64-character mapping for crypt's base64 variant */
static const char itoa64[] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* Converts 24 bits from 'v' into 4 base64-like chars */
static void __md5_to64(char *s, unsigned long v, int n)
{
	while (n-- > 0) {
		*s++ = itoa64[v & 0x3f];
		v >>= 6;
	}
}

char *__md5_crypt(const char *pw, const char *salt, char *passwd)
{
	const char *sp, *ep;
	char *p;
	unsigned char final[17];  /* final[16] exists only to aid in looping */
	int sl, pl, i, pw_len;
	unsigned long l;

	MD5_CTX ctx, ctx1;

	/* Refine the salt */
	sp = salt;
	if (!strncmp(sp, __md5__magic, strlen(__md5__magic)))
		sp += strlen(__md5__magic);

	for (ep = sp; *ep && *ep != '$' && ep < (sp + 8); ep++);
	sl = ep - sp;

	/* Start main digest */
	MD5_Init(&ctx);

	pw_len = strlen(pw);
	MD5_Update(&ctx, (const unsigned char *)pw, pw_len);
	MD5_Update(&ctx, (const unsigned char *)__md5__magic, strlen(__md5__magic));
	MD5_Update(&ctx, (const unsigned char *)sp, sl);

	/* MD5(pw, salt, pw) */
	MD5_Init(&ctx1);
	MD5_Update(&ctx1, (const unsigned char *)pw, pw_len);
	MD5_Update(&ctx1, (const unsigned char *)sp, sl);
	MD5_Update(&ctx1, (const unsigned char *)pw, pw_len);
	MD5_Final(final, &ctx1);

	for (pl = pw_len; pl > 0; pl -= 16)
		MD5_Update(&ctx, final, pl > 16 ? 16 : pl);

	memset(final, 0, sizeof final);

	for (i = pw_len; i; i >>= 1)
		MD5_Update(&ctx, (i & 1) ? final : (const unsigned char *)pw, 1);

	strncpy(passwd, __md5__magic, 4);
	strncat(passwd, sp, sl);
	strcat(passwd, "$");

	MD5_Final(final, &ctx);

	/* Stretching */
	for (i = 0; i < 1000; i++) {
		MD5_Init(&ctx1);

		if (i & 1)
			MD5_Update(&ctx1, (const unsigned char *)pw, pw_len);
		else
			MD5_Update(&ctx1, final, 16);

		if (i % 3)
			MD5_Update(&ctx1, (const unsigned char *)sp, sl);
		if (i % 7)
			MD5_Update(&ctx1, (const unsigned char *)pw, pw_len);

		if (i & 1)
			MD5_Update(&ctx1, final, 16);
		else
			MD5_Update(&ctx1, (const unsigned char *)pw, pw_len);

		MD5_Final(final, &ctx1);
	}

	/* Encode final hash */
	p = passwd + strlen(passwd);
	final[16] = final[5];
	for (i = 0; i < 5; i++) {
		l = (final[i] << 16) | (final[i + 6] << 8) | final[i + 12];
		__md5_to64(p, l, 4);
		p += 4;
	}
	l = final[11];
	__md5_to64(p, l, 2);
	p += 2;
	*p = '\0';

	memset(final, 0, sizeof final);
	return passwd;
}
#endif /* WITH_LIB_MD5 */

/* ----------------------------------------------------------------------
 * DES
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_DES

#if defined(__GNUC__) && (__GNUC__ * 100 + __GNUC_MINOR__ >= 406)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

void oscam_des_set_key(const uint8_t *key, des_key_schedule *schedule)
{
	/* On OpenSSL builds, des_key_schedule is the library type (DES_key_schedule). */
	DES_set_key_unchecked((const_DES_cblock *)key, schedule);
}

void oscam_des_set_odd_parity(uint8_t key8[8])
{
	DES_set_odd_parity((DES_cblock *)key8);
}

void oscam_des_set_odd_parity_all(uint8_t *key, size_t len)
{
	for (; len >= 8; len -= 8, key += 8)
		DES_set_odd_parity((DES_cblock *)key);
}

void oscam_des(uint8_t *data, des_key_schedule *schedule, int enc)
{
	DES_cblock b;
	memcpy(b, data, 8);
	DES_ecb_encrypt(&b, &b, schedule,
					enc ? DES_ENCRYPT : DES_DECRYPT);
	memcpy(data, b, 8);
}

void oscam_des_ecb_encrypt(uint8_t *data, const uint8_t *key, int32_t len)
{
	DES_key_schedule ks;
	DES_set_key_unchecked((const_DES_cblock *)key, &ks);
	DES_cblock b;
	for (int32_t i = 0; i + 8 <= (len & ~7); i += 8) {
		memcpy(b, data + i, 8);
		DES_ecb_encrypt(&b, &b, &ks, DES_ENCRYPT);
		memcpy(data + i, b, 8);
	}
}

void oscam_des_ecb_decrypt(uint8_t *data, const uint8_t *key, int32_t len)
{
	DES_key_schedule ks;
	DES_set_key_unchecked((const_DES_cblock *)key, &ks);
	DES_cblock b;
	for (int32_t i = 0; i + 8 <= (len & ~7); i += 8) {
		memcpy(b, data + i, 8);
		DES_ecb_encrypt(&b, &b, &ks, DES_DECRYPT);
		memcpy(data + i, b, 8);
	}
}

void oscam_des_cbc_encrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key, int32_t len)
{
	DES_key_schedule ks;
	DES_set_key_unchecked((const_DES_cblock *)key, &ks);
	DES_cblock ivc;
	memcpy(ivc, iv, 8);
	DES_ncbc_encrypt(data, data, len & ~7, &ks, &ivc, DES_ENCRYPT);
}

void oscam_des_cbc_decrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key, int32_t len)
{
	DES_key_schedule ks;
	DES_set_key_unchecked((const_DES_cblock *)key, &ks);
	DES_cblock ivc;
	memcpy(ivc, iv, 8);
	DES_ncbc_encrypt(data, data, len & ~7, &ks, &ivc, DES_DECRYPT);
}

void oscam_des_ede2_cbc_encrypt(uint8_t *data, const uint8_t *iv,
                                const uint8_t *k1, const uint8_t *k2, int32_t len)
{
	DES_key_schedule ks1, ks2;
	DES_set_key_unchecked((const_DES_cblock *)k1, &ks1);
	DES_set_key_unchecked((const_DES_cblock *)k2, &ks2);
	DES_key_schedule ks3 = ks1; /* EDE2 */
	DES_cblock ivc;
	memcpy(ivc, iv, 8);
	DES_ede3_cbc_encrypt(data, data, len & ~7, &ks1, &ks2, &ks3, &ivc, DES_ENCRYPT);
}

void oscam_des_ede2_cbc_decrypt(uint8_t *data, const uint8_t *iv,
                                const uint8_t *k1, const uint8_t *k2, int32_t len)
{
	DES_key_schedule ks1, ks2;
	DES_set_key_unchecked((const_DES_cblock *)k1, &ks1);
	DES_set_key_unchecked((const_DES_cblock *)k2, &ks2);
	DES_key_schedule ks3 = ks1; /* EDE2 */
	DES_cblock ivc;
	memcpy(ivc, iv, 8);
	DES_ede3_cbc_encrypt(data, data, len & ~7, &ks1, &ks2, &ks3, &ivc, DES_DECRYPT);
}

void oscam_des_ecb3_encrypt(uint8_t *data, const uint8_t *key16)
{
	DES_cblock in, out;
	memcpy(in, data, 8);
	DES_key_schedule k1, k2, k3;
	/* EDE2 mode: 2-key Triple-DES, K3 == K1 (total 16-byte key)
	For true 3-key EDE3 (24 bytes): load k3 from key+16. */
	DES_set_key_unchecked((const_DES_cblock *)(key16 + 0),  &k1);
	DES_set_key_unchecked((const_DES_cblock *)(key16 + 8),  &k2);
	k3 = k1;
	DES_ecb3_encrypt(&in, &out, &k1, &k2, &k3, DES_ENCRYPT);
	memcpy(data, out, 8);
}

void oscam_des_ecb3_decrypt(uint8_t *data, const uint8_t *key16)
{
	DES_cblock in, out;
	memcpy(in, data, 8);
	DES_key_schedule k1, k2, k3;
	/* EDE2 mode: 2-key Triple-DES, K3 == K1 (total 16-byte key)
	For true 3-key EDE3 (24 bytes): load k3 from key+16. */
	DES_set_key_unchecked((const_DES_cblock *)(key16 + 0),  &k1);
	DES_set_key_unchecked((const_DES_cblock *)(key16 + 8),  &k2);
	k3 = k1;
	DES_ecb3_encrypt(&in, &out, &k1, &k2, &k3, DES_DECRYPT);
	memcpy(data, out, 8);
}

#if defined(__GNUC__) && (__GNUC__ * 100 + __GNUC_MINOR__ >= 406)
#pragma GCC diagnostic pop
#endif
#endif /* WITH_LIB_DES */

/* ----------------------------------------------------------------------
 * SHA256
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_SHA256
void SHA256_Free(SHA256_CTX *c) { (void)c; }
#endif /* WITH_LIB_SHA256 */

/* ----------------------------------------------------------------------
 * AES
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_AES
typedef struct {
	EVP_CIPHER_CTX *enc;      /* ECB/CBC encrypt context (no padding) */
	EVP_CIPHER_CTX *dec;      /* ECB/CBC decrypt context (no padding) */
	unsigned char   iv[16];
	unsigned char   mode;     /* CBC or ECB (0) */
	unsigned char   nr;       /* kept for symmetry */
	int             key_bits; /* 128 / 192 / 256 */
} ossl_aesctx;

static inline const EVP_CIPHER *aes_ecb_cipher(int bits)
{
	switch (bits) {
		case 128: return EVP_aes_128_ecb();
		case 192: return EVP_aes_192_ecb();
		case 256: return EVP_aes_256_ecb();
		default:  return NULL;
	}
}

static inline const EVP_CIPHER *aes_cbc_cipher(int bits)
{
	switch (bits) {
		case 128: return EVP_aes_128_cbc();
		case 192: return EVP_aes_192_cbc();
		case 256: return EVP_aes_256_cbc();
		default:  return NULL;
	}
}

static inline ossl_aesctx *AES_C(AesCtx *c) { return (ossl_aesctx *)c; }

static int aes_ctx_init_pair(ossl_aesctx *C, const unsigned char *key, int key_bits, int mode)
{
	const EVP_CIPHER *cipher =
		(mode == CBC) ? aes_cbc_cipher(key_bits) : aes_ecb_cipher(key_bits);
	if (!cipher)
		return -1;

	C->enc = EVP_CIPHER_CTX_new();
	C->dec = EVP_CIPHER_CTX_new();
	if (!C->enc || !C->dec)
		return -1;

	/* iv is NULL here; we set it separately below for CBC */
	if (!EVP_EncryptInit_ex(C->enc, cipher, NULL, key, NULL)) return -1;
	if (!EVP_DecryptInit_ex(C->dec, cipher, NULL, key, NULL)) return -1;

	EVP_CIPHER_CTX_set_padding(C->enc, 0);
	EVP_CIPHER_CTX_set_padding(C->dec, 0);
	C->key_bits = key_bits;
	return 0;
}

int AesCtxIni(AesCtx *c, const unsigned char *iv, const unsigned char *key, int keylen, int mode)
{
	/* keylen is in bytes (16/24/32) */
	const int key_bits =
		(keylen == 16) ? 128 :
		(keylen == 24) ? 192 :
		(keylen == 32) ? 256 : 0;

	if (!key_bits)
		return -1;

	ossl_aesctx *C = AES_C(c);
	if (aes_ctx_init_pair(C, key, key_bits, mode) != 0)
		return -1;
	if (iv) {
		memcpy(C->iv, iv, 16);
		if (mode == CBC) {
			/* set IV in the OpenSSL context once */
			EVP_CipherInit_ex(C->enc, NULL, NULL, NULL, C->iv, 1);
			EVP_CipherInit_ex(C->dec, NULL, NULL, NULL, C->iv, 0);
		}
	}
	C->mode = (unsigned char)mode;
	C->nr   = (keylen == 16 ? 10 : keylen == 24 ? 12 : 14);
	return 0;
}

int AesEncrypt(AesCtx *c, const unsigned char *in, unsigned char *out, int len)
{
	ossl_aesctx *C = AES_C(c);
	int outl;

	if (C->mode == CBC) {
		if (!EVP_EncryptUpdate(C->enc, out, &outl, in, len)) return -1;
		/* Optionally mirror IV update into C->iv using last block of out */
		if (len >= AES_BLOCK_SIZE)
			memcpy(C->iv, out + len - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		return outl;
	} else {
		for (int i = 0; i < len; i += AES_BLOCK_SIZE) {
			if (!EVP_EncryptUpdate(C->enc, out + i, &outl, in + i, AES_BLOCK_SIZE))
				return -1;
		}
		return len;
	}
}

int AesDecrypt(AesCtx *c, const unsigned char *in, unsigned char *out, int len)
{
	ossl_aesctx *C = AES_C(c);
	int outl;

	if (C->mode == CBC) {
		if (!EVP_DecryptUpdate(C->dec, out, &outl, in, len)) return -1;
		if (len >= AES_BLOCK_SIZE)
			memcpy(C->iv, in + len - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		return outl;
	} else {
		for (int i = 0; i < len; i += AES_BLOCK_SIZE) {
			if (!EVP_DecryptUpdate(C->dec, out + i, &outl, in + i, AES_BLOCK_SIZE))
				return -1;
		}
		return len;
	}
}

/* Pair used by per-reader AES key list */
typedef struct {
	EVP_CIPHER_CTX *enc;  /* ECB, no padding */
	EVP_CIPHER_CTX *dec;  /* ECB, no padding */
	int             key_bits;
} ossl_pair;

static int pair_init(ossl_pair *p, const unsigned char *key, int key_bits)
{
	const EVP_CIPHER *ecb = aes_ecb_cipher(key_bits);
	if (!ecb) return -1;

	p->enc = EVP_CIPHER_CTX_new();
	p->dec = EVP_CIPHER_CTX_new();
	if (!p->enc || !p->dec) return -1;

	if (!EVP_EncryptInit_ex(p->enc, ecb, NULL, key, NULL)) return -1;
	if (!EVP_DecryptInit_ex(p->dec, ecb, NULL, key, NULL)) return -1;

	EVP_CIPHER_CTX_set_padding(p->enc, 0);
	EVP_CIPHER_CTX_set_padding(p->dec, 0);
	p->key_bits = key_bits;
	return 0;
}

void aes_set_key(void *aes, char *key)
{
	ossl_pair *p = (ossl_pair *)aes;
	if (!p || !key) return;
	/* existing code always uses 128-bit session keys here */
	(void)pair_init(p, (unsigned char *)key, 128);
}

bool aes_set_key_alloc(aes_keys **aes, char *key)
{
	ossl_pair *p;
	if (!cs_malloc(&p, sizeof(*p))) return false;
	*aes = (aes_keys *)p;
	aes_set_key(p, key);
	return true;
}

void aes_decrypt(void *aes, uint8_t *buf, int32_t n)
{
	ossl_pair *p = (ossl_pair *)aes;
	int outl;
	for (int32_t i = 0; i < n; i += AES_BLOCK_SIZE)
		EVP_DecryptUpdate(p->dec, buf + i, &outl, buf + i, AES_BLOCK_SIZE);
}

void aes_encrypt_idx(void *aes, uint8_t *buf, int32_t n)
{
	ossl_pair *p = (ossl_pair *)aes;
	int outl;
	for (int32_t i = 0; i < n; i += AES_BLOCK_SIZE)
		EVP_EncryptUpdate(p->enc, buf + i, &outl, buf + i, AES_BLOCK_SIZE);
}

void aes_cbc_encrypt(void *aes, uint8_t *buf, int32_t n, uint8_t *iv)
{
	ossl_pair *p = (ossl_pair *)aes;
	const EVP_CIPHER *cbc = aes_cbc_cipher(p->key_bits ? p->key_bits : 128);
	int outl;

	/* Reuse enc ctx with CBC + IV; no padding */
	EVP_CipherInit_ex(p->enc, cbc, NULL, NULL, iv, 1);
	EVP_CIPHER_CTX_set_padding(p->enc, 0);
	EVP_CipherUpdate(p->enc, buf, &outl, buf, n);
}

void aes_cbc_decrypt(void *aes, uint8_t *buf, int32_t n, uint8_t *iv)
{
	ossl_pair *p = (ossl_pair *)aes;
	const EVP_CIPHER *cbc = aes_cbc_cipher(p->key_bits ? p->key_bits : 128);
	int outl;

	EVP_CipherInit_ex(p->dec, cbc, NULL, NULL, iv, 0);
	EVP_CIPHER_CTX_set_padding(p->dec, 0);
	EVP_CipherUpdate(p->dec, buf, &outl, buf, n);
}

/* --- List management for per-reader AES keys --- */
void add_aes_entry(AES_ENTRY **list, uint16_t caid, uint32_t ident, int32_t keyid, uint8_t *aesKey)
{
	AES_ENTRY *e;
	if (!cs_malloc(&e, sizeof(*e))) return;

	memcpy(e->plainkey, aesKey, 16);
	e->caid = caid;
	e->ident = ident;
	e->keyid = keyid;
	e->next = NULL;

	if (memcmp(aesKey, "\xFF\xFF", 2) != 0) {
		ossl_pair *p;
		if (!cs_malloc(&p, sizeof(*p))) { free(e); return; }
		if (pair_init(p, aesKey, 128) != 0) { free(p); free(e); return; }
		e->key = p;
	} else {
		e->key = NULL; /* dummy -> card decrypts */
	}

	if (!*list) {
		*list = e;
		return;
	}
	AES_ENTRY *cur = *list;
	while (cur->next) cur = cur->next;
	cur->next = e;
}

void parse_aes_entry(AES_ENTRY **list, char *label, char *value)
{
	uint16_t caid, dummy;
	uint32_t ident;
	int32_t len;
	char *tmp;
	int32_t nb_keys = 0, key_id = 0;
	uint8_t aes_key[16];
	char *save = NULL;

	tmp = strtok_r(value, "@", &save);
	len = cs_strlen(tmp);
	if (len == 0 || len > 4) return;

	len = cs_strlen(save);
	if (len == 0) return;

	caid = a2i(tmp, 2);
	tmp  = strtok_r(NULL, ":", &save);

	len = cs_strlen(tmp);
	if (len == 0 || len > 6) return;

	ident = a2i(tmp, 3);

	while ((tmp = strtok_r(NULL, ",", &save))) {
		dummy = 0;
		len = cs_strlen(tmp);

		if (len != 32) {
			dummy = a2i(tmp, 1);
			if ((dummy != 0xFF && dummy != 0x00) || len > 2) {
				key_id++;
				cs_log("AES key length error .. not adding");
				continue;
			}
			if (dummy == 0x00) {
				key_id++;
				continue;
			}
		}

		nb_keys++;
		if (dummy)
			memset(aes_key, 0xFF, 16);
		else
			key_atob_l(tmp, aes_key, 32);

		add_aes_entry(list, caid, ident, key_id, aes_key);
		key_id++;
	}

	cs_log("%d AES key(s) added on reader %s for %04X@%06X", nb_keys, label, caid, ident);
}

void aes_clear_entries(AES_ENTRY **list)
{
	AES_ENTRY *cur = *list, *nxt;
	while (cur) {
		nxt = cur->next;
		if (cur->key) {
			ossl_pair *p = (ossl_pair *)cur->key;
			if (p->enc) EVP_CIPHER_CTX_free(p->enc);
			if (p->dec) EVP_CIPHER_CTX_free(p->dec);
			free(p);
		}
		free(cur);
		cur = nxt;
	}
	*list = NULL;
}

void parse_aes_keys(struct s_reader *rdr, char *value)
{
	char *entry;
	char *save = NULL;
	AES_ENTRY *newlist = NULL, *savelist = rdr->aes_list;

	for (entry = strtok_r(value, ";", &save); entry; entry = strtok_r(NULL, ";", &save))
		parse_aes_entry(&newlist, rdr->label, entry);

	rdr->aes_list = newlist;
	aes_clear_entries(&savelist);
}

static AES_ENTRY *aes_list_find(AES_ENTRY *list, uint16_t caid, uint32_t provid, int32_t keyid)
{
	for (AES_ENTRY *cur = list; cur; cur = cur->next) {
		if (cur->caid == caid && cur->ident == provid && cur->keyid == keyid)
			return cur;
	}
	cs_log("AES Decrypt key %d not found for %04X@%06X (aka V %06X E%X ...)",
			keyid, caid, provid, provid, keyid);
	return NULL;
}

int32_t aes_decrypt_from_list(AES_ENTRY *list, uint16_t caid, uint32_t provid, int32_t keyid,
								uint8_t *buf, int32_t n)
{
	AES_ENTRY *cur = aes_list_find(list, caid, provid, keyid);
	if (!cur) return 0;
	if (!cur->key) return 1; /* dummy */

	ossl_pair *p = (ossl_pair *)cur->key;
	int outl;
	for (int32_t i = 0; i < n; i += AES_BLOCK_SIZE)
		EVP_DecryptUpdate(p->dec, buf + i, &outl, buf + i, AES_BLOCK_SIZE);
	return 1;
}

int32_t aes_present(AES_ENTRY *list, uint16_t caid, uint32_t provid, int32_t keyid)
{
	return aes_list_find(list, caid, provid, keyid) != NULL;
}
#endif /* WITH_LIB_AES */

#endif /* WITH_OPENSSL */

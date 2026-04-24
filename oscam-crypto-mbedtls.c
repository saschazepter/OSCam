#define MODULE_LOG_PREFIX "crypto-mbedtls"

/* Enable access to private mbedTLS identifiers. Needed because mbedTLS 4.x
 * moved bignum (mbedtls_mpi_*) to the private API and PSA Crypto offers no
 * public bignum primitives. Scoped to this file only (not globally) to avoid
 * type-conflict issues in other TUs. MUST precede all mbedTLS includes. */
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS

#include "globals.h"
#include "oscam-crypto.h"
#include "oscam-string.h"

#ifdef WITH_MBEDTLS
/* MbedTLS backend only build of oscam-crypto */

/* ===========================================================
 * MbedTLS backend
 * =========================================================== */
#include "mbedtls/platform.h"

/* PSA Crypto umbrella header — one include covers MD5, SHA1, SHA256 and AES.
 * Gated so builds without any PSA-backed crypto feature don't pull it in. */
#if defined(WITH_SSL) || defined(WITH_LIB_AES) || defined(WITH_LIB_MD5) \
	|| defined(WITH_LIB_SHA1) || defined(WITH_LIB_SHA256)
#include "psa/crypto.h"
#endif

/* ----------------------------------------------------------------------
 * Compile-time size checks for opaque buffers
 * Ensures our wrapper structs are large enough for MbedTLS contexts.
 * Uses negative array size trick for C89/C99 compatibility.
 * ---------------------------------------------------------------------- */
#define OSCAM_STATIC_ASSERT(cond, name) \
	typedef char static_assert_##name[(cond) ? 1 : -1]

/* DES: standalone implementation — DES was removed in mbedTLS 4.0.
 * Our des_key_schedule opaque buffer is 160 bytes; we only need 8 bytes
 * for the raw key, so this is fine. */

/* Size checks for opaque PSA contexts embedded in the shim's CTX buffers.
 * psa_hash_operation_t fits comfortably in our 128/256-byte opaque buffers. */
#if defined(WITH_LIB_SHA1)
OSCAM_STATIC_ASSERT(sizeof(psa_hash_operation_t) <= 256,
	SHA_CTX_too_small);
#endif

#if defined(WITH_LIB_SHA256)
OSCAM_STATIC_ASSERT(sizeof(psa_hash_operation_t) <= 256,
	SHA256_CTX_too_small);
#endif

/* ----------------------------------------------------------------------
 * Unified hash helper
 * ---------------------------------------------------------------------- */
int oscam_hash(oscam_hash_alg alg, const unsigned char *d1, size_t l1, const unsigned char *d2, size_t l2, unsigned char *out)
{
	if (!out)
		return -1;

	switch (alg) {
	case OSCAM_HASH_SHA1:
#ifdef WITH_LIB_SHA1
	{
		SHA_CTX ctx;
		/* SHA functions return 1 on success (OpenSSL convention) */
		if (SHA1_Init(&ctx) != 1) return -1;
		if (d1 && l1) if (SHA1_Update(&ctx, d1, l1) != 1) return -1;
		if (d2 && l2) if (SHA1_Update(&ctx, d2, l2) != 1) return -1;
		if (SHA1_Final(out, &ctx) != 1) return -1;
		return 0;
	}
#else
		return -1;
#endif

	case OSCAM_HASH_SHA256:
#ifdef WITH_LIB_SHA256
	{
		SHA256_CTX ctx;
		/* SHA functions return 1 on success (OpenSSL convention) */
		if (SHA256_Init(&ctx) != 1) return -1;
		if (d1 && l1) if (SHA256_Update(&ctx, d1, l1) != 1) return -1;
		if (d2 && l2) if (SHA256_Update(&ctx, d2, l2) != 1) return -1;
		if (SHA256_Final(out, &ctx) != 1) return -1;
		return 0;
	}
#else
		return -1;
#endif

	default:
		return -1;
	}
}

/* ----------------------------------------------------------------------
 * MD5 (via PSA Crypto API)
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_MD5
unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md)
{
	static unsigned char m[MD5_DIGEST_LENGTH];
	size_t out_len = 0;

	if (md == NULL)
		md = m;

	if (psa_hash_compute(PSA_ALG_MD5, d, n, md, MD5_DIGEST_LENGTH, &out_len) != PSA_SUCCESS)
		return NULL;

	return md;
}

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
	size_t out_len = 0;

	psa_hash_operation_t ctx  = PSA_HASH_OPERATION_INIT;
	psa_hash_operation_t ctx1 = PSA_HASH_OPERATION_INIT;

	/* Refine the salt */
	sp = salt;
	if (!strncmp(sp, __md5__magic, strlen(__md5__magic)))
		sp += strlen(__md5__magic);

	for (ep = sp; *ep && *ep != '$' && ep < (sp + 8); ep++);
	sl = ep - sp;

	/* Start main digest */
	if (psa_hash_setup(&ctx, PSA_ALG_MD5) != PSA_SUCCESS)
		return NULL;

	pw_len = strlen(pw);
	psa_hash_update(&ctx, (const unsigned char *)pw, pw_len);
	psa_hash_update(&ctx, (const unsigned char *)__md5__magic, strlen(__md5__magic));
	psa_hash_update(&ctx, (const unsigned char *)sp, sl);

	/* MD5(pw, salt, pw) */
	psa_hash_setup(&ctx1, PSA_ALG_MD5);
	psa_hash_update(&ctx1, (const unsigned char *)pw, pw_len);
	psa_hash_update(&ctx1, (const unsigned char *)sp, sl);
	psa_hash_update(&ctx1, (const unsigned char *)pw, pw_len);
	psa_hash_finish(&ctx1, final, 16, &out_len);

	for (pl = pw_len; pl > 0; pl -= 16)
		psa_hash_update(&ctx, final, pl > 16 ? 16 : pl);

	memset(final, 0, sizeof final);

	for (i = pw_len; i; i >>= 1)
		psa_hash_update(&ctx, (i & 1) ? final : (const unsigned char *)pw, 1);

	strncpy(passwd, __md5__magic, 4);
	strncat(passwd, sp, sl);
	strcat(passwd, "$");

	psa_hash_finish(&ctx, final, 16, &out_len);

	/* Stretching — fresh PSA hash op per iteration */
	for (i = 0; i < 1000; i++) {
		psa_hash_abort(&ctx1);
		ctx1 = (psa_hash_operation_t)PSA_HASH_OPERATION_INIT;
		psa_hash_setup(&ctx1, PSA_ALG_MD5);

		if (i & 1)
			psa_hash_update(&ctx1, (const unsigned char *)pw, pw_len);
		else
			psa_hash_update(&ctx1, final, 16);

		if (i % 3)
			psa_hash_update(&ctx1, (const unsigned char *)sp, sl);
		if (i % 7)
			psa_hash_update(&ctx1, (const unsigned char *)pw, pw_len);

		if (i & 1)
			psa_hash_update(&ctx1, final, 16);
		else
			psa_hash_update(&ctx1, (const unsigned char *)pw, pw_len);

		psa_hash_finish(&ctx1, final, 16, &out_len);
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

	/* Cleanup */
	memset(final, 0, sizeof final);
	psa_hash_abort(&ctx);
	psa_hash_abort(&ctx1);

	return passwd;
}
#endif/* WITH_LIB_MD5 */

/* DES: standalone implementation in oscam-crypto.c (removed from mbedTLS 4.0) */

/* ----------------------------------------------------------------------
 * SHA1 (via PSA Crypto API)
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_SHA1
static inline psa_hash_operation_t *SHA1_S(SHA_CTX *c) { return (psa_hash_operation_t *)c; }

unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md)
{
	static unsigned char _buf[SHA_DIGEST_LENGTH];
	size_t out_len = 0;
	if (!md) md = _buf;
	if (psa_hash_compute(PSA_ALG_SHA_1, d, n, md, SHA_DIGEST_LENGTH, &out_len) != PSA_SUCCESS)
		return NULL;
	return md;
}

/* Return values follow OpenSSL convention: 1 = success, 0 = failure */
int SHA1_Init(SHA_CTX *c)
{
	psa_hash_operation_t *op = SHA1_S(c);
	*op = (psa_hash_operation_t)PSA_HASH_OPERATION_INIT;
	return (psa_hash_setup(op, PSA_ALG_SHA_1) == PSA_SUCCESS) ? 1 : 0;
}

int SHA1_Update(SHA_CTX *c, const void *data, size_t len)
{
	return (psa_hash_update(SHA1_S(c), data, len) == PSA_SUCCESS) ? 1 : 0;
}

int SHA1_Final(unsigned char *md, SHA_CTX *c)
{
	size_t out_len = 0;
	return (psa_hash_finish(SHA1_S(c), md, SHA_DIGEST_LENGTH, &out_len) == PSA_SUCCESS) ? 1 : 0;
}
#endif/* WITH_LIB_SHA1 */

/* ----------------------------------------------------------------------
 * SHA256 (via PSA Crypto API)
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_SHA256
static inline psa_hash_operation_t *SHA256_S(SHA256_CTX *c) { return (psa_hash_operation_t *)c; }

/* Return values follow OpenSSL convention: 1 = success, 0 = failure */
int SHA256_Init(SHA256_CTX *c)
{
	psa_hash_operation_t *op = SHA256_S(c);
	*op = (psa_hash_operation_t)PSA_HASH_OPERATION_INIT;
	return (psa_hash_setup(op, PSA_ALG_SHA_256) == PSA_SUCCESS) ? 1 : 0;
}

int SHA256_Update(SHA256_CTX *c, const void *d, size_t l)
{
	return (psa_hash_update(SHA256_S(c), d, l) == PSA_SUCCESS) ? 1 : 0;
}

int SHA256_Final(unsigned char *md, SHA256_CTX *c)
{
	size_t out_len = 0;
	return (psa_hash_finish(SHA256_S(c), md, SHA256_DIGEST_LENGTH, &out_len) == PSA_SUCCESS) ? 1 : 0;
}

void SHA256_Free(SHA256_CTX *c)
{
	psa_hash_abort(SHA256_S(c));
}
#endif/* WITH_LIB_SHA256 */

/* ----------------------------------------------------------------------
 * AES
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_AES

/* ---- PSA-based AES helpers ----
 *
 * PSA keys have a fixed algorithm policy. Since oscam uses both ECB and CBC
 * with the same key material (e.g. AES_KEY used by both AES_encrypt (ECB)
 * and AES_cbc_encrypt (CBC)), we store the raw key bytes and import a
 * temporary PSA key per operation. This is simple and correct; PSA caches
 * builtin AES internally so the per-call cost is modest.
 */

/* Generic AES context: raw key + optional IV + mode flag.
 * __may_alias__ is required because this struct is used as a type-punned
 * view over AesCtx / AES_KEY / aes_keys (caller-owned storage declared as
 * other types). Without it, GCC's TBAA at -O2 treats writes through this
 * type as unrelated to the backing object, deleting the writes as dead
 * stores and leaving later reads returning stale/zero bytes. */
typedef struct __attribute__((__may_alias__)) {
	uint8_t key[32];       /* up to AES-256 */
	uint8_t iv[16];
	uint8_t keylen;        /* 16, 24, or 32 */
	uint8_t mode;          /* CBC or ECB */
} oscam_psa_aes;

static psa_status_t psa_aes_run(const uint8_t *key, size_t keylen,
								psa_algorithm_t alg,
								int enc,
								const uint8_t *iv, size_t iv_len,
								const uint8_t *in, size_t in_len,
								uint8_t *out, size_t out_size,
								size_t *out_len)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
	psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
	psa_status_t st;
	size_t n1 = 0, n2 = 0;

	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attr, alg);
	psa_set_key_bits(&attr, (size_t)keylen * 8);

	st = psa_import_key(&attr, key, keylen, &kid);
	if (st != PSA_SUCCESS) return st;

	if (enc)
		st = psa_cipher_encrypt_setup(&op, kid, alg);
	else
		st = psa_cipher_decrypt_setup(&op, kid, alg);
	if (st != PSA_SUCCESS) goto done;

	if (iv) {
		st = psa_cipher_set_iv(&op, iv, iv_len);
		if (st != PSA_SUCCESS) goto done;
	}

	st = psa_cipher_update(&op, in, in_len, out, out_size, &n1);
	if (st != PSA_SUCCESS) goto done;

	st = psa_cipher_finish(&op, out + n1, out_size - n1, &n2);
	if (out_len) *out_len = n1 + n2;

done:
	if (st != PSA_SUCCESS) psa_cipher_abort(&op);
	psa_destroy_key(kid);
	return st;
}

/* ---- AesCtx (keyed context with persistent IV + mode) ---- */
static inline oscam_psa_aes *AES_C(AesCtx *c) { return (oscam_psa_aes *)c; }

int AesCtxIni(AesCtx *c, const unsigned char *iv, const unsigned char *key, int keylen, int mode)
{
	oscam_psa_aes *C = AES_C(c);
	if (keylen != 16 && keylen != 24 && keylen != 32) return -1;
	memcpy(C->key, key, keylen);
	C->keylen = (uint8_t)keylen;
	C->mode   = (unsigned char)mode;
	if (iv) memcpy(C->iv, iv, 16);
	else    memset(C->iv, 0, 16);
	return 0;
}

int AesEncrypt(AesCtx *c, const unsigned char *in, unsigned char *out, int len)
{
	oscam_psa_aes *C = AES_C(c);
	size_t out_len = 0;
	if (C->mode == CBC) {
		uint8_t iv_local[16]; memcpy(iv_local, C->iv, 16);
		if (psa_aes_run(C->key, C->keylen, PSA_ALG_CBC_NO_PADDING, 1,
						iv_local, 16, in, len, out, len, &out_len) != PSA_SUCCESS)
			return -1;
		/* Preserve running IV: last block of ciphertext */
		if (len >= 16) memcpy(C->iv, out + len - 16, 16);
	} else {
		if (psa_aes_run(C->key, C->keylen, PSA_ALG_ECB_NO_PADDING, 1,
						NULL, 0, in, len, out, len, &out_len) != PSA_SUCCESS)
			return -1;
	}
	return len;
}

int AesDecrypt(AesCtx *c, const unsigned char *in, unsigned char *out, int len)
{
	oscam_psa_aes *C = AES_C(c);
	size_t out_len = 0;
	if (C->mode == CBC) {
		uint8_t iv_local[16]; memcpy(iv_local, C->iv, 16);
		uint8_t last_cipher[16] = {0};
		if (len >= 16) memcpy(last_cipher, in + len - 16, 16);
		if (psa_aes_run(C->key, C->keylen, PSA_ALG_CBC_NO_PADDING, 0,
						iv_local, 16, in, len, out, len, &out_len) != PSA_SUCCESS)
			return -1;
		/* Running IV: last ciphertext block */
		if (len >= 16) memcpy(C->iv, last_cipher, 16);
	} else {
		if (psa_aes_run(C->key, C->keylen, PSA_ALG_ECB_NO_PADDING, 0,
						NULL, 0, in, len, out, len, &out_len) != PSA_SUCCESS)
			return -1;
	}
	return len;
}

/* ---- AES_KEY: OpenSSL-like API ----
 * __may_alias__: same rationale as oscam_psa_aes above — this is a
 * type-punned view over caller's AES_KEY/aes_keys storage. */
typedef struct __attribute__((__may_alias__)) {
	uint8_t key[32];
	uint8_t keylen;
	uint8_t has_enc;
	uint8_t has_dec;
} oscam_psa_aeskey;

static inline oscam_psa_aeskey *AK(const AES_KEY *k) { return (oscam_psa_aeskey *)(void*)k; }
static inline oscam_psa_aeskey *AKw(AES_KEY *k)      { return (oscam_psa_aeskey *)(void*)k; }

int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key)
{
	if (!key) return -1;
	if (bits != 128 && bits != 192 && bits != 256) return -1;
	oscam_psa_aeskey *K = AKw(key);
	K->keylen = (uint8_t)(bits / 8);
	memcpy(K->key, userKey, K->keylen);
	K->has_enc = 1;
	return 0;
}

int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key)
{
	if (!key) return -1;
	if (bits != 128 && bits != 192 && bits != 256) return -1;
	oscam_psa_aeskey *K = AKw(key);
	K->keylen = (uint8_t)(bits / 8);
	memcpy(K->key, userKey, K->keylen);
	K->has_dec = 1;
	return 0;
}

void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
	if (!key) return;
	size_t out_len = 0;
	uint8_t tmp[32];
	oscam_psa_aeskey *K = AK(key);
	if (psa_aes_run(K->key, K->keylen, PSA_ALG_ECB_NO_PADDING, 1,
					NULL, 0, in, 16, tmp, sizeof(tmp), &out_len) == PSA_SUCCESS)
		memcpy(out, tmp, 16);
}

void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
	if (!key) return;
	size_t out_len = 0;
	uint8_t tmp[32];
	oscam_psa_aeskey *K = AK(key);
	if (psa_aes_run(K->key, K->keylen, PSA_ALG_ECB_NO_PADDING, 0,
					NULL, 0, in, 16, tmp, sizeof(tmp), &out_len) == PSA_SUCCESS)
		memcpy(out, tmp, 16);
}

int AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
					size_t length, const AES_KEY *key,
					unsigned char *ivec, const int enc)
{
	if (!key || !ivec) return -1;
	oscam_psa_aeskey *K = AK(key);
	size_t out_len = 0;
	uint8_t last_cipher[16] = {0};
	if (!enc && length >= 16) memcpy(last_cipher, in + length - 16, 16);

	if (psa_aes_run(K->key, K->keylen, PSA_ALG_CBC_NO_PADDING, enc,
					ivec, 16, in, length, out, length, &out_len) != PSA_SUCCESS)
		return -1;

	/* Update the caller's IV to the last block, matching OpenSSL/mbedTLS semantics */
	if (length >= 16) {
		if (enc) memcpy(ivec, out + length - 16, 16);
		else     memcpy(ivec, last_cipher, 16);
	}
	return 0;
}

/* ---- aes_keys (void*): dynamically-allocated key wrapper ---- */
void aes_set_key(void *aes, char *key)
{
	oscam_psa_aeskey *p = (oscam_psa_aeskey *)aes;
	if (!p || !key) return;
	memcpy(p->key, key, 16);
	p->keylen = 16;
	p->has_enc = p->has_dec = 1;
}

bool aes_set_key_alloc(aes_keys **aes, char *key)
{
	oscam_psa_aeskey *p;
	if (!cs_malloc(&p, sizeof(*p))) return false;
	*aes = (aes_keys *)p;
	aes_set_key(p, key);
	return true;
}

void aes_decrypt(void *aes, uint8_t *buf, int32_t n)
{
	oscam_psa_aeskey *p = (oscam_psa_aeskey *)aes;
	size_t out_len = 0;
	uint8_t tmp[32];
	for (int32_t i = 0; i < n; i += 16) {
		if (psa_aes_run(p->key, p->keylen, PSA_ALG_ECB_NO_PADDING, 0,
						NULL, 0, buf + i, 16, tmp, sizeof(tmp), &out_len) == PSA_SUCCESS)
			memcpy(buf + i, tmp, 16);
	}
}

void aes_encrypt_idx(void *aes, uint8_t *buf, int32_t n)
{
	oscam_psa_aeskey *p = (oscam_psa_aeskey *)aes;
	size_t out_len = 0;
	uint8_t tmp[32];
	for (int32_t i = 0; i < n; i += 16) {
		if (psa_aes_run(p->key, p->keylen, PSA_ALG_ECB_NO_PADDING, 1,
						NULL, 0, buf + i, 16, tmp, sizeof(tmp), &out_len) == PSA_SUCCESS)
			memcpy(buf + i, tmp, 16);
	}
}

void aes_cbc_encrypt(void *aes, uint8_t *buf, int32_t n, uint8_t *iv)
{
	oscam_psa_aeskey *p = (oscam_psa_aeskey *)aes;
	size_t out_len = 0;
	psa_aes_run(p->key, p->keylen, PSA_ALG_CBC_NO_PADDING, 1,
				iv, 16, buf, n, buf, n, &out_len);
	if (n >= 16) memcpy(iv, buf + n - 16, 16);
}

void aes_cbc_decrypt(void *aes, uint8_t *buf, int32_t n, uint8_t *iv)
{
	oscam_psa_aeskey *p = (oscam_psa_aeskey *)aes;
	size_t out_len = 0;
	uint8_t last_cipher[16] = {0};
	if (n >= 16) memcpy(last_cipher, buf + n - 16, 16);
	psa_aes_run(p->key, p->keylen, PSA_ALG_CBC_NO_PADDING, 0,
				iv, 16, buf, n, buf, n, &out_len);
	if (n >= 16) memcpy(iv, last_cipher, 16);
}

/* --- List management for per-reader AES keys --- */
void add_aes_entry(AES_ENTRY **list, uint16_t caid, uint32_t ident, int32_t keyid, uint8_t *aesKey)
{
	AES_ENTRY *e;
	if (!cs_malloc(&e, sizeof(*e))) return;

	memcpy(e->plainkey, aesKey, 16);
	e->caid = caid; e->ident = ident; e->keyid = keyid; e->next = NULL;

	if (memcmp(aesKey, "\xFF\xFF", 2) != 0) {
		oscam_psa_aeskey *p;
		if (!cs_malloc(&p, sizeof(*p))) { free(e); return; }
		memcpy(p->key, aesKey, 16);
		p->keylen = 16;
		p->has_enc = p->has_dec = 1;
		e->key = p;
	} else {
		e->key = NULL;
	}

	if (!*list) { *list = e; return; }
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
			/* FF => card decrypts; 00 => no key */
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
		if (cur->key)
			free(cur->key);
		free(cur);
		cur = nxt;
	}
	*list = NULL;
}

#ifdef READER_VIACCESS
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
#endif /* READER_VIACCESS */

/* Helper function to find AES entry in list */
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

/* Now uses aes_list_find() helper instead of duplicating the search logic */
int32_t aes_decrypt_from_list(AES_ENTRY *list, uint16_t caid, uint32_t provid, int32_t keyid,
							  uint8_t *buf, int32_t n)
{
	AES_ENTRY *cur = aes_list_find(list, caid, provid, keyid);

	if (!cur) {
		return 0;
	}
	if (!cur->key) return 1;

	oscam_psa_aeskey *p = (oscam_psa_aeskey *)cur->key;
	size_t out_len = 0;
	uint8_t tmp[32];
	for (int32_t i = 0; i < n; i += 16) {
		if (psa_aes_run(p->key, p->keylen, PSA_ALG_ECB_NO_PADDING, 0,
						NULL, 0, buf + i, 16, tmp, sizeof(tmp), &out_len) == PSA_SUCCESS)
			memcpy(buf + i, tmp, 16);
	}
	return 1;
}

int32_t aes_present(AES_ENTRY *list, uint16_t caid, uint32_t provid, int32_t keyid)
{
	return aes_list_find(list, caid, provid, keyid) != NULL;
}
#endif/* WITH_LIB_AES */

/* ----------------------------------------------------------------------
 * BIGNUM
 *
 * Uses the private mbedtls_mpi_* API. PSA Crypto provides no public
 * bignum primitives, so this section remains on the legacy API gated
 * by MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS (defined at top of file).
 * If a future mbedTLS release removes this API, readers that rely on
 * BIGNUM (nagra, conax, cryptoworks) will need an alternative backend.
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_BIGNUM
#include "mbedtls/private/bignum.h"

BN_CTX *BN_CTX_new(void) { return (BN_CTX *)mbedtls_calloc(1, sizeof(BN_CTX)); }
void BN_CTX_free(BN_CTX *ctx) { if (ctx) mbedtls_free(ctx); }
void BN_CTX_start(BN_CTX *ctx) { (void)ctx; }
void BN_CTX_end(BN_CTX *ctx) { (void)ctx; }

BIGNUM *BN_CTX_get(BN_CTX *ctx)
{
	(void)ctx;
	BIGNUM *bn = mbedtls_calloc(1, sizeof(BIGNUM));
	if (bn)
		mbedtls_mpi_init(bn);
	return bn;
}

BIGNUM *BN_new(void)
{
	BIGNUM *bn = mbedtls_calloc(1, sizeof(BIGNUM));
	if (bn)
		mbedtls_mpi_init(bn);
	return bn;
}

void BN_free(BIGNUM *bn)
{
	if (bn) {
		mbedtls_mpi_free(bn);
		mbedtls_free(bn);
	}
}

int BN_num_bytes(const BIGNUM *bn)
{
	if (!bn) return 0;
	return (int)mbedtls_mpi_size(bn);
}

BIGNUM *BN_bin2bn(const unsigned char *in, int len, BIGNUM *bn)
{
	if (!bn) bn = BN_new();
	if (!bn) return NULL;
	mbedtls_mpi_read_binary(bn, in, len);
	return bn;
}

int BN_bn2bin(const BIGNUM *bn, unsigned char *out)
{
	if (!bn || !out) return 0;
	size_t olen = mbedtls_mpi_size(bn);
	mbedtls_mpi_write_binary(bn, out, olen);
	return (int)olen;
}

int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
			   const BIGNUM *m, BN_CTX *ctx)
{
	(void)ctx;
	int ret = mbedtls_mpi_exp_mod(r, a, p, m, NULL);
	return (ret == 0); // mimic OpenSSL: 1 on success, 0 on error
}

int BN_add_word(BIGNUM *a, unsigned long w)
{
	mbedtls_mpi T;
	mbedtls_mpi_init(&T);
	mbedtls_mpi_lset(&T, (mbedtls_mpi_sint)w);
	int ret = mbedtls_mpi_add_mpi(a, a, &T);
	mbedtls_mpi_free(&T);
	return (ret == 0);
}

int BN_sub_word(BIGNUM *a, unsigned long w)
{
	mbedtls_mpi T;
	mbedtls_mpi_init(&T);
	mbedtls_mpi_lset(&T, (mbedtls_mpi_sint)w);
	int ret = mbedtls_mpi_sub_mpi(a, a, &T);
	mbedtls_mpi_free(&T);
	return (ret == 0);
}

int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
	(void)ctx;
	return (mbedtls_mpi_mul_mpi(r, a, b) == 0);
}

BIGNUM *BN_mod_inverse(BIGNUM *r, const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
{
	(void)ctx;
	int ret = mbedtls_mpi_inv_mod(r, a, n);
	if (ret != 0)
		return NULL;
	return r;
}

int BN_cmp(const BIGNUM *a, const BIGNUM *b)
{
	return mbedtls_mpi_cmp_mpi(a, b);
}

BIGNUM *BN_copy(BIGNUM *to, const BIGNUM *from)
{
	if (!to || !from)
		return NULL;
	if (mbedtls_mpi_copy(to, from) != 0)
		return NULL;
	return to;
}

int BN_set_word(BIGNUM *a, unsigned long w)
{
	/* OpenSSL returns 1 on success, MbedTLS returns 0 on success */
	return (mbedtls_mpi_lset(a, (mbedtls_mpi_sint)w) == 0) ? 1 : 0;
}

unsigned long BN_get_word(const BIGNUM *a)
{
	uint64_t val = 0;
	unsigned char buf[8] = {0};

	if (!a) return 0;

	size_t nbytes = mbedtls_mpi_size(a);
	if (nbytes > sizeof(buf))
		nbytes = sizeof(buf);

	// Export the lowest bytes
	if (mbedtls_mpi_write_binary(a, buf + (sizeof(buf) - nbytes), nbytes) != 0)
		return 0;

	// Convert to integer (big-endian)
	for (size_t i = 0; i < sizeof(buf); i++)
		val = (val << 8) | buf[i];

	return (unsigned long)val;
}
#endif /* WITH_LIB_BIGNUM */

#endif /* WITH_MBEDTLS */

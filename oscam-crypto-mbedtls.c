#define MODULE_LOG_PREFIX "crypto"

#include "globals.h"
#include "oscam-crypto.h"
#include "oscam-string.h"

#ifdef WITH_MBEDTLS
/* MbedTLS backend only build of oscam-crypto */


/* ===========================================================
 * MbedTLS backend
 * =========================================================== */
#include "mbedtls/platform.h"
#if defined(WITH_SSL) || defined(WITH_LIB_AES)
#include "mbedtls/aes.h"
#endif
#if defined(WITH_SSL) || defined(WITH_LIB_DES) || defined(WITH_LIB_MDC2)
#include "mbedtls/des.h"
#endif
#if defined(WITH_SSL) || defined(WITH_LIB_MD5)
#include "mbedtls/md5.h"
#endif
#if defined(WITH_SSL) || defined(WITH_LIB_SHA1)
#include "mbedtls/sha1.h"
#endif
#if defined(WITH_SSL) || defined(WITH_LIB_SHA256)
#include "mbedtls/sha256.h"
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
		if (SHA1_Init(&ctx) != 0) return -1;
		if (d1 && l1) if (SHA1_Update(&ctx, d1, l1) != 0) return -1;
		if (d2 && l2) if (SHA1_Update(&ctx, d2, l2) != 0) return -1;
		if (SHA1_Final(out, &ctx) != 0) return -1;
		return 0;
	}
#else
		return -1;
#endif

	case OSCAM_HASH_SHA256:
#ifdef WITH_LIB_SHA256
	{
		SHA256_CTX ctx;
		if (SHA256_Init(&ctx) != 0) return -1;
		if (d1 && l1) if (SHA256_Update(&ctx, d1, l1) != 0) return -1;
		if (d2 && l2) if (SHA256_Update(&ctx, d2, l2) != 0) return -1;
		if (SHA256_Final(out, &ctx) != 0) return -1;
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
 * MD5
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_MD5
unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md)
{
	static unsigned char m[MD5_DIGEST_LENGTH];

	if (md == NULL)
		md = m;

	mbedtls_md5_context ctx;
	mbedtls_md5_init(&ctx);
	mbedtls_md5_starts(&ctx);
	mbedtls_md5_update(&ctx, d, n);
	mbedtls_md5_finish(&ctx, md);
	mbedtls_md5_free(&ctx);

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

	mbedtls_md5_context ctx, ctx1;

	/* Refine the salt */
	sp = salt;
	if (!strncmp(sp, __md5__magic, strlen(__md5__magic)))
		sp += strlen(__md5__magic);

	for (ep = sp; *ep && *ep != '$' && ep < (sp + 8); ep++);
	sl = ep - sp;

	/* Start main digest */
	mbedtls_md5_init(&ctx);
	mbedtls_md5_starts(&ctx);

	pw_len = strlen(pw);
	mbedtls_md5_update(&ctx, (const unsigned char *)pw, pw_len);
	mbedtls_md5_update(&ctx, (const unsigned char *)__md5__magic, strlen(__md5__magic));
	mbedtls_md5_update(&ctx, (const unsigned char *)sp, sl);

	/* MD5(pw, salt, pw) */
	mbedtls_md5_init(&ctx1);
	mbedtls_md5_starts(&ctx1);
	mbedtls_md5_update(&ctx1, (const unsigned char *)pw, pw_len);
	mbedtls_md5_update(&ctx1, (const unsigned char *)sp, sl);
	mbedtls_md5_update(&ctx1, (const unsigned char *)pw, pw_len);
	mbedtls_md5_finish(&ctx1, final);

	for (pl = pw_len; pl > 0; pl -= 16)
		mbedtls_md5_update(&ctx, final, pl > 16 ? 16 : pl);

	memset(final, 0, sizeof final);

	for (i = pw_len; i; i >>= 1)
		mbedtls_md5_update(&ctx, (i & 1) ? final : (const unsigned char *)pw, 1);

	strncpy(passwd, __md5__magic, 4);
	strncat(passwd, sp, sl);
	strcat(passwd, "$");

	mbedtls_md5_finish(&ctx, final);

	/* Stretching */
	for (i = 0; i < 1000; i++) {
		mbedtls_md5_free(&ctx1);
		mbedtls_md5_init(&ctx1);
		mbedtls_md5_starts(&ctx1);

		if (i & 1)
			mbedtls_md5_update(&ctx1, (const unsigned char *)pw, pw_len);
		else
			mbedtls_md5_update(&ctx1, final, 16);

		if (i % 3)
			mbedtls_md5_update(&ctx1, (const unsigned char *)sp, sl);
		if (i % 7)
			mbedtls_md5_update(&ctx1, (const unsigned char *)pw, pw_len);

		if (i & 1)
			mbedtls_md5_update(&ctx1, final, 16);
		else
			mbedtls_md5_update(&ctx1, (const unsigned char *)pw, pw_len);

		mbedtls_md5_finish(&ctx1, final);
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
	mbedtls_md5_free(&ctx);
	mbedtls_md5_free(&ctx1);

	return passwd;
}
#endif/* WITH_LIB_MD5 */

/* ----------------------------------------------------------------------
 * DES
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_DES
typedef struct {
	unsigned char k8[8];
} mbed_des_key_schedule;

static inline mbed_des_key_schedule *DES_S(des_key_schedule *s) { return (mbed_des_key_schedule *)s; }

void oscam_des_set_key(const uint8_t *key, des_key_schedule *schedule)
{
	mbed_des_key_schedule *S = DES_S(schedule);
	memcpy(S->k8, key, 8);
}

void oscam_des_set_odd_parity(uint8_t key8[8])
{
	mbedtls_des_key_set_parity(key8);
}

void oscam_des_set_odd_parity_all(uint8_t *key, size_t len)
{
	if (!key || len == 0)
		return;

	while (len >= 8) {
		mbedtls_des_key_set_parity(key);
		key += 8;
		len -= 8;
	}
}

void oscam_des(uint8_t *data, des_key_schedule *schedule, int enc)
{
	mbed_des_key_schedule *S = DES_S(schedule);
	mbedtls_des_context ctx;
	mbedtls_des_init(&ctx);

	if (enc)
		mbedtls_des_setkey_enc(&ctx, S->k8);
	else
		mbedtls_des_setkey_dec(&ctx, S->k8);

	mbedtls_des_crypt_ecb(&ctx, data, data);
	mbedtls_des_free(&ctx);
}

// --- Single DES ECB ---
void oscam_des_ecb_encrypt(uint8_t *data, const uint8_t *key, int32_t len)
{
	mbedtls_des_context ctx;
	mbedtls_des_init(&ctx);
	mbedtls_des_setkey_enc(&ctx, key);
	len &= ~7;
	for (int i = 0; i < len; i += 8)
		mbedtls_des_crypt_ecb(&ctx, data + i, data + i);
	mbedtls_des_free(&ctx);
}

void oscam_des_ecb_decrypt(uint8_t *data, const uint8_t *key, int32_t len)
{
	mbedtls_des_context ctx;
	mbedtls_des_init(&ctx);
	mbedtls_des_setkey_dec(&ctx, key);
	len &= ~7;
	for (int i = 0; i < len; i += 8)
		mbedtls_des_crypt_ecb(&ctx, data + i, data + i);
	mbedtls_des_free(&ctx);
}

// --- DES CBC ---
void oscam_des_cbc_encrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key, int32_t len)
{
	mbedtls_des_context ctx;
	unsigned char iv_copy[8];
	memcpy(iv_copy, iv, 8);

	mbedtls_des_init(&ctx);
	mbedtls_des_setkey_enc(&ctx, key);
	mbedtls_des_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, len & ~7, iv_copy, data, data);
	mbedtls_des_free(&ctx);
}

void oscam_des_cbc_decrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key, int32_t len)
{
	mbedtls_des_context ctx;
	unsigned char iv_copy[8];
	memcpy(iv_copy, iv, 8);

	mbedtls_des_init(&ctx);
	mbedtls_des_setkey_dec(&ctx, key);
	mbedtls_des_crypt_cbc(&ctx, MBEDTLS_DES_DECRYPT, len & ~7, iv_copy, data, data);
	mbedtls_des_free(&ctx);
}

// --- 2-key 3DES (EDE2) CBC ---
void oscam_des_ede2_cbc_encrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key1, const uint8_t *key2, int32_t len)
{
	mbedtls_des3_context ctx;
	unsigned char iv_copy[8];
	unsigned char key24[24];
	size_t n = (size_t)len & ~7u;

	memcpy(iv_copy, iv, 8);
	memcpy(key24,       key1, 8);
	memcpy(key24 + 8,   key2, 8);
	memcpy(key24 + 16,  key1, 8); /* repeat key1 for 2-key 3DES */

	mbedtls_des3_init(&ctx);
	mbedtls_des3_set3key_enc(&ctx, key24);
	mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, n, iv_copy, data, data);
	mbedtls_des3_free(&ctx);
}

void oscam_des_ede2_cbc_decrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key1, const uint8_t *key2, int32_t len)
{
	mbedtls_des3_context ctx;
	unsigned char iv_copy[8];
	unsigned char key24[24];
	size_t n = (size_t)len & ~7u;

	memcpy(iv_copy, iv, 8);
	memcpy(key24,       key1, 8);
	memcpy(key24 + 8,   key2, 8);
	memcpy(key24 + 16,  key1, 8);

	mbedtls_des3_init(&ctx);
	mbedtls_des3_set3key_dec(&ctx, key24);
	mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_DECRYPT, n, iv_copy, data, data);
	mbedtls_des3_free(&ctx);
}

// --- 3DES ECB ---
void oscam_des_ecb3_decrypt(uint8_t *data, const uint8_t *key)
{
	mbedtls_des3_context ctx;
	mbedtls_des3_init(&ctx);

	/* 2-key EDE2 mode (16-byte key). For true 3-key EDE3 (24 bytes),
	use mbedtls_des3_set3key_dec() instead. */
	mbedtls_des3_set2key_dec(&ctx, key);
	mbedtls_des3_crypt_ecb(&ctx, data, data);

	mbedtls_des3_free(&ctx);
}

void oscam_des_ecb3_encrypt(uint8_t *data, const uint8_t *key)
{
	mbedtls_des3_context ctx;
	mbedtls_des3_init(&ctx);

	/* 2-key EDE2 mode (16-byte key). For true 3-key EDE3 (24 bytes),
	use mbedtls_des3_set3key_enc() instead. */
	mbedtls_des3_set2key_enc(&ctx, key);
	mbedtls_des3_crypt_ecb(&ctx, data, data);

	mbedtls_des3_free(&ctx);
}
#endif/* WITH_LIB_DES */

/* ----------------------------------------------------------------------
 * SHA1
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_SHA1
typedef struct { mbedtls_sha1_context ctx; } mbed_sha1;
static inline mbed_sha1 *SHA1_S(SHA_CTX *c) { return (mbed_sha1 *)c; }

unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md)
{
	static unsigned char _buf[SHA_DIGEST_LENGTH];
	if (!md) md = _buf;
	SHA_CTX c;
	SHA1_Init(&c);
	SHA1_Update(&c, d, n);
	SHA1_Final(md, &c);
	return md;
}

int SHA1_Init(SHA_CTX *c)
{
	mbed_sha1 *S = SHA1_S(c);
	mbedtls_sha1_init(&S->ctx);
	return mbedtls_sha1_starts(&S->ctx);
}

int SHA1_Update(SHA_CTX *c, const void *data, size_t len)
{
	return mbedtls_sha1_update(&SHA1_S(c)->ctx, data, len);
}

int SHA1_Final(unsigned char *md, SHA_CTX *c)
{
	mbed_sha1 *S = SHA1_S(c);
	int ret = mbedtls_sha1_finish(&S->ctx, md);
	mbedtls_sha1_free(&S->ctx);
	return ret;
}
#endif/* WITH_LIB_SHA1 */

/* ----------------------------------------------------------------------
 * SHA256
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_SHA256
typedef struct { mbedtls_sha256_context ctx; } mbed_sha256;
static inline mbed_sha256 *SHA256_S(SHA256_CTX *c) { return (mbed_sha256 *)c; }

int SHA256_Init(SHA256_CTX *c) {
	mbed_sha256 *S = SHA256_S(c);
	mbedtls_sha256_init(&S->ctx);
	return mbedtls_sha256_starts(&S->ctx, 0);
}

int SHA256_Update(SHA256_CTX *c, const void *d, size_t l) {
	return mbedtls_sha256_update(&SHA256_S(c)->ctx, d, l);
}

int SHA256_Final(unsigned char *md, SHA256_CTX *c)
{
    mbed_sha256 *S = SHA256_S(c);
    int rc = mbedtls_sha256_finish(&S->ctx, md);
    mbedtls_sha256_free(&S->ctx);
    return rc;
}

void SHA256_Free(SHA256_CTX *c)
{
	mbed_sha256 *S = SHA256_S(c);
	mbedtls_sha256_free(&S->ctx);
}
#endif/* WITH_LIB_SHA256 */

/* ----------------------------------------------------------------------
 * AES
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_AES
typedef struct {
	mbedtls_aes_context enc;
	mbedtls_aes_context dec;
	unsigned char iv[16];
	unsigned char mode;
	unsigned char nr;
} mbed_aesctx;

static inline mbed_aesctx *AES_C(AesCtx *c) { return (mbed_aesctx *)c; }

int AesCtxIni(AesCtx *c, const unsigned char *iv, const unsigned char *key, int keylen, int mode)
{
	mbed_aesctx *C = AES_C(c);
	mbedtls_aes_init(&C->enc);
	mbedtls_aes_init(&C->dec);
	int bits = keylen * 8;
	if (mbedtls_aes_setkey_enc(&C->enc, key, bits) != 0) return -1;
	if (mbedtls_aes_setkey_dec(&C->dec, key, bits) != 0) return -1;
	if (iv) memcpy(C->iv, iv, 16);
	C->mode = (unsigned char)mode;
	C->nr = (keylen == 16 ? 10 : keylen == 24 ? 12 : 14);
	return 0;
}

int AesEncrypt(AesCtx *c, const unsigned char *in, unsigned char *out, int len)
{
	mbed_aesctx *C = AES_C(c);
	if (C->mode == CBC) {
		unsigned char iv_local[16]; memcpy(iv_local, C->iv, 16);
		int rc = mbedtls_aes_crypt_cbc(&C->enc, MBEDTLS_AES_ENCRYPT, (size_t)len, iv_local, in, out);
		if (rc) return -1;
		memcpy(C->iv, iv_local, 16);
	} else {
		for (int i = 0; i < len; i += 16)
			mbedtls_aes_crypt_ecb(&C->enc, MBEDTLS_AES_ENCRYPT, in + i, out + i);
	}
	return len;
}

int AesDecrypt(AesCtx *c, const unsigned char *in, unsigned char *out, int len)
{
	mbed_aesctx *C = AES_C(c);
	if (C->mode == CBC) {
		unsigned char iv_local[16]; memcpy(iv_local, C->iv, 16);
		int rc = mbedtls_aes_crypt_cbc(&C->dec, MBEDTLS_AES_DECRYPT, (size_t)len, iv_local, in, out);
		if (rc) return -1;
		memcpy(C->iv, iv_local, 16);
	} else {
		for (int i = 0; i < len; i += 16)
			mbedtls_aes_crypt_ecb(&C->dec, MBEDTLS_AES_DECRYPT, in + i, out + i);
	}
	return len;
}

typedef struct {
	mbedtls_aes_context enc_ctx;
	mbedtls_aes_context dec_ctx;
} mbed_aeskey;

static inline mbed_aeskey *AK(const AES_KEY *k) { return (mbed_aeskey *)(void*)k; }
static inline mbed_aeskey *AKw(AES_KEY *k)      { return (mbed_aeskey *)(void*)k; }

int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key)
{
	if (!key) return -1;
	mbed_aeskey *K = AKw(key);
	mbedtls_aes_init(&K->enc_ctx);
	//mbedtls_aes_init(&K->dec_ctx);
	return mbedtls_aes_setkey_enc(&K->enc_ctx, userKey, bits);
}

int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key)
{
	if (!key) return -1;
	mbed_aeskey *K = AKw(key);
	//mbedtls_aes_init(&K->enc_ctx);
	mbedtls_aes_init(&K->dec_ctx);
	return mbedtls_aes_setkey_dec(&K->dec_ctx, userKey, bits);
}

void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
	if (!key) return;
	(void)mbedtls_aes_crypt_ecb(&AK(key)->enc_ctx, MBEDTLS_AES_ENCRYPT, in, out);
}

void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
	if (!key) return;
	(void)mbedtls_aes_crypt_ecb(&AK(key)->dec_ctx, MBEDTLS_AES_DECRYPT, in, out);
}

int AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
					size_t length, const AES_KEY *key,
					unsigned char *ivec, const int enc)
{
	if (!key || !ivec) return -1;
	mbed_aeskey *K = AK(key);
	return mbedtls_aes_crypt_cbc(enc ? &K->enc_ctx : &K->dec_ctx,
								 enc, length, ivec, in, out);
}

typedef struct { mbedtls_aes_context enc, dec; } mbed_pair;

void aes_set_key(void *aes, char *key)
{
	mbed_pair *p = (mbed_pair *)aes;
	if (!p || !key) return;
	mbedtls_aes_init(&p->enc); mbedtls_aes_init(&p->dec);
	mbedtls_aes_setkey_enc(&p->enc, (unsigned char *)key, 128);
	mbedtls_aes_setkey_dec(&p->dec, (unsigned char *)key, 128);
}

bool aes_set_key_alloc(aes_keys **aes, char *key)
{
	mbed_pair *p;
	if (!cs_malloc(&p, sizeof(*p))) return false;
	*aes = (aes_keys *)p;
	aes_set_key(p, key);
	return true;
}

void aes_decrypt(void *aes, uint8_t *buf, int32_t n)
{
	mbed_pair *p = (mbed_pair *)aes;
	for (int32_t i = 0; i < n; i += 16)
		mbedtls_aes_crypt_ecb(&p->dec, MBEDTLS_AES_DECRYPT, buf + i, buf + i);
}

void aes_encrypt_idx(void *aes, uint8_t *buf, int32_t n)
{
	mbed_pair *p = (mbed_pair *)aes;
	for (int32_t i = 0; i < n; i += 16)
		mbedtls_aes_crypt_ecb(&p->enc, MBEDTLS_AES_ENCRYPT, buf + i, buf + i);
}

void aes_cbc_encrypt(void *aes, uint8_t *buf, int32_t n, uint8_t *iv)
{
	mbed_pair *p = (mbed_pair *)aes;
	mbedtls_aes_crypt_cbc(&p->enc, MBEDTLS_AES_ENCRYPT, n, iv, buf, buf);
}

void aes_cbc_decrypt(void *aes, uint8_t *buf, int32_t n, uint8_t *iv)
{
	mbed_pair *p = (mbed_pair *)aes;
	mbedtls_aes_crypt_cbc(&p->dec, MBEDTLS_AES_DECRYPT, n, iv, buf, buf);
}

/* --- List management for per-reader AES keys --- */
void add_aes_entry(AES_ENTRY **list, uint16_t caid, uint32_t ident, int32_t keyid, uint8_t *aesKey)
{
	AES_ENTRY *e;
	if (!cs_malloc(&e, sizeof(*e))) return;

	memcpy(e->plainkey, aesKey, 16);
	e->caid = caid; e->ident = ident; e->keyid = keyid; e->next = NULL;

	if (memcmp(aesKey, "\xFF\xFF", 2) != 0) {
		mbed_pair *p;
		if (!cs_malloc(&p, sizeof(*p))) { free(e); return; }
		mbedtls_aes_init(&p->dec); mbedtls_aes_init(&p->enc);
		mbedtls_aes_setkey_dec(&p->dec, aesKey, 128);
		mbedtls_aes_setkey_enc(&p->enc, aesKey, 128);
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
		if (cur->key) {
			mbed_pair *p = (mbed_pair *)cur->key;
			mbedtls_aes_free(&p->dec);
			mbedtls_aes_free(&p->enc);
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
	AES_ENTRY *cur;
	for (cur = list; cur; cur = cur->next)
		if (cur->caid == caid && cur->ident == provid && cur->keyid == keyid) break;

	if (!cur) {
		cs_log("AES Decrypt key %d not found for %04X@%06X (aka V %06X E%X ...)", keyid, caid, provid, provid, keyid);
		return 0;
	}
	if (!cur->key) return 1;

	mbed_pair *p = (mbed_pair *)cur->key;
	for (int32_t i = 0; i < n; i += 16)
		mbedtls_aes_crypt_ecb(&p->dec, MBEDTLS_AES_DECRYPT, buf + i, buf + i);
	return 1;
}

int32_t aes_present(AES_ENTRY *list, uint16_t caid, uint32_t provid, int32_t keyid)
{
	return aes_list_find(list, caid, provid, keyid) != NULL;
}
#endif/* WITH_LIB_AES */

/* ----------------------------------------------------------------------
 * BIGNUM
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_BIGNUM
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
	return mbedtls_mpi_lset(a, (mbedtls_mpi_sint)w);
}

unsigned long BN_get_word(const BIGNUM *a)
{
	uint64_t val = 0;
	unsigned char buf[8] = {0};

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

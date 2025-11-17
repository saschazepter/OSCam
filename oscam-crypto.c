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

/* EVP_MD_CTX_create/free were renamed in 1.1.0 */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#ifndef EVP_MD_CTX_create
#define EVP_MD_CTX_create EVP_MD_CTX_new
#endif
#ifndef EVP_MD_CTX_destroy
#define EVP_MD_CTX_destroy EVP_MD_CTX_free
#endif
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
EVP_CIPHER_CTX *oscam_EVP_CIPHER_CTX_new(void)
{
	EVP_CIPHER_CTX *ctx = OPENSSL_malloc(sizeof(EVP_CIPHER_CTX));
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
	OPENSSL_free(ctx);
}
#endif

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

void oscam_des_ecb_encrypt(uint8_t *data, const uint8_t *key, int32_t len) {
	DES_key_schedule ks; DES_set_key_unchecked((const_DES_cblock*)key, &ks);
	DES_cblock b;
	for (int32_t i = 0; i + 8 <= (len & ~7); i += 8) {
		memcpy(b, data + i, 8);
		DES_ecb_encrypt(&b, &b, &ks, DES_ENCRYPT);
		memcpy(data + i, b, 8);
	}
}

void des_ecb_decrypt(uint8_t *data, const uint8_t *key, int32_t len) {
	DES_key_schedule ks; DES_set_key_unchecked((const_DES_cblock*)key, &ks);
	DES_cblock b;
	for (int32_t i = 0; i + 8 <= (len & ~7); i += 8) {
		memcpy(b, data + i, 8);
		DES_ecb_encrypt(&b, &b, &ks, DES_DECRYPT);
		memcpy(data + i, b, 8);
	}
}

void oscam_des_cbc_encrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key, int32_t len) {
	DES_key_schedule ks; DES_set_key_unchecked((const_DES_cblock*)key, &ks);
	DES_cblock ivc; memcpy(ivc, iv, 8);
	DES_ncbc_encrypt(data, data, len & ~7, &ks, &ivc, DES_ENCRYPT);
}

void des_cbc_decrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key, int32_t len) {
	DES_key_schedule ks; DES_set_key_unchecked((const_DES_cblock*)key, &ks);
	DES_cblock ivc; memcpy(ivc, iv, 8);
	DES_ncbc_encrypt(data, data, len & ~7, &ks, &ivc, DES_DECRYPT);
}

void oscam_des_ede2_cbc_encrypt(uint8_t *data, const uint8_t *iv,
						  const uint8_t *k1, const uint8_t *k2, int32_t len) {
	DES_key_schedule ks1, ks2;
	DES_set_key_unchecked((const_DES_cblock*)k1, &ks1);
	DES_set_key_unchecked((const_DES_cblock*)k2, &ks2);
	DES_key_schedule ks3 = ks1; /* EDE2 */
	DES_cblock ivc; memcpy(ivc, iv, 8);
	DES_ede3_cbc_encrypt(data, data, len & ~7, &ks1, &ks2, &ks3, &ivc, DES_ENCRYPT);
}

void des_ede2_cbc_decrypt(uint8_t *data, const uint8_t *iv,
						  const uint8_t *k1, const uint8_t *k2, int32_t len) {
	DES_key_schedule ks1, ks2;
	DES_set_key_unchecked((const_DES_cblock*)k1, &ks1);
	DES_set_key_unchecked((const_DES_cblock*)k2, &ks2);
	DES_key_schedule ks3 = ks1; /* EDE2 */
	DES_cblock ivc; memcpy(ivc, iv, 8);
	DES_ede3_cbc_encrypt(data, data, len & ~7, &ks1, &ks2, &ks3, &ivc, DES_DECRYPT);
}

void oscam_des_ecb3_encrypt(uint8_t *data, const uint8_t *key16)
{
	DES_cblock in, out; memcpy(in, data, 8);
	DES_key_schedule k1, k2, k3;
	/* EDE2 mode: 2-key Triple-DES, K3 == K1 (total 16-byte key)
	For true 3-key EDE3 (24 bytes): load k3 from key+16. */
	DES_set_key_unchecked((const_DES_cblock*)(key16+0),  &k1);
	DES_set_key_unchecked((const_DES_cblock*)(key16+8),  &k2);
	k3 = k1;
	DES_ecb3_encrypt(&in, &out, &k1, &k2, &k3, DES_ENCRYPT);
	memcpy(data, out, 8);
}

void des_ecb3_decrypt(uint8_t *data, const uint8_t *key16) {
	DES_cblock in, out; memcpy(in, data, 8);
	DES_key_schedule k1, k2, k3;
	/* EDE2 mode: 2-key Triple-DES, K3 == K1 (total 16-byte key)
	For true 3-key EDE3 (24 bytes): load k3 from key+16. */
	DES_set_key_unchecked((const_DES_cblock*)(key16+0),  &k1);
	DES_set_key_unchecked((const_DES_cblock*)(key16+8),  &k2);
	k3 = k1;
	DES_ecb3_encrypt(&in, &out, &k1, &k2, &k3, DES_DECRYPT);
	memcpy(data, out, 8);
}

#if defined(__GNUC__) && (__GNUC__ * 100 + __GNUC_MINOR__ >= 406)
#pragma GCC diagnostic pop
#endif
#endif/* WITH_LIB_DES */

/* ----------------------------------------------------------------------
 * SHA256
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_SHA256
void SHA256_Free(SHA256_CTX *c) { (void)c; }
#endif/* WITH_LIB_SHA256 */

/* ----------------------------------------------------------------------
 * AES
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_AES
typedef struct {
	EVP_CIPHER_CTX *enc;	  /* ECB encrypt context (no padding) */
    EVP_CIPHER_CTX *dec;	  /* ECB decrypt context (no padding) */
    unsigned char   iv[16];
    unsigned char   mode;	 /* CBC or ECB (0) */
    unsigned char   nr;	   /* kept for symmetry */
    int             key_bits; /* 128 / 192 / 256 */
} ossl_aesctx;

static inline const EVP_CIPHER *aes_ecb_cipher(int bits) {
	switch (bits) {
		case 128: return EVP_aes_128_ecb();
		case 192: return EVP_aes_192_ecb();
		case 256: return EVP_aes_256_ecb();
		default:  return NULL;
	}
}

static inline const EVP_CIPHER *aes_cbc_cipher(int bits) {
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
	if (!cipher) return -1;

	C->enc = EVP_CIPHER_CTX_new();
	C->dec = EVP_CIPHER_CTX_new();
	if (!C->enc || !C->dec) return -1;

	// iv is NULL here; we set it separately below for CBC
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

	if (!key_bits) return -1;

	ossl_aesctx *C = AES_C(c);
	if (aes_ctx_init_pair(C, key, key_bits, mode) != 0) return -1;
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
		// Optionally mirror IV update into C->iv using last block of out
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
		int outl;
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
	e->caid = caid; e->ident = ident; e->keyid = keyid; e->next = NULL;

	if (memcmp(aesKey, "\xFF\xFF", 2) != 0) {
		ossl_pair *p;
		if (!cs_malloc(&p, sizeof(*p))) { free(e); return; }
		if (pair_init(p, aesKey, 128) != 0) { free(p); free(e); return; }
		e->key = p;
	} else {
		e->key = NULL; /* dummy -> card decrypts */
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

#else /* WITH_OPENSSL -------------------------------------------------- */

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

void des_ecb_decrypt(uint8_t *data, const uint8_t *key, int32_t len)
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

void des_cbc_decrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key, int32_t len)
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

void des_ede2_cbc_decrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key1, const uint8_t *key2, int32_t len)
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
void des_ecb3_decrypt(uint8_t *data, const uint8_t *key)
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

#endif /* WITH_OPENSSL */

/* ----------------------------------------------------------------------
 * MDC2 (internal implementation, not provided by mbedtls nor openssl)
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_MDC2
typedef struct {
	unsigned int num;
	unsigned int pad_type;
	unsigned char h[MDC2_BLOCK];
	unsigned char hh[MDC2_BLOCK];
	unsigned char data[MDC2_BLOCK];
} mdc2_int;

static inline mdc2_int *MDC2_S(MDC2_CTX *c) { return (mdc2_int *)c; }

static inline uint32_t c2l(const unsigned char **c)
{
	const unsigned char *p = *c;
	uint32_t l = ((uint32_t)p[0]) |
				 ((uint32_t)p[1] << 8) |
				 ((uint32_t)p[2] << 16) |
				 ((uint32_t)p[3] << 24);
	*c += 4;
	return l;
}

static inline void l2c(uint32_t l, unsigned char **c)
{
	unsigned char *p = *c;
	p[0] = (unsigned char)(l);
	p[1] = (unsigned char)(l >> 8);
	p[2] = (unsigned char)(l >> 16);
	p[3] = (unsigned char)(l >> 24);
	*c += 4;
}

static void mdc2_body(MDC2_CTX *c, const unsigned char *in, size_t len)
{
	mdc2_int *C = MDC2_S(c);
	uint32_t tin0, tin1, ttin0, ttin1;
	uint8_t block[8], hkey[8], hhkey[8], tmp[8], tmp2[8];
	des_key_schedule k;

	for (size_t i = 0; i < len; i += 8) {
		const unsigned char *p = in + i;

		tin0 = c2l(&p);
		tin1 = c2l(&p);

		memcpy(block, in + i, 8);
		memcpy(hkey,  C->h,  8);
		memcpy(hhkey, C->hh, 8);

		hkey[0]  = (hkey[0]  & 0x9f) | 0x40;
		hhkey[0] = (hhkey[0] & 0x9f) | 0x20;

		/* Encrypt block with both DES keys */
		oscam_des_set_key(hkey, &k);
		memcpy(tmp, block, 8);
		des(tmp, &k, 1);

		oscam_des_set_key(hhkey, &k);
		memcpy(tmp2, block, 8);
		des(tmp2, &k, 1);

		ttin0 = tin0 ^ ((uint32_t)tmp2[0] | ((uint32_t)tmp2[1] << 8) |
						((uint32_t)tmp2[2] << 16) | ((uint32_t)tmp2[3] << 24));
		ttin1 = tin1 ^ ((uint32_t)tmp2[4] | ((uint32_t)tmp2[5] << 8) |
						((uint32_t)tmp2[6] << 16) | ((uint32_t)tmp2[7] << 24));

		tin0 ^= ((uint32_t)tmp[0] | ((uint32_t)tmp[1] << 8) |
				 ((uint32_t)tmp[2] << 16) | ((uint32_t)tmp[3] << 24));
		tin1 ^= ((uint32_t)tmp[4] | ((uint32_t)tmp[5] << 8) |
				 ((uint32_t)tmp[6] << 16) | ((uint32_t)tmp[7] << 24));

		unsigned char *q = C->h;
		l2c(tin0, &q);
		l2c(ttin1, &q);
		q = C->hh;
		l2c(ttin0, &q);
		l2c(tin1, &q);
	}
}

int MDC2_Init(MDC2_CTX *c)
{
	mdc2_int *C = MDC2_S(c);
	C->num = 0;
	C->pad_type = 1;
	memset(C->h,  0x52, MDC2_BLOCK);
	memset(C->hh, 0x25, MDC2_BLOCK);
	memset(C->data, 0, sizeof(C->data));
	return 1;
}

int MDC2_Update(MDC2_CTX *c, const unsigned char *in, size_t len)
{
	mdc2_int *C = MDC2_S(c);
	size_t i = C->num;

	if (i != 0) {
		if (len < MDC2_BLOCK - i) {
			memcpy(&C->data[i], in, len);
			C->num += (unsigned int)len;
			return 1;
		} else {
			size_t j = MDC2_BLOCK - i;
			memcpy(&C->data[i], in, j);
			len -= j;
			in += j;
			C->num = 0;
			mdc2_body(c, C->data, MDC2_BLOCK);
		}
	}

	size_t blocks = len & ~(MDC2_BLOCK - 1);
	if (blocks > 0)
		mdc2_body(c, in, blocks);

	size_t rem = len - blocks;
	if (rem > 0) {
		memcpy(C->data, in + blocks, rem);
		C->num = (unsigned int)rem;
	}
	return 1;
}

int MDC2_Final(unsigned char *md, MDC2_CTX *c)
{
	mdc2_int *C = MDC2_S(c);
	if (C->num > 0 || C->pad_type == 2) {
		if (C->pad_type == 2)
			C->data[C->num++] = 0x80;
		memset(C->data + C->num, 0, MDC2_BLOCK - C->num);
		mdc2_body(c, C->data, MDC2_BLOCK);
	}

	memcpy(md, C->h, MDC2_BLOCK);
	memcpy(md + MDC2_BLOCK, C->hh, MDC2_BLOCK);
	return 1;
}
#endif /* WITH_LIB_MDC2 */

/* ----------------------------------------------------------------------
 * IDEA (internal implementation, not provided by mbedtls nor openssl)
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_IDEA
/* ====================================================================
 * Local IDEA (Eric Young) internals
 * ====================================================================
 * Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is based on SSL implementation written
 * by Eric Young (eay@cryptsoft.com) with some modifications.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifndef __OSC_INTERNAL_IDEA
#define __OSC_INTERNAL_IDEA

/* All IDEA big-endian packing macros must remain bit-identical to
   Eric Young’s original implementation (OpenSSL <= 1.0.x).
   Do NOT convert them to loops or refactor them. */

#define n2ln(c,l1,l2,n) do {                                           \
		(c) += (n);                                                    \
		(l1) = (l2) = 0;                                               \
		switch (n) {                                                   \
		case 8: (l2)  = (uint32_t)(*(--(c)));       /* fall through */ \
		case 7: (l2) |= (uint32_t)(*(--(c))) <<  8; /* fall through */ \
		case 6: (l2) |= (uint32_t)(*(--(c))) << 16; /* fall through */ \
		case 5: (l2) |= (uint32_t)(*(--(c))) << 24; /* fall through */ \
		case 4: (l1)  = (uint32_t)(*(--(c)));       /* fall through */ \
		case 3: (l1) |= (uint32_t)(*(--(c))) <<  8; /* fall through */ \
		case 2: (l1) |= (uint32_t)(*(--(c))) << 16; /* fall through */ \
		case 1: (l1) |= (uint32_t)(*(--(c))) << 24;                    \
		}                                                              \
	} while (0)

#define l2nn(l1,l2,c,n) do {                                               \
		(c) += (n);                                                        \
		switch (n) {                                                       \
		case 8: *(--(c)) = (uint8_t)((l2)      & 0xff); /* fall through */ \
		case 7: *(--(c)) = (uint8_t)(((l2)>> 8)& 0xff); /* fall through */ \
		case 6: *(--(c)) = (uint8_t)(((l2)>>16)& 0xff); /* fall through */ \
		case 5: *(--(c)) = (uint8_t)(((l2)>>24)& 0xff); /* fall through */ \
		case 4: *(--(c)) = (uint8_t)((l1)      & 0xff); /* fall through */ \
		case 3: *(--(c)) = (uint8_t)(((l1)>> 8)& 0xff); /* fall through */ \
		case 2: *(--(c)) = (uint8_t)(((l1)>>16)& 0xff); /* fall through */ \
		case 1: *(--(c)) = (uint8_t)(((l1)>>24)& 0xff);                    \
		}                                                                  \
	} while (0)

#undef n2l
#define n2l(c,l) (                               \
		(l)  = ((uint32_t)(*((c)++))) << 24,     \
		(l) |= ((uint32_t)(*((c)++))) << 16,     \
		(l) |= ((uint32_t)(*((c)++))) <<  8,     \
		(l) |= ((uint32_t)(*((c)++)))      )

#undef l2n
#define l2n(l,c) do {                            \
		*((c)++) = (uint8_t)(((l)>>24) & 0xff);  \
		*((c)++) = (uint8_t)(((l)>>16) & 0xff);  \
		*((c)++) = (uint8_t)(((l)>> 8) & 0xff);  \
		*((c)++) = (uint8_t)(((l)     ) & 0xff); \
	} while (0)

#undef s2n
#define s2n(v,c) do {                            \
		*((c)++) = (uint8_t)((v)      & 0xff);   \
		*((c)++) = (uint8_t)(((v)>> 8) & 0xff);  \
	} while (0)

#undef n2s
#define n2s(c,v) do {                            \
		(v)  = (IDEA_INT)(*((c)++)) << 8;        \
		(v) |= (IDEA_INT)(*((c)++));             \
	} while (0)

#ifndef IDEA_DEFAULT_OPTIONS
# define IDEA_DEFAULT_OPTIONS "idea(16 bit)"
#endif

#endif /* __OSC_INTERNAL_IDEA */

/* 16-bit multiplicative group multiply used by IDEA.
 * Bit-exact to Eric Young's macro version.
 */
static inline IDEA_INT idea_mul16(IDEA_INT a, IDEA_INT b)
{
	unsigned long ul = (unsigned long)a * b; /* 32-bit is enough, but UL is OK */
	IDEA_INT r;

	if (ul != 0) {
		ul = (ul & 0xffffUL) - (ul >> 16);
		r = (IDEA_INT)ul;
		r -= (IDEA_INT)(r >> 16);
	} else {
		/* assuming a or b is 0 and in range */
		r = (IDEA_INT)(-(int)a - (int)b + 1);
	}

	return r;
}

/* Multiplicative inverse in GF(65537), bit-compatible with original */
static inline IDEA_INT idea_inverse(unsigned int xin)
{
	long n1, n2, q, r, b1, b2, t;

	if (xin == 0) {
		b2 = 0;
	} else {
		n1 = 0x10001L;
		n2 = xin;
		b2 = 1;
		b1 = 0;

		do {
			r = (n1 % n2);
			q = (n1 - r) / n2;
			if (r == 0) {
				if (b2 < 0)
					b2 = 0x10001L + b2;
			} else {
				n1 = n2;
				n2 = r;
				t  = b2;
				b2 = b1 - q * b2;
				b1 = t;
			}
		} while (r != 0);
	}
	return (IDEA_INT)b2;
}

/* 8 full IDEA rounds, bit-identical to the macro version */
static inline void idea_rounds(uint32_t *x1p, uint32_t *x2p, uint32_t *x3p, uint32_t *x4p, IDEA_INT **kp)
{
	uint32_t x1 = *x1p;
	uint32_t x2 = *x2p;
	uint32_t x3 = *x3p;
	uint32_t x4 = *x4p;
	IDEA_INT *p = *kp;
	int round;

	for (round = 0; round < 8; round++) {
		uint32_t t0, t1;

		x1 &= 0xffffU;
		x1 = (uint32_t)idea_mul16((IDEA_INT)x1, *p++);
		x2 = (x2 + *p++) & 0xffffU;
		x3 = (x3 + *p++) & 0xffffU;
		x4 &= 0xffffU;
		x4 = (uint32_t)idea_mul16((IDEA_INT)x4, *p++);

		t0 = (x1 ^ x3) & 0xffffU;
		t0 = (uint32_t)idea_mul16((IDEA_INT)t0, *p++);
		t1 = (t0 + ((x2 ^ x4) & 0xffffU)) & 0xffffU;
		t1 = (uint32_t)idea_mul16((IDEA_INT)t1, *p++);

		t0 = (t0 + t1) & 0xffffU;

		x1 ^= t1;
		x4 ^= t0;

		{
			uint32_t tmp = x2 ^ t0;
			x2 = x3 ^ t1;
			x3 = tmp;
		}
	}

	*x1p = x1;
	*x2p = x2;
	*x3p = x3;
	*x4p = x4;
	*kp  = p;
}

void oscam_idea_set_encrypt_key(const unsigned char *key, IDEA_KEY_SCHEDULE *ks)
{
	int i;
	IDEA_INT *kt, *kf, r0, r1, r2;

	kt = &ks->data[0][0];

	n2s(key, kt[0]);
	n2s(key, kt[1]);
	n2s(key, kt[2]);
	n2s(key, kt[3]);
	n2s(key, kt[4]);
	n2s(key, kt[5]);
	n2s(key, kt[6]);
	n2s(key, kt[7]);

	kf = kt;
	kt += 8;

	for (i = 0; i < 6; i++) {
		r2 = kf[1];
		r1 = kf[2];
		*(kt++) = (IDEA_INT)(((r2 << 9) | (r1 >> 7)) & 0xffff);
		r0 = kf[3];
		*(kt++) = (IDEA_INT)(((r1 << 9) | (r0 >> 7)) & 0xffff);
		r1 = kf[4];
		*(kt++) = (IDEA_INT)(((r0 << 9) | (r1 >> 7)) & 0xffff);
		r0 = kf[5];
		*(kt++) = (IDEA_INT)(((r1 << 9) | (r0 >> 7)) & 0xffff);
		r1 = kf[6];
		*(kt++) = (IDEA_INT)(((r0 << 9) | (r1 >> 7)) & 0xffff);
		r0 = kf[7];
		*(kt++) = (IDEA_INT)(((r1 << 9) | (r0 >> 7)) & 0xffff);
		r1 = kf[0];
		if (i >= 5)
			break;
		*(kt++) = (IDEA_INT)(((r0 << 9) | (r1 >> 7)) & 0xffff);
		*(kt++) = (IDEA_INT)(((r1 << 9) | (r2 >> 7)) & 0xffff);
		kf += 8;
	}
}

void oscam_idea_set_decrypt_key(IDEA_KEY_SCHEDULE *ek, IDEA_KEY_SCHEDULE *dk)
{
	int r;
	IDEA_INT *fp, *tp, t;

	tp = &dk->data[0][0];
	fp = &ek->data[8][0];

	for (r = 0; r < 9; r++) {
		*(tp++) = idea_inverse(fp[0]);
		*(tp++) = (IDEA_INT)((0x10000L - fp[2]) & 0xffff);
		*(tp++) = (IDEA_INT)((0x10000L - fp[1]) & 0xffff);
		*(tp++) = idea_inverse(fp[3]);
		if (r == 8)
			break;
		fp -= 6;
		*(tp++) = fp[4];
		*(tp++) = fp[5];
	}

	/* Swaps required by algorithm */
	t = dk->data[0][1];
	dk->data[0][1] = dk->data[0][2];
	dk->data[0][2] = t;

	t = dk->data[8][1];
	dk->data[8][1] = dk->data[8][2];
	dk->data[8][2] = t;
}

void oscam_idea_encrypt(unsigned long *d, IDEA_KEY_SCHEDULE *key)
{
	IDEA_INT *p = &key->data[0][0];
	uint32_t x1, x2, x3, x4;

	x2 = (uint32_t)d[0];
	x1 = x2 >> 16;
	x2 &= 0xffffU;

	x4 = (uint32_t)d[1];
	x3 = x4 >> 16;
	x4 &= 0xffffU;

	idea_rounds(&x1, &x2, &x3, &x4, &p);

	x1 &= 0xffffU;
	x1 = (uint32_t)idea_mul16((IDEA_INT)x1, *p++);

	{
		uint32_t t0 = (x3 + *p++) & 0xffffU;
		uint32_t t1 = (x2 + *p++) & 0xffffU;

		x4 &= 0xffffU;
		x4 = (uint32_t)idea_mul16((IDEA_INT)x4, *p);

		d[0] = (unsigned long)((t0 & 0xffffU) | ((x1 & 0xffffU) << 16));
		d[1] = (unsigned long)((x4 & 0xffffU) | ((t1 & 0xffffU) << 16));
	}
}

void oscam_idea_ecb_encrypt(const unsigned char *in, unsigned char *out, IDEA_KEY_SCHEDULE *ks)
{
	uint32_t d0, d1;
	unsigned long d[2];

	n2l(in, d0);
	n2l(in, d1);
	d[0] = d0;
	d[1] = d1;

	idea_encrypt(d, ks);

	d0 = (uint32_t)d[0];
	d1 = (uint32_t)d[1];
	l2n(d0, out);
	l2n(d1, out);

	d[0] = d[1] = 0;
}

void oscam_idea_cbc_encrypt(const unsigned char *in, unsigned char *out, long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv, int encrypt)
{
	uint32_t tin0 = 0, tin1 = 0;
	uint32_t tout0 = 0, tout1 = 0;
	uint32_t xor0 = 0, xor1 = 0;
	long l = length;
	unsigned long d[2];

	if (encrypt) {
		n2l(iv, tout0);
		n2l(iv, tout1);
		iv -= 8;

		for (l -= 8; l >= 0; l -= 8) {
			n2l(in, tin0);
			n2l(in, tin1);
			tin0 ^= tout0;
			tin1 ^= tout1;
			d[0] = tin0;
			d[1] = tin1;
			idea_encrypt(d, ks);
			tout0 = (uint32_t)d[0];
			l2n(tout0, out);
			tout1 = (uint32_t)d[1];
			l2n(tout1, out);
		}
		if (l != -8) {
			n2ln(in, tin0, tin1, l + 8);
			tin0 ^= tout0;
			tin1 ^= tout1;
			d[0] = tin0;
			d[1] = tin1;
			idea_encrypt(d, ks);
			tout0 = (uint32_t)d[0];
			l2n(tout0, out);
			tout1 = (uint32_t)d[1];
			l2n(tout1, out);
		}
		l2n(tout0, iv);
		l2n(tout1, iv);
	} else {
		n2l(iv, xor0);
		n2l(iv, xor1);
		iv -= 8;

		for (l -= 8; l >= 0; l -= 8) {
			n2l(in, tin0);
			n2l(in, tin1);
			d[0] = tin0;
			d[1] = tin1;
			idea_encrypt(d, ks);
			tout0 = (uint32_t)d[0] ^ xor0;
			tout1 = (uint32_t)d[1] ^ xor1;
			l2n(tout0, out);
			l2n(tout1, out);
			xor0 = tin0;
			xor1 = tin1;
		}
		if (l != -8) {
			n2l(in, tin0);
			n2l(in, tin1);
			d[0] = tin0;
			d[1] = tin1;
			idea_encrypt(d, ks);
			tout0 = (uint32_t)d[0] ^ xor0;
			tout1 = (uint32_t)d[1] ^ xor1;
			l2nn(tout0, tout1, out, l + 8);
			xor0 = tin0;
			xor1 = tin1;
		}
		l2n(xor0, iv);
		l2n(xor1, iv);
	}
	d[0] = d[1] = 0;
}

void oscam_idea_cfb64_encrypt(const unsigned char *in, unsigned char *out, long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv, int *num, int enc)
{
	int n = *num;
	uint32_t d0, d1;
	unsigned long d[2];
	uint8_t block, c;

	while (length-- > 0) {

		if (n == 0) {
			n2l(iv, d0);
			n2l(iv, d1);
			d[0] = d0;
			d[1] = d1;
			idea_encrypt(d, ks);
			d0 = (uint32_t)d[0];
			d1 = (uint32_t)d[1];
			iv -= 8;
			l2n(d0, iv);
			l2n(d1, iv);
			n = 0;
		}

		block = iv[n];

		if (enc) {
			c = (uint8_t)(*in ^ block);
			*out = c;
			iv[n] = c;
		} else {
			c = (uint8_t)*in;
			*out = (uint8_t)(c ^ block);
			iv[n] = c;
		}

		in++;
		out++;
		n = (n + 1) & 0x07;
	}

	*num = n;
}

void oscam_idea_ofb64_encrypt(const unsigned char *in, unsigned char *out, long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv, int *num)
{
	int n = *num;
	uint32_t d0, d1;
	unsigned long d[2];
	uint8_t block;

	while (length-- > 0) {

		if (n == 0) {
			n2l(iv, d0);
			n2l(iv, d1);
			d[0] = d0;
			d[1] = d1;
			idea_encrypt(d, ks);
			d0 = (uint32_t)d[0];
			d1 = (uint32_t)d[1];
			iv -= 8;
			l2n(d0, iv);
			l2n(d1, iv);
			n = 0;
		}

		block = iv[n];
		*out = (uint8_t)(*in ^ block);

		in++;
		out++;
		n = (n + 1) & 0x07;
	}

	*num = n;
}

const char *oscam_idea_options(void)
{
	if (sizeof(short) != sizeof(IDEA_INT))
		return "idea(int)";
	else
		return "idea(short)";
}

#endif /* WITH_LIB_IDEA */

/* ----------------------------------------------------------------------
 * RC6 (internal implementation, not provided by mbedtls nor openssl)
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_RC6
#define ROTL32(x,y) (((x) << ((y) & (RC6_W - 1))) | ((x) >> (RC6_W - ((y) & (RC6_W - 1)))))
#define ROTR32(x,y) (((x) >> ((y) & (RC6_W - 1))) | ((x) << (RC6_W - ((y) & (RC6_W - 1)))))

void rc6_key_setup(unsigned char *K, int b, RC6KEY S)
{
	int i, j, s, v;
	unsigned int L[(32 + 4 - 1) / 4] = {0}; /* max 32-byte key */
	unsigned int A = 0, B = 0;
	int c = (b + 3) / 4;

	L[c - 1] = 0;
	for (i = b - 1; i >= 0; i--)
		L[i / 4] = (L[i / 4] << 8) + K[i];

	S[0] = RC6_P32;
	for (i = 1; i <= 2 * RC6_R + 3; i++)
		S[i] = S[i - 1] + RC6_Q32;

	A = B = i = j = 0;
	v = (c > (2 * RC6_R + 4)) ? c : (2 * RC6_R + 4);
	v *= 3;

	for (s = 1; s <= v; s++) {
		A = S[i] = ROTL32(S[i] + A + B, 3);
		B = L[j] = ROTL32(L[j] + A + B, A + B);
		i = (i + 1) % (2 * RC6_R + 4);
		j = (j + 1) % c;
	}
}

void rc6_block_encrypt(unsigned int *pt, unsigned int *ct, int block_count, RC6KEY S)
{
	while (block_count-- > 0) {
		unsigned int A = pt[0], B = pt[1], C = pt[2], D = pt[3];
		unsigned int t, u, x;
		int i;

		B += S[0];
		D += S[1];
		for (i = 2; i <= 2 * RC6_R; i += 2) {
			t = ROTL32(B * (2 * B + 1), RC6_LGW);
			u = ROTL32(D * (2 * D + 1), RC6_LGW);
			A = ROTL32(A ^ t, u) + S[i];
			C = ROTL32(C ^ u, t) + S[i + 1];
			x = A; A = B; B = C; C = D; D = x;
		}
		A += S[2 * RC6_R + 2];
		C += S[2 * RC6_R + 3];
		ct[0] = A; ct[1] = B; ct[2] = C; ct[3] = D;
		pt += 4; ct += 4;
	}
}

void rc6_block_decrypt(unsigned int *ct, unsigned int *pt, int block_count, RC6KEY S)
{
	while (block_count-- > 0) {
		unsigned int A = ct[0], B = ct[1], C = ct[2], D = ct[3];
		unsigned int t, u, x;
		int i;

		C -= S[2 * RC6_R + 3];
		A -= S[2 * RC6_R + 2];
		for (i = 2 * RC6_R; i >= 2; i -= 2) {
			x = D; D = C; C = B; B = A; A = x;
			u = ROTL32(D * (2 * D + 1), RC6_LGW);
			t = ROTL32(B * (2 * B + 1), RC6_LGW);
			C = ROTR32(C - S[i + 1], t) ^ u;
			A = ROTR32(A - S[i], u) ^ t;
		}
		D -= S[1];
		B -= S[0];
		pt[0] = A; pt[1] = B; pt[2] = C; pt[3] = D;
		ct += 4; pt += 4;
	}
}
#endif /* WITH_LIB_RC6 */

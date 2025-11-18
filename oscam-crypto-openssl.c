#define MODULE_LOG_PREFIX "crypto-openssl"

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

/* Provided by oscam-ssl-openssl.c */
EVP_MD_CTX *EVP_MD_CTX_new(void);
void        EVP_MD_CTX_free(EVP_MD_CTX *ctx);
#endif

/* ----------------------------------------------------------------------
 * Unified hash helper
 * ---------------------------------------------------------------------- */
int oscam_hash(oscam_hash_alg alg, const unsigned char *d1, size_t l1, const unsigned char *d2, size_t l2, unsigned char *out)
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

#endif /* WITH_OPENSSL */

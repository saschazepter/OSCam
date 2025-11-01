#include "globals.h"
#include "oscam-crypto.h"

#ifdef WITH_LIBCRYPTO

/* mbedTLS */
#include "mbedtls/platform.h"

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

static inline uint32_t c2l(const unsigned char **c)
{
	const unsigned char *p = *c;
	uint32_t l = ((uint32_t)p[0])	   |
				 ((uint32_t)p[1] << 8)  |
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
	uint32_t tin0, tin1, ttin0, ttin1;
	uint8_t block[8];
	uint8_t hkey[8], hhkey[8];
	uint8_t tmp[8];
	des_key_schedule k;

	for (size_t i = 0; i < len; i += 8) {
		const unsigned char *p = in + i;

		tin0 = c2l(&p);
		tin1 = c2l(&p);

		memcpy(block, in + i, 8);

		memcpy(hkey, c->h, 8);
		memcpy(hhkey, c->hh, 8);

		hkey[0]  = (hkey[0]  & 0x9f) | 0x40;
		hhkey[0] = (hhkey[0] & 0x9f) | 0x20;

		des_set_key(hkey, &k);
		memcpy(tmp, block, 8);
		des(tmp, &k, 1);

		des_set_key(hhkey, &k);
		uint8_t tmp2[8];
		memcpy(tmp2, block, 8);
		des(tmp2, &k, 1);

		ttin0 = tin0 ^ ((uint32_t)tmp2[0] | ((uint32_t)tmp2[1]<<8) |
						((uint32_t)tmp2[2]<<16) | ((uint32_t)tmp2[3]<<24));
		ttin1 = tin1 ^ ((uint32_t)tmp2[4] | ((uint32_t)tmp2[5]<<8) |
						((uint32_t)tmp2[6]<<16) | ((uint32_t)tmp2[7]<<24));
		tin0 ^= ((uint32_t)tmp[0] | ((uint32_t)tmp[1]<<8) |
				 ((uint32_t)tmp[2]<<16) | ((uint32_t)tmp[3]<<24));
		tin1 ^= ((uint32_t)tmp[4] | ((uint32_t)tmp[5]<<8) |
				 ((uint32_t)tmp[6]<<16) | ((uint32_t)tmp[7]<<24));

		unsigned char *q = c->h;
		l2c(tin0, &q);
		l2c(ttin1, &q);
		q = c->hh;
		l2c(ttin0, &q);
		l2c(tin1, &q);
	}
}

int MDC2_Init(MDC2_CTX *c)
{
	c->num = 0;
	c->pad_type = 1;
	memset(c->h,  0x52, MDC2_BLOCK);
	memset(c->hh, 0x25, MDC2_BLOCK);
	return 1;
}

int MDC2_Update(MDC2_CTX *c, const unsigned char *in, size_t len)
{
	size_t i = c->num;

	if (i != 0) {
		if (len < MDC2_BLOCK - i) {
			memcpy(&c->data[i], in, len);
			c->num += (unsigned int)len;
			return 1;
		} else {
			size_t j = MDC2_BLOCK - i;
			memcpy(&c->data[i], in, j);
			len -= j;
			in += j;
			c->num = 0;
			mdc2_body(c, c->data, MDC2_BLOCK);
		}
	}

	size_t blocks = len & ~(MDC2_BLOCK - 1);
	if (blocks > 0)
		mdc2_body(c, in, blocks);

	size_t rem = len - blocks;
	if (rem > 0) {
		memcpy(c->data, in + blocks, rem);
		c->num = (unsigned int)rem;
	}
	return 1;
}

int MDC2_Final(unsigned char *md, MDC2_CTX *c)
{
	if (c->num > 0 || c->pad_type == 2) {
		if (c->pad_type == 2)
			c->data[c->num++] = 0x80;
		memset(c->data + c->num, 0, MDC2_BLOCK - c->num);
		mdc2_body(c, c->data, MDC2_BLOCK);
	}

	memcpy(md, c->h, MDC2_BLOCK);
	memcpy(md + MDC2_BLOCK, c->hh, MDC2_BLOCK);
	return 1;
}

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

static inline void idea_mul(IDEA_INT *r, IDEA_INT a, IDEA_INT b)
{
	uint32_t p = (uint32_t)a * b;
	if (p != 0) {
		uint32_t lo = p & 0xFFFF;
		uint32_t hi = p >> 16;
		uint32_t v = lo - hi + (lo < hi);
		*r = (IDEA_INT)v;
	} else {
		*r = (IDEA_INT)(1 - a - b);
	}
}

static IDEA_INT idea_inv(IDEA_INT xin)
{
	int32_t n1 = 0x10001, n2 = xin;
	int32_t b1 = 0, b2 = 1, t;
	if (xin <= 1) return xin;
	do {
		int32_t q = n1 / n2;
		int32_t r = n1 % n2;
		n1 = n2; n2 = r;
		t = b1 - q * b2; b1 = b2; b2 = t;
	} while (n2 != 0);
	if (b1 < 0) b1 += 0x10001;
	return (IDEA_INT)b1;
}

void idea_set_encrypt_key(const unsigned char *key, IDEA_KEY_SCHEDULE *ks)
{
	IDEA_INT *kt = &ks->data[0][0];
	for (int i = 0; i < 8; i++)
		kt[i] = ((IDEA_INT)key[2 * i] << 8) | key[2 * i + 1];
	for (int i = 8; i < 52; i++) {
		int j = i - 8;
		if ((i & 7) < 6)
			kt[i] = ((kt[j + 1] << 9) | (kt[j + 2] >> 7)) & 0xFFFF;
		else if ((i & 7) == 6)
			kt[i] = ((kt[j + 2] << 9) | (kt[j - 5] >> 7)) & 0xFFFF;
		else
			kt[i] = ((kt[j - 7] << 9) | (kt[j - 6] >> 7)) & 0xFFFF;
	}
}

void idea_set_decrypt_key(IDEA_KEY_SCHEDULE *ek, IDEA_KEY_SCHEDULE *dk)
{
	IDEA_INT *fp = &ek->data[0][0];
	IDEA_INT *tp = &dk->data[0][0];

	for (int r = 0; r < 9; r++) {
		int i = 6 * (8 - r);
		if (r == 0) {
			tp[0] = idea_inv(fp[i]);
			tp[1] = (0x10000 - fp[i + 1]) & 0xFFFF;
			tp[2] = (0x10000 - fp[i + 2]) & 0xFFFF;
			tp[3] = idea_inv(fp[i + 3]);
		} else {
			tp[0] = idea_inv(fp[i]);
			tp[1] = (0x10000 - fp[i + 2]) & 0xFFFF;
			tp[2] = (0x10000 - fp[i + 1]) & 0xFFFF;
			tp[3] = idea_inv(fp[i + 3]);
		}
		if (r < 8) {
			tp[4] = fp[i - 2];
			tp[5] = fp[i - 1];
		}
		tp += 6;
	}
}

void idea_encrypt(uint32_t *d, IDEA_KEY_SCHEDULE *ks)
{
	uint32_t x1 = d[0] >> 16, x2 = d[0] & 0xFFFF;
	uint32_t x3 = d[1] >> 16, x4 = d[1] & 0xFFFF;
	const IDEA_INT *p = &ks->data[0][0];

	for (int round = 0; round < 8; round++) {
		IDEA_INT r;
		idea_mul(&r, x1, *p++); x1 = r;
		x2 = (x2 + *p++) & 0xFFFF;
		x3 = (x3 + *p++) & 0xFFFF;
		idea_mul(&r, x4, *p++); x4 = r;

		uint32_t t0 = x1 ^ x3;
		idea_mul(&r, t0, *p++); t0 = r;
		uint32_t t1 = (t0 + (x2 ^ x4)) & 0xFFFF;
		idea_mul(&r, t1, *p++); t1 = r;
		t0 = (t0 + t1) & 0xFFFF;
		x1 ^= t1; x4 ^= t0;
		uint32_t tmp = x2; x2 = x3 ^ t1; x3 = tmp ^ t0;
	}

	IDEA_INT r;
	idea_mul(&r, x1, *p++); x1 = r;
	uint32_t t0 = (x3 + *p++) & 0xFFFF;
	uint32_t t1 = (x2 + *p++) & 0xFFFF;
	idea_mul(&r, x4, *p++); x4 = r;

	d[0] = (x1 << 16) | t0;
	d[1] = (x4 << 16) | t1;
}

void idea_ecb_encrypt(const unsigned char *in, unsigned char *out, IDEA_KEY_SCHEDULE *ks)
{
	uint32_t l0 = (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | in[3];
	uint32_t l1 = (in[4] << 24) | (in[5] << 16) | (in[6] << 8) | in[7];
	uint32_t d[2] = { l0, l1 };
	idea_encrypt(d, ks);
	out[0] = (d[0] >> 24) & 0xFF;
	out[1] = (d[0] >> 16) & 0xFF;
	out[2] = (d[0] >> 8) & 0xFF;
	out[3] = d[0] & 0xFF;
	out[4] = (d[1] >> 24) & 0xFF;
	out[5] = (d[1] >> 16) & 0xFF;
	out[6] = (d[1] >> 8) & 0xFF;
	out[7] = d[1] & 0xFF;
}

void idea_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
					  IDEA_KEY_SCHEDULE *ks, unsigned char *iv, int enc)
{
	unsigned char tmp[IDEA_BLOCK];
	unsigned char prev[IDEA_BLOCK];
	memcpy(prev, iv, IDEA_BLOCK);

	for (long i = 0; i < length; i += IDEA_BLOCK) {
		if (enc == IDEA_ENCRYPT) {
			for (int j = 0; j < IDEA_BLOCK; j++) tmp[j] = in[i + j] ^ prev[j];
			idea_ecb_encrypt(tmp, out + i, ks);
			memcpy(prev, out + i, IDEA_BLOCK);
		} else {
			idea_ecb_encrypt(in + i, tmp, ks);
			for (int j = 0; j < IDEA_BLOCK; j++) out[i + j] = tmp[j] ^ prev[j];
			memcpy(prev, in + i, IDEA_BLOCK);
		}
	}
	memcpy(iv, prev, IDEA_BLOCK);
}

void idea_cfb64_encrypt(const unsigned char *in, unsigned char *out,
						long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv,
						int *num, int enc)
{
	unsigned char keystream[IDEA_BLOCK];
	int n = (num && *num >= 0 && *num < IDEA_BLOCK) ? *num : 0;

	while (length-- > 0) {
		if (n == 0) {
			/* Generate keystream = E(IV) into keystream[] */
			idea_ecb_encrypt(iv, keystream, ks);
		}

		if (enc) {
			/* Encrypt: C = P ^ KS; IV[n] = C */
			unsigned char c = (unsigned char)(*in ^ keystream[n]);
			*out = c;
			iv[n] = c;
		} else {
			/* Decrypt: P = C ^ KS; IV[n] = C */
			unsigned char c = *in;
			*out = (unsigned char)(c ^ keystream[n]);
			iv[n] = c;
		}

		in++; out++;
		n = (n + 1) & 7;
		if (n == 0) {
			/* On each full block, copy new IV = last ciphertext block is already in iv[] */
			/* (We’ve been updating iv[n] as we go, so iv[] contains C_{i} now.) */
		}
	}

	if (num) *num = n;
}

void idea_ofb64_encrypt(const unsigned char *in, unsigned char *out,
						long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv,
						int *num)
{
	unsigned char keystream[IDEA_BLOCK];
	int n = (num && *num >= 0 && *num < IDEA_BLOCK) ? *num : 0;

	while (length-- > 0) {
		if (n == 0) {
			/* OFB uses keystream chaining: IV = E(IV) */
			unsigned char tmp[IDEA_BLOCK];
			idea_ecb_encrypt(iv, tmp, ks);
			/* Copy tmp back into IV */
			for (int i = 0; i < IDEA_BLOCK; i++) iv[i] = tmp[i];
			/* And use iv as keystream */
			for (int i = 0; i < IDEA_BLOCK; i++) keystream[i] = iv[i];
		}

		*out = (unsigned char)(*in ^ keystream[n]);

		in++; out++;
		n = (n + 1) & 7;
		if (n == 0) {
			/* regenerate next keystream by encrypting updated IV again (done at top of loop) */
		}
	}

	if (num) *num = n;
}

const char *idea_options(void)
{
	return "IDEA-ECB/CBC (oscam-crypto)";
}

int SHA1_Init(SHA_CTX *c)
{
	mbedtls_sha1_init(&c->ctx);
	return mbedtls_sha1_starts(&c->ctx);
}

int SHA1_Update(SHA_CTX *c, const void *data, size_t len)
{
	return mbedtls_sha1_update(&c->ctx, data, len);
}

int SHA1_Final(unsigned char *md, SHA_CTX *c)
{
	int ret = mbedtls_sha1_finish(&c->ctx, md);
	mbedtls_sha1_free(&c->ctx);
	return ret;
}

void AesCtxIni(AesCtx *c, const unsigned char *iv, const unsigned char *key, int keylen, int mode)
{
	mbedtls_aes_init(&c->ctx);
	memcpy(c->iv, iv, BLOCKSZ);
	c->Mode = mode;

	int keybits = keylen * 8;
	mbedtls_aes_setkey_enc(&c->ctx, key, keybits);
}

void AesEncrypt(AesCtx *c, const unsigned char *input, unsigned char *output, int len)
{
	if (c->Mode == CBC)
	{
		mbedtls_aes_crypt_cbc(&c->ctx, MBEDTLS_AES_ENCRYPT, len, c->iv, input, output);
	}
	else  /* EBC (legacy typo for ECB) */
	{
		int blocks = len / BLOCKSZ;
		for (int i = 0; i < blocks; i++)
			mbedtls_aes_crypt_ecb(&c->ctx, MBEDTLS_AES_ENCRYPT, input + i * BLOCKSZ, output + i * BLOCKSZ);
	}
}

void AesDecrypt(AesCtx *c, const unsigned char *input, unsigned char *output, int len)
{
	if (c->Mode == CBC)
	{
		mbedtls_aes_crypt_cbc(&c->ctx, MBEDTLS_AES_DECRYPT, len, c->iv, input, output);
	}
	else  /* EBC (legacy typo for ECB) */
	{
		int blocks = len / BLOCKSZ;
		for (int i = 0; i < blocks; i++)
			mbedtls_aes_crypt_ecb(&c->ctx, MBEDTLS_AES_DECRYPT, input + i * BLOCKSZ, output + i * BLOCKSZ);
	}
}

int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key)
{
	mbedtls_aes_init(&key->ctx);
	return mbedtls_aes_setkey_enc(&key->ctx, userKey, bits);
}

int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key)
{
	mbedtls_aes_init(&key->ctx);
	return mbedtls_aes_setkey_dec(&key->ctx, userKey, bits);
}

void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
	mbedtls_aes_crypt_ecb(&((AES_KEY *)key)->ctx, MBEDTLS_AES_ENCRYPT, in, out);
}

void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
{
	mbedtls_aes_crypt_ecb(&((AES_KEY *)key)->ctx, MBEDTLS_AES_DECRYPT, in, out);
}

int AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
					size_t length, const AES_KEY *key, unsigned char *ivec,
					const int enc)
{
	return mbedtls_aes_crypt_cbc(&((AES_KEY *)key)->ctx,
								 enc == AES_ENCRYPT ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
								 length,
								 ivec,
								 in,
								 out);
}

// Compatibility wrapper for the old API
void des_set_key(const uint8_t *key, des_key_schedule *schedule)
{
	mbedtls_des_init(&schedule->ctx);
	memcpy(schedule->key, key, 8);
	mbedtls_des_setkey_enc(&schedule->ctx, schedule->key);
}

void des(uint8_t *data, des_key_schedule *schedule, int encrypt)
{
	if (encrypt)
		mbedtls_des_setkey_enc(&schedule->ctx, schedule->key);
	else
		mbedtls_des_setkey_dec(&schedule->ctx, schedule->key);

	mbedtls_des_crypt_ecb(&schedule->ctx, data, data);
}

// --- Single DES ECB ---
void des_ecb_encrypt(uint8_t *data, const uint8_t *key, int32_t len)
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
void des_cbc_encrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key, int32_t len)
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
void des_ede2_cbc_encrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key1, const uint8_t *key2, int32_t len)
{
	mbedtls_des3_context ctx;
	unsigned char iv_copy[8];
	unsigned char key24[24];

	memcpy(iv_copy, iv, 8);
	memcpy(key24, key1, 8);
	memcpy(key24 + 8, key2, 8);
	memcpy(key24 + 16, key1, 8); // repeat key1 for 2-key 3DES

	mbedtls_des3_init(&ctx);
	mbedtls_des3_set3key_enc(&ctx, key24);
	mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, len & ~7, iv_copy, data, data);
	mbedtls_des3_free(&ctx);
}

void des_ede2_cbc_decrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key1, const uint8_t *key2, int32_t len)
{
	mbedtls_des3_context ctx;
	unsigned char iv_copy[8];
	unsigned char key24[24];

	memcpy(iv_copy, iv, 8);
	memcpy(key24, key1, 8);
	memcpy(key24 + 8, key2, 8);
	memcpy(key24 + 16, key1, 8);

	mbedtls_des3_init(&ctx);
	mbedtls_des3_set3key_dec(&ctx, key24);
	mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_DECRYPT, len & ~7, iv_copy, data, data);
	mbedtls_des3_free(&ctx);
}

// --- 3DES ECB ---

void des_ecb3_decrypt(uint8_t *data, const uint8_t *key)
{
	mbedtls_des3_context ctx;
	mbedtls_des3_init(&ctx);

	// use 2-key EDE decryption
	mbedtls_des3_set2key_dec(&ctx, key); // 3-key: mbedtls_des3_set3key_enc
	mbedtls_des3_crypt_ecb(&ctx, data, data);

	mbedtls_des3_free(&ctx);
}

void des_ecb3_encrypt(uint8_t *data, const uint8_t *key)
{
	mbedtls_des3_context ctx;
	mbedtls_des3_init(&ctx);

	// use 2-key EDE encryption
	mbedtls_des3_set2key_enc(&ctx, key); // 3-key: mbedtls_des3_set3key_dec
	mbedtls_des3_crypt_ecb(&ctx, data, data);

	mbedtls_des3_free(&ctx);
}

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


#endif /* WITH_LIBCRYPTO */

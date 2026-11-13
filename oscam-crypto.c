#define MODULE_LOG_PREFIX "crypto"

#include "globals.h"
#include "oscam-crypto.h"
#include "oscam-string.h"

/* ----------------------------------------------------------------------
 * MDC2 (oscam custom implementation, not provided by mbedtls nor openssl)
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
 * IDEA (oscam custom implementation, not provided by mbedtls nor openssl)
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
 * RC6 (oscam custom implementation, not provided by mbedtls nor openssl)
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

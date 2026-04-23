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

		/* MDC2 per ISO 10118-2 requires each derived DES key to be
		 * parity-adjusted before use. Matches master/OpenSSL mdc2.c
		 * which calls DES_set_odd_parity(&c->h) / (&c->hh) here. */
		des_set_odd_parity(hkey);
		des_set_odd_parity(hhkey);

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

void oscam_idea_cbc_encrypt(const unsigned char *in, unsigned char *out, long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv, int enc)
{
	uint32_t tin0 = 0, tin1 = 0;
	uint32_t tout0 = 0, tout1 = 0;
	uint32_t xor0 = 0, xor1 = 0;
	long l = length;
	unsigned long d[2];

	if (enc) {
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

/* ----------------------------------------------------------------------
 *  DES / 3DES (oscam-internal, required by MDC2 and DES-based readers)
 *
 *  mbedTLS 4.0+ removed all DES code. We therefore ship the proven DES
 *  implementation from master's cscrypt/des.c verbatim here. To avoid
 *  name clashes with the shim wrappers, the two lowest-level primitives
 *  are temporarily renamed via macros while the master block is parsed:
 *  afterwards we restore the header's public names.
 * ---------------------------------------------------------------------- */
#if (defined(WITH_LIB_DES) || defined(WITH_LIB_MDC2)) && !defined(WITH_OPENSSL)

/* Quarantine master's `des_set_key` and `des` symbols so we can provide
 * wrappers below with the shim's struct-typed `des_key_schedule *`. */
#undef des_set_key
#undef des
#define des_set_key _internal_des_set_key
#define des _internal_des

/* ==== BEGIN master cscrypt/des.c (proven reference implementation) ==== */

static const uint8_t weak_keys[16][8] =
{
	// weak keys
	{0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01},
	{0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE},
	{0x1F,0x1F,0x1F,0x1F,0x1F,0x1F,0x1F,0x1F},
	{0xE0,0xE0,0xE0,0xE0,0xE0,0xE0,0xE0,0xE0},
	// semi-weak keys
	{0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE},
	{0xFE,0x01,0xFE,0x01,0xFE,0x01,0xFE,0x01},
	{0x1F,0xE0,0x1F,0xE0,0x0E,0xF1,0x0E,0xF1},
	{0xE0,0x1F,0xE0,0x1F,0xF1,0x0E,0xF1,0x0E},
	{0x01,0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1},
	{0xE0,0x01,0xE0,0x01,0xF1,0x01,0xF1,0x01},
	{0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E,0xFE},
	{0xFE,0x1F,0xFE,0x1F,0xFE,0x0E,0xFE,0x0E},
	{0x01,0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E},
	{0x1F,0x01,0x1F,0x01,0x0E,0x01,0x0E,0x01},
	{0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1,0xFE},
	{0xFE,0xE0,0xFE,0xE0,0xFE,0xF1,0xFE,0xF1}
};

static const uint8_t odd_parity[] =
{
	1,  1,  2,  2,  4,  4,  7,  7,  8,  8, 11, 11, 13, 13, 14, 14,
	16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
	32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
	49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
	64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
	81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
	97, 97, 98, 98, 100,100,103,103,104,104,107,107,109,109,110,110,
	112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
	128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
	145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
	161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
	176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
	193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
	208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
	224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
	241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
};

static const uint8_t shifts2[16] = {0,0,1,1,1,1,1,1,0,1,1,1,1,1,1,0};

static const uint32_t des_skb[8][64] =
{
	{
		0x00000000,0x00000010,0x20000000,0x20000010,
		0x00010000,0x00010010,0x20010000,0x20010010,
		0x00000800,0x00000810,0x20000800,0x20000810,
		0x00010800,0x00010810,0x20010800,0x20010810,
		0x00000020,0x00000030,0x20000020,0x20000030,
		0x00010020,0x00010030,0x20010020,0x20010030,
		0x00000820,0x00000830,0x20000820,0x20000830,
		0x00010820,0x00010830,0x20010820,0x20010830,
		0x00080000,0x00080010,0x20080000,0x20080010,
		0x00090000,0x00090010,0x20090000,0x20090010,
		0x00080800,0x00080810,0x20080800,0x20080810,
		0x00090800,0x00090810,0x20090800,0x20090810,
		0x00080020,0x00080030,0x20080020,0x20080030,
		0x00090020,0x00090030,0x20090020,0x20090030,
		0x00080820,0x00080830,0x20080820,0x20080830,
		0x00090820,0x00090830,0x20090820,0x20090830,
	},{

		0x00000000,0x02000000,0x00002000,0x02002000,
		0x00200000,0x02200000,0x00202000,0x02202000,
		0x00000004,0x02000004,0x00002004,0x02002004,
		0x00200004,0x02200004,0x00202004,0x02202004,
		0x00000400,0x02000400,0x00002400,0x02002400,
		0x00200400,0x02200400,0x00202400,0x02202400,
		0x00000404,0x02000404,0x00002404,0x02002404,
		0x00200404,0x02200404,0x00202404,0x02202404,
		0x10000000,0x12000000,0x10002000,0x12002000,
		0x10200000,0x12200000,0x10202000,0x12202000,
		0x10000004,0x12000004,0x10002004,0x12002004,
		0x10200004,0x12200004,0x10202004,0x12202004,
		0x10000400,0x12000400,0x10002400,0x12002400,
		0x10200400,0x12200400,0x10202400,0x12202400,
		0x10000404,0x12000404,0x10002404,0x12002404,
		0x10200404,0x12200404,0x10202404,0x12202404,
	},{

		0x00000000,0x00000001,0x00040000,0x00040001,
		0x01000000,0x01000001,0x01040000,0x01040001,
		0x00000002,0x00000003,0x00040002,0x00040003,
		0x01000002,0x01000003,0x01040002,0x01040003,
		0x00000200,0x00000201,0x00040200,0x00040201,
		0x01000200,0x01000201,0x01040200,0x01040201,
		0x00000202,0x00000203,0x00040202,0x00040203,
		0x01000202,0x01000203,0x01040202,0x01040203,
		0x08000000,0x08000001,0x08040000,0x08040001,
		0x09000000,0x09000001,0x09040000,0x09040001,
		0x08000002,0x08000003,0x08040002,0x08040003,
		0x09000002,0x09000003,0x09040002,0x09040003,
		0x08000200,0x08000201,0x08040200,0x08040201,
		0x09000200,0x09000201,0x09040200,0x09040201,
		0x08000202,0x08000203,0x08040202,0x08040203,
		0x09000202,0x09000203,0x09040202,0x09040203,
	},{

		0x00000000,0x00100000,0x00000100,0x00100100,
		0x00000008,0x00100008,0x00000108,0x00100108,
		0x00001000,0x00101000,0x00001100,0x00101100,
		0x00001008,0x00101008,0x00001108,0x00101108,
		0x04000000,0x04100000,0x04000100,0x04100100,
		0x04000008,0x04100008,0x04000108,0x04100108,
		0x04001000,0x04101000,0x04001100,0x04101100,
		0x04001008,0x04101008,0x04001108,0x04101108,
		0x00020000,0x00120000,0x00020100,0x00120100,
		0x00020008,0x00120008,0x00020108,0x00120108,
		0x00021000,0x00121000,0x00021100,0x00121100,
		0x00021008,0x00121008,0x00021108,0x00121108,
		0x04020000,0x04120000,0x04020100,0x04120100,
		0x04020008,0x04120008,0x04020108,0x04120108,
		0x04021000,0x04121000,0x04021100,0x04121100,
		0x04021008,0x04121008,0x04021108,0x04121108,
	},{

		0x00000000,0x10000000,0x00010000,0x10010000,
		0x00000004,0x10000004,0x00010004,0x10010004,
		0x20000000,0x30000000,0x20010000,0x30010000,
		0x20000004,0x30000004,0x20010004,0x30010004,
		0x00100000,0x10100000,0x00110000,0x10110000,
		0x00100004,0x10100004,0x00110004,0x10110004,
		0x20100000,0x30100000,0x20110000,0x30110000,
		0x20100004,0x30100004,0x20110004,0x30110004,
		0x00001000,0x10001000,0x00011000,0x10011000,
		0x00001004,0x10001004,0x00011004,0x10011004,
		0x20001000,0x30001000,0x20011000,0x30011000,
		0x20001004,0x30001004,0x20011004,0x30011004,
		0x00101000,0x10101000,0x00111000,0x10111000,
		0x00101004,0x10101004,0x00111004,0x10111004,
		0x20101000,0x30101000,0x20111000,0x30111000,
		0x20101004,0x30101004,0x20111004,0x30111004,
	},{

		0x00000000,0x08000000,0x00000008,0x08000008,
		0x00000400,0x08000400,0x00000408,0x08000408,
		0x00020000,0x08020000,0x00020008,0x08020008,
		0x00020400,0x08020400,0x00020408,0x08020408,
		0x00000001,0x08000001,0x00000009,0x08000009,
		0x00000401,0x08000401,0x00000409,0x08000409,
		0x00020001,0x08020001,0x00020009,0x08020009,
		0x00020401,0x08020401,0x00020409,0x08020409,
		0x02000000,0x0A000000,0x02000008,0x0A000008,
		0x02000400,0x0A000400,0x02000408,0x0A000408,
		0x02020000,0x0A020000,0x02020008,0x0A020008,
		0x02020400,0x0A020400,0x02020408,0x0A020408,
		0x02000001,0x0A000001,0x02000009,0x0A000009,
		0x02000401,0x0A000401,0x02000409,0x0A000409,
		0x02020001,0x0A020001,0x02020009,0x0A020009,
		0x02020401,0x0A020401,0x02020409,0x0A020409,
	},{

		0x00000000,0x00000100,0x00080000,0x00080100,
		0x01000000,0x01000100,0x01080000,0x01080100,
		0x00000010,0x00000110,0x00080010,0x00080110,
		0x01000010,0x01000110,0x01080010,0x01080110,
		0x00200000,0x00200100,0x00280000,0x00280100,
		0x01200000,0x01200100,0x01280000,0x01280100,
		0x00200010,0x00200110,0x00280010,0x00280110,
		0x01200010,0x01200110,0x01280010,0x01280110,
		0x00000200,0x00000300,0x00080200,0x00080300,
		0x01000200,0x01000300,0x01080200,0x01080300,
		0x00000210,0x00000310,0x00080210,0x00080310,
		0x01000210,0x01000310,0x01080210,0x01080310,
		0x00200200,0x00200300,0x00280200,0x00280300,
		0x01200200,0x01200300,0x01280200,0x01280300,
		0x00200210,0x00200310,0x00280210,0x00280310,
		0x01200210,0x01200310,0x01280210,0x01280310,
	},{

		0x00000000,0x04000000,0x00040000,0x04040000,
		0x00000002,0x04000002,0x00040002,0x04040002,
		0x00002000,0x04002000,0x00042000,0x04042000,
		0x00002002,0x04002002,0x00042002,0x04042002,
		0x00000020,0x04000020,0x00040020,0x04040020,
		0x00000022,0x04000022,0x00040022,0x04040022,
		0x00002020,0x04002020,0x00042020,0x04042020,
		0x00002022,0x04002022,0x00042022,0x04042022,
		0x00000800,0x04000800,0x00040800,0x04040800,
		0x00000802,0x04000802,0x00040802,0x04040802,
		0x00002800,0x04002800,0x00042800,0x04042800,
		0x00002802,0x04002802,0x00042802,0x04042802,
		0x00000820,0x04000820,0x00040820,0x04040820,
		0x00000822,0x04000822,0x00040822,0x04040822,
		0x00002820,0x04002820,0x00042820,0x04042820,
		0x00002822,0x04002822,0x00042822,0x04042822,
	}
};

static const uint32_t des_SPtrans[8][64] =
{
	{
		0x00820200, 0x00020000, 0x80800000, 0x80820200,
		0x00800000, 0x80020200, 0x80020000, 0x80800000,
		0x80020200, 0x00820200, 0x00820000, 0x80000200,
		0x80800200, 0x00800000, 0x00000000, 0x80020000,
		0x00020000, 0x80000000, 0x00800200, 0x00020200,
		0x80820200, 0x00820000, 0x80000200, 0x00800200,
		0x80000000, 0x00000200, 0x00020200, 0x80820000,
		0x00000200, 0x80800200, 0x80820000, 0x00000000,
		0x00000000, 0x80820200, 0x00800200, 0x80020000,
		0x00820200, 0x00020000, 0x80000200, 0x00800200,
		0x80820000, 0x00000200, 0x00020200, 0x80800000,
		0x80020200, 0x80000000, 0x80800000, 0x00820000,
		0x80820200, 0x00020200, 0x00820000, 0x80800200,
		0x00800000, 0x80000200, 0x80020000, 0x00000000,
		0x00020000, 0x00800000, 0x80800200, 0x00820200,
		0x80000000, 0x80820000, 0x00000200, 0x80020200,
	},{

		0x10042004, 0x00000000, 0x00042000, 0x10040000,
		0x10000004, 0x00002004, 0x10002000, 0x00042000,
		0x00002000, 0x10040004, 0x00000004, 0x10002000,
		0x00040004, 0x10042000, 0x10040000, 0x00000004,
		0x00040000, 0x10002004, 0x10040004, 0x00002000,
		0x00042004, 0x10000000, 0x00000000, 0x00040004,
		0x10002004, 0x00042004, 0x10042000, 0x10000004,
		0x10000000, 0x00040000, 0x00002004, 0x10042004,
		0x00040004, 0x10042000, 0x10002000, 0x00042004,
		0x10042004, 0x00040004, 0x10000004, 0x00000000,
		0x10000000, 0x00002004, 0x00040000, 0x10040004,
		0x00002000, 0x10000000, 0x00042004, 0x10002004,
		0x10042000, 0x00002000, 0x00000000, 0x10000004,
		0x00000004, 0x10042004, 0x00042000, 0x10040000,
		0x10040004, 0x00040000, 0x00002004, 0x10002000,
		0x10002004, 0x00000004, 0x10040000, 0x00042000,
	},{

		0x41000000, 0x01010040, 0x00000040, 0x41000040,
		0x40010000, 0x01000000, 0x41000040, 0x00010040,
		0x01000040, 0x00010000, 0x01010000, 0x40000000,
		0x41010040, 0x40000040, 0x40000000, 0x41010000,
		0x00000000, 0x40010000, 0x01010040, 0x00000040,
		0x40000040, 0x41010040, 0x00010000, 0x41000000,
		0x41010000, 0x01000040, 0x40010040, 0x01010000,
		0x00010040, 0x00000000, 0x01000000, 0x40010040,
		0x01010040, 0x00000040, 0x40000000, 0x00010000,
		0x40000040, 0x40010000, 0x01010000, 0x41000040,
		0x00000000, 0x01010040, 0x00010040, 0x41010000,
		0x40010000, 0x01000000, 0x41010040, 0x40000000,
		0x40010040, 0x41000000, 0x01000000, 0x41010040,
		0x00010000, 0x01000040, 0x41000040, 0x00010040,
		0x01000040, 0x00000000, 0x41010000, 0x40000040,
		0x41000000, 0x40010040, 0x00000040, 0x01010000,
	},{

		0x00100402, 0x04000400, 0x00000002, 0x04100402,
		0x00000000, 0x04100000, 0x04000402, 0x00100002,
		0x04100400, 0x04000002, 0x04000000, 0x00000402,
		0x04000002, 0x00100402, 0x00100000, 0x04000000,
		0x04100002, 0x00100400, 0x00000400, 0x00000002,
		0x00100400, 0x04000402, 0x04100000, 0x00000400,
		0x00000402, 0x00000000, 0x00100002, 0x04100400,
		0x04000400, 0x04100002, 0x04100402, 0x00100000,
		0x04100002, 0x00000402, 0x00100000, 0x04000002,
		0x00100400, 0x04000400, 0x00000002, 0x04100000,
		0x04000402, 0x00000000, 0x00000400, 0x00100002,
		0x00000000, 0x04100002, 0x04100400, 0x00000400,
		0x04000000, 0x04100402, 0x00100402, 0x00100000,
		0x04100402, 0x00000002, 0x04000400, 0x00100402,
		0x00100002, 0x00100400, 0x04100000, 0x04000402,
		0x00000402, 0x04000000, 0x04000002, 0x04100400,
	},{

		0x02000000, 0x00004000, 0x00000100, 0x02004108,
		0x02004008, 0x02000100, 0x00004108, 0x02004000,
		0x00004000, 0x00000008, 0x02000008, 0x00004100,
		0x02000108, 0x02004008, 0x02004100, 0x00000000,
		0x00004100, 0x02000000, 0x00004008, 0x00000108,
		0x02000100, 0x00004108, 0x00000000, 0x02000008,
		0x00000008, 0x02000108, 0x02004108, 0x00004008,
		0x02004000, 0x00000100, 0x00000108, 0x02004100,
		0x02004100, 0x02000108, 0x00004008, 0x02004000,
		0x00004000, 0x00000008, 0x02000008, 0x02000100,
		0x02000000, 0x00004100, 0x02004108, 0x00000000,
		0x00004108, 0x02000000, 0x00000100, 0x00004008,
		0x02000108, 0x00000100, 0x00000000, 0x02004108,
		0x02004008, 0x02004100, 0x00000108, 0x00004000,
		0x00004100, 0x02004008, 0x02000100, 0x00000108,
		0x00000008, 0x00004108, 0x02004000, 0x02000008,
	},{

		0x20000010, 0x00080010, 0x00000000, 0x20080800,
		0x00080010, 0x00000800, 0x20000810, 0x00080000,
		0x00000810, 0x20080810, 0x00080800, 0x20000000,
		0x20000800, 0x20000010, 0x20080000, 0x00080810,
		0x00080000, 0x20000810, 0x20080010, 0x00000000,
		0x00000800, 0x00000010, 0x20080800, 0x20080010,
		0x20080810, 0x20080000, 0x20000000, 0x00000810,
		0x00000010, 0x00080800, 0x00080810, 0x20000800,
		0x00000810, 0x20000000, 0x20000800, 0x00080810,
		0x20080800, 0x00080010, 0x00000000, 0x20000800,
		0x20000000, 0x00000800, 0x20080010, 0x00080000,
		0x00080010, 0x20080810, 0x00080800, 0x00000010,
		0x20080810, 0x00080800, 0x00080000, 0x20000810,
		0x20000010, 0x20080000, 0x00080810, 0x00000000,
		0x00000800, 0x20000010, 0x20000810, 0x20080800,
		0x20080000, 0x00000810, 0x00000010, 0x20080010,
	},{

		0x00001000, 0x00000080, 0x00400080, 0x00400001,
		0x00401081, 0x00001001, 0x00001080, 0x00000000,
		0x00400000, 0x00400081, 0x00000081, 0x00401000,
		0x00000001, 0x00401080, 0x00401000, 0x00000081,
		0x00400081, 0x00001000, 0x00001001, 0x00401081,
		0x00000000, 0x00400080, 0x00400001, 0x00001080,
		0x00401001, 0x00001081, 0x00401080, 0x00000001,
		0x00001081, 0x00401001, 0x00000080, 0x00400000,
		0x00001081, 0x00401000, 0x00401001, 0x00000081,
		0x00001000, 0x00000080, 0x00400000, 0x00401001,
		0x00400081, 0x00001081, 0x00001080, 0x00000000,
		0x00000080, 0x00400001, 0x00000001, 0x00400080,
		0x00000000, 0x00400081, 0x00400080, 0x00001080,
		0x00000081, 0x00001000, 0x00401081, 0x00400000,
		0x00401080, 0x00000001, 0x00001001, 0x00401081,
		0x00400001, 0x00401080, 0x00401000, 0x00001001,
	},{

		0x08200020, 0x08208000, 0x00008020, 0x00000000,
		0x08008000, 0x00200020, 0x08200000, 0x08208020,
		0x00000020, 0x08000000, 0x00208000, 0x00008020,
		0x00208020, 0x08008020, 0x08000020, 0x08200000,
		0x00008000, 0x00208020, 0x00200020, 0x08008000,
		0x08208020, 0x08000020, 0x00000000, 0x00208000,
		0x08000000, 0x00200000, 0x08008020, 0x08200020,
		0x00200000, 0x00008000, 0x08208000, 0x00000020,
		0x00200000, 0x00008000, 0x08000020, 0x08208020,
		0x00008020, 0x08000000, 0x00000000, 0x00208000,
		0x08200020, 0x08008020, 0x08008000, 0x00200020,
		0x08208000, 0x00000020, 0x00200020, 0x08008000,
		0x08208020, 0x00200000, 0x08200000, 0x08000020,
		0x00208000, 0x00008020, 0x08008020, 0x08200000,
		0x00000020, 0x08208000, 0x00208020, 0x00000000,
		0x08000000, 0x08200020, 0x00008000, 0x00208020,
	}
};

static const int32_t DES_KEY_SZ=8;

void des_set_odd_parity(uint8_t* key)
{
	int32_t i;

	for (i=0; i < DES_KEY_SZ; i++)
		key[i]=odd_parity[key[i]&0xff];
}

int8_t check_parity(const uint8_t* key)
{
	int32_t i;

	for (i=0; i < DES_KEY_SZ; i++)
	{
		if (key[i] != odd_parity[key[i]&0xff])
			return 0;
	}
	return 1;
}

int8_t des_is_weak_key(const uint8_t* key)
{
	int32_t i, j;

	for (i=0; i < 16; i++)
	{
		for(j=0; j < DES_KEY_SZ; j++)
		{
			if (weak_keys[i][j] != key[j])
			{
				// not weak
				continue;
			}
		}
		// weak
		return 1;
	}
	return 0;
}

static uint32_t Get32bits(const uint8_t* key, int32_t kindex)
{
	return(((key[kindex+3]&0xff)<<24) + ((key[kindex+2]&0xff)<<16) + ((key[kindex+1]&0xff)<<8) + (key[kindex]&0xff));
}

int8_t des_set_key(const uint8_t* key, uint32_t* schedule)
{
	uint32_t c,d,t,s;
	int32_t inIndex;
	int32_t kIndex;
	int32_t i;
	inIndex=0;
	kIndex=0;
	c =Get32bits(key, inIndex);
	d =Get32bits(key, inIndex+4);
	t=(((d>>4)^c)&0x0f0f0f0f);
	c^=t;
	d^=(t<<4);
	t=(((c<<(16-(-2)))^c)&0xcccc0000);
	c=c^t^(t>>(16-(-2)));
	t=((d<<(16-(-2)))^d)&0xcccc0000;
	d=d^t^(t>>(16-(-2)));
	t=((d>>1)^c)&0x55555555;
	c^=t;
	d^=(t<<1);
	t=((c>>8)^d)&0x00ff00ff;
	d^=t;
	c^=(t<<8);
	t=((d>>1)^c)&0x55555555;
	c^=t;
	d^=(t<<1);
	d=	(((d&0x000000ff)<<16)| (d&0x0000ff00) |((d&0x00ff0000)>>16)|((c&0xf0000000)>>4));
	c&=0x0fffffff;
	for (i=0; i < 16; i++)
	{
		if (shifts2[i])
		{
			c=((c>>2)|(c<<26));
			d=((d>>2)|(d<<26));
		}
		else
		{
			c=((c>>1)|(c<<27));
			d=((d>>1)|(d<<27));
		}
		c&=0x0fffffff;
		d&=0x0fffffff;
		s=	des_skb[0][ (c    )&0x3f                ]|
			des_skb[1][((c>> 6)&0x03)|((c>> 7)&0x3c)]|
			des_skb[2][((c>>13)&0x0f)|((c>>14)&0x30)]|
			des_skb[3][((c>>20)&0x01)|((c>>21)&0x06) |
						  ((c>>22)&0x38)];
		t=	des_skb[4][ (d    )&0x3f                ]|
			des_skb[5][((d>> 7)&0x03)|((d>> 8)&0x3c)]|
			des_skb[6][ (d>>15)&0x3f                ]|
			des_skb[7][((d>>21)&0x0f)|((d>>22)&0x30)];
		schedule[kIndex++]=((t<<16)|(s&0x0000ffff))&0xffffffff;
		s=((s>>16)|(t&0xffff0000));
		s=(s<<4)|(s>>28);
		schedule[kIndex++]=s&0xffffffff;
	}
	return 1;
}

static uint32_t _lrotr(uint32_t i)
{
	return((i>>4) | ((i&0xff)<<28));
}

static void des_encrypt_int(uint32_t* data, const uint32_t* ks, int8_t do_encrypt)
{
	uint32_t l=0,r=0,t=0,u=0;
	int32_t i;

	u=data[0];
	r=data[1];

	{
		uint32_t tt;

		tt=((r>>4)^u)&0x0f0f0f0f;
		u^=tt;
		r^=(tt<<4);
		tt=(((u>>16)^r)&0x0000ffff);
		r^=tt;
		u^=(tt<<16);
		tt=(((r>>2)^u)&0x33333333);
		u^=tt;
		r^=(tt<<2);
		tt=(((u>>8)^r)&0x00ff00ff);
		r^=tt;
		u^=(tt<<8);
		tt=(((r>>1)^u)&0x55555555);
		u^=tt;
		r^=(tt<<1);
	}

	l=(r<<1)|(r>>31);
	r=(u<<1)|(u>>31);
	l&=0xffffffff;
	r&=0xffffffff;

	if (do_encrypt)
	{
		for (i=0; i < 32; i+=8)
		{
			{
				u=(r^ks[i+0 ]);
				t=r^ks[i+0+1];
				t=(_lrotr(t));
				l^= des_SPtrans[1][(t )&0x3f]| des_SPtrans[3][(t>> 8)&0x3f]| des_SPtrans[5][(t>>16)&0x3f]| des_SPtrans[7][(t>>24)&0x3f]| des_SPtrans[0][(u )&0x3f]| des_SPtrans[2][(u>> 8)&0x3f]| des_SPtrans[4][(u>>16)&0x3f]| des_SPtrans[6][(u>>24)&0x3f];
			};
			{
				u=(l^ks[i+2 ]);
				t=l^ks[i+2+1];
				t=(_lrotr(t));
				r^= des_SPtrans[1][(t )&0x3f]| des_SPtrans[3][(t>> 8)&0x3f]| des_SPtrans[5][(t>>16)&0x3f]| des_SPtrans[7][(t>>24)&0x3f]| des_SPtrans[0][(u )&0x3f]| des_SPtrans[2][(u>> 8)&0x3f]| des_SPtrans[4][(u>>16)&0x3f]| des_SPtrans[6][(u>>24)&0x3f];
			};
			{
				u=(r^ks[i+4 ]);
				t=r^ks[i+4+1];
				t=(_lrotr(t));
				l^= des_SPtrans[1][(t )&0x3f]| des_SPtrans[3][(t>> 8)&0x3f]| des_SPtrans[5][(t>>16)&0x3f]| des_SPtrans[7][(t>>24)&0x3f]| des_SPtrans[0][(u )&0x3f]| des_SPtrans[2][(u>> 8)&0x3f]| des_SPtrans[4][(u>>16)&0x3f]| des_SPtrans[6][(u>>24)&0x3f];
			};
			{
				u=(l^ks[i+6 ]);
				t=l^ks[i+6+1];
				t=(_lrotr(t));
				r^= des_SPtrans[1][(t )&0x3f]| des_SPtrans[3][(t>> 8)&0x3f]| des_SPtrans[5][(t>>16)&0x3f]| des_SPtrans[7][(t>>24)&0x3f]| des_SPtrans[0][(u )&0x3f]| des_SPtrans[2][(u>> 8)&0x3f]| des_SPtrans[4][(u>>16)&0x3f]| des_SPtrans[6][(u>>24)&0x3f];
			};
		}
	}
	else
	{
		for (i=30; i > 0; i-=8)
		{
			{
				u=(r^ks[i-0 ]);
				t=r^ks[i-0+1];
				t=(_lrotr(t));
				l^= des_SPtrans[1][(t )&0x3f]| des_SPtrans[3][(t>> 8)&0x3f]| des_SPtrans[5][(t>>16)&0x3f]| des_SPtrans[7][(t>>24)&0x3f]| des_SPtrans[0][(u )&0x3f]| des_SPtrans[2][(u>> 8)&0x3f]| des_SPtrans[4][(u>>16)&0x3f]| des_SPtrans[6][(u>>24)&0x3f];
			};
			{
				u=(l^ks[i-2 ]);
				t=l^ks[i-2+1];
				t=(_lrotr(t));
				r^= des_SPtrans[1][(t )&0x3f]| des_SPtrans[3][(t>> 8)&0x3f]| des_SPtrans[5][(t>>16)&0x3f]| des_SPtrans[7][(t>>24)&0x3f]| des_SPtrans[0][(u )&0x3f]| des_SPtrans[2][(u>> 8)&0x3f]| des_SPtrans[4][(u>>16)&0x3f]| des_SPtrans[6][(u>>24)&0x3f];
			};
			{
				u=(r^ks[i-4 ]);
				t=r^ks[i-4+1];
				t=(_lrotr(t));
				l^= des_SPtrans[1][(t )&0x3f]| des_SPtrans[3][(t>> 8)&0x3f]| des_SPtrans[5][(t>>16)&0x3f]| des_SPtrans[7][(t>>24)&0x3f]| des_SPtrans[0][(u )&0x3f]| des_SPtrans[2][(u>> 8)&0x3f]| des_SPtrans[4][(u>>16)&0x3f]| des_SPtrans[6][(u>>24)&0x3f];
			};
			{
				u=(l^ks[i-6 ]);
				t=l^ks[i-6+1];
				t=(_lrotr(t));
				r^= des_SPtrans[1][(t )&0x3f]| des_SPtrans[3][(t>> 8)&0x3f]| des_SPtrans[5][(t>>16)&0x3f]| des_SPtrans[7][(t>>24)&0x3f]| des_SPtrans[0][(u )&0x3f]| des_SPtrans[2][(u>> 8)&0x3f]| des_SPtrans[4][(u>>16)&0x3f]| des_SPtrans[6][(u>>24)&0x3f];
			};
		}
	}

	l=(l>>1)|(l<<31);
	r=(r>>1)|(r<<31);
	l&=0xffffffff;
	r&=0xffffffff;

	{
		uint32_t tt;
		tt=(((r>>1)^l)&0x55555555);
		l^=tt;
		r^=(tt<<1);
		tt=(((l>>8)^r)&0x00ff00ff);
		r^=tt;
		l^=(tt<<8);
		tt=(((r>>2)^l)&0x33333333);
		l^=tt;
		r^=(tt<<2);
		tt=(((l>>16)^r)&0x0000ffff);
		r^=tt;
		l^=(tt<<16);
		tt=(((r>>4)^l)&0x0f0f0f0f);
		l^=tt;
		r^=(tt<<4);
	}

	data[0]=l;
	data[1]=r;
}

void des(uint8_t* data, const uint32_t* schedule, int8_t do_encrypt)
{
	uint32_t l, ll[2];
	int32_t inIndex;
	int32_t outIndex;

	inIndex=0;
	outIndex=0;

	l = Get32bits(data, inIndex);
	ll[0]=l;

	l = Get32bits(data, inIndex+4);
	ll[1]=l;

	des_encrypt_int(ll, schedule, do_encrypt);

	l=ll[0];

	data[outIndex++] = (l&0xff);
	data[outIndex++] = ((l>>8)&0xff);
	data[outIndex++] = ((l>>16)&0xff);
	data[outIndex++] = ((l>>24)&0xff);
	l=ll[1];
	data[outIndex++] = (l&0xff);
	data[outIndex++] = ((l>>8) &0xff);
	data[outIndex++] = ((l>>16) &0xff);
	data[outIndex++] = ((l>>24) &0xff);
}

static inline void xxor(uint8_t *data, int32_t len, const uint8_t *v1, const uint8_t *v2)
{
	uint32_t i;
	switch(len)
	{
	case 16:
		for(i = 0; i < 16; ++i)
		{
			data[i] = v1[i] ^ v2[i];
		}
		break;
	case 8:
		for(i = 0; i < 8; ++i)
		{
			data[i] = v1[i] ^ v2[i];
		}
		break;
	case 4:
		for(i = 0; i < 4; ++i)
		{
			data[i] = v1[i] ^ v2[i];
		}
		break;
	default:
		while(len--)
		{
			*data++ = *v1++ ^ *v2++;
		}
		break;
	}
}

void des_ecb_encrypt(uint8_t* data, const uint8_t* key, int32_t len)
{
	uint32_t schedule[32];
	int32_t i;

	des_set_key(key, schedule);

	len&=~7;

	for(i=0; i<len; i+=8)
	{
		des(&data[i], schedule, 1);
	}
}

void des_ecb_decrypt(uint8_t* data, const uint8_t* key, int32_t len)
{
	uint32_t schedule[32];
	int32_t i;

	des_set_key(key, schedule);

	len&=~7;

	for(i=0; i<len; i+=8)
	{
		des(&data[i], schedule, 0);
	}
}

void des_cbc_encrypt(uint8_t* data, const uint8_t* iv, const uint8_t* key, int32_t len)
{
	const uint8_t *civ = iv;
	uint32_t schedule[32];
	int32_t i;

	des_set_key(key, schedule);

	len&=~7;

	for(i=0; i<len; i+=8)
	{
		xxor(&data[i],8,&data[i],civ);
		civ=&data[i];
		des(&data[i], schedule, 1);
	}
}

void des_cbc_decrypt(uint8_t* data, const uint8_t* iv, const uint8_t* key, int32_t len)
{
	uint8_t civ[2][8];
	uint32_t schedule[32];
	int32_t i, n=0;

	des_set_key(key, schedule);

	len&=~7;

	memcpy(civ[n],iv,8);
	for(i=0; i<len; i+=8,data+=8,n^=1)
	{
		memcpy(civ[1-n],data,8);
		des(data, schedule,0);
		xxor(data,8,data,civ[n]);
	}
}

void des_ede2_cbc_encrypt(uint8_t* data, const uint8_t* iv, const uint8_t* key1, const uint8_t* key2, int32_t len)
{
	const uint8_t *civ = iv;
	uint32_t schedule1[32], schedule2[32];
	int32_t i;

	des_set_key(key1, schedule1);
	des_set_key(key2, schedule2);

	len&=~7;

	for(i=0; i<len; i+=8)
	{
		xxor(&data[i],8,&data[i],civ);
		civ=&data[i];

		des(&data[i], schedule1, 1);
		des(&data[i], schedule2, 0);
		des(&data[i], schedule1, 1);
	}
}

void des_ede2_cbc_decrypt(uint8_t* data, const uint8_t* iv, const uint8_t* key1, const uint8_t* key2, int32_t len)
{
	uint8_t civ[2][8];
	uint32_t schedule1[32], schedule2[32];
	int32_t i, n=0;

	des_set_key(key1, schedule1);
	des_set_key(key2, schedule2);

	len&=~7;

	memcpy(civ[n],iv,8);
	for(i=0; i<len; i+=8,data+=8,n^=1)
	{
		memcpy(civ[1-n],data,8);
		des(data, schedule1, 0);
		des(data, schedule2, 1);
		des(data, schedule1, 0);
		xxor(data,8,data,civ[n]);
	}
}

void des_ecb3_decrypt(uint8_t* data, const uint8_t* key)
{
	uint8_t desA[8];
	uint8_t desB[8];

	uint32_t schedule1[32];
	uint32_t schedule2[32];

	memcpy(desA, key, 8);
	des_set_key(desA, schedule1);
	memcpy(desB, key+8, 8);
	des_set_key(desB, schedule2);

	des(data, schedule1, 0);
	des(data, schedule2, 1);
	des(data, schedule1, 0);
}

void des_ecb3_encrypt(uint8_t* data, const uint8_t* key)
{
	uint8_t desA[8];
	uint8_t desB[8];

	uint32_t schedule1[32];
	uint32_t schedule2[32];

	memcpy(desA, key, 8);
	des_set_key(desA, schedule1);
	memcpy(desB, key+8, 8);
	des_set_key(desB, schedule2);

	des(data, schedule1, 1);
	des(data, schedule2, 0);
	des(data, schedule1, 1);
}
/* ==== END master cscrypt/des.c ==== */

/* Restore header-level macros for the public names */
#undef des_set_key
#undef des
#define des_set_key          oscam_des_set_key
#define des                  oscam_des

/* Shim wrappers: forward to the internal symbols, adapting the opaque
 * des_key_schedule struct used by oscam callers to master's uint32_t[32]. */
void oscam_des_set_key(const uint8_t *key, des_key_schedule *schedule)
{
	_internal_des_set_key(key, (uint32_t *)schedule);
}

void oscam_des(uint8_t *data, des_key_schedule *schedule, int enc)
{
	_internal_des(data, (const uint32_t *)schedule, (int8_t)enc);
}

/* Convenience helper shipped by oscam but not in master: parity over any
 * buffer length (used by a few card modules). */
void oscam_des_set_odd_parity_all(uint8_t *key, size_t len)
{
	if (!key || len == 0) return;
	for (size_t i = 0; i < len; i++) {
		uint8_t x = key[i];
		uint8_t parity = 0;
		for (int b = 1; b < 8; b++) parity ^= (x >> b) & 1;
		key[i] = (x & 0xFE) | (parity ^ 1);
	}
}

#endif /* (WITH_LIB_DES || WITH_LIB_MDC2) && !WITH_OPENSSL */

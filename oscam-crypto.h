#ifndef OSCAM_CRYPTO_H
#define OSCAM_CRYPTO_H

#ifdef WITH_LIBCRYPTO

/* mbedTLS */
#include "mbedtls/aes.h"
#include "mbedtls/bignum.h"
#include "mbedtls/des.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"

/* ===== MDC2 compatibility ===== */

#define MDC2_BLOCK		  8
#define MDC2_DIGEST_LENGTH  16

typedef struct {
	unsigned char h[MDC2_BLOCK];
	unsigned char hh[MDC2_BLOCK];
	unsigned char data[MDC2_BLOCK];
	unsigned int num;
	int pad_type;
} MDC2_CTX;

int MDC2_Init(MDC2_CTX *c);
int MDC2_Update(MDC2_CTX *c, const unsigned char *in, size_t len);
int MDC2_Final(unsigned char *md, MDC2_CTX *c);

/* ===== MD5 compatibility ===== */
#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md);
char *__md5_crypt(const char *pw, const char *salt, char *passwd);

/* ===== RC6 compatibility ===== */
#define RC6_W 32
#define RC6_R 20
#define RC6_P32 0xB7E15163U
#define RC6_Q32 0x9E3779B9U
#define RC6_LGW 5

typedef uint32_t RC6KEY[2 * RC6_R + 4];

void rc6_key_setup(unsigned char *K, int b, RC6KEY S);
void rc6_block_encrypt(unsigned int *pt, unsigned int *ct, int block_count, RC6KEY S);
void rc6_block_decrypt(unsigned int *ct, unsigned int *pt, int block_count, RC6KEY S);

/* ===== IDEA compatibility ===== */
#define IDEA_INT uint16_t
#define IDEA_ENCRYPT 1
#define IDEA_DECRYPT 0
#define IDEA_BLOCK 8
#define IDEA_KEY_LENGTH 16

typedef struct idea_key_st {
	IDEA_INT data[9][6];
} IDEA_KEY_SCHEDULE;

const char *idea_options(void);
void idea_ecb_encrypt(const unsigned char *in, unsigned char *out, IDEA_KEY_SCHEDULE *ks);
void idea_set_encrypt_key(const unsigned char *key, IDEA_KEY_SCHEDULE *ks);
void idea_set_decrypt_key(IDEA_KEY_SCHEDULE *ek, IDEA_KEY_SCHEDULE *dk);
void idea_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
					  IDEA_KEY_SCHEDULE *ks, unsigned char *iv, int enc);
void idea_encrypt(uint32_t *in, IDEA_KEY_SCHEDULE *ks);
void idea_cfb64_encrypt(const unsigned char *in, unsigned char *out,
						long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv,
						int *num, int enc);

void idea_ofb64_encrypt(const unsigned char *in, unsigned char *out,
						long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv,
						int *num);

/* ===== SHA1 compatibility ===== */
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

typedef struct {
	mbedtls_sha1_context ctx;
} SHA_CTX;

int SHA1_Init(SHA_CTX *c);
int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
int SHA1_Final(unsigned char *md, SHA_CTX *c);

unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

/* ===== AES compatibility layer ===== */

/* key length in bytes */
#define KEY128 16
#define KEY192 24
#define KEY256 32
/* block size in bytes */
#define BLOCKSZ 16
/* mode */
#define EBC 0
#define CBC 1

typedef struct
{
	unsigned int Ek[60]; /* unused in shim, for binary compatibility */
	unsigned int Dk[60];
	unsigned int Iv[4];
	unsigned char Nr;
	unsigned char Mode;

	mbedtls_aes_context ctx;  /* real mbedtls context */
	unsigned char iv[BLOCKSZ];
} AesCtx;

void AesCtxIni(AesCtx *c, const unsigned char *iv, const unsigned char *key, int keylen, int mode);
void AesEncrypt(AesCtx *c, const unsigned char *input, unsigned char *output, int len);
void AesDecrypt(AesCtx *c, const unsigned char *input, unsigned char *output, int len);

#define AES_ENCRYPT 1
#define AES_DECRYPT 0

typedef struct {
	mbedtls_aes_context ctx;
} AES_KEY;

int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);

#ifndef AES_ENCRYPT
#define AES_ENCRYPT MBEDTLS_AES_ENCRYPT
#define AES_DECRYPT MBEDTLS_AES_DECRYPT
#endif

int AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
					size_t length, const AES_KEY *key, unsigned char *ivec,
					const int enc);

/* ===== SHA256 compatibility ===== */
typedef mbedtls_sha256_context SHA256_CTX;

static inline void SHA256_Init(SHA256_CTX *ctx)
{
	mbedtls_sha256_init(ctx);
	mbedtls_sha256_starts(ctx, 0);
}

static inline void SHA256_Update(SHA256_CTX *ctx, const void *data, size_t len)
{
	mbedtls_sha256_update(ctx, data, len);
}

static inline void SHA256_Final(unsigned char *out, SHA256_CTX *ctx)
{
	mbedtls_sha256_finish(ctx, out);
	mbedtls_sha256_free(ctx);
}

/* ===== DES compatibility ===== */
typedef struct {
	mbedtls_des_context ctx;
	unsigned char key[8];   // store raw key for decrypt mode
} des_key_schedule;

void des_set_key(const uint8_t *key, des_key_schedule *schedule);
void des(uint8_t *data, des_key_schedule *schedule, int encrypt);

void des_ecb_encrypt(uint8_t *data, const uint8_t *key, int32_t len);
void des_ecb_decrypt(uint8_t *data, const uint8_t *key, int32_t len);
void des_cbc_encrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key, int32_t len);
void des_cbc_decrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key, int32_t len);
void des_ede2_cbc_encrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key1, const uint8_t *key2, int32_t len);
void des_ede2_cbc_decrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key1, const uint8_t *key2, int32_t len);
void des_ecb3_encrypt(uint8_t *data, const uint8_t *key);
void des_ecb3_decrypt(uint8_t *data, const uint8_t *key);

/* ===== BIGNUM compatibility ===== */
typedef mbedtls_mpi BIGNUM;
typedef struct {
	/* MbedTLS doesn't need a context pool; kept for compatibility */
	int dummy;
} BN_CTX;

/* Context management */
BN_CTX *BN_CTX_new(void);
void BN_CTX_free(BN_CTX *ctx);
void BN_CTX_start(BN_CTX *ctx);
void BN_CTX_end(BN_CTX *ctx);
BIGNUM *BN_CTX_get(BN_CTX *ctx);

/* Core operations */
BIGNUM *BN_new(void);
void BN_free(BIGNUM *bn);
int BN_num_bytes(const BIGNUM *bn);
BIGNUM *BN_bin2bn(const unsigned char *in, int len, BIGNUM *bn);
int BN_bn2bin(const BIGNUM *bn, unsigned char *out);
int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx);
int BN_add_word(BIGNUM *a, unsigned long w);
int BN_sub_word(BIGNUM *a, unsigned long w);
int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
BIGNUM *BN_mod_inverse(BIGNUM *r, const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
int BN_cmp(const BIGNUM *a, const BIGNUM *b);
BIGNUM *BN_copy(BIGNUM *to, const BIGNUM *from);
int BN_set_word(BIGNUM *a, unsigned long w);
unsigned long BN_get_word(const BIGNUM *a);

#endif /* WITH_LIBCRYPTO */
#endif /* OSCAM_CRYPTO_H */

#ifndef OSCAM_CRYPTO_H
#define OSCAM_CRYPTO_H

#include "config.h"

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
#if defined(WITH_SSL) || defined(WITH_LIB_BIGNUM)
#include "mbedtls/bignum.h"
#endif

#ifdef WITH_LIB_MDC2
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
#endif

#ifdef WITH_LIB_DES
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
#endif

#ifdef WITH_LIB_MD5
/* ===== MD5 compatibility ===== */
#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md);
char *__md5_crypt(const char *pw, const char *salt, char *passwd);
#endif

#ifdef WITH_LIB_RC6
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
#endif

#ifdef WITH_LIB_IDEA
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
#endif

#if defined(WITH_SSL) || defined(WITH_LIB_SHA1)

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
#endif

#ifdef WITH_LIB_SHA256
#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif
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

static inline void SHA256_Final(SHA256_CTX *ctx, unsigned char *out)
{
	mbedtls_sha256_finish(ctx, out);
}

static inline void SHA256_Free(SHA256_CTX *ctx) {
	mbedtls_sha256_free(ctx);
}
#endif

#ifdef WITH_LIB_AES
#define KEY128 16
#define KEY192 24
#define KEY256 32
#define BLOCKSZ 16
#define ECB 0
#define CBC 1

typedef struct
{
	/* Legacy fast_aes fields (must not be reordered or removed) */
	unsigned int Ek[60];
	unsigned int Dk[60];
	unsigned int Iv[4];
	unsigned char Nr;
	unsigned char Mode;

	/* Appended shim internals for MbedTLS */
	mbedtls_aes_context enc_ctx;
	mbedtls_aes_context dec_ctx;
} AesCtx;

int AesCtxIni(AesCtx *c, const unsigned char *iv, const unsigned char *key, int keylen, int mode);
int AesEncrypt(AesCtx *c, const unsigned char *input, unsigned char *output, int len);
int AesDecrypt(AesCtx *c, const unsigned char *input, unsigned char *output, int len);

static inline void AesFree(AesCtx *c)
{
	if (!c) return;
	mbedtls_aes_free(&c->enc_ctx);
	mbedtls_aes_free(&c->dec_ctx);
}

#define AES_ENCRYPT 1
#define AES_DECRYPT 0
#define AES_BLOCK_SIZE 16

typedef struct {
	mbedtls_aes_context enc_ctx;
	mbedtls_aes_context dec_ctx;
} AES_CTX_MBED;

typedef AES_CTX_MBED AES_KEY;
typedef AES_CTX_MBED aes_keys;

int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
int AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, unsigned char *ivec, const int enc);

static inline void AES_free(AES_KEY *key)
{
	if (key) {
		mbedtls_aes_free(&key->enc_ctx);
		mbedtls_aes_free(&key->dec_ctx);
	}
}

typedef struct aes_entry {
	uint16_t             caid;
	uint32_t             ident;
	int32_t              keyid;
	uint8_t              plainkey[16];
	mbedtls_aes_context  key;         /* decrypt-context for this entry */
	struct aes_entry    *next;
} AES_ENTRY;

typedef struct aes_entry AES_ENTRY;
struct s_reader;

void aes_set_key(aes_keys *aes, char *key);
bool aes_set_key_alloc(aes_keys **aes, char *key);
void aes_decrypt(aes_keys *aes, uint8_t *buf, int32_t n);
void aes_encrypt_idx(aes_keys *aes, uint8_t *buf, int32_t n);
void aes_cbc_encrypt(aes_keys *aes, uint8_t *buf, int32_t n, uint8_t *iv);
void aes_cbc_decrypt(aes_keys *aes, uint8_t *buf, int32_t n, uint8_t *iv);

void add_aes_entry(AES_ENTRY **list, uint16_t caid, uint32_t ident, int32_t keyid, uint8_t *aesKey);
void parse_aes_entry(AES_ENTRY **list, char *label, char *value);
void parse_aes_keys(struct s_reader *rdr, char *value);
void aes_clear_entries(AES_ENTRY **list);
int32_t aes_decrypt_from_list(AES_ENTRY *list, uint16_t caid, uint32_t provid, int32_t keyid, uint8_t *buf, int32_t n);
int32_t aes_present(AES_ENTRY *list, uint16_t caid, uint32_t provid, int32_t keyid);
#else
typedef void AES_ENTRY; /* forward placeholder to satisfy struct s_reader */
#endif

#ifdef WITH_LIB_BIGNUM
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
#endif

#endif /* OSCAM_CRYPTO_H */

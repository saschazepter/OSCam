#ifndef OSCAM_CRYPTO_H
#define OSCAM_CRYPTO_H

/* =====================================================================
 *  OSCam unified crypto API header
 *  ---------------------------------------------------------------
 *  - Independent of backend (OpenSSL / MbedTLS)
 *  - No heavy library includes
 *  - All real includes live in oscam-crypto.c
 * ===================================================================== */

#include "config.h"

#ifdef WITH_OPENSSL

#include <openssl/opensslv.h>
#include <openssl/evp.h>

/*
 * OpenSSL < 1.1.0 does not have EVP_CIPHER_CTX_new/free.
 * Some vendor toolchains (e.g. Dreambox) ship headers that declare them
 * but the library does not implement them.
 *
 * We avoid fighting with those declarations by providing our own
 * wrapper functions with different names and then remapping
 * EVP_CIPHER_CTX_new/free to those wrappers.
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L

EVP_CIPHER_CTX *oscam_EVP_CIPHER_CTX_new(void);
void            oscam_EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);

#define EVP_CIPHER_CTX_new  oscam_EVP_CIPHER_CTX_new
#define EVP_CIPHER_CTX_free oscam_EVP_CIPHER_CTX_free

#endif /* < 1.1.0 */

/*
 * OpenSSL 3.x deprecates low-level MD5/SHA1 (SHA_CTX/MD5_CTX, *_Init/Update/Final).
 * To avoid touching all call sites, we provide tiny shims that map the old API
 * to EVP when building against >= 1.1.0. For <= 1.0.x we keep the originals.
 */

#if defined(WITH_SSL) || defined(WITH_LIB_MD5)
#include <openssl/md5.h>
#endif

#if defined(WITH_SSL) || defined(WITH_LIB_SHA1) || defined(WITH_LIB_SHA256)
#include <openssl/sha.h>
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
/* -------- MD5 shim (old-style calls) ---------- */
typedef struct { EVP_MD_CTX *p; } OSCAM_MD5_CTX;
#define MD5_CTX OSCAM_MD5_CTX
static inline unsigned char *OSCAM_MD5(const unsigned char *d, size_t n, unsigned char *md) {
	unsigned int md_len = 0;
	EVP_Digest(d, n, md, &md_len, EVP_md5(), NULL);
	return md;
}
static inline int OSCAM_MD5_Init(MD5_CTX *c) {
	c->p = EVP_MD_CTX_new();
	return c->p && EVP_DigestInit_ex(c->p, EVP_md5(), NULL);
}
static inline int OSCAM_MD5_Update(MD5_CTX *c, const void *d, size_t l) {
	return EVP_DigestUpdate(c->p, d, l);
}
static inline int OSCAM_MD5_Final(unsigned char *md, MD5_CTX *c) {
	int ok = EVP_DigestFinal_ex(c->p, md, NULL);
	EVP_MD_CTX_free(c->p); c->p = NULL;
	return ok;
}
#undef  MD5
#undef  MD5_Init
#undef  MD5_Update
#undef  MD5_Final
#define MD5        OSCAM_MD5
#define MD5_Init   OSCAM_MD5_Init
#define MD5_Update OSCAM_MD5_Update
#define MD5_Final  OSCAM_MD5_Final

/* -------- SHA1 shim (old-style calls) ---------- */
typedef struct { EVP_MD_CTX *p; } OSCAM_SHA_CTX;
#define SHA_CTX OSCAM_SHA_CTX
static inline int OSCAM_SHA1_Init(SHA_CTX *c) {
	c->p = EVP_MD_CTX_new();
	return c->p && EVP_DigestInit_ex(c->p, EVP_sha1(), NULL);
}
static inline int OSCAM_SHA1_Update(SHA_CTX *c, const void *d, size_t l) {
	return EVP_DigestUpdate(c->p, d, l);
}
static inline int OSCAM_SHA1_Final(unsigned char *md, SHA_CTX *c) {
	int ok = EVP_DigestFinal_ex(c->p, md, NULL);
	EVP_MD_CTX_free(c->p); c->p = NULL;
	return ok;
}
#undef  SHA1_Init
#undef  SHA1_Update
#undef  SHA1_Final
#define SHA1_Init   OSCAM_SHA1_Init
#define SHA1_Update OSCAM_SHA1_Update
#define SHA1_Final  OSCAM_SHA1_Final

/* -------- SHA256 shim (old-style calls) ---------- */
typedef struct { EVP_MD_CTX *p; } OSCAM_SHA256_CTX;
#define SHA256_CTX OSCAM_SHA256_CTX

static inline int OSCAM_SHA256_Init(SHA256_CTX *c) {
	c->p = EVP_MD_CTX_new();
	return c->p && EVP_DigestInit_ex(c->p, EVP_sha256(), NULL);
}
static inline int OSCAM_SHA256_Update(SHA256_CTX *c, const void *d, size_t l) {
	return EVP_DigestUpdate(c->p, d, l);
}
static inline int OSCAM_SHA256_Final(unsigned char *md, SHA256_CTX *c) {
	int ok = EVP_DigestFinal_ex(c->p, md, NULL);
	EVP_MD_CTX_free(c->p); c->p = NULL;
	return ok;
}

#undef  SHA256_Init
#undef  SHA256_Update
#undef  SHA256_Final
#define SHA256_Init   OSCAM_SHA256_Init
#define SHA256_Update OSCAM_SHA256_Update
#define SHA256_Final  OSCAM_SHA256_Final
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

#if defined(WITH_SSL) || defined(WITH_LIB_MDC2) || defined(WITH_LIB_DES)
#include <openssl/des.h>
typedef DES_key_schedule des_key_schedule;
#endif

#if defined(WITH_SSL) || defined(WITH_LIB_AES)
#include <openssl/aes.h>
#endif

#if defined(WITH_SSL) || defined(WITH_LIB_BIGNUM)
#include <openssl/bn.h>
#endif

#else

#if defined(WITH_SSL) || defined(WITH_LIB_BIGNUM)
#include "mbedtls/bignum.h"
#endif

#endif /* WITH_OPENSSL */

/* =====================================================================
 *  Forward declarations for compatibility
 *  ---------------------------------------------------------------
 *  (needed because globals.h includes this header)
 * ===================================================================== */

/* ---- Project-owned opaques: always visible ---- */
#ifndef WITH_OPENSSL
typedef struct oscam_des_key_schedule   des_key_schedule;
#endif
typedef struct aes_keys                 aes_keys;

/* ---- OpenSSL-owned types: only forward-declare when NOT using OpenSSL ---- */
#ifndef WITH_OPENSSL
typedef struct MD5_CTX            MD5_CTX;
typedef struct SHA_CTX            SHA_CTX;
typedef struct SHA256_CTX         SHA256_CTX;
typedef struct AES_KEY            AES_KEY;
#endif

/* --- Basic digest / block size constants (defined if missing) --- */
#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif
#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif
#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE 16
#endif

/* ----------------------------------------------------------------------
 * MD5
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_MD5
#ifndef WITH_OPENSSL
#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md);
#endif /* WITH_OPENSSL */
char *__md5_crypt(const char *pw, const char *salt, char *passwd);
#endif /* WITH_LIB_MD5 */

/* ----------------------------------------------------------------------
 * DES
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_DES
#ifndef WITH_OPENSSL
struct oscam_des_key_schedule {
	unsigned char opaque[160];
};
#endif

/* When using OpenSSL, des_* are legacy macros in <openssl/des.h>.
   Undef them so our aliases are clean and consistent on 0.9.8/1.0.x/3.x. */
#if defined(WITH_OPENSSL)
# undef des_set_key
# undef des_ecb_encrypt
# undef des_ecb_decrypt
# undef des_cbc_encrypt
# undef des_cbc_decrypt
# undef des_ede2_cbc_encrypt
# undef des_ede2_cbc_decrypt
# undef des_ecb3_encrypt
# undef des_ecb3_decrypt
# undef des
# undef des_set_odd_parity
# undef des_set_odd_parity_all
#endif

/* Public API names used by the rest of OSCam */
#define des_set_key              oscam_des_set_key
#define des                      oscam_des
#define des_set_odd_parity       oscam_des_set_odd_parity
#define des_set_odd_parity_all   oscam_des_set_odd_parity_all

#define des_ecb_encrypt          oscam_des_ecb_encrypt
#define des_ecb_decrypt          oscam_des_ecb_decrypt
#define des_cbc_encrypt          oscam_des_cbc_encrypt
#define des_cbc_decrypt          oscam_des_cbc_decrypt
#define des_ede2_cbc_encrypt     oscam_des_ede2_cbc_encrypt
#define des_ede2_cbc_decrypt     oscam_des_ede2_cbc_decrypt
#define des_ecb3_encrypt         oscam_des_ecb3_encrypt
#define des_ecb3_decrypt         oscam_des_ecb3_decrypt

void oscam_des_set_key(const uint8_t *key, des_key_schedule *schedule);
void oscam_des(uint8_t *data, des_key_schedule *schedule, int enc);
void des_set_odd_parity(uint8_t key8[8]);
void des_set_odd_parity_all(uint8_t *key, size_t len);

void oscam_des_ecb_encrypt(uint8_t *data, const uint8_t *key, int32_t len);
void oscam_des_ecb_decrypt(uint8_t *data, const uint8_t *key, int32_t len);
void oscam_des_cbc_encrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key, int32_t len);
void oscam_des_cbc_decrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key, int32_t len);
void oscam_des_ede2_cbc_encrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key1, const uint8_t *key2, int32_t len);
void oscam_des_ede2_cbc_decrypt(uint8_t *data, const uint8_t *iv, const uint8_t *key1, const uint8_t *key2, int32_t len);
void oscam_des_ecb3_encrypt(uint8_t *data, const uint8_t *key);
void oscam_des_ecb3_decrypt(uint8_t *data, const uint8_t *key);
#endif

/* ----------------------------------------------------------------------
 * SHA-1
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_SHA1
#ifndef WITH_OPENSSL
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

struct SHA_CTX {
	unsigned char opaque[128];
};

int SHA1_Init(SHA_CTX *c);
int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
int SHA1_Final(unsigned char *md, SHA_CTX *c);
unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
#endif /* WITH_OPENSSL */
#endif /* WITH_LIB_SHA1 */

/* ----------------------------------------------------------------------
 * SHA-256
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_SHA256
#ifndef WITH_OPENSSL
#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

struct SHA256_CTX {
	unsigned char opaque[256];
};

int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);
#endif /* WITH_OPENSSL */
void SHA256_Free(SHA256_CTX *c);
#endif /* WITH_LIB_SHA256 */

/* ----------------------------------------------------------------------
 * AES
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_AES
#define KEY128  16
#define KEY192  24
#define KEY256  32
#define BLOCKSZ 16
#define ECB     0
#define CBC     1

typedef struct {
	unsigned int Ek[60];
	unsigned int Dk[60];
	unsigned int Iv[4];
	unsigned char Nr;
	unsigned char Mode;
	unsigned char opaque[256];
} AesCtx;

int AesCtxIni(AesCtx *c, const unsigned char *iv, const unsigned char *key, int keylen, int mode);
int AesEncrypt(AesCtx *c, const unsigned char *input, unsigned char *output, int len);
int AesDecrypt(AesCtx *c, const unsigned char *input, unsigned char *output, int len);

/* --- generic AES API --- */
#ifndef WITH_OPENSSL
#define AES_ENCRYPT    1
#define AES_DECRYPT    0
#define AES_BLOCK_SIZE 16

struct AES_KEY {
	unsigned char opaque[256];
};

int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
int AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, unsigned char *ivec, const int enc);
#endif /* WITH_OPENSSL */

void aes_set_key(void *aes, char *key);
bool aes_set_key_alloc(aes_keys **aes, char *key);
void aes_decrypt(void *aes, uint8_t *buf, int32_t n);
void aes_encrypt_idx(void *aes, uint8_t *buf, int32_t n);
void aes_cbc_encrypt(void *aes, uint8_t *buf, int32_t n, uint8_t *iv);
void aes_cbc_decrypt(void *aes, uint8_t *buf, int32_t n, uint8_t *iv);

/* --- linked list AES entries (reader keys) --- */
typedef struct aes_entry AES_ENTRY;
struct aes_entry {
	uint16_t caid;
	uint32_t ident;
	int32_t  keyid;
	uint8_t  plainkey[16];
	void    *key;      /* opaque backend-specific key ctx */
	AES_ENTRY *next;
};
struct s_reader;

void add_aes_entry(AES_ENTRY **list, uint16_t caid, uint32_t ident, int32_t keyid, uint8_t *aesKey);
void parse_aes_entry(AES_ENTRY **list, char *label, char *value);
void parse_aes_keys(struct s_reader *rdr, char *value);
void aes_clear_entries(AES_ENTRY **list);
int32_t aes_decrypt_from_list(AES_ENTRY *list, uint16_t caid, uint32_t provid, int32_t keyid, uint8_t *buf, int32_t n);
int32_t aes_present(AES_ENTRY *list, uint16_t caid, uint32_t provid, int32_t keyid);
#endif /* WITH_LIB_AES */

/* ----------------------------------------------------------------------
 * BIGNUM
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_BIGNUM

/* ----------------- OpenSSL backend ----------------- */
#ifdef WITH_OPENSSL
typedef struct bignum_st  BIGNUM;
typedef struct bignum_ctx BN_CTX;
#else
typedef mbedtls_mpi BIGNUM;
typedef struct { int dummy; } BN_CTX;

BN_CTX *BN_CTX_new(void);
void BN_CTX_free(BN_CTX *ctx);
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
void BN_CTX_start(BN_CTX *ctx);
BIGNUM *BN_CTX_get(BN_CTX *ctx);
void BN_CTX_end(BN_CTX *ctx);
#endif /* WITH_OPENSSL */
#endif /* WITH_LIB_BIGNUM */

/* ----------------------------------------------------------------------
 * MDC2 (internal implementation, not provided by mbedtls nor openssl)
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_MDC2
#define MDC2_BLOCK          8
#define MDC2_DIGEST_LENGTH 16

typedef struct {
	unsigned int num;
	unsigned int pad_type;
	unsigned char h[MDC2_BLOCK];
	unsigned char hh[MDC2_BLOCK];
	unsigned char data[MDC2_BLOCK];
} MDC2_CTX;

int MDC2_Init(MDC2_CTX *c);
int MDC2_Update(MDC2_CTX *c, const unsigned char *in, size_t len);
int MDC2_Final(unsigned char *md, MDC2_CTX *c);
#endif /* WITH_LIB_MDC2 */

/* ----------------------------------------------------------------------
 * IDEA (internal implementation, not provided by mbedtls nor openssl)
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_IDEA
#define IDEA_INT unsigned int
#define IDEA_ENCRYPT    1
#define IDEA_DECRYPT    0
#define IDEA_BLOCK      8
#define IDEA_KEY_LENGTH 16

typedef struct idea_key_st
{
	IDEA_INT data[9][6];
} IDEA_KEY_SCHEDULE;

/*
 * Some OpenSSL versions still ship IDEA and export the same symbols
 * (idea_set_encrypt_key, idea_ecb_encrypt, etc.).  We always use our
 * own internal copy and avoid link-time collisions by renaming all
 * public entry points to oscam_idea_* and then mapping the classic
 * names via macros.
 */
#ifdef WITH_OPENSSL
# undef idea_set_encrypt_key
# undef idea_set_decrypt_key
# undef idea_ecb_encrypt
# undef idea_cbc_encrypt
# undef idea_encrypt
# undef idea_cfb64_encrypt
# undef idea_ofb64_encrypt
# undef idea_options
#endif

/* public names used by the rest of OSCam */
#define idea_set_encrypt_key  oscam_idea_set_encrypt_key
#define idea_set_decrypt_key  oscam_idea_set_decrypt_key
#define idea_ecb_encrypt      oscam_idea_ecb_encrypt
#define idea_cbc_encrypt      oscam_idea_cbc_encrypt
#define idea_encrypt          oscam_idea_encrypt
#define idea_cfb64_encrypt    oscam_idea_cfb64_encrypt
#define idea_ofb64_encrypt    oscam_idea_ofb64_encrypt
#define idea_options          oscam_idea_options

void oscam_idea_set_encrypt_key(const unsigned char *key, IDEA_KEY_SCHEDULE *ks);
void oscam_idea_set_decrypt_key(IDEA_KEY_SCHEDULE *ek, IDEA_KEY_SCHEDULE *dk);
void oscam_idea_ecb_encrypt(const unsigned char *in, unsigned char *out, IDEA_KEY_SCHEDULE *ks);
void oscam_idea_cbc_encrypt(const unsigned char *in, unsigned char *out, long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv, int enc);
void oscam_idea_encrypt(unsigned long *in, IDEA_KEY_SCHEDULE *ks);
void oscam_idea_cfb64_encrypt(const unsigned char *in, unsigned char *out, long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv, int *num, int enc);
void oscam_idea_ofb64_encrypt(const unsigned char *in, unsigned char *out, long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv, int *num);
const char *oscam_idea_options(void);
#endif /* WITH_LIB_IDEA */

/* ----------------------------------------------------------------------
 * RC6 (internal implementation, not provided by mbedtls nor openssl)
 * ---------------------------------------------------------------------- */
#ifdef WITH_LIB_RC6
#define RC6_W   32
#define RC6_R   20
#define RC6_P32 0xB7E15163U
#define RC6_Q32 0x9E3779B9U
#define RC6_LGW 5

typedef uint32_t RC6KEY[2 * RC6_R + 4];

void rc6_key_setup(unsigned char *K, int b, RC6KEY S);
void rc6_block_encrypt(unsigned int *pt, unsigned int *ct, int block_count, RC6KEY S);
void rc6_block_decrypt(unsigned int *ct, unsigned int *pt, int block_count, RC6KEY S);
#endif

#endif /* OSCAM_CRYPTO_H */

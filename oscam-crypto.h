#ifndef OSCAM_CRYPTO_H
#define OSCAM_CRYPTO_H

#include "config.h"

#ifdef WITH_OPENSSL

#include <openssl/opensslv.h>
#include <openssl/evp.h>

/* ----------------------------------------------------------------------
 * Optional runtime loader API for OpenSSL
 * ---------------------------------------------------------------------- */

#ifdef WITH_OPENSSL_DLOPEN
/*
 * libcrypto dlopen shim:
 *  - oscam-crypto-openssl.c provides:
 *      int oscam_ossl_crypto_available(void);
 *      void *oscam_libcrypto; and all function pointers below.
 *  - This header exposes function pointer types, externs and
 *    inline wrappers that remap the OpenSSL API names.
 */

/* ------------------------------------------------------------------
 * Shared OpenSSL dlopen helper macros (crypto + ssl backends)
 * ------------------------------------------------------------------ */
/* Declare a global function-pointer named oscam_<name> of given type */
#define DECLARE_OSSL_PTR(name, type) type oscam_##name = NULL
/* Reset an OpenSSL function-pointer */
#define RESET_OSSL_PTR(name) do { oscam_##name = NULL; } while (0)

typedef enum {
	OSSL_FROM_CRYPTO_FIRST,
	OSSL_FROM_SSL_FIRST
} oscam_ossl_lookup_order_t;

/* Loader state (implemented in oscam-crypto-openssl.c) */
int         oscam_ossl_crypto_available(void);
int         oscam_ossl_load(int need_ssl);
void        oscam_ossl_unload(void);
void       *oscam_ossl_sym(const char *name, oscam_ossl_lookup_order_t order);
int         oscam_ossl_have_crypto(void);
int         oscam_ossl_have_ssl(void);
void        oscam_crypto_init_dlopen(void);
const char *oscam_ossl_crypto_soname(void);
const char *oscam_ossl_ssl_soname(void);

/* ===== EVP digest / cipher function pointer typedefs ===== */
typedef const EVP_MD *(*oscam_EVP_md5_f)(void);
typedef const EVP_MD *(*oscam_EVP_sha1_f)(void);
typedef const EVP_MD *(*oscam_EVP_sha256_f)(void);

typedef EVP_MD_CTX *(*oscam_EVP_MD_CTX_new_f)(void);
typedef void        (*oscam_EVP_MD_CTX_free_f)(EVP_MD_CTX *);

typedef int (*oscam_EVP_DigestInit_ex_f)(EVP_MD_CTX *, const EVP_MD *, ENGINE *);
typedef int (*oscam_EVP_DigestUpdate_f)(EVP_MD_CTX *, const void *, size_t);
typedef int (*oscam_EVP_DigestFinal_ex_f)(EVP_MD_CTX *, unsigned char *, unsigned int *);

typedef int (*oscam_EVP_Digest_f)(const void *, size_t, unsigned char *, unsigned int *,
								  const EVP_MD *, ENGINE *);

/* Ciphers */
typedef const EVP_CIPHER *(*oscam_EVP_aes_128_ecb_f)(void);
typedef const EVP_CIPHER *(*oscam_EVP_aes_192_ecb_f)(void);
typedef const EVP_CIPHER *(*oscam_EVP_aes_256_ecb_f)(void);
typedef const EVP_CIPHER *(*oscam_EVP_aes_128_cbc_f)(void);
typedef const EVP_CIPHER *(*oscam_EVP_aes_192_cbc_f)(void);
typedef const EVP_CIPHER *(*oscam_EVP_aes_256_cbc_f)(void);
typedef const EVP_CIPHER *(*oscam_EVP_des_cbc_f)(void);

typedef EVP_CIPHER_CTX *(*oscam_EVP_CIPHER_CTX_new_f)(void);
typedef void            (*oscam_EVP_CIPHER_CTX_free_f)(EVP_CIPHER_CTX *);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
typedef int  (*oscam_EVP_CIPHER_CTX_cleanup_f)(EVP_CIPHER_CTX *);
typedef void (*oscam_EVP_CIPHER_CTX_init_f)(EVP_CIPHER_CTX *);
#endif

typedef int (*oscam_EVP_CIPHER_CTX_set_padding_f)(EVP_CIPHER_CTX *, int);

typedef int (*oscam_EVP_CipherInit_ex_f)(EVP_CIPHER_CTX *, const EVP_CIPHER *,
										 ENGINE *, const unsigned char *,
										 const unsigned char *, int);
typedef int (*oscam_EVP_CipherUpdate_f)(EVP_CIPHER_CTX *, unsigned char *,
										int *, const unsigned char *, int);

typedef int (*oscam_EVP_EncryptInit_ex_f)(EVP_CIPHER_CTX *, const EVP_CIPHER *,
										  ENGINE *, const unsigned char *,
										  const unsigned char *);
typedef int (*oscam_EVP_EncryptUpdate_f)(EVP_CIPHER_CTX *, unsigned char *,
										 int *, const unsigned char *, int);
typedef int (*oscam_EVP_DecryptInit_ex_f)(EVP_CIPHER_CTX *, const EVP_CIPHER *,
										  ENGINE *, const unsigned char *,
										  const unsigned char *);
typedef int (*oscam_EVP_DecryptUpdate_f)(EVP_CIPHER_CTX *, unsigned char *,
										 int *, const unsigned char *, int);

/* ===== extern function pointer storage (defined in oscam-crypto-openssl.c) ===== */

extern oscam_EVP_md5_f                    oscam_EVP_md5;
extern oscam_EVP_sha1_f                   oscam_EVP_sha1;
extern oscam_EVP_sha256_f                 oscam_EVP_sha256;
extern oscam_EVP_MD_CTX_new_f             oscam_EVP_MD_CTX_new;
extern oscam_EVP_MD_CTX_free_f            oscam_EVP_MD_CTX_free;
extern oscam_EVP_DigestInit_ex_f          oscam_EVP_DigestInit_ex;
extern oscam_EVP_DigestUpdate_f           oscam_EVP_DigestUpdate;
extern oscam_EVP_DigestFinal_ex_f         oscam_EVP_DigestFinal_ex;
extern oscam_EVP_Digest_f                 oscam_EVP_Digest;

/* Cipher getters */
extern oscam_EVP_aes_128_ecb_f            oscam_EVP_aes_128_ecb;
extern oscam_EVP_aes_192_ecb_f            oscam_EVP_aes_192_ecb;
extern oscam_EVP_aes_256_ecb_f            oscam_EVP_aes_256_ecb;
extern oscam_EVP_aes_128_cbc_f            oscam_EVP_aes_128_cbc;
extern oscam_EVP_aes_192_cbc_f            oscam_EVP_aes_192_cbc;
extern oscam_EVP_aes_256_cbc_f            oscam_EVP_aes_256_cbc;
extern oscam_EVP_des_cbc_f                oscam_EVP_des_cbc;

/* Cipher ctx / cipher operations */
extern oscam_EVP_CIPHER_CTX_new_f         oscam_EVP_CIPHER_CTX_new;
extern oscam_EVP_CIPHER_CTX_free_f        oscam_EVP_CIPHER_CTX_free;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
extern oscam_EVP_CIPHER_CTX_cleanup_f     oscam_EVP_CIPHER_CTX_cleanup;
extern oscam_EVP_CIPHER_CTX_init_f        oscam_EVP_CIPHER_CTX_init;
#endif
extern oscam_EVP_CIPHER_CTX_set_padding_f oscam_EVP_CIPHER_CTX_set_padding;

extern oscam_EVP_CipherInit_ex_f          oscam_EVP_CipherInit_ex;
extern oscam_EVP_CipherUpdate_f           oscam_EVP_CipherUpdate;

extern oscam_EVP_EncryptInit_ex_f         oscam_EVP_EncryptInit_ex;
extern oscam_EVP_EncryptUpdate_f          oscam_EVP_EncryptUpdate;
extern oscam_EVP_DecryptInit_ex_f         oscam_EVP_DecryptInit_ex;
extern oscam_EVP_DecryptUpdate_f          oscam_EVP_DecryptUpdate;

/* ===== inline wrappers for EVP digests ===== */
static inline const EVP_MD *EVP_md5_shim(void)
{
	if (!oscam_ossl_crypto_available()) return NULL;
	return oscam_EVP_md5 ? oscam_EVP_md5() : NULL;
}

static inline const EVP_MD *EVP_sha1_shim(void)
{
	if (!oscam_ossl_crypto_available()) return NULL;
	return oscam_EVP_sha1 ? oscam_EVP_sha1() : NULL;
}

static inline const EVP_MD *EVP_sha256_shim(void)
{
	if (!oscam_ossl_crypto_available()) return NULL;
	return oscam_EVP_sha256 ? oscam_EVP_sha256() : NULL;
}

static inline EVP_MD_CTX *EVP_MD_CTX_new_shim(void)
{
	if (!oscam_ossl_crypto_available()) return NULL;
	return oscam_EVP_MD_CTX_new ? oscam_EVP_MD_CTX_new() : NULL;
}

static inline void EVP_MD_CTX_free_shim(EVP_MD_CTX *ctx)
{
	if (!ctx) return;
	if (!oscam_ossl_crypto_available()) return;
	if (oscam_EVP_MD_CTX_free) oscam_EVP_MD_CTX_free(ctx);
}

static inline int EVP_DigestInit_ex_shim(EVP_MD_CTX *ctx,
										 const EVP_MD *type, ENGINE *impl)
{
	if (!oscam_ossl_crypto_available()) return 0;
	return oscam_EVP_DigestInit_ex ? oscam_EVP_DigestInit_ex(ctx, type, impl) : 0;
}

static inline int EVP_DigestUpdate_shim(EVP_MD_CTX *ctx,
										const void *d, size_t cnt)
{
	if (!oscam_ossl_crypto_available()) return 0;
	return oscam_EVP_DigestUpdate ? oscam_EVP_DigestUpdate(ctx, d, cnt) : 0;
}

static inline int EVP_DigestFinal_ex_shim(EVP_MD_CTX *ctx,
										  unsigned char *md, unsigned int *s)
{
	if (!oscam_ossl_crypto_available()) return 0;
	return oscam_EVP_DigestFinal_ex ? oscam_EVP_DigestFinal_ex(ctx, md, s) : 0;
}

static inline int EVP_Digest_shim(const void *data, size_t count,
								  unsigned char *md, unsigned int *size,
								  const EVP_MD *type, ENGINE *impl)
{
	if (!oscam_ossl_crypto_available()) return 0;
	return oscam_EVP_Digest ? oscam_EVP_Digest(data, count, md, size, type, impl) : 0;
}

/* ===== inline wrappers for EVP ciphers / contexts ===== */
static inline const EVP_CIPHER *EVP_aes_128_ecb_shim(void)
{
	if (!oscam_ossl_crypto_available()) return NULL;
	return oscam_EVP_aes_128_ecb ? oscam_EVP_aes_128_ecb() : NULL;
}
static inline const EVP_CIPHER *EVP_aes_192_ecb_shim(void)
{
	if (!oscam_ossl_crypto_available()) return NULL;
	return oscam_EVP_aes_192_ecb ? oscam_EVP_aes_192_ecb() : NULL;
}
static inline const EVP_CIPHER *EVP_aes_256_ecb_shim(void)
{
	if (!oscam_ossl_crypto_available()) return NULL;
	return oscam_EVP_aes_256_ecb ? oscam_EVP_aes_256_ecb() : NULL;
}
static inline const EVP_CIPHER *EVP_aes_128_cbc_shim(void)
{
	if (!oscam_ossl_crypto_available()) return NULL;
	return oscam_EVP_aes_128_cbc ? oscam_EVP_aes_128_cbc() : NULL;
}
static inline const EVP_CIPHER *EVP_aes_192_cbc_shim(void)
{
	if (!oscam_ossl_crypto_available()) return NULL;
	return oscam_EVP_aes_192_cbc ? oscam_EVP_aes_192_cbc() : NULL;
}
static inline const EVP_CIPHER *EVP_aes_256_cbc_shim(void)
{
	if (!oscam_ossl_crypto_available()) return NULL;
	return oscam_EVP_aes_256_cbc ? oscam_EVP_aes_256_cbc() : NULL;
}
static inline const EVP_CIPHER *EVP_des_cbc_shim(void)
{
	if (!oscam_ossl_crypto_available()) return NULL;
	return oscam_EVP_des_cbc ? oscam_EVP_des_cbc() : NULL;
}
static inline EVP_CIPHER_CTX *EVP_CIPHER_CTX_new_shim(void)
{
	if (!oscam_ossl_crypto_available()) return NULL;
	return oscam_EVP_CIPHER_CTX_new ? oscam_EVP_CIPHER_CTX_new() : NULL;
}
static inline void EVP_CIPHER_CTX_free_shim(EVP_CIPHER_CTX *ctx)
{
	if (!ctx) return;
	if (!oscam_ossl_crypto_available()) return;
	if (oscam_EVP_CIPHER_CTX_free) oscam_EVP_CIPHER_CTX_free(ctx);
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static inline int EVP_CIPHER_CTX_cleanup_shim(EVP_CIPHER_CTX *ctx)
{
	if (!oscam_ossl_crypto_available()) return 0;
	return oscam_EVP_CIPHER_CTX_cleanup ? oscam_EVP_CIPHER_CTX_cleanup(ctx) : 0;
}

static inline void EVP_CIPHER_CTX_init_shim(EVP_CIPHER_CTX *ctx)
{
	if (!oscam_ossl_crypto_available()) return;
	if (oscam_EVP_CIPHER_CTX_init) oscam_EVP_CIPHER_CTX_init(ctx);
}
#endif

static inline int EVP_CIPHER_CTX_set_padding_shim(EVP_CIPHER_CTX *ctx, int pad)
{
	if (!oscam_ossl_crypto_available()) return 0;
	return oscam_EVP_CIPHER_CTX_set_padding ? oscam_EVP_CIPHER_CTX_set_padding(ctx, pad) : 0;
}

static inline int EVP_CipherInit_ex_shim(EVP_CIPHER_CTX *ctx,
										 const EVP_CIPHER *type, ENGINE *e,
										 const unsigned char *k,
										 const unsigned char *iv, int enc)
{
	if (!oscam_ossl_crypto_available()) return 0;
	return oscam_EVP_CipherInit_ex ? oscam_EVP_CipherInit_ex(ctx, type, e, k, iv, enc) : 0;
}

static inline int EVP_CipherUpdate_shim(EVP_CIPHER_CTX *ctx,
										unsigned char *out, int *outl,
										const unsigned char *in, int inl)
{
	if (!oscam_ossl_crypto_available()) return 0;
	return oscam_EVP_CipherUpdate ? oscam_EVP_CipherUpdate(ctx, out, outl, in, inl) : 0;
}

static inline int EVP_EncryptInit_ex_shim(EVP_CIPHER_CTX *ctx,
										  const EVP_CIPHER *type, ENGINE *e,
										  const unsigned char *k,
										  const unsigned char *iv)
{
	if (!oscam_ossl_crypto_available()) return 0;
	return oscam_EVP_EncryptInit_ex ? oscam_EVP_EncryptInit_ex(ctx, type, e, k, iv) : 0;
}

static inline int EVP_EncryptUpdate_shim(EVP_CIPHER_CTX *ctx, unsigned char *out,
										 int *outl, const unsigned char *in, int inl)
{
	if (!oscam_ossl_crypto_available()) return 0;
	return oscam_EVP_EncryptUpdate ? oscam_EVP_EncryptUpdate(ctx, out, outl, in, inl) : 0;
}

static inline int EVP_DecryptInit_ex_shim(EVP_CIPHER_CTX *ctx,
										  const EVP_CIPHER *type, ENGINE *e,
										  const unsigned char *k,
										  const unsigned char *iv)
{
	if (!oscam_ossl_crypto_available()) return 0;
	return oscam_EVP_DecryptInit_ex ? oscam_EVP_DecryptInit_ex(ctx, type, e, k, iv) : 0;
}

static inline int EVP_DecryptUpdate_shim(EVP_CIPHER_CTX *ctx, unsigned char *out,
										 int *outl, const unsigned char *in, int inl)
{
	if (!oscam_ossl_crypto_available()) return 0;
	return oscam_EVP_DecryptUpdate ? oscam_EVP_DecryptUpdate(ctx, out, outl, in, inl) : 0;
}

/* Remove OpenSSL's definitions (OpenSSL 1.1+ uses reset() instead) */
#undef EVP_CIPHER_CTX_init
#undef EVP_CIPHER_CTX_cleanup
#undef EVP_CipherInit_ex

/* Map all EVP names used in the codebase to the shim versions */
#define EVP_md5                    EVP_md5_shim
#define EVP_sha1                   EVP_sha1_shim
#define EVP_sha256                 EVP_sha256_shim
#define EVP_MD_CTX_new             EVP_MD_CTX_new_shim
#define EVP_MD_CTX_free            EVP_MD_CTX_free_shim
#define EVP_DigestInit_ex          EVP_DigestInit_ex_shim
#define EVP_DigestUpdate           EVP_DigestUpdate_shim
#define EVP_DigestFinal_ex         EVP_DigestFinal_ex_shim
#define EVP_Digest                 EVP_Digest_shim

#define EVP_aes_128_ecb            EVP_aes_128_ecb_shim
#define EVP_aes_192_ecb            EVP_aes_192_ecb_shim
#define EVP_aes_256_ecb            EVP_aes_256_ecb_shim
#define EVP_aes_128_cbc            EVP_aes_128_cbc_shim
#define EVP_aes_192_cbc            EVP_aes_192_cbc_shim
#define EVP_aes_256_cbc            EVP_aes_256_cbc_shim
#define EVP_des_cbc                EVP_des_cbc_shim

#define EVP_CIPHER_CTX_new         EVP_CIPHER_CTX_new_shim
#define EVP_CIPHER_CTX_free        EVP_CIPHER_CTX_free_shim

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_CIPHER_CTX_cleanup     EVP_CIPHER_CTX_cleanup_shim
#define EVP_CIPHER_CTX_init        EVP_CIPHER_CTX_init_shim
#endif

#define EVP_CIPHER_CTX_set_padding EVP_CIPHER_CTX_set_padding_shim
#define EVP_CipherInit_ex          EVP_CipherInit_ex_shim
#define EVP_CipherUpdate           EVP_CipherUpdate_shim
#define EVP_EncryptInit_ex         EVP_EncryptInit_ex_shim
#define EVP_EncryptUpdate          EVP_EncryptUpdate_shim
#define EVP_DecryptInit_ex         EVP_DecryptInit_ex_shim
#define EVP_DecryptUpdate          EVP_DecryptUpdate_shim

#else  /* !WITH_OPENSSL_DLOPEN */

/* When not using dlopen, these do nothing. */
#define DECLARE_OSSL_PTR(name, type)
#define RESET_OSSL_PTR(name)  do { } while (0)

/*
 * OpenSSL < 1.1.0 often lacks EVP_CIPHER_CTX_new/free in libcrypto
 * even if headers declare them (seen on various vendor toolchains).
 * For non-dlopen builds we provide our own implementation and
 * remap the public names.
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L && !defined(WITH_OPENSSL_DLOPEN)

EVP_CIPHER_CTX *oscam_EVP_CIPHER_CTX_new(void);
void            oscam_EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);

#define EVP_CIPHER_CTX_new  oscam_EVP_CIPHER_CTX_new
#define EVP_CIPHER_CTX_free oscam_EVP_CIPHER_CTX_free

#endif

#endif /* WITH_OPENSSL_DLOPEN */

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

#if OPENSSL_VERSION_NUMBER >= 0x10100000L || defined(WITH_OPENSSL_DLOPEN)
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
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L || WITH_OPENSSL_DLOPEN */

#if defined(WITH_SSL) || defined(WITH_LIB_MDC2) || defined(WITH_LIB_DES)
/*
 * OpenSSL 3.x marks low-level DES APIs as deprecated via OSSL_DEPRECATEDIN_3_0.
 * We still need them for legacy MDC2/DES helpers, so locally neutralize that
 * macro instead of using compiler-specific pragmas.
 */
#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#ifdef OSSL_DEPRECATEDIN_3_0
#undef OSSL_DEPRECATEDIN_3_0
#endif
/* make OSSL_DEPRECATEDIN_3_0 expand to nothing in this TU */
#define OSSL_DEPRECATEDIN_3_0
#endif

#include <openssl/des.h>
typedef DES_key_schedule des_key_schedule;

#if WITH_OPENSSL_DLOPEN
/* ===== DES dlopen shims (only when DES is actually used) ===== */

typedef void (*oscam_DES_set_key_unchecked_f)(const_DES_cblock *, DES_key_schedule *);
typedef void (*oscam_DES_ecb_encrypt_f)(const_DES_cblock *, DES_cblock *,
										DES_key_schedule *, int);
typedef void (*oscam_DES_ecb3_encrypt_f)(const_DES_cblock *, DES_cblock *,
										DES_key_schedule *, DES_key_schedule *,
										DES_key_schedule *, int);
typedef void (*oscam_DES_set_odd_parity_f)(DES_cblock *);
typedef void (*oscam_DES_ede3_cbc_encrypt_f)(const unsigned char *, unsigned char *,
										long, DES_key_schedule *, DES_key_schedule *,
										DES_key_schedule *, DES_cblock *, int);
typedef void (*oscam_DES_ncbc_encrypt_f)(const unsigned char *in, unsigned char *out,
										long length, DES_key_schedule *ks,
										DES_cblock *iv, int enc);

extern oscam_DES_set_key_unchecked_f oscam_DES_set_key_unchecked;
extern oscam_DES_ecb_encrypt_f       oscam_DES_ecb_encrypt;
extern oscam_DES_ecb3_encrypt_f      oscam_DES_ecb3_encrypt;
extern oscam_DES_set_odd_parity_f    oscam_DES_set_odd_parity;
extern oscam_DES_ede3_cbc_encrypt_f  oscam_DES_ede3_cbc_encrypt;
extern oscam_DES_ncbc_encrypt_f      oscam_DES_ncbc_encrypt;

static inline void DES_set_key_unchecked_shim(const_DES_cblock *k, DES_key_schedule *s)
{
	if (!oscam_ossl_crypto_available()) return;
	if (oscam_DES_set_key_unchecked) oscam_DES_set_key_unchecked(k, s);
}
static inline void DES_ecb_encrypt_shim(const_DES_cblock *in, DES_cblock *out,
										DES_key_schedule *ks, int enc)
{
	if (!oscam_ossl_crypto_available()) return;
	if (oscam_DES_ecb_encrypt) oscam_DES_ecb_encrypt(in, out, ks, enc);
}
static inline void DES_ecb3_encrypt_shim(const_DES_cblock *in, DES_cblock *out,
										 DES_key_schedule *ks1, DES_key_schedule *ks2,
										 DES_key_schedule *ks3, int enc)
{
	if (!oscam_ossl_crypto_available()) return;
	if (oscam_DES_ecb3_encrypt) oscam_DES_ecb3_encrypt(in, out, ks1, ks2, ks3, enc);
}
static inline void DES_set_odd_parity_shim(DES_cblock *d)
{
	if (!oscam_ossl_crypto_available()) return;
	if (oscam_DES_set_odd_parity) oscam_DES_set_odd_parity(d);
}
static inline void DES_ede3_cbc_encrypt_shim(const unsigned char *in, unsigned char *out,
											 long len,
											 DES_key_schedule *ks1,
											 DES_key_schedule *ks2,
											 DES_key_schedule *ks3,
											 DES_cblock *iv,
											 int enc)
{
	if (!oscam_ossl_crypto_available()) return;
	if (oscam_DES_ede3_cbc_encrypt)
		oscam_DES_ede3_cbc_encrypt(in, out, len, ks1, ks2, ks3, iv, enc);
}
static inline void DES_ncbc_encrypt_shim(const unsigned char *in,
										 unsigned char *out,
										 long length,
										 DES_key_schedule *ks,
										 DES_cblock *iv,
										 int enc)
{
	if (!oscam_ossl_crypto_available()) return;
	if (oscam_DES_ncbc_encrypt)
		oscam_DES_ncbc_encrypt(in, out, length, ks, iv, enc);
}

#define DES_set_key_unchecked  DES_set_key_unchecked_shim
#define DES_ecb_encrypt        DES_ecb_encrypt_shim
#define DES_ecb3_encrypt       DES_ecb3_encrypt_shim
#define DES_set_odd_parity     DES_set_odd_parity_shim
#define DES_ede3_cbc_encrypt   DES_ede3_cbc_encrypt_shim
#define DES_ncbc_encrypt DES_ncbc_encrypt_shim

#endif /* WITH_OPENSSL_DLOPEN */

#endif /* DES-related includes */

#if defined(WITH_SSL) || defined(WITH_LIB_AES)
#include <openssl/aes.h>
#endif

#if defined(WITH_SSL) || defined(WITH_LIB_BIGNUM)
#include <openssl/bn.h>
#endif

#else  /* !WITH_OPENSSL */

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

/* ---- Unified hashing API (SHA1 / SHA256) ---- */
typedef enum {
	OSCAM_HASH_SHA1   = 1,
	OSCAM_HASH_SHA256 = 2
} oscam_hash_alg;

int oscam_hash(oscam_hash_alg alg, const unsigned char *data1, size_t len1, const unsigned char *data2, size_t len2, unsigned char *out);

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

void oscam_des_set_key(const uint8_t *key, des_key_schedule *schedule);
void oscam_des(uint8_t *data, des_key_schedule *schedule, int enc);
void oscam_des_set_odd_parity(uint8_t key8[8]);
void oscam_des_set_odd_parity_all(uint8_t *key, size_t len);

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

static inline int oscam_sha1(const unsigned char *data, size_t len, unsigned char *out)
{
	return oscam_hash(OSCAM_HASH_SHA1, data, len, NULL, 0, out);
}

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

static inline int oscam_sha256(const unsigned char *data, size_t len, unsigned char *out)
{
	return oscam_hash(OSCAM_HASH_SHA256, data, len, NULL, 0, out);
}

static inline int oscam_sha256_stream(const unsigned char *d1,size_t l1, const unsigned char *d2,size_t l2, unsigned char *out)
{
	return oscam_hash(OSCAM_HASH_SHA256, d1, l1, d2, l2, out);
}

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

#if WITH_OPENSSL_DLOPEN
/* ===== BIGNUM dlopen shims (only when BIGNUM is enabled) ===== */
typedef BN_CTX  *(*oscam_BN_CTX_new_f)(void);
typedef void     (*oscam_BN_CTX_free_f)(BN_CTX *);
typedef void     (*oscam_BN_CTX_start_f)(BN_CTX *);
typedef void     (*oscam_BN_CTX_end_f)(BN_CTX *);
typedef BIGNUM  *(*oscam_BN_CTX_get_f)(BN_CTX *);

typedef BIGNUM  *(*oscam_BN_new_f)(void);
typedef void     (*oscam_BN_free_f)(BIGNUM *);

typedef BIGNUM  *(*oscam_BN_bin2bn_f)(const unsigned char *, int, BIGNUM *);
typedef int      (*oscam_BN_bn2bin_f)(const BIGNUM *, unsigned char *);

typedef int      (*oscam_BN_mod_exp_f)(BIGNUM *, const BIGNUM *,
									   const BIGNUM *, const BIGNUM *, BN_CTX *);
typedef int      (*oscam_BN_num_bits_f)(const BIGNUM *);
typedef int      (*oscam_BN_mul_f)(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
typedef int      (*oscam_BN_add_word_f)(BIGNUM *, BN_ULONG);
typedef int      (*oscam_BN_sub_word_f)(BIGNUM *, BN_ULONG);
typedef BIGNUM  *(*oscam_BN_mod_inverse_f)(BIGNUM *, const BIGNUM *,
										   const BIGNUM *, BN_CTX *);

/* extern pointers (defined in oscam-crypto-openssl.c) */
extern oscam_BN_CTX_new_f       oscam_BN_CTX_new;
extern oscam_BN_CTX_free_f      oscam_BN_CTX_free;
extern oscam_BN_CTX_start_f     oscam_BN_CTX_start;
extern oscam_BN_CTX_end_f       oscam_BN_CTX_end;
extern oscam_BN_CTX_get_f       oscam_BN_CTX_get;

extern oscam_BN_new_f           oscam_BN_new;
extern oscam_BN_free_f          oscam_BN_free;

extern oscam_BN_bin2bn_f        oscam_BN_bin2bn;
extern oscam_BN_bn2bin_f        oscam_BN_bn2bin;

extern oscam_BN_mod_exp_f       oscam_BN_mod_exp;
extern oscam_BN_num_bits_f      oscam_BN_num_bits;
extern oscam_BN_mul_f           oscam_BN_mul;
extern oscam_BN_add_word_f      oscam_BN_add_word;
extern oscam_BN_sub_word_f      oscam_BN_sub_word;
extern oscam_BN_mod_inverse_f   oscam_BN_mod_inverse;

/* wrappers */
static inline BN_CTX *BN_CTX_new_shim(void)
{
	if (!oscam_ossl_crypto_available()) return NULL;
	return oscam_BN_CTX_new ? oscam_BN_CTX_new() : NULL;
}
static inline void BN_CTX_free_shim(BN_CTX *c)
{
	if (!c) return;
	if (!oscam_ossl_crypto_available()) return;
	if (oscam_BN_CTX_free) oscam_BN_CTX_free(c);
}
static inline void BN_CTX_start_shim(BN_CTX *c)
{
	if (!oscam_ossl_crypto_available()) return;
	if (oscam_BN_CTX_start) oscam_BN_CTX_start(c);
}
static inline void BN_CTX_end_shim(BN_CTX *c)
{
	if (!oscam_ossl_crypto_available()) return;
	if (oscam_BN_CTX_end) oscam_BN_CTX_end(c);
}
static inline BIGNUM *BN_CTX_get_shim(BN_CTX *c)
{
	if (!oscam_ossl_crypto_available()) return NULL;
	return oscam_BN_CTX_get ? oscam_BN_CTX_get(c) : NULL;
}

static inline BIGNUM *BN_new_shim(void)
{
	if (!oscam_ossl_crypto_available()) return NULL;
	return oscam_BN_new ? oscam_BN_new() : NULL;
}
static inline void BN_free_shim(BIGNUM *a)
{
	if (!a) return;
	if (!oscam_ossl_crypto_available()) return;
	if (oscam_BN_free) oscam_BN_free(a);
}

static inline BIGNUM *BN_bin2bn_shim(const unsigned char *s, int len, BIGNUM *ret)
{
	if (!oscam_ossl_crypto_available()) return NULL;
	return oscam_BN_bin2bn ? oscam_BN_bin2bn(s, len, ret) : NULL;
}
static inline int BN_bn2bin_shim(const BIGNUM *a, unsigned char *to)
{
	if (!oscam_ossl_crypto_available()) return 0;
	return oscam_BN_bn2bin ? oscam_BN_bn2bin(a, to) : 0;
}
static inline int BN_mod_exp_shim(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
								  const BIGNUM *m, BN_CTX *ctx)
{
	if (!oscam_ossl_crypto_available()) return 0;
	return oscam_BN_mod_exp ? oscam_BN_mod_exp(r, a, p, m, ctx) : 0;
}
static inline int BN_num_bits_shim(const BIGNUM *a)
{
	if (!oscam_ossl_crypto_available()) return 0;
	return oscam_BN_num_bits ? oscam_BN_num_bits(a) : 0;
}
static inline int BN_mul_shim(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
	if (!oscam_ossl_crypto_available()) return 0;
	return oscam_BN_mul ? oscam_BN_mul(r, a, b, ctx) : 0;
}
static inline int BN_add_word_shim(BIGNUM *a, BN_ULONG w)
{
	if (!oscam_ossl_crypto_available()) return 0;
	return oscam_BN_add_word ? oscam_BN_add_word(a, w) : 0;
}
static inline int BN_sub_word_shim(BIGNUM *a, BN_ULONG w)
{
	if (!oscam_ossl_crypto_available()) return 0;
	return oscam_BN_sub_word ? oscam_BN_sub_word(a, w) : 0;
}
static inline BIGNUM *BN_mod_inverse_shim(BIGNUM *ret, const BIGNUM *a,
										  const BIGNUM *n, BN_CTX *ctx)
{
	if (!oscam_ossl_crypto_available()) return NULL;
	return oscam_BN_mod_inverse ? oscam_BN_mod_inverse(ret, a, n, ctx) : NULL;
}

/* map BN APIs */
#define BN_CTX_new        BN_CTX_new_shim
#define BN_CTX_free       BN_CTX_free_shim
#define BN_CTX_start      BN_CTX_start_shim
#define BN_CTX_end        BN_CTX_end_shim
#define BN_CTX_get        BN_CTX_get_shim
#define BN_new            BN_new_shim
#define BN_free           BN_free_shim
#define BN_bin2bn         BN_bin2bn_shim
#define BN_bn2bin         BN_bn2bin_shim
#define BN_mod_exp        BN_mod_exp_shim
#define BN_num_bits       BN_num_bits_shim
#define BN_mul            BN_mul_shim
#define BN_add_word       BN_add_word_shim
#define BN_sub_word       BN_sub_word_shim
#define BN_mod_inverse    BN_mod_inverse_shim

#endif /* WITH_OPENSSL_DLOPEN */

#else  /* !WITH_OPENSSL */

/* ----------------- mbedTLS backend ----------------- */
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
#undef idea_set_encrypt_key
#undef idea_set_decrypt_key
#undef idea_ecb_encrypt
#undef idea_cbc_encrypt
#undef idea_encrypt
#undef idea_cfb64_encrypt
#undef idea_ofb64_encrypt
#undef idea_options
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

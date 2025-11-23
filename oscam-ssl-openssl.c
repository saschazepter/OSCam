#define MODULE_LOG_PREFIX "ssl"

#include "globals.h"
#include "oscam-time.h"
#include "oscam-string.h"
#include "oscam-ssl.h"

#ifdef WITH_SSL

/* ============================================================
 * BACKEND SELECTOR
 * ============================================================ */
#ifdef WITH_OPENSSL
/* ========================= OPENSSL BACKEND ========================== */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/opensslv.h>

#ifdef WITH_OPENSSL_DLOPEN

/* ------------------------------------------------------------------
 * OpenSSL dlopen glue for the SSL backend
 *
 * This reuses the shared lib loader (oscam_ossl_load / oscam_ossl_sym)
 * implemented in oscam-crypto-openssl.c. We only keep function pointers
 * here; library handles and dlopen logic stay in the crypto backend.
 * ------------------------------------------------------------------ */

/* --- function-pointer instances (variables) --- */
DECLARE_OSSL_PTR(SSLv23_server_method,                   oscam_SSLv23_server_method_f);
DECLARE_OSSL_PTR(TLS_server_method,                      oscam_TLS_server_method_f);
DECLARE_OSSL_PTR(TLS_method,                             oscam_TLS_method_f);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
DECLARE_OSSL_PTR(SSL_library_init,                       oscam_SSL_library_init_f);
DECLARE_OSSL_PTR(SSL_load_error_strings,                 oscam_SSL_load_error_strings_f);
DECLARE_OSSL_PTR(OpenSSL_add_all_algorithms,             oscam_OpenSSL_add_all_algorithms_f);
#endif

DECLARE_OSSL_PTR(SSL_CTX_new,                            oscam_SSL_CTX_new_f);
DECLARE_OSSL_PTR(SSL_CTX_free,                           oscam_SSL_CTX_free_f);
DECLARE_OSSL_PTR(SSL_CTX_set_options,                    oscam_SSL_CTX_set_options_f);
DECLARE_OSSL_PTR(SSL_CTX_set_verify,                     oscam_SSL_CTX_set_verify_f);
DECLARE_OSSL_PTR(SSL_CTX_load_verify_locations,          oscam_SSL_CTX_load_verify_locations_f);
DECLARE_OSSL_PTR(SSL_CTX_use_certificate_chain_file,     oscam_SSL_CTX_use_certificate_chain_file_f);
DECLARE_OSSL_PTR(SSL_CTX_use_certificate_file,           oscam_SSL_CTX_use_certificate_file_f);
DECLARE_OSSL_PTR(SSL_CTX_use_PrivateKey_file,            oscam_SSL_CTX_use_PrivateKey_file_f);
DECLARE_OSSL_PTR(SSL_CTX_check_private_key,              oscam_SSL_CTX_check_private_key_f);
DECLARE_OSSL_PTR(SSL_CTX_set_min_proto_version,          oscam_SSL_CTX_set_min_proto_version_f);
DECLARE_OSSL_PTR(SSL_CTX_set_cipher_list,                oscam_SSL_CTX_set_cipher_list_f);
DECLARE_OSSL_PTR(SSL_CTX_set_default_passwd_cb_userdata, oscam_SSL_CTX_set_default_passwd_cb_userdata_f);

DECLARE_OSSL_PTR(SSL_new,                                oscam_SSL_new_f);
DECLARE_OSSL_PTR(SSL_free,                               oscam_SSL_free_f);
DECLARE_OSSL_PTR(SSL_set_fd,                             oscam_SSL_set_fd_f);
DECLARE_OSSL_PTR(SSL_do_handshake,                       oscam_SSL_do_handshake_f);
DECLARE_OSSL_PTR(SSL_accept,                             oscam_SSL_accept_f);
DECLARE_OSSL_PTR(SSL_connect,                            oscam_SSL_connect_f);
DECLARE_OSSL_PTR(SSL_read,                               oscam_SSL_read_f);
DECLARE_OSSL_PTR(SSL_write,                              oscam_SSL_write_f);
DECLARE_OSSL_PTR(SSL_shutdown,                           oscam_SSL_shutdown_f);
DECLARE_OSSL_PTR(SSL_get_error,                          oscam_SSL_get_error_f);
DECLARE_OSSL_PTR(SSL_pending,                            oscam_SSL_pending_f);
DECLARE_OSSL_PTR(SSL_get_verify_result,                  oscam_SSL_get_verify_result_f);
DECLARE_OSSL_PTR(SSL_get_peer_certificate,               oscam_SSL_get_peer_certificate_f);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
DECLARE_OSSL_PTR(CRYPTO_cleanup_all_ex_data,             oscam_CRYPTO_cleanup_all_ex_data_f);
DECLARE_OSSL_PTR(CRYPTO_add,                             oscam_CRYPTO_add_f);
DECLARE_OSSL_PTR(SSLeay_version,                         oscam_SSLeay_version_f);
#else
DECLARE_OSSL_PTR(OpenSSL_version,                        oscam_OpenSSL_version_f);
#endif

DECLARE_OSSL_PTR(ERR_get_error,                          oscam_ERR_get_error_f);
DECLARE_OSSL_PTR(ERR_error_string_n,                     oscam_ERR_error_string_n_f);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
DECLARE_OSSL_PTR(ERR_free_strings,                       oscam_ERR_free_strings_f);
#endif

DECLARE_OSSL_PTR(RAND_bytes,                             oscam_RAND_bytes_f);

/* --- libcrypto function-pointer instances used by SSL backend --- */
DECLARE_OSSL_PTR(EVP_PKEY_new,                           oscam_EVP_PKEY_new_f);
DECLARE_OSSL_PTR(EVP_PKEY_free,                          oscam_EVP_PKEY_free_f);
DECLARE_OSSL_PTR(EVP_PKEY_CTX_new_id,                    oscam_EVP_PKEY_CTX_new_id_f);
DECLARE_OSSL_PTR(EVP_PKEY_keygen_init,                   oscam_EVP_PKEY_keygen_init_f);
DECLARE_OSSL_PTR(EVP_PKEY_CTX_set_rsa_keygen_bits,       oscam_EVP_PKEY_CTX_set_rsa_keygen_bits_f);
DECLARE_OSSL_PTR(EVP_PKEY_keygen,                        oscam_EVP_PKEY_keygen_f);
DECLARE_OSSL_PTR(EVP_PKEY_CTX_new,                       oscam_EVP_PKEY_CTX_new_f);
DECLARE_OSSL_PTR(EVP_PKEY_verify_init,                   oscam_EVP_PKEY_verify_init_f);
DECLARE_OSSL_PTR(EVP_PKEY_CTX_set_signature_md,          oscam_EVP_PKEY_CTX_set_signature_md_f);
DECLARE_OSSL_PTR(EVP_PKEY_verify,                        oscam_EVP_PKEY_verify_f);
DECLARE_OSSL_PTR(EVP_PKEY_CTX_free,                      oscam_EVP_PKEY_CTX_free_f);
DECLARE_OSSL_PTR(EVP_PKEY_bits,                          oscam_EVP_PKEY_bits_f);
DECLARE_OSSL_PTR(EVP_PKEY_dup,                           oscam_EVP_PKEY_dup_f);
DECLARE_OSSL_PTR(EVP_PKEY_base_id,                       oscam_EVP_PKEY_base_id_f);
DECLARE_OSSL_PTR(EVP_PKEY_type,                          oscam_EVP_PKEY_type_f);
DECLARE_OSSL_PTR(EVP_PKEY_get1_RSA,                      oscam_EVP_PKEY_get1_RSA_f);
DECLARE_OSSL_PTR(EVP_PKEY_get1_EC_KEY,                   oscam_EVP_PKEY_get1_EC_KEY_f);

DECLARE_OSSL_PTR(RSA_verify,                             oscam_RSA_verify_f);
DECLARE_OSSL_PTR(RSA_free,                               oscam_RSA_free_f);
DECLARE_OSSL_PTR(ECDSA_verify,                           oscam_ECDSA_verify_f);
DECLARE_OSSL_PTR(EC_KEY_free,                            oscam_EC_KEY_free_f);

DECLARE_OSSL_PTR(X509_new,                               oscam_X509_new_f);
DECLARE_OSSL_PTR(X509_free,                              oscam_X509_free_f);
DECLARE_OSSL_PTR(X509_set_version,                       oscam_X509_set_version_f);
DECLARE_OSSL_PTR(X509_get_serialNumber,                  oscam_X509_get_serialNumber_f);
DECLARE_OSSL_PTR(X509_get_pubkey,                        oscam_X509_get_pubkey_f);
DECLARE_OSSL_PTR(X509_set_pubkey,                        oscam_X509_set_pubkey_f);
DECLARE_OSSL_PTR(X509_get_version,                       oscam_X509_get_version_f);

DECLARE_OSSL_PTR(X509_get_subject_name,                  oscam_X509_get_subject_name_f);
DECLARE_OSSL_PTR(X509_get_issuer_name,                   oscam_X509_get_issuer_name_f);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
DECLARE_OSSL_PTR(X509_getm_notBefore,                    oscam_X509_getm_notBefore_f);
DECLARE_OSSL_PTR(X509_getm_notAfter,                     oscam_X509_getm_notAfter_f);
#else
DECLARE_OSSL_PTR(X509_get_notBefore,                     oscam_X509_get_notBefore_f);
DECLARE_OSSL_PTR(X509_get_notAfter,                      oscam_X509_get_notAfter_f);
#endif
DECLARE_OSSL_PTR(X509_gmtime_adj,                        oscam_X509_gmtime_adj_f);

DECLARE_OSSL_PTR(ASN1_INTEGER_to_BN,                     oscam_ASN1_INTEGER_to_BN_f);
DECLARE_OSSL_PTR(BN_bn2hex,                              oscam_BN_bn2hex_f);
DECLARE_OSSL_PTR(BN_to_ASN1_INTEGER,                     oscam_BN_to_ASN1_INTEGER_f);

DECLARE_OSSL_PTR(X509_NAME_new,                          oscam_X509_NAME_new_f);
DECLARE_OSSL_PTR(X509_NAME_free,                         oscam_X509_NAME_free_f);
DECLARE_OSSL_PTR(X509_NAME_add_entry_by_txt,             oscam_X509_NAME_add_entry_by_txt_f);
DECLARE_OSSL_PTR(X509_set_subject_name,                  oscam_X509_set_subject_name_f);
DECLARE_OSSL_PTR(X509_set_issuer_name,                   oscam_X509_set_issuer_name_f);

DECLARE_OSSL_PTR(X509V3_set_ctx,                         oscam_X509V3_set_ctx_f);
DECLARE_OSSL_PTR(X509V3_EXT_conf_nid,                    oscam_X509V3_EXT_conf_nid_f);
DECLARE_OSSL_PTR(X509_add_ext,                           oscam_X509_add_ext_f);
DECLARE_OSSL_PTR(X509_EXTENSION_free,                    oscam_X509_EXTENSION_free_f);
DECLARE_OSSL_PTR(X509V3_EXT_i2d,                         oscam_X509V3_EXT_i2d_f);

DECLARE_OSSL_PTR(OPENSSL_sk_new_null,                    oscam_OPENSSL_sk_new_null_f);
DECLARE_OSSL_PTR(OPENSSL_sk_push,                        oscam_OPENSSL_sk_push_f);
DECLARE_OSSL_PTR(OPENSSL_sk_pop_free,                    oscam_OPENSSL_sk_pop_free_f);
DECLARE_OSSL_PTR(OPENSSL_free,                           oscam_OPENSSL_free_f);

DECLARE_OSSL_PTR(GENERAL_NAME_new,                       oscam_GENERAL_NAME_new_f);
DECLARE_OSSL_PTR(GENERAL_NAME_free,                      oscam_GENERAL_NAME_free_f);
DECLARE_OSSL_PTR(GENERAL_NAME_set0_value,                oscam_GENERAL_NAME_set0_value_f);

DECLARE_OSSL_PTR(ASN1_IA5STRING_new,                     oscam_ASN1_IA5STRING_new_f);
DECLARE_OSSL_PTR(ASN1_OCTET_STRING_new,                  oscam_ASN1_OCTET_STRING_new_f);
DECLARE_OSSL_PTR(ASN1_OCTET_STRING_set,                  oscam_ASN1_OCTET_STRING_set_f);
DECLARE_OSSL_PTR(ASN1_STRING_set,                        oscam_ASN1_STRING_set_f);

DECLARE_OSSL_PTR(BIO_new,                                oscam_BIO_new_f);
DECLARE_OSSL_PTR(BIO_new_mem_buf,                        oscam_BIO_new_mem_buf_f);
DECLARE_OSSL_PTR(BIO_new_file,                           oscam_BIO_new_file_f);
DECLARE_OSSL_PTR(BIO_s_mem,                              oscam_BIO_s_mem_f);
DECLARE_OSSL_PTR(BIO_free,                               oscam_BIO_free_f);
DECLARE_OSSL_PTR(BIO_read,                               oscam_BIO_read_f);
DECLARE_OSSL_PTR(BIO_ctrl,                               oscam_BIO_ctrl_f);

DECLARE_OSSL_PTR(PEM_read_bio_X509,                      oscam_PEM_read_bio_X509_f);
DECLARE_OSSL_PTR(PEM_write_X509,                         oscam_PEM_write_X509_f);
DECLARE_OSSL_PTR(PEM_write_PrivateKey,                   oscam_PEM_write_PrivateKey_f);
DECLARE_OSSL_PTR(d2i_X509_bio,                           oscam_d2i_X509_bio_f);

DECLARE_OSSL_PTR(ASN1_TIME_print,                        oscam_ASN1_TIME_print_f);
DECLARE_OSSL_PTR(i2d_X509,                               oscam_i2d_X509_f);

DECLARE_OSSL_PTR(X509_STORE_new,                         oscam_X509_STORE_new_f);
DECLARE_OSSL_PTR(X509_STORE_free,                        oscam_X509_STORE_free_f);
DECLARE_OSSL_PTR(X509_STORE_add_cert,                    oscam_X509_STORE_add_cert_f);
DECLARE_OSSL_PTR(X509_STORE_CTX_new,                     oscam_X509_STORE_CTX_new_f);
DECLARE_OSSL_PTR(X509_STORE_CTX_free,                    oscam_X509_STORE_CTX_free_f);
DECLARE_OSSL_PTR(X509_STORE_CTX_init,                    oscam_X509_STORE_CTX_init_f);
DECLARE_OSSL_PTR(X509_verify_cert,                       oscam_X509_verify_cert_f);
DECLARE_OSSL_PTR(X509_sign,                              oscam_X509_sign_f);

DECLARE_OSSL_PTR(X509_NAME_get_index_by_NID,             oscam_X509_NAME_get_index_by_NID_f);
DECLARE_OSSL_PTR(X509_NAME_get_entry,                    oscam_X509_NAME_get_entry_f);
DECLARE_OSSL_PTR(X509_NAME_ENTRY_get_data,               oscam_X509_NAME_ENTRY_get_data_f);
DECLARE_OSSL_PTR(X509_NAME_print_ex,                     oscam_X509_NAME_print_ex_f);
DECLARE_OSSL_PTR(ASN1_STRING_to_UTF8,                    oscam_ASN1_STRING_to_UTF8_f);

/* OpenSSL 3.x does not export BIO_get_mem_data (macro onto BIO_ctrl),
 * so we implement it ourselves on top of BIO_ctrl.
 */
oscam_BIO_get_mem_data_f oscam_BIO_get_mem_data = NULL;
static long oscam_BIO_get_mem_data_impl(BIO *b, char **pp)
{
	if (!oscam_BIO_ctrl)
		return 0;

	return oscam_BIO_ctrl(b, BIO_CTRL_INFO, 0, (void *)pp);
}

/* --- symbol binding using the shared loader --- */
static int oscam_ossl_resolve_ssl_symbols(void)
{
#define RESOLVE_OSSL_SSL_FN_EX(sym, var, type, required)                                  \
	do {                                                                                  \
		/* First try libssl */                                                            \
		var = (type)oscam_ossl_sym(1, #sym);                                              \
		/* Fall back to libcrypto */                                                      \
		if (!(var)) {                                                                     \
			cs_log_dbg(D_TRACE, "OpenSSL: fallback for symbol '%s' to libcrypto", #sym);  \
			var = (type)oscam_ossl_sym(0, #sym);                                          \
		}                                                                                 \
		if (!(var)) {                                                                     \
			if (required) {                                                               \
				cs_log_dbg(D_TRACE, "OpenSSL: required symbol '%s' not found!", #sym);    \
				return 0;                                                                 \
			} else {                                                                      \
				cs_log_dbg(D_TRACE, "OpenSSL: optional symbol '%s' not found", #sym);     \
			}                                                                             \
		}                                                                                 \
	} while (0)

#define RESOLVE_OSSL_SSL_FN(name, type, required)                                         \
	RESOLVE_OSSL_SSL_FN_EX(name, oscam_##name, type, required)

	/* Ensure libcrypto is actually loaded (trigger dlopen if needed) */
	if (!oscam_ossl_crypto_available())
		return 0;

	/* Ensure libssl is loaded (dlopen) */
	if (!oscam_ossl_have_ssl()) {
		if (oscam_ossl_load(1) < 2)
			return 0;
	}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	RESOLVE_OSSL_SSL_FN(SSL_library_init,                       oscam_SSL_library_init_f, 0);
	RESOLVE_OSSL_SSL_FN(SSL_load_error_strings,                 oscam_SSL_load_error_strings_f, 0);
	RESOLVE_OSSL_SSL_FN(OpenSSL_add_all_algorithms,             oscam_OpenSSL_add_all_algorithms_f, 0);
#endif

	/* Server-method resolution (server + generic + legacy) */
	RESOLVE_OSSL_SSL_FN(TLS_server_method,                      oscam_TLS_server_method_f, 0);
	RESOLVE_OSSL_SSL_FN(TLS_method,                             oscam_TLS_method_f, 0);
	RESOLVE_OSSL_SSL_FN(SSLv23_server_method,                   oscam_SSLv23_server_method_f, 0);

	if (!oscam_TLS_server_method &&
		!oscam_TLS_method &&
		!oscam_SSLv23_server_method) {
		cs_log("OpenSSL: No usable TLS server method found in libssl!");
		return 0;
	}

	/* SSL_CTX API */
	RESOLVE_OSSL_SSL_FN(SSL_CTX_new,                            oscam_SSL_CTX_new_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_CTX_free,                           oscam_SSL_CTX_free_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_CTX_set_options,                    oscam_SSL_CTX_set_options_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_CTX_set_verify,                     oscam_SSL_CTX_set_verify_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_CTX_load_verify_locations,          oscam_SSL_CTX_load_verify_locations_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_CTX_use_certificate_chain_file,     oscam_SSL_CTX_use_certificate_chain_file_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_CTX_use_certificate_file,           oscam_SSL_CTX_use_certificate_file_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_CTX_use_PrivateKey_file,            oscam_SSL_CTX_use_PrivateKey_file_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_CTX_check_private_key,              oscam_SSL_CTX_check_private_key_f, 1);

#ifdef SSL_CTX_set_min_proto_version
	RESOLVE_OSSL_SSL_FN(SSL_CTX_set_min_proto_version,          oscam_SSL_CTX_set_min_proto_version_f, 0);
#endif
	RESOLVE_OSSL_SSL_FN(SSL_CTX_set_cipher_list,                oscam_SSL_CTX_set_cipher_list_f, 1);
#ifdef SSL_CTX_set_default_passwd_cb_userdata
	RESOLVE_OSSL_SSL_FN(SSL_CTX_set_default_passwd_cb_userdata, oscam_SSL_CTX_set_default_passwd_cb_userdata_f, 0);
#endif

	/* SSL connection API */
	RESOLVE_OSSL_SSL_FN(SSL_new,                                oscam_SSL_new_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_free,                               oscam_SSL_free_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_set_fd,                             oscam_SSL_set_fd_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_do_handshake,                       oscam_SSL_do_handshake_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_accept,                             oscam_SSL_accept_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_connect,                            oscam_SSL_connect_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_read,                               oscam_SSL_read_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_write,                              oscam_SSL_write_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_shutdown,                           oscam_SSL_shutdown_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_get_error,                          oscam_SSL_get_error_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_pending,                            oscam_SSL_pending_f, 1);
	RESOLVE_OSSL_SSL_FN(SSL_get_verify_result,                  oscam_SSL_get_verify_result_f, 1);

	/* Error helpers */
	RESOLVE_OSSL_SSL_FN(ERR_get_error,                          oscam_ERR_get_error_f, 1);
	RESOLVE_OSSL_SSL_FN(ERR_error_string_n,                     oscam_ERR_error_string_n_f, 1);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	RESOLVE_OSSL_SSL_FN(ERR_free_strings,                       oscam_ERR_free_strings_f, 1);
#endif

	/* Random */
	RESOLVE_OSSL_SSL_FN(RAND_bytes,                             oscam_RAND_bytes_f, 1);

	/* Cleanup helpers for older OpenSSL */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	RESOLVE_OSSL_SSL_FN(CRYPTO_cleanup_all_ex_data,             oscam_CRYPTO_cleanup_all_ex_data_f, 1);
	RESOLVE_OSSL_SSL_FN(CRYPTO_add,                             oscam_CRYPTO_add_f, 1);
	RESOLVE_OSSL_SSL_FN(SSLeay_version,                         oscam_SSLeay_version_f, 1);
#else
	RESOLVE_OSSL_SSL_FN(OpenSSL_version,                        oscam_OpenSSL_version_f, 1);
#endif

	/* EVP_PKEY / RSA / EC / EVP_MD */
	RESOLVE_OSSL_SSL_FN(EVP_PKEY_new,                           oscam_EVP_PKEY_new_f, 1);
	RESOLVE_OSSL_SSL_FN(EVP_PKEY_free,                          oscam_EVP_PKEY_free_f, 1);
	RESOLVE_OSSL_SSL_FN(EVP_PKEY_CTX_new_id,                    oscam_EVP_PKEY_CTX_new_id_f, 1);
	RESOLVE_OSSL_SSL_FN(EVP_PKEY_keygen_init,                   oscam_EVP_PKEY_keygen_init_f, 1);
	RESOLVE_OSSL_SSL_FN(EVP_PKEY_CTX_set_rsa_keygen_bits,       oscam_EVP_PKEY_CTX_set_rsa_keygen_bits_f, 1);
	RESOLVE_OSSL_SSL_FN(EVP_PKEY_keygen,                        oscam_EVP_PKEY_keygen_f, 1);
	RESOLVE_OSSL_SSL_FN(EVP_PKEY_CTX_new,                       oscam_EVP_PKEY_CTX_new_f, 1);
	RESOLVE_OSSL_SSL_FN(EVP_PKEY_verify_init,                   oscam_EVP_PKEY_verify_init_f, 1);
	RESOLVE_OSSL_SSL_FN(EVP_PKEY_CTX_set_signature_md,          oscam_EVP_PKEY_CTX_set_signature_md_f, 1);
	RESOLVE_OSSL_SSL_FN(EVP_PKEY_verify,                        oscam_EVP_PKEY_verify_f, 1);
	RESOLVE_OSSL_SSL_FN(EVP_PKEY_CTX_free,                      oscam_EVP_PKEY_CTX_free_f, 1);
	/* Try EVP_PKEY_bits first (OpenSSL <= 1.1.x may export this) */
	RESOLVE_OSSL_SSL_FN(EVP_PKEY_bits,                          oscam_EVP_PKEY_bits_f, 0);
	/* If EVP_PKEY_bits is not exported, try EVP_PKEY_get_bits (OpenSSL 3.x) */
	if (!oscam_EVP_PKEY_bits) {
		RESOLVE_OSSL_SSL_FN_EX(EVP_PKEY_get_bits,
							oscam_EVP_PKEY_bits,                oscam_EVP_PKEY_bits_f, 1);
	}

	RESOLVE_OSSL_SSL_FN(EVP_PKEY_dup,                           oscam_EVP_PKEY_dup_f, 1);
	RESOLVE_OSSL_SSL_FN(EVP_PKEY_base_id,                       oscam_EVP_PKEY_base_id_f, 1);
	RESOLVE_OSSL_SSL_FN(EVP_PKEY_type,                          oscam_EVP_PKEY_type_f, 1);
	RESOLVE_OSSL_SSL_FN(EVP_PKEY_get1_RSA,                      oscam_EVP_PKEY_get1_RSA_f, 1);
	RESOLVE_OSSL_SSL_FN(EVP_PKEY_get1_EC_KEY,                   oscam_EVP_PKEY_get1_EC_KEY_f, 1);
	RESOLVE_OSSL_SSL_FN(RSA_verify,                             oscam_RSA_verify_f, 1);
	RESOLVE_OSSL_SSL_FN(RSA_free,                               oscam_RSA_free_f, 1);
	RESOLVE_OSSL_SSL_FN(ECDSA_verify,                           oscam_ECDSA_verify_f, 1);
	RESOLVE_OSSL_SSL_FN(EC_KEY_free,                            oscam_EC_KEY_free_f, 1);

	/* X509 / NAME / serial / version */
	RESOLVE_OSSL_SSL_FN(X509_new,                               oscam_X509_new_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_free,                              oscam_X509_free_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_set_version,                       oscam_X509_set_version_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_get_serialNumber,                  oscam_X509_get_serialNumber_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_set_pubkey,                        oscam_X509_set_pubkey_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_get_version,                       oscam_X509_get_version_f, 1);

	RESOLVE_OSSL_SSL_FN(X509_get_subject_name,                  oscam_X509_get_subject_name_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_get_issuer_name,                   oscam_X509_get_issuer_name_f, 1);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	RESOLVE_OSSL_SSL_FN(X509_getm_notBefore,                    oscam_X509_getm_notBefore_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_getm_notAfter,                     oscam_X509_getm_notAfter_f, 1);
#else
	RESOLVE_OSSL_SSL_FN(X509_get_notBefore,                     oscam_X509_get_notBefore_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_get_notAfter,                      oscam_X509_get_notAfter_f, 1);
#endif
	RESOLVE_OSSL_SSL_FN(X509_gmtime_adj,                        oscam_X509_gmtime_adj_f, 1);

	RESOLVE_OSSL_SSL_FN(ASN1_INTEGER_to_BN,                     oscam_ASN1_INTEGER_to_BN_f, 1);
	RESOLVE_OSSL_SSL_FN(BN_bn2hex,                              oscam_BN_bn2hex_f, 1);
	RESOLVE_OSSL_SSL_FN(BN_to_ASN1_INTEGER,                     oscam_BN_to_ASN1_INTEGER_f, 1);

	RESOLVE_OSSL_SSL_FN(X509_NAME_new,                          oscam_X509_NAME_new_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_NAME_free,                         oscam_X509_NAME_free_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_NAME_add_entry_by_txt,             oscam_X509_NAME_add_entry_by_txt_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_set_subject_name,                  oscam_X509_set_subject_name_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_set_issuer_name,                   oscam_X509_set_issuer_name_f, 1);

	RESOLVE_OSSL_SSL_FN(X509V3_set_ctx,                         oscam_X509V3_set_ctx_f, 1);
	RESOLVE_OSSL_SSL_FN(X509V3_EXT_conf_nid,                    oscam_X509V3_EXT_conf_nid_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_add_ext,                           oscam_X509_add_ext_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_EXTENSION_free,                    oscam_X509_EXTENSION_free_f, 1);
	RESOLVE_OSSL_SSL_FN(X509V3_EXT_i2d,                         oscam_X509V3_EXT_i2d_f, 1);

	RESOLVE_OSSL_SSL_FN(OPENSSL_sk_new_null,                    oscam_OPENSSL_sk_new_null_f, 1);
	RESOLVE_OSSL_SSL_FN(OPENSSL_sk_push,                        oscam_OPENSSL_sk_push_f, 1);
	RESOLVE_OSSL_SSL_FN(OPENSSL_sk_pop_free,                    oscam_OPENSSL_sk_pop_free_f, 1);

	RESOLVE_OSSL_SSL_FN(GENERAL_NAME_new,                       oscam_GENERAL_NAME_new_f, 1);
	RESOLVE_OSSL_SSL_FN(GENERAL_NAME_free,                      oscam_GENERAL_NAME_free_f, 1);
	RESOLVE_OSSL_SSL_FN(GENERAL_NAME_set0_value,                oscam_GENERAL_NAME_set0_value_f, 1);

	RESOLVE_OSSL_SSL_FN(ASN1_IA5STRING_new,                     oscam_ASN1_IA5STRING_new_f, 1);
	RESOLVE_OSSL_SSL_FN(ASN1_OCTET_STRING_new,                  oscam_ASN1_OCTET_STRING_new_f, 1);
	RESOLVE_OSSL_SSL_FN(ASN1_OCTET_STRING_set,                  oscam_ASN1_OCTET_STRING_set_f, 1);
	RESOLVE_OSSL_SSL_FN(ASN1_STRING_set,                        oscam_ASN1_STRING_set_f, 1);

	RESOLVE_OSSL_SSL_FN(BIO_new,                                oscam_BIO_new_f, 1);
	RESOLVE_OSSL_SSL_FN(BIO_new_mem_buf,                        oscam_BIO_new_mem_buf_f, 1);
	RESOLVE_OSSL_SSL_FN(BIO_new_file,                           oscam_BIO_new_file_f, 1);
	RESOLVE_OSSL_SSL_FN(BIO_s_mem,                              oscam_BIO_s_mem_f, 1);
	RESOLVE_OSSL_SSL_FN(BIO_free,                               oscam_BIO_free_f, 1);
	RESOLVE_OSSL_SSL_FN(BIO_read,                               oscam_BIO_read_f, 1);

	RESOLVE_OSSL_SSL_FN(PEM_read_bio_X509,                      oscam_PEM_read_bio_X509_f, 1);
	RESOLVE_OSSL_SSL_FN(PEM_write_X509,                         oscam_PEM_write_X509_f, 1);
	RESOLVE_OSSL_SSL_FN(PEM_write_PrivateKey,                   oscam_PEM_write_PrivateKey_f, 1);
	RESOLVE_OSSL_SSL_FN(d2i_X509_bio,                           oscam_d2i_X509_bio_f, 1);

	RESOLVE_OSSL_SSL_FN(ASN1_TIME_print,                        oscam_ASN1_TIME_print_f, 1);
	RESOLVE_OSSL_SSL_FN(i2d_X509,                               oscam_i2d_X509_f, 1);

	RESOLVE_OSSL_SSL_FN(X509_STORE_new,                         oscam_X509_STORE_new_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_STORE_free,                        oscam_X509_STORE_free_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_STORE_add_cert,                    oscam_X509_STORE_add_cert_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_STORE_CTX_new,                     oscam_X509_STORE_CTX_new_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_STORE_CTX_free,                    oscam_X509_STORE_CTX_free_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_STORE_CTX_init,                    oscam_X509_STORE_CTX_init_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_verify_cert,                       oscam_X509_verify_cert_f, 1);

	RESOLVE_OSSL_SSL_FN(X509_NAME_get_index_by_NID,             oscam_X509_NAME_get_index_by_NID_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_NAME_get_entry,                    oscam_X509_NAME_get_entry_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_NAME_ENTRY_get_data,               oscam_X509_NAME_ENTRY_get_data_f, 1);
	RESOLVE_OSSL_SSL_FN(ASN1_STRING_to_UTF8,                    oscam_ASN1_STRING_to_UTF8_f, 1);

	RESOLVE_OSSL_SSL_FN(OPENSSL_free,                           oscam_OPENSSL_free_f, 0);
	if (!oscam_OPENSSL_free) {
		RESOLVE_OSSL_SSL_FN_EX(CRYPTO_free,
							oscam_OPENSSL_free,                 oscam_OPENSSL_free_f, 1);
	}

	RESOLVE_OSSL_SSL_FN(X509_sign,                              oscam_X509_sign_f, 1);

	RESOLVE_OSSL_SSL_FN(SSL_get_peer_certificate,               oscam_SSL_get_peer_certificate_f, 1);

	RESOLVE_OSSL_SSL_FN(X509_get_pubkey,                        oscam_X509_get_pubkey_f, 1);
	RESOLVE_OSSL_SSL_FN(X509_NAME_print_ex,                     oscam_X509_NAME_print_ex_f, 1);
	RESOLVE_OSSL_SSL_FN(BIO_ctrl,                               oscam_BIO_ctrl_f, 1);

	/* We cannot dlsym BIO_get_mem_data on OpenSSL 3.x (macro only),
	 * so we always use our own implementation on top of BIO_ctrl.
	 */
	oscam_BIO_get_mem_data = oscam_BIO_get_mem_data_impl;

#undef RESOLVE_OSSL_SSL_FN_EX
#undef RESOLVE_OSSL_SSL_FN
	return 1;
}

#ifdef WITH_OPENSSL_DLOPEN

static const SSL_METHOD *oscam_ssl_choose_server_method(void)
{
	if (oscam_TLS_server_method)
		return oscam_TLS_server_method();

	if (oscam_TLS_method)
		return oscam_TLS_method();

	if (oscam_SSLv23_server_method)
		return oscam_SSLv23_server_method();

	return NULL;
}

#else  /* !WITH_OPENSSL_DLOPEN */

/* Static-linking path: use compile-time API directly */
static const SSL_METHOD *oscam_ssl_choose_server_method(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	/* OpenSSL 1.1.0+ / 3.x */
	return TLS_server_method();
#else
	/* Very old OpenSSL: SSLv23_server_method */
	return SSLv23_server_method();
#endif
}

#endif /* WITH_OPENSSL_DLOPEN */

#endif /* WITH_OPENSSL_DLOPEN */

/* Some very old OpenSSL releases (0.9.8 / 1.0.0) don't define these.
 * Define them as 0 so SSL_CTX_set_options() still compiles. */
#ifndef SSL_OP_NO_TLSv1_1
#define SSL_OP_NO_TLSv1_1 0
#endif
#ifndef SSL_OP_NO_TLSv1_2
#define SSL_OP_NO_TLSv1_2 0
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* --------------------------------------------------------------------
 * OpenSSL 1.0.2 compatibility: ASN1_TIME_to_tm()
 *
 * OpenSSL < 1.1.0 does not provide ASN1_TIME_to_tm, so we emulate it
 * using ASN1_TIME_print() + sscanf. Format is typically:
 *   "MMM DD HH:MM:SS YYYY GMT"
 * which is stable enough for our "display validity" use-case.
 * ------------------------------------------------------------------ */
static int ASN1_TIME_to_tm(const ASN1_TIME *t, struct tm *tm)
{
	if (!t || !tm)
		return 0;

	BIO *bio = oscam_BIO_new(oscam_BIO_s_mem());
	if (!bio)
		return 0;

	if (oscam_ASN1_TIME_print(bio, (ASN1_TIME *)t) <= 0) {
		oscam_BIO_free(bio);
		return 0;
	}

	char buf[64];
	int len = oscam_BIO_read(bio, buf, sizeof(buf) - 1);
	oscam_BIO_free(bio);

	if (len <= 0)
		return 0;

	buf[len] = '\0';

	/* Expected format: "MMM DD HH:MM:SS YYYY GMT" */
	char mon_str[4] = {0};
	int day = 0, year = 0;
	int hour = 0, min = 0, sec = 0;

	if (sscanf(buf, "%3s %d %d:%d:%d %d",
			   mon_str, &day, &hour, &min, &sec, &year) != 6)
		return 0;

	static const char *months = "JanFebMarAprMayJunJulAugSepOctNovDec";
	char *m = strstr(months, mon_str);
	int mon = 0;
	if (m)
		mon = (int)((m - months) / 3);

	memset(tm, 0, sizeof(*tm));
	tm->tm_year = year - 1900;
	tm->tm_mon  = mon;
	tm->tm_mday = day;
	tm->tm_hour = hour;
	tm->tm_min  = min;
	tm->tm_sec  = sec;

	return 1;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

/* Opaque structs defined here (match header typedefs) */
struct oscam_ssl_conf_s {
	SSL_CTX  *ctx;
	X509     *ca_chain;
	X509     *own_cert;
	EVP_PKEY *own_key;
};

struct oscam_ssl_s {
	SSL *ssl;
	int fd;
};

struct oscam_x509_crt_s {
	X509 *crt;
	struct oscam_x509_crt_s *next;
};

struct oscam_pk_context_s {
	EVP_PKEY *pk;
};

/* --- Opaque alloc helpers --- */

oscam_x509_crt *oscam_ssl_cert_new(void)
{
	oscam_x509_crt *crt = calloc(1, sizeof(*crt));
	if (crt)
		oscam_ssl_cert_init(crt);
	return crt;
}

void oscam_ssl_cert_delete(oscam_x509_crt *crt)
{
	if (!crt) return;
	oscam_ssl_cert_free(crt);
	free(crt);
}

oscam_pk_context *oscam_ssl_pk_new(void)
{
	oscam_pk_context *pk = calloc(1, sizeof(*pk));
	return pk;
}

void oscam_ssl_pk_delete(oscam_pk_context *pk)
{
	if (!pk) return;
	oscam_ssl_pk_free(pk);
	free(pk);
}

/* ============================================================
 * OpenSSL Backend Implementation
 * ============================================================ */

int oscam_ssl_global_init(void)
{
#ifdef WITH_OPENSSL_DLOPEN
	/* Request both libcrypto + libssl from the shared loader */
	if (!oscam_ossl_load(1))
	{
		cs_log("FATAL: OpenSSL backend selected, but runtime libraries could not be loaded (libcrypto/libssl)!");
		cs_exit_oscam();
		return OSCAM_SSL_FATAL;
	}

	if (!oscam_ossl_resolve_ssl_symbols()) {
		cs_log("FATAL: OpenSSL symbol binding failed!");
		cs_exit_oscam();
		return OSCAM_SSL_FATAL;
	}
#endif /* WITH_OPENSSL_DLOPEN */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef WITH_OPENSSL_DLOPEN
	if (oscam_SSL_library_init)
		oscam_SSL_library_init();
	if (oscam_SSL_load_error_strings)
		oscam_SSL_load_error_strings();
	if (oscam_OpenSSL_add_all_algorithms)
		oscam_OpenSSL_add_all_algorithms();
#else
	/* Static-linking path: call OpenSSL directly */
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
#endif
#endif

	return OSCAM_SSL_OK;
}

void oscam_ssl_global_free(void)
{
	/* For older OpenSSL we call only the pieces that are safe.
	 * EVP_cleanup is intentionally left to the crypto side (or skipped). */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	if (oscam_CRYPTO_cleanup_all_ex_data)
		oscam_CRYPTO_cleanup_all_ex_data();
	if (oscam_ERR_free_strings)
		oscam_ERR_free_strings();
#endif

#if defined(WITH_OPENSSL_DLOPEN)
	oscam_ossl_unload();
#endif
}

int oscam_ssl_random(void *buf, size_t len)
{
	if (!buf) return OSCAM_SSL_PARAM;
	if (!oscam_RAND_bytes)
		return OSCAM_SSL_ERR;
	return oscam_RAND_bytes(buf, (int)len) == 1 ? OSCAM_SSL_OK : OSCAM_SSL_ERR;
}

/* SSL Config object */
oscam_ssl_conf_t *oscam_ssl_conf_build(oscam_ssl_mode_t mode)
{
	oscam_ssl_conf_t *conf = calloc(1, sizeof(*conf));
	if (!conf) return NULL;

#ifdef WITH_OPENSSL_DLOPEN
	if (!oscam_SSL_CTX_new)
	{
		free(conf);
		return NULL;
	}
#endif

	const SSL_METHOD *meth = oscam_ssl_choose_server_method();
	if (!meth) {
		free(conf);
		return NULL;
	}

	conf->ctx = oscam_SSL_CTX_new(meth);
	if (!conf->ctx) {
		free(conf);
		return NULL;
	}

	/* Enable ECDHE key exchange support */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L && OPENSSL_VERSION_NUMBER < 0x10100000L
	/* OpenSSL 1.0.2: has SSL_CTX_set_ecdh_auto() */
#ifdef SSL_CTX_set_ecdh_auto
	SSL_CTX_set_ecdh_auto(conf->ctx, 1);
#endif
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(WITH_OPENSSL_DLOPEN)
	/* OpenSSL 1.1.0+ and 3.x: use explicit groups */
	SSL_CTX_set1_groups_list(conf->ctx, "P-256:P-384");
#else
	/* OpenSSL 0.9.8 – 1.0.1: either no ECDHE or configured elsewhere */
	/* nothing */
#endif

#ifdef SSL_CTX_set_min_proto_version
	/* We have SSL_CTX_set_min_proto_version (OpenSSL >= 1.1.0 or compatible) */
# if OPENSSL_VERSION_NUMBER < 0x10100000L
	/* Weird combo: headers define SSL_CTX_set_min_proto_version but OpenSSL is < 1.1.0
	   -> fall back to masking out old protocols, but guard TLSv1.1 symbol. */
	long opts = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
#  ifdef SSL_OP_NO_TLSv1
	opts |= SSL_OP_NO_TLSv1;
#  endif
#  ifdef SSL_OP_NO_TLSv1_1
	opts |= SSL_OP_NO_TLSv1_1;
#  endif
	if (oscam_SSL_CTX_set_options)
		oscam_SSL_CTX_set_options(conf->ctx, opts);
# else
	/* Normal modern case: just require TLS 1.2+ */
	if (oscam_SSL_CTX_set_min_proto_version)
		oscam_SSL_CTX_set_min_proto_version(conf->ctx, TLS1_2_VERSION);
# endif
#else  /* !SSL_CTX_set_min_proto_version */
	/* Old OpenSSL (<= 1.0.x) – only options mask available */
	long opts = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
# ifdef SSL_OP_NO_TLSv1
	opts |= SSL_OP_NO_TLSv1;
# endif
# ifdef SSL_OP_NO_TLSv1_1
	opts |= SSL_OP_NO_TLSv1_1;
# endif
	if (oscam_SSL_CTX_set_options)
		oscam_SSL_CTX_set_options(conf->ctx, opts);
#endif

	switch (mode)
	{
		case OSCAM_SSL_MODE_STRICT:
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
			if (oscam_SSL_CTX_set_cipher_list)
				oscam_SSL_CTX_set_cipher_list(conf->ctx,
					"TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:"
					"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256");
#else
			if (oscam_SSL_CTX_set_cipher_list)
				oscam_SSL_CTX_set_cipher_list(conf->ctx,
					"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
					"DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA");
#endif
			break;

		case OSCAM_SSL_MODE_LEGACY:
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
			if (oscam_SSL_CTX_set_cipher_list)
				oscam_SSL_CTX_set_cipher_list(conf->ctx,
					"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
					"AES256-SHA:AES128-SHA");
#else
			if (oscam_SSL_CTX_set_cipher_list)
				oscam_SSL_CTX_set_cipher_list(conf->ctx,
					"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
					"AES256-SHA:AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA");
#endif
			break;

		default:
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
			if (oscam_SSL_CTX_set_cipher_list)
				oscam_SSL_CTX_set_cipher_list(conf->ctx,
					"TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:"
					"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
					"AES256-SHA:AES128-SHA");
#else
			if (oscam_SSL_CTX_set_cipher_list)
				oscam_SSL_CTX_set_cipher_list(conf->ctx,
					"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
					"AES256-SHA:AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA");
#endif
	}

	if (oscam_SSL_CTX_set_verify)
		oscam_SSL_CTX_set_verify(conf->ctx, SSL_VERIFY_NONE, NULL);
	return conf;
}

void oscam_ssl_conf_free(oscam_ssl_conf_t *conf)
{
	if (!conf) return;
	if (conf->ctx && oscam_SSL_CTX_free)      oscam_SSL_CTX_free(conf->ctx);
	if (conf->own_key)  oscam_EVP_PKEY_free(conf->own_key);
	if (conf->own_cert) oscam_X509_free(conf->own_cert);
	if (conf->ca_chain) oscam_X509_free(conf->ca_chain);
	free(conf);
}

int oscam_ssl_conf_set_min_tls12(oscam_ssl_conf_t *conf)
{
	if (!conf) return OSCAM_SSL_PARAM;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	if (oscam_SSL_CTX_set_options)
		oscam_SSL_CTX_set_options(conf->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
#else
	if (oscam_SSL_CTX_set_min_proto_version)
		oscam_SSL_CTX_set_min_proto_version(conf->ctx, TLS1_2_VERSION);
#endif
	return OSCAM_SSL_OK;
}

/* CA load and cert/key load mirror mbedTLS behavior */
int oscam_ssl_conf_load_ca(oscam_ssl_conf_t *conf, const char *ca_pem_path)
{
	if (!conf) return OSCAM_SSL_PARAM;

	if (!ca_pem_path) {
		if (oscam_SSL_CTX_set_verify)
			oscam_SSL_CTX_set_verify(conf->ctx, SSL_VERIFY_NONE, NULL);
		return OSCAM_SSL_OK;
	}

	if (!oscam_SSL_CTX_load_verify_locations ||
		!oscam_SSL_CTX_load_verify_locations(conf->ctx, ca_pem_path, NULL))
		return OSCAM_SSL_CERT_FAIL;

	if (oscam_SSL_CTX_set_verify)
		oscam_SSL_CTX_set_verify(conf->ctx, SSL_VERIFY_PEER, NULL);
	return OSCAM_SSL_OK;
}

int oscam_ssl_conf_use_own_cert_pem(oscam_ssl_conf_t *conf,
									const char *pem_path,
									const char *key_pass)
{
	if (!conf || !pem_path) return OSCAM_SSL_PARAM;

	if (key_pass && oscam_SSL_CTX_set_default_passwd_cb_userdata)
		oscam_SSL_CTX_set_default_passwd_cb_userdata(conf->ctx, (void*)key_pass);

	if (!oscam_SSL_CTX_use_certificate_chain_file ||
		!oscam_SSL_CTX_use_certificate_chain_file(conf->ctx, pem_path))
		return OSCAM_SSL_CERT_FAIL;

	if (!oscam_SSL_CTX_use_PrivateKey_file ||
		!oscam_SSL_CTX_use_PrivateKey_file(conf->ctx, pem_path, SSL_FILETYPE_PEM))
		return OSCAM_SSL_CERT_FAIL;

	if (!oscam_SSL_CTX_check_private_key ||
		!oscam_SSL_CTX_check_private_key(conf->ctx))
		return OSCAM_SSL_CERT_FAIL;

	return OSCAM_SSL_OK;
}

/* SSL connection */
oscam_ssl_t *oscam_ssl_new(oscam_ssl_conf_t *conf, int fd)
{
	if (!conf || !oscam_SSL_new || !oscam_SSL_set_fd || !oscam_SSL_accept)
		return NULL;

	oscam_ssl_t *ssl = calloc(1, sizeof(*ssl));
	if (!ssl) return NULL;

	ssl->ssl = oscam_SSL_new(conf->ctx);
	ssl->fd = fd;
	oscam_SSL_set_fd(ssl->ssl, fd);

	int ret = oscam_SSL_accept(ssl->ssl);
	if (ret <= 0) {
		oscam_SSL_free(ssl->ssl);
		free(ssl);
		return NULL;
	}

	return ssl;
}

int oscam_ssl_handshake(oscam_ssl_t *ssl)
{
	if (!ssl || !oscam_SSL_do_handshake || !oscam_SSL_get_error)
		return OSCAM_SSL_ERR;

	int ret = oscam_SSL_do_handshake(ssl->ssl);
	if (ret == 1) return OSCAM_SSL_OK;

	int e = oscam_SSL_get_error(ssl->ssl, ret);
	return (e == SSL_ERROR_WANT_READ)  ? OSCAM_SSL_WANT_READ :
		   (e == SSL_ERROR_WANT_WRITE) ? OSCAM_SSL_WANT_WRITE :
										   OSCAM_SSL_HANDSHAKE_FAIL;
}

int oscam_ssl_handshake_blocking(oscam_ssl_t *ssl, int fd, int timeout)
{
	(void)fd;
	(void)timeout;

	return oscam_ssl_handshake(ssl);
}

int oscam_ssl_accept(oscam_ssl_t *ssl, int fd, int timeout)
{
	(void)fd;
	(void)timeout;

	return oscam_ssl_handshake(ssl);
}

/* IO */
int oscam_ssl_read(oscam_ssl_t *ssl, void *buf, size_t len)
{
	if (!ssl || !oscam_SSL_read)
		return OSCAM_SSL_ERR;

	int ret = oscam_SSL_read(ssl->ssl, buf, (int)len);
	if (ret >= 0) return ret;
	return OSCAM_SSL_ERR;
}

int oscam_ssl_write(oscam_ssl_t *ssl, const unsigned char *buf, size_t len)
{
	if (!ssl || !oscam_SSL_write)
		return OSCAM_SSL_ERR;

	size_t done = 0;
	while (done < len) {
		int r = oscam_SSL_write(ssl->ssl, buf + done, (int)(len - done));
		if (r <= 0) return OSCAM_SSL_ERR;
		done += r;
	}
	return (int)done;
}

void oscam_ssl_close_notify(oscam_ssl_t *ssl)
{
	if (!ssl || !oscam_SSL_shutdown)
		return;

	oscam_SSL_shutdown(ssl->ssl);
}

void oscam_ssl_free(oscam_ssl_t *ssl)
{
	if (!ssl) return;
	if (ssl->ssl && oscam_SSL_free)
		oscam_SSL_free(ssl->ssl);
	free(ssl);
}

/* Peer info */
int oscam_ssl_get_peer_cn(oscam_ssl_t *ssl, char *out, size_t outlen)
{
	if (!ssl || !out || !outlen)
		return OSCAM_SSL_PARAM;

	X509 *peer = oscam_SSL_get_peer_certificate(ssl->ssl);
	if (!peer) return OSCAM_SSL_ERR;

	X509_NAME *subj = oscam_X509_get_subject_name(peer);
	int idx = oscam_X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
	if (idx < 0) { oscam_X509_free(peer); return OSCAM_SSL_ERR; }

	X509_NAME_ENTRY *e = oscam_X509_NAME_get_entry(subj, idx);
	ASN1_STRING     *cn = oscam_X509_NAME_ENTRY_get_data(e);
	unsigned char *utf8 = NULL;

	int len = oscam_ASN1_STRING_to_UTF8(&utf8, cn);
	if (len <= 0 || (size_t)len >= outlen) {
		oscam_X509_free(peer);
		return OSCAM_SSL_ERR;
	}

	memcpy(out, utf8, len);
	out[len] = '\0';
	oscam_OPENSSL_free(utf8);
	oscam_X509_free(peer);
	return OSCAM_SSL_OK;
}

const char *oscam_ssl_version(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	return oscam_OpenSSL_version ? oscam_OpenSSL_version(OPENSSL_VERSION) : "OpenSSL (version unknown)";
#else
	return oscam_SSLeay_version ? oscam_SSLeay_version(SSLEAY_VERSION) : "OpenSSL (version unknown)";
#endif
}

/* basic error mapping */
int oscam_ssl_get_error(oscam_ssl_t *ssl, int ret)
{
	(void)ssl;
	(void)ret;

	return OSCAM_SSL_ERR;
}

void oscam_ssl_strerror(int err, char *buf, size_t len)
{
	if (!buf || !len)
		return;

	if (oscam_ERR_error_string_n)
		oscam_ERR_error_string_n((unsigned long)err, buf, len);
	else
		cs_strncpy(buf, "OpenSSL error", len);
}

/* x509 */
int oscam_ssl_cert_parse(oscam_x509_crt *crt,
						 const unsigned char *buf, size_t len)
{
	if (!crt || !buf || len == 0)
		return OSCAM_SSL_PARAM;

	/* Clear any previous chain on this head */
	oscam_ssl_cert_free(crt);

	/* Try PEM chain first */
	BIO *bio = oscam_BIO_new_mem_buf((void *)buf, (int)len);
	if (!bio)
		return OSCAM_SSL_ERR;

	int count = 0;
	oscam_x509_crt *head = crt;
	oscam_x509_crt *tail = head;

	for (;;) {
		X509 *x = oscam_PEM_read_bio_X509(bio, NULL, 0, NULL);
		if (!x)
			break; /* no more PEM certs */

		if (count == 0) {
			/* First cert goes into the head node */
			head->crt  = x;
			head->next = NULL;
			tail       = head;
		} else {
			/* Additional certs get their own wrapper nodes */
			oscam_x509_crt *node = calloc(1, sizeof(*node));
			if (!node) {
				oscam_X509_free(x);
				break; /* out of memory; keep what we already have */
			}
			node->crt  = x;
			node->next = NULL;
			tail->next = node;
			tail       = node;
		}
		count++;
	}

	oscam_BIO_free(bio);

	/* If we parsed at least one PEM cert, we’re done. */
	if (count > 0)
		return OSCAM_SSL_OK;

	/* No PEM? Try a single DER cert. */
	bio = oscam_BIO_new_mem_buf((void *)buf, (int)len);
	if (!bio)
		return OSCAM_SSL_ERR;

	X509 *x = oscam_d2i_X509_bio(bio, NULL);
	oscam_BIO_free(bio);

	if (!x)
		return OSCAM_SSL_CERT_FAIL;

	head->crt  = x;
	head->next = NULL;
	return OSCAM_SSL_OK;
}

int oscam_ssl_cert_parse_file(oscam_x509_crt *crt, const char *path)
{
	if (!crt || !path)
		return OSCAM_SSL_PARAM;

	oscam_ssl_cert_free(crt);

	BIO *bio = oscam_BIO_new_file(path, "rb");
	if (!bio)
		return OSCAM_SSL_CERT_FAIL;

	int count = 0;
	oscam_x509_crt *head = crt;
	oscam_x509_crt *tail = head;

	for (;;) {
		X509 *x = oscam_PEM_read_bio_X509(bio, NULL, 0, NULL);
		if (!x)
			break;

		if (count == 0) {
			head->crt  = x;
			head->next = NULL;
			tail       = head;
		} else {
			oscam_x509_crt *node = calloc(1, sizeof(*node));
			if (!node) {
				oscam_X509_free(x);
				break;
			}
			node->crt  = x;
			node->next = NULL;
			tail->next = node;
			tail       = node;
		}
		count++;
	}

	oscam_BIO_free(bio);

	/* CA bundles are expected to be PEM; if none parsed, fail. */
	return (count > 0) ? OSCAM_SSL_OK : OSCAM_SSL_CERT_FAIL;
}

void oscam_ssl_cert_init(oscam_x509_crt *crt)
{
	if (!crt)
		return;

	crt->crt  = NULL;
	crt->next = NULL;
}

/*
 * Free the whole chain hanging off 'crt', but do NOT free 'crt' itself.
 * That’s handled by oscam_ssl_cert_delete() or by the caller (stack use).
 */
void oscam_ssl_cert_free(oscam_x509_crt *crt)
{
	if (!crt)
		return;

	/* Free X509 in the head node */
	if (crt->crt) {
		oscam_X509_free(crt->crt);
		crt->crt = NULL;
	}

	/* Walk and free any dynamically allocated tail nodes */
	oscam_x509_crt *cur = crt->next;
	crt->next = NULL;

	while (cur) {
		oscam_x509_crt *next = cur->next;
		if (cur->crt)
			oscam_X509_free(cur->crt);
		free(cur);
		cur = next;
	}
}

int oscam_ssl_cert_verify(oscam_x509_crt *crt, oscam_x509_crt *trust)
{
	if (!crt || !trust || !crt->crt || !trust->crt)
		return OSCAM_SSL_PARAM;

	X509_STORE *st = oscam_X509_STORE_new();
	if (!st)
		return OSCAM_SSL_ERR;

	int ret = OSCAM_SSL_ERR;
	if (oscam_X509_STORE_add_cert(st, trust->crt)) {
		X509_STORE_CTX *ctx = oscam_X509_STORE_CTX_new();
		if (ctx) {
			if (oscam_X509_STORE_CTX_init(ctx, st, crt->crt, NULL) == 1 &&
				oscam_X509_verify_cert(ctx) == 1) {
				ret = OSCAM_SSL_OK;
			} else {
				ret = OSCAM_SSL_CERT_FAIL;
			}
			oscam_X509_STORE_CTX_free(ctx);
		}
	}

	oscam_X509_STORE_free(st);
	return ret;
}

oscam_x509_crt *oscam_ssl_cert_get_next(oscam_x509_crt *crt)
{
	if (!crt)
		return NULL;
	return crt->next;
}

const void *oscam_ssl_cert_get_subject(const oscam_x509_crt *crt)
{
	if (!crt || !crt->crt) return NULL;
	return oscam_X509_get_subject_name(crt->crt);
}

const void *oscam_ssl_cert_get_issuer(const oscam_x509_crt *crt)
{
	if (!crt || !crt->crt) return NULL;
	return (const void *)oscam_X509_get_issuer_name(crt->crt);
}

int oscam_ssl_cert_dn_gets(char *buf, size_t size, const void *dn)
{
	if (!buf || size == 0 || !dn)
		return OSCAM_SSL_ERR;

	buf[0] = '\0';

	BIO *bio = oscam_BIO_new(oscam_BIO_s_mem());
	if (!bio)
		return OSCAM_SSL_ERR;

	/* OpenSSL 0.9.8 – 3.x compatible print */
	if (oscam_X509_NAME_print_ex(bio, (X509_NAME *)dn, 0, XN_FLAG_RFC2253) < 0)
	{
		oscam_BIO_free(bio);
		return OSCAM_SSL_ERR;
	}

	char *ptr = NULL;
	long len = oscam_BIO_get_mem_data(bio, &ptr);

	if (len > 0) {
		size_t copy = (len < (long)size - 1) ? (size_t)len : size - 1;
		memcpy(buf, ptr, copy);
		buf[copy] = '\0';
	}

	oscam_BIO_free(bio);
	return OSCAM_SSL_OK;
}

void oscam_ssl_cert_serial_gets(const oscam_x509_crt *crt, char *buf, size_t len)
{
	if (!crt || !crt->crt || !buf || !len) return;
	ASN1_INTEGER *serial = oscam_X509_get_serialNumber(crt->crt);
	BIGNUM *bn = oscam_ASN1_INTEGER_to_BN(serial, NULL);
	char *hex = oscam_BN_bn2hex(bn);
	cs_strncpy(buf, hex, len);
	oscam_OPENSSL_free(hex);
	oscam_BN_free(bn);
}

int oscam_ssl_cert_get_version(const oscam_x509_crt *crt)
{
	if (!crt || !crt->crt) return -1;
	/* X509 version is 0-based; convert to human numbering */
	long ver = oscam_X509_get_version(crt->crt);
	return (int)ver + 1;
}

void oscam_ssl_cert_raw(const oscam_x509_crt *crt,
						const unsigned char **buf, size_t *len)
{
	if (!buf || !len)
		return;

	if (!crt || !crt->crt) {
		*buf = NULL;
		*len = 0;
		return;
	}

	/* We need to re-encode DER (OpenSSL stores ASN.1 internally) */
	int l = oscam_i2d_X509(crt->crt, NULL);
	if (l <= 0) {
		*buf = NULL;
		*len = 0;
		return;
	}

	unsigned char *tmp = malloc(l);
	if (!tmp) {
		*buf = NULL;
		*len = 0;
		return;
	}

	unsigned char *p = tmp;
	l = oscam_i2d_X509(crt->crt, &p);

	*buf = tmp;
	*len = (size_t)l;
}

/* ----------------- VALIDITY INFO ----------------- */
void oscam_ssl_cert_get_validity(const oscam_x509_crt *crt, oscam_cert_time_t *from, oscam_cert_time_t *to)
{
	if (!crt || !crt->crt || !from || !to)
		return;

	const ASN1_TIME *nb;
	const ASN1_TIME *na;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	nb = oscam_X509_getm_notBefore(crt->crt);
	na = oscam_X509_getm_notAfter(crt->crt);
#else
	nb = oscam_X509_get_notBefore(crt->crt);
	na = oscam_X509_get_notAfter(crt->crt);
#endif

	struct tm tm_from, tm_to;
	memset(&tm_from, 0, sizeof(tm_from));
	memset(&tm_to,   0, sizeof(tm_to));

	/* Convert ASN1_TIME → struct tm */
	ASN1_TIME_to_tm(nb, &tm_from);
	ASN1_TIME_to_tm(na, &tm_to);

	/* Fill our simple struct */
	from->year = tm_from.tm_year + 1900;
	from->mon  = tm_from.tm_mon  + 1;
	from->day  = tm_from.tm_mday;
	from->hour = tm_from.tm_hour;
	from->min  = tm_from.tm_min;
	from->sec  = tm_from.tm_sec;

	to->year = tm_to.tm_year + 1900;
	to->mon  = tm_to.tm_mon  + 1;
	to->day  = tm_to.tm_mday;
	to->hour = tm_to.tm_hour;
	to->min  = tm_to.tm_min;
	to->sec  = tm_to.tm_sec;
}

int oscam_ssl_pk_get_bits(const oscam_pk_context *pk)
{
	if (!pk || !pk->pk) return 0;
	return oscam_EVP_PKEY_bits(pk->pk);
}

/* ----------------- KEY LENGTH ----------------- */
int oscam_ssl_pk_get_bitlen(const oscam_pk_context *pk)
{
	if (!pk || !pk->pk) return 0;
	return oscam_EVP_PKEY_bits(pk->pk);
}

const oscam_pk_context *oscam_ssl_cert_get_pubkey(const oscam_x509_crt *crt)
{
	if (!crt || !crt->crt) return NULL;
	EVP_PKEY *pk = oscam_X509_get_pubkey(crt->crt);
	if (!pk) return NULL;

	oscam_pk_context *wrap = calloc(1, sizeof(*wrap));
	if (!wrap) {
		oscam_EVP_PKEY_free(pk);
		return NULL;
	}
	wrap->pk = pk;
	return wrap;
}

void oscam_ssl_pk_free(oscam_pk_context *pk)
{
	if (!pk) return;
	if (pk->pk)
		oscam_EVP_PKEY_free(pk->pk);
	pk->pk = NULL;
}

int oscam_ssl_pk_clone(oscam_pk_context *dst, const oscam_pk_context *src)
{
	if (!dst || !src || !src->pk)
		return OSCAM_SSL_PARAM;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	if (!oscam_CRYPTO_add)
		return OSCAM_SSL_ERR;
	oscam_CRYPTO_add(&((EVP_PKEY *)src->pk)->references, 1, CRYPTO_LOCK_EVP_PKEY);
	dst->pk = src->pk;
#else
	dst->pk = oscam_EVP_PKEY_dup(src->pk);
#endif
	return dst->pk ? OSCAM_SSL_OK : OSCAM_SSL_ERR;
}

int oscam_ssl_pk_get_type(const oscam_pk_context *pk)
{
	if (!pk || !pk->pk)
		return OSCAM_PK_NONE;

	/* ================================================================
	 * OpenSSL 3.0+ — no deprecated APIs, rely only on base ID
	 * ================================================================ */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	int id = oscam_EVP_PKEY_base_id(pk->pk);
	switch (id) {
		case EVP_PKEY_RSA: return OSCAM_PK_RSA;
		case EVP_PKEY_EC:  return OSCAM_PK_EC;
		default:           return OSCAM_PK_NONE;
	}

	/* ================================================================
	 * OpenSSL 1.1.0 – 1.1.1 — EVP_PKEY_base_id available
	 * ================================================================ */
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L

	int id = oscam_EVP_PKEY_base_id(pk->pk);
	switch (id) {
		case EVP_PKEY_RSA: return OSCAM_PK_RSA;
		case EVP_PKEY_EC:  return OSCAM_PK_EC;
		default: break;
	}

	return OSCAM_PK_NONE;

	/* ================================================================
	 * OpenSSL 0.9.8 – 1.0.2 — no base_id, must rely on EVP_PKEY_type
	 * + safe probing with RSA_get/EC_get
	 * ================================================================ */
#else

	int id = oscam_EVP_PKEY_type(pk->pk->type);
	if (id == EVP_PKEY_RSA)
		return OSCAM_PK_RSA;

# ifdef EVP_PKEY_EC
	if (id == EVP_PKEY_EC)
		return OSCAM_PK_EC;
# endif

	/* --- Fallback probing ONLY on old OpenSSL --- */
	RSA *rsa = oscam_EVP_PKEY_get1_RSA(pk->pk);
	if (rsa) {
		oscam_RSA_free(rsa);
		return OSCAM_PK_RSA;
	}

# ifdef EVP_PKEY_EC
	EC_KEY *ec = oscam_EVP_PKEY_get1_EC_KEY(pk->pk);
	if (ec) {
		oscam_EC_KEY_free(ec);
		return OSCAM_PK_EC;
	}
# endif

	return OSCAM_PK_NONE;

#endif
}

int oscam_ssl_pk_verify(oscam_pk_context *pk,
						const unsigned char *hash, size_t hash_len,
						const unsigned char *sig,  size_t sig_len)
{
	if (!pk || !pk->pk || !hash || !sig)
		return -1;

	EVP_PKEY *pkey = pk->pk;

	/* ================================================================
	 * Modern EVP_PKEY path (OpenSSL >= 1.0.2)
	 *   - used on 1.0.2, 1.1.x and 3.x+
	 *   - treats `hash` as already-digested SHA-256
	 * ================================================================ */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L

	const EVP_MD *md = oscam_EVP_sha256();
	EVP_PKEY_CTX *ctx = oscam_EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx)
		return -1;

	int ok  = 1;
	int ret = -1;

	/* Initialize verification context */
	if (ok) ok = (oscam_EVP_PKEY_verify_init(ctx) > 0);

	/* Configure signature to use SHA256 digest (but DO NOT hash `hash` again) */
	if (ok && md) ok = (oscam_EVP_PKEY_CTX_set_signature_md(ctx, md) > 0);

	/* EVP_PKEY_verify() takes the precomputed digest directly */
	if (ok)
		ret = oscam_EVP_PKEY_verify(ctx, sig, sig_len, hash, hash_len);

	oscam_EVP_PKEY_CTX_free(ctx);
	return (ret == 1) ? 0 : -1;

#else /* OPENSSL_VERSION_NUMBER < 0x10002000L */

/* ================================================================
 * Legacy path: OpenSSL 0.9.8 – 1.0.1
 *   - RSA_verify / ECDSA_verify expect precomputed digest
 * ================================================================ */

	/* Try RSA first */
	RSA *rsa = oscam_EVP_PKEY_get1_RSA(pkey);
	if (rsa) {
		int ok = oscam_RSA_verify(NID_sha256,
							hash, (unsigned int)hash_len,
							(unsigned char *)sig, (unsigned int)sig_len,
							rsa);
		oscam_RSA_free(rsa);
		return ok == 1 ? 0 : -1;
	}

# ifdef EVP_PKEY_EC
	/* Then EC */
	EC_KEY *eckey = oscam_EVP_PKEY_get1_EC_KEY(pkey);
	if (eckey) {
		int ok = oscam_ECDSA_verify(0,
							  hash, (int)hash_len,
							  sig,  (int)sig_len,
							  eckey);
		oscam_EC_KEY_free(eckey);
		return ok == 1 ? 0 : -1;
	}
# endif

	return -1;

#endif /* version split */
}

static void oscam_sk_GENERAL_NAME_free_cb(void *p)
{
	if (!p)
		return;
	oscam_GENERAL_NAME_free((GENERAL_NAME *)p);
}

int oscam_ssl_generate_selfsigned(const char *path)
{
	int ret = OSCAM_SSL_ERR;
	EVP_PKEY *pkey = NULL;
	X509 *crt = NULL;
	FILE *f = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_PKEY_CTX *kctx = NULL;
#else
	RSA *rsa = NULL;
#endif

	struct utsname un;
	const char *cn;
	char subject[256];
	time_t now = time(NULL);
	struct tm start_tm, end_tm;

	if (!path || !*path)
		return OSCAM_SSL_ERR;

	/* ---- Create empty PKEY ---- */
	pkey = oscam_EVP_PKEY_new();
	if (!pkey)
		goto cleanup;

	/* ===============================================
	 * KEY GENERATION
	 * =============================================== */

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

	/* ---- OpenSSL 3.x (modern API only) ---- */
	kctx = oscam_EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!kctx)
		goto cleanup;

	if (oscam_EVP_PKEY_keygen_init(kctx) <= 0)
		goto cleanup;
	if (oscam_EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 4096) <= 0)
		goto cleanup;
	if (oscam_EVP_PKEY_keygen(kctx, &pkey) <= 0)
		goto cleanup;

	oscam_EVP_PKEY_CTX_free(kctx);
	kctx = NULL;

#else /* OPENSSL_VERSION_NUMBER < 0x30000000L */

	/* ---- Legacy OpenSSL (<3.0) ----
	 * Works on 0.9.8 .. 1.0.x .. 1.1.x
	 */
	BIGNUM *e = BN_new();
	if (!e)
		goto cleanup;

	if (!BN_set_word(e, RSA_F4)) {
		BN_free(e);
		goto cleanup;
	}

	rsa = RSA_new();
	if (!rsa) {
		BN_free(e);
		goto cleanup;
	}

	if (!RSA_generate_key_ex(rsa, 4096, e, NULL)) {
		BN_free(e);
		goto cleanup;
	}
	BN_free(e);

	if (!pkey) {
		pkey = EVP_PKEY_new();
		if (!pkey) {
			RSA_free(rsa);
			rsa = NULL;
			goto cleanup;
		}
	}

	if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
		RSA_free(rsa);
		rsa = NULL;
		goto cleanup;
	}

	rsa = NULL; /* ownership transferred to pkey */

#endif /* OPENSSL_VERSION_NUMBER */

	/* ===============================================
	 * CERTIFICATE BUILD
	 * =============================================== */

	crt = oscam_X509_new();
	if (!crt) goto cleanup;

	oscam_X509_set_version(crt, 2);

	/* Serial random */
	{
		unsigned char serial_bytes[16];
		ASN1_INTEGER *serial = oscam_X509_get_serialNumber(crt);
		BIGNUM *bn;

		if (!oscam_RAND_bytes ||
			oscam_RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1)
			goto cleanup;

		bn = oscam_BN_bin2bn(serial_bytes, sizeof(serial_bytes), NULL);
		if (!bn || !oscam_BN_to_ASN1_INTEGER(bn, serial)) {
			oscam_BN_free(bn);
			goto cleanup;
		}
		oscam_BN_free(bn);
	}

	/* Validity */
	gmtime_r(&now, &start_tm);
	end_tm = start_tm;
	end_tm.tm_year += OSCAM_SSL_CERT_YEARS;

	#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		if (!oscam_X509_gmtime_adj(oscam_X509_getm_notBefore(crt), 0))
			goto cleanup;
		if (!oscam_X509_gmtime_adj(
				oscam_X509_getm_notAfter(crt),
				(long)3600 * 24 * 365 * OSCAM_SSL_CERT_YEARS))
			goto cleanup;
	#else
		if (!oscam_X509_gmtime_adj(oscam_X509_get_notBefore(crt), 0))
			goto cleanup;
		if (!oscam_X509_gmtime_adj(
				oscam_X509_get_notAfter(crt),
				(long)3600 * 24 * 365 * OSCAM_SSL_CERT_YEARS))
			goto cleanup;
	#endif

	if (!oscam_X509_set_pubkey(crt, pkey))
		goto cleanup;

	/* Subject CN */
	if (uname(&un) == 0 && un.nodename[0])
		cn = un.nodename;
	else
		cn = "localhost";

	snprintf(subject, sizeof(subject),
			 "CN=%s,O=OSCam AutoCert,OU=Private WebIf Certificate", cn);

	X509_NAME *name = oscam_X509_NAME_new();
	if (!name) goto cleanup;

	oscam_X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
							   (const unsigned char*)cn, -1, -1, 0);
	oscam_X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
							   (unsigned char*)"OSCam AutoCert", -1, -1, 0);
	oscam_X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,
							   (unsigned char*)"Private WebIf Certificate", -1, -1, 0);

	oscam_X509_set_subject_name(crt, name);
	oscam_X509_set_issuer_name(crt, name);
	oscam_X509_NAME_free(name);

	/* Extensions */
	{
		X509V3_CTX ctx;
		X509V3_set_ctx_nodb(&ctx);
		oscam_X509V3_set_ctx(&ctx, crt, crt, NULL, NULL, 0);

		X509_EXTENSION *ext;

		ext = oscam_X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE");
		if (ext) { oscam_X509_add_ext(crt, ext, -1); oscam_X509_EXTENSION_free(ext); }

		ext = oscam_X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage,
								  "digitalSignature,keyEncipherment");
		if (ext) { oscam_X509_add_ext(crt, ext, -1); oscam_X509_EXTENSION_free(ext); }

		ext = oscam_X509V3_EXT_conf_nid(NULL, &ctx, NID_netscape_cert_type, "server");
		if (ext) { oscam_X509_add_ext(crt, ext, -1); oscam_X509_EXTENSION_free(ext); }
	}

	/* SAN */
	{
		GENERAL_NAMES *gens = (GENERAL_NAMES *)oscam_OPENSSL_sk_new_null();
		GENERAL_NAME *gn;
		X509_EXTENSION *ext;

		/* DNS: CN */
		gn = oscam_GENERAL_NAME_new();
		ASN1_IA5STRING *dns1 = oscam_ASN1_IA5STRING_new();
		oscam_ASN1_STRING_set(dns1, cn, strlen(cn));
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		oscam_GENERAL_NAME_set0_value(gn, GEN_DNS, dns1);
#else
		/* OpenSSL 1.0.2 and below: only manual setting */
		gn->type = GEN_DNS;
		gn->d.ia5 = ASN1_IA5STRING_new();
		ASN1_STRING_set(gn->d.ia5, cn, strlen(cn));
#endif
		oscam_OPENSSL_sk_push((void*)gens, gn);

		/* DNS: CN.local */
		char buf[256];
		snprintf(buf, sizeof(buf), "%s.local", cn);
		gn = oscam_GENERAL_NAME_new();
		ASN1_IA5STRING *dns2 = oscam_ASN1_IA5STRING_new();
		oscam_ASN1_STRING_set(dns2, buf, strlen(buf));
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		oscam_GENERAL_NAME_set0_value(gn, GEN_DNS, dns2);
#else
		/* OpenSSL 1.0.2 and below: only manual setting */
		gn->type = GEN_DNS;
		gn->d.ia5 = ASN1_IA5STRING_new();
		ASN1_STRING_set(gn->d.ia5, buf, strlen(buf));
#endif
		oscam_OPENSSL_sk_push((void*)gens, gn);

		/* IPv4 127.0.0.1 */
		gn = oscam_GENERAL_NAME_new();
		{
			unsigned char ip4[4] = {127,0,0,1};
			ASN1_OCTET_STRING *ip = oscam_ASN1_OCTET_STRING_new();
			oscam_ASN1_OCTET_STRING_set(ip, ip4, 4);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
			oscam_GENERAL_NAME_set0_value(gn, GEN_IPADD, ip);
#else
			/* OpenSSL 1.0.2 and below: manual GEN_IPADD with OCTET_STRING */
			gn->type   = GEN_IPADD;
			gn->d.ip   = ip;    /* note: union field is 'ip' in older OpenSSL */
			/* do NOT free 'ip' separately; GENERAL_NAME_free() will own it */
#endif
			oscam_OPENSSL_sk_push((void*)gens, gn);
		}

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
		/* IPv6 ::1 */
		gn = oscam_GENERAL_NAME_new();
		{
			unsigned char ip6[16] = {0};
			ip6[15] = 1;
			ASN1_OCTET_STRING *ipx = oscam_ASN1_OCTET_STRING_new();
			oscam_ASN1_OCTET_STRING_set(ipx, ip6, 16);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
			oscam_GENERAL_NAME_set0_value(gn, GEN_IPADD, ipx);
#else
			gn->type = GEN_IPADD;
			gn->d.ip = ipx;
#endif
			oscam_OPENSSL_sk_push((void*)gens, gn);
		}
#else
		cs_log("OpenSSL: IPv6 SAN skipped (OpenSSL < 1.0.2)");
#endif

		ext = oscam_X509V3_EXT_i2d(NID_subject_alt_name, 0, gens);
		if (ext) {
			oscam_X509_add_ext(crt, ext, -1);
			oscam_X509_EXTENSION_free(ext);
		}
		oscam_OPENSSL_sk_pop_free((_STACK *)gens, oscam_sk_GENERAL_NAME_free_cb);
	}

	/* Sign cert */
	if (!oscam_X509_sign(crt, pkey, oscam_EVP_sha256())) {
		if (!oscam_X509_sign(crt, pkey, EVP_sha1()))
			goto cleanup;
	}

	/* Write PEM (cert + key) */
	f = fopen(path, "wb");
	if (!f) goto cleanup;

	if (!oscam_PEM_write_X509(f, crt))
		goto cleanup;
	if (!oscam_PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL))
		goto cleanup;

	ret = OSCAM_SSL_OK;

cleanup:
	if (crt) oscam_X509_free(crt);
	if (pkey) oscam_EVP_PKEY_free(pkey);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (kctx) oscam_EVP_PKEY_CTX_free(kctx);
#else
	if (rsa) oscam_RSA_free(rsa);
#endif

	if (f) fclose(f);
	return ret;
}

int oscam_ssl_get_fd(oscam_ssl_t *ssl)
{
	return ssl ? ssl->fd : -1;
}

int oscam_ssl_pending(oscam_ssl_t *ssl)
{
	if (!ssl || !ssl->ssl || !oscam_SSL_pending) return 0;
	return oscam_SSL_pending(ssl->ssl);
}

#endif /* WITH_OPENSSL */

#endif /* WITH_SSL */

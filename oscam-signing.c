#define MODULE_LOG_PREFIX "signing"

#include "globals.h"
#include "oscam-signing.h"
#include "oscam-string.h"
#include "oscam-time.h"
#include "oscam-files.h"

extern char *config_cert;
struct o_sign_info osi;

static void hex_encode(const unsigned char *readbuf, void *writebuf, size_t len)
{
	char *out = (char *)writebuf;
	size_t i;

	for (i = 0; i < len; i++)
	{
		/* 3 = two hex digits + null terminator (overwritten next iteration) */
		snprintf(out + (i * 2), 3, "%02x", readbuf[i]);
	}

	out[len * 2] = '\0';
}

static char* cert_dn_to_str(const void *dn)
{
	if (!dn) return cs_strdup("");
	char buf[256];
	if (oscam_ssl_cert_dn_gets(buf, sizeof(buf), dn) != OSCAM_SSL_OK)
		return cs_strdup("");
	return cs_strdup(buf);
}

static void format_cert_time(const oscam_cert_time_t *t, char *buf, size_t len)
{
	struct tm tmv;
	memset(&tmv, 0, sizeof(tmv));
	tmv.tm_year = t->year - 1900;
	tmv.tm_mon  = t->mon  - 1;
	tmv.tm_mday = t->day;
	tmv.tm_hour = t->hour;
	tmv.tm_min  = t->min;
	tmv.tm_sec  = t->sec;
	strftime(buf, len, "%d.%m.%Y %H:%M:%S", &tmv);
}

static bool issuer_in_system_store(const char *issuer_dn)
{
	if (!issuer_dn || !*issuer_dn)
		return false;

	char system_ca_file[MAX_LEN];
	snprintf(system_ca_file, sizeof(system_ca_file), "%s/%s",
			 CA_SYSTEM_LOCATION, CA_FILE_NAME);

	oscam_x509_crt *sys = oscam_ssl_cert_new();
	if (!sys)
		return false;

	if (oscam_ssl_cert_parse_file(sys, system_ca_file) != OSCAM_SSL_OK)
	{
		oscam_ssl_cert_delete(sys);
		return false;
	}

	bool found = false;
	for (const oscam_x509_crt *c = sys; c != NULL; c = oscam_ssl_cert_get_next((oscam_x509_crt *)c))
	{
		char dn[512];
		if (oscam_ssl_cert_dn_gets(dn, sizeof(dn), oscam_ssl_cert_get_subject(c)) != OSCAM_SSL_OK)
			continue;

		if (strcmp(dn, issuer_dn) == 0)
		{
			found = true;
			break;
		}
	}

	oscam_ssl_cert_delete(sys);
	return found;
}

static oscam_pk_context *verify_cert(void)
{
	int ret;
	oscam_x509_crt *crt = oscam_ssl_cert_new();
	if (!crt)
		return NULL;

	ret = oscam_ssl_cert_parse(crt,
	                           (const unsigned char *)config_cert,
	                           strlen(config_cert) + 1);
	if (ret != OSCAM_SSL_OK)
	{
		char estr[128];
		oscam_ssl_strerror(ret, estr, sizeof(estr));
		cs_log("Error: unable to parse built-in certificate (%s)", estr);
		oscam_ssl_cert_delete(crt);
		return NULL;
	}

	/* ---- Certificate information ---- */

	osi.cert_version = oscam_ssl_cert_get_version(crt);

	oscam_cert_time_t vfrom, vto;
	oscam_ssl_cert_get_validity(crt, &vfrom, &vto);

	format_cert_time(&vfrom, osi.cert_valid_from, sizeof(osi.cert_valid_from));
	format_cert_time(&vto,   osi.cert_valid_to,   sizeof(osi.cert_valid_to));

	time_t now = time(NULL);
	struct tm lt;
	memset(&lt, 0, sizeof(lt));
	localtime_r(&now, &lt);

	osi.cert_is_expired =
		(vto.year <  lt.tm_year + 1900) ||
		(vto.year == lt.tm_year + 1900 && vto.mon < lt.tm_mon + 1);

	/* Serial */
	char serial_hex[128];
	oscam_ssl_cert_serial_gets(crt, serial_hex, sizeof(serial_hex));
	osi.cert_serial = cs_strdup(strtolower(serial_hex));

	/* Fingerprint (SHA-1 of raw DER) */
	const unsigned char *der = NULL;
	size_t der_len = 0;
	oscam_ssl_cert_raw(crt, &der, &der_len);

	if (der && der_len > 0)
	{
		unsigned char fp[SHA_DIGEST_LENGTH];
		oscam_ssl_sha1(der, der_len, fp);
		char fphex[2 * SHA_DIGEST_LENGTH + 1];
		hex_encode(fp, fphex, SHA_DIGEST_LENGTH);
		osi.cert_fingerprint = cs_strdup(strtolower(fphex));
	}
	else
	{
		osi.cert_fingerprint = cs_strdup("");
	}

	/* Subject / issuer */
	osi.cert_subject = cert_dn_to_str(oscam_ssl_cert_get_subject(crt));
	osi.cert_issuer  = cert_dn_to_str(oscam_ssl_cert_get_issuer(crt));
	osi.cert_is_cacert       = strcmp(osi.cert_subject, osi.cert_issuer) != 0;
	osi.cert_is_valid_self   = false;
	osi.cert_is_valid_system = false;
	osi.cert_is_internal_ca  = false;

	/* Parse the full built-in certificate chain (one or more PEM blocks) */
	oscam_x509_crt *chain = oscam_ssl_cert_new();
	if (chain)
	{
		int rself = oscam_ssl_cert_parse(chain,
		                                 (const unsigned char *)config_cert,
		                                 strlen(config_cert) + 1);
		if (rself == OSCAM_SSL_OK)
		{
			/* The first cert in the chain is our leaf (signing cert).
			   Any additional certs in the same PEM block become next, next->next, etc. */
			oscam_x509_crt *crt_leaf   = chain;
			oscam_x509_crt *trust_self = oscam_ssl_cert_get_next(crt_leaf);

			if (trust_self) {
				int vr = oscam_ssl_cert_verify(crt_leaf, trust_self);
				if (vr == OSCAM_SSL_OK) {
					osi.cert_is_valid_self = true;
				}
			}
		}
		oscam_ssl_cert_delete(chain);
	}

	/* If not trusted by the built-in chain, try system CA bundle */
	if (!osi.cert_is_valid_self)
	{
		char system_ca_file[MAX_LEN];
		const char *ca_path = NULL;

		snprintf(system_ca_file, sizeof(system_ca_file), "%s/%s",
		         CA_SYSTEM_LOCATION, CA_FILE_NAME);

		if (!file_exists(system_ca_file)) {
			ca_path = getenv("SSL_CERT_DIR");
			if (!ca_path)
				ca_path = "/etc/ssl/certs";

			snprintf(system_ca_file, sizeof(system_ca_file), "%s/%s",
			         ca_path, CA_FILE_NAME);
		}

		if (cs_malloc(&osi.system_ca_file, cs_strlen(system_ca_file) + 1)) {
			cs_strncpy(osi.system_ca_file, system_ca_file,
			           cs_strlen(system_ca_file) + 1);
		}

		oscam_x509_crt *trust_sys = oscam_ssl_cert_new();
		if (trust_sys)
		{
			int rsys = oscam_ssl_cert_parse_file(trust_sys, system_ca_file);
			if (rsys == OSCAM_SSL_OK) {
				int vr = oscam_ssl_cert_verify(crt, trust_sys);
				if (vr == OSCAM_SSL_OK)
					osi.cert_is_valid_system = true;
			}
			else {
				cs_log("Error: unable to load CA bundle from %s", system_ca_file);
			}
			oscam_ssl_cert_delete(trust_sys);
		}
	}

	if (osi.cert_is_valid_self && !osi.cert_is_valid_system)
	{
		if (!issuer_in_system_store(osi.cert_issuer))
			osi.cert_is_internal_ca = true;
	}

	/* Public-key type */
	const oscam_pk_context *pub = oscam_ssl_cert_get_pubkey(crt);
	int bits     = pub ? oscam_ssl_pk_get_bits(pub) : 0;
	int ptype_id = pub ? oscam_ssl_pk_get_type(pub) : OSCAM_PK_NONE;

	const char *ptype_name =
		(ptype_id == OSCAM_PK_RSA) ? "RSA" :
		(ptype_id == OSCAM_PK_EC)  ? "ECDSA" : "Other";

	char ptype[64];
	snprintf(ptype, sizeof(ptype), "%d-bit %s Key", bits, ptype_name);
	osi.pkey_type = cs_strdup(ptype);

	/* Clone the public key into an independent context (unchanged logic) */
	oscam_pk_context *pk = oscam_ssl_pk_new();
	if (!pk)
	{
		oscam_ssl_cert_delete(crt);
		return NULL;
	}

	if (pub)
	{
		int rc = oscam_ssl_pk_clone(pk, pub);
		if (rc != OSCAM_SSL_OK)
		{
			char estr[128];
			oscam_ssl_strerror(rc, estr, sizeof(estr));
			cs_log("Error: failed to clone public key (rc=%d, %s)", rc, estr);
			oscam_ssl_pk_delete(pk);
			pk = NULL;
		}
	}
	else
	{
		oscam_ssl_pk_delete(pk);
		pk = NULL;
	}

	oscam_ssl_cert_delete(crt);
	return pk;
}

static DIGEST hashBinary(const char *binfile, DIGEST *sign)
{
	DIGEST arRetval = {NULL, 0};
	struct stat *fi;
	unsigned char *signature_enc;
	size_t file_size = 0, offset = 0, end = 0, signature_size = 0;
	unsigned char *data = NULL, *signature_start = NULL, *signature_end = NULL, *p = NULL;

	if (cs_malloc(&fi, sizeof(struct stat)))
	{
		if (!stat(binfile, fi))
		{
			file_size = fi->st_size;
			// Read binary into memory
			int fd = open(binfile, O_RDONLY);
			if (fd >= 0)
			{
				data = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
				if (data != MAP_FAILED)
				{
					end = file_size;

					// Find last OBSM marker
					p = data;
					while ((p = memmem(p, file_size - offset, OBSM, cs_strlen(OBSM))))
					{
						offset = p - data;
						p += cs_strlen(OBSM);
						signature_start = p;
					}

					// Find next UPXM marker
					p = signature_start ? memmem(signature_start, file_size - offset, UPXM, cs_strlen(UPXM)) : NULL;
					if (p != NULL)
					{
						end = p - data;
						signature_end = p;
					}
					else
					{
						signature_end = data + end; // default to EOF
					}

					// Extract encrypted signature
					if (offset > 0 && end > offset + cs_strlen(OBSM))
					{
						signature_size = end - offset - cs_strlen(OBSM);
						if (cs_malloc(&signature_enc, signature_size))
						{
							memcpy(signature_enc, signature_start, signature_size);
							sign->data = signature_enc;
							sign->size = signature_size;
						}
					}
					else
					{
						offset = file_size;
					}

					// SHA256 hash binary (excluding signature)
					arRetval.data = malloc(SHA256_DIGEST_LENGTH);
					if (arRetval.data) {
						oscam_ssl_sha256_stream(
							data, offset,                       // first part of file
							signature_end, file_size - end,     // second part of file
							arRetval.data
						);
						arRetval.size = SHA256_DIGEST_LENGTH;
					}

					munmap(data, file_size);
				}
				close(fd);
			}
		}
		free(fi);
	}

	return arRetval;
}

static bool verifyBin(const char *binfile, oscam_pk_context *pubkey)
{
	DIGEST sign = { NULL, 0 };
	DIGEST hash = hashBinary(binfile, &sign);

	osi.is_verified = false;
	osi.sign_digest_size = sign.size;

	if (hash.data)
	{
		char shaVal[2 * hash.size + 1];
		hex_encode(hash.data, shaVal, hash.size);

		osi.hash_digest_size = hash.size;
		osi.hash_size = strlen(shaVal);
		if (cs_malloc(&osi.hash_sha256, osi.hash_size + 1))
			cs_strncpy(osi.hash_sha256, strtolower(shaVal), osi.hash_size + 1);

		if (pubkey && sign.data)
		{
			/* behavior: final_digest = SHA256( lowercase_hex(sha256(file_wo_sig)) ) */
			unsigned char final_digest[32];
			oscam_ssl_sha256((const unsigned char *)osi.hash_sha256,
							 strlen(osi.hash_sha256),
							 final_digest);

			int ret = oscam_ssl_pk_verify(pubkey,
										final_digest, sizeof(final_digest),
										sign.data, sign.size);

			osi.is_verified = (ret == 0);
		}
		free(hash.data);
	}

	if (sign.data)
		free(sign.data);

	return osi.is_verified;
}

bool init_signing_info(const char *binfile)
{
	oscam_pk_context *pubkey = NULL;
	memset(&osi, 0, sizeof(struct o_sign_info));

	// verify signing certificate and extract public key
	pubkey = verify_cert();

	// resolve binfile in PATH
	char *tmp = find_in_path(binfile);
	osi.binfile_exists = (tmp != NULL);
	snprintf(osi.resolved_binfile, sizeof(osi.resolved_binfile), "%s", tmp ? tmp : binfile);

	cs_log ("Binary         = %s file %s%s",
			(osi.binfile_exists ? "Verifying" : "Unable to access"),
			osi.resolved_binfile,
			(osi.binfile_exists ? "..." : "!"));

	// verify binfile using public key
	bool ret = verifyBin(osi.resolved_binfile, pubkey);

	cs_log ("Signature      = %s", (ret ? "Valid - Binary's signature was successfully verified using the built-in Public Key"
										: "Error: Binary's signature is invalid! Shutting down..."));

	if (pubkey)
	{
		cs_log("Certificate    = %s %s%s Certificate, %s %s",
				((osi.cert_is_valid_self || osi.cert_is_valid_system) ? "Trusted" : "Untrusted"),
				(osi.cert_is_internal_ca ? "Internal " : ""),
				(osi.cert_is_cacert ? "CA" : "Self Signed"),
				(osi.cert_is_expired ? "expired since" : "valid until"),
				osi.cert_valid_to);
	}
	else
	{
		cs_log("Certificate    = Error: Built-in Public Key could not be extracted!");
	}

	if (tmp) free(tmp);
	if (pubkey) {
		oscam_ssl_pk_delete(pubkey);
	}

	return ret;
}

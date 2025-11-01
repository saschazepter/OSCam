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

static char* cert_dn_to_str(const mbedtls_x509_name *dn)
{
	if (!dn) return NULL;
	char buf[256];
	oscam_ssl_cert_dn_gets(buf, sizeof(buf), dn);
	return cs_strdup(buf);
}

static void format_cert_time(const mbedtls_x509_time *t, char *buf, size_t len)
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

	oscam_x509_crt sys;
	oscam_ssl_cert_init(&sys);

	if (oscam_ssl_cert_parse_file(&sys, system_ca_file) != 0)
	{
		oscam_ssl_cert_free(&sys);
		return false;
	}

	bool found = false;
	for (const oscam_x509_crt *c = &sys; c != NULL && c->crt.raw.p != NULL; c = (oscam_x509_crt *)c->crt.next)
	{
		char dn[512];
		oscam_ssl_cert_dn_gets(dn, sizeof(dn), oscam_ssl_cert_get_subject(c));
		if (strcmp(dn, issuer_dn) == 0)
		{
			found = true;
			break;
		}
	}

	oscam_ssl_cert_free(&sys);
	return found;
}

static oscam_pk_context *verify_cert(void)
{
	oscam_x509_crt crt;
	oscam_ssl_cert_init(&crt);

	int ret = oscam_ssl_cert_parse(&crt,
									 (const unsigned char *)config_cert,
									 strlen(config_cert) + 1);
	if (ret != 0)
	{
		char estr[128];
		oscam_ssl_strerror(ret, estr, sizeof(estr));
		cs_log("Error: unable to parse built-in certificate (%s)", estr);
		return NULL;
	}

	// ---- Certificate information ----

	osi.cert_version = crt.crt.version;

	format_cert_time(&crt.crt.valid_from, osi.cert_valid_from, sizeof(osi.cert_valid_from));
	format_cert_time(&crt.crt.valid_to, osi.cert_valid_to, sizeof(osi.cert_valid_to));

	time_t now = time(NULL);
	struct tm t;
	memset(&t, 0, sizeof(t));
	localtime_r(&now, &t);
	osi.cert_is_expired =
		(crt.crt.valid_to.year  <  t.tm_year + 1900) ||
		(crt.crt.valid_to.year == t.tm_year + 1900 && crt.crt.valid_to.mon < t.tm_mon + 1);

	// Serial
	char serial_hex[128];
	oscam_ssl_cert_serial_gets(&crt, serial_hex, sizeof(serial_hex));
	osi.cert_serial = cs_strdup(strtolower(serial_hex));

	// Fingerprint (SHA-1 of raw DER)
	unsigned char fp[SHA_DIGEST_LENGTH];
	oscam_ssl_sha1(crt.crt.raw.p, crt.crt.raw.len, fp);
	char fphex[2 * SHA_DIGEST_LENGTH + 1];
	hex_encode(fp, fphex, SHA_DIGEST_LENGTH);
	osi.cert_fingerprint = cs_strdup(strtolower(fphex));

	// Subject / issuer
	osi.cert_subject = cert_dn_to_str(&crt.crt.subject);
	osi.cert_issuer  = cert_dn_to_str(&crt.crt.issuer);
	osi.cert_is_cacert = strcmp(osi.cert_subject, osi.cert_issuer) != 0;
	osi.cert_is_valid_self  = false;
	osi.cert_is_valid_system = false;
	osi.cert_is_internal_ca = false;

	/* Parse the full built-in certificate chain (one or more PEM blocks) */
	oscam_x509_crt chain;
	oscam_ssl_cert_init(&chain);

	int rself = oscam_ssl_cert_parse(&chain,
									 (const unsigned char *)config_cert,
									 strlen(config_cert) + 1);
	if (rself == 0) {
		/* The first cert in the chain is our leaf (signing cert).
		   Any additional certs in the same PEM block become chain.next, chain.next->next, etc. */
		oscam_x509_crt *crt_leaf  = &chain;
		oscam_x509_crt *trust_self = (oscam_x509_crt *) oscam_ssl_cert_get_next(crt_leaf);


		if (trust_self) {
			int vr = oscam_ssl_cert_verify(crt_leaf, trust_self);
			if (vr == 0) {
				osi.cert_is_valid_self = true;
			}
		}
	}

	oscam_ssl_cert_free(&chain);

	/* If not trusted by the built-in chain, try system CA bundle */
	if (!osi.cert_is_valid_self) {
		char system_ca_file[MAX_LEN];
		const char *ca_path = NULL;

		/* default location (matches your macros) */
		snprintf(system_ca_file, sizeof(system_ca_file), "%s/%s",
				 CA_SYSTEM_LOCATION, CA_FILE_NAME);

		if (!file_exists(system_ca_file)) {
			/* emulate the OpenSSL fallback behavior */
			ca_path = getenv("SSL_CERT_DIR");  /* like X509_get_default_cert_dir_env() */
			if (!ca_path) {
				/* OpenSSL default; you already define CA_SYSTEM_LOCATION/FILE; keep a fallback */
				ca_path = "/etc/ssl/certs";
			}
			snprintf(system_ca_file, sizeof(system_ca_file), "%s/%s",
					 ca_path, CA_FILE_NAME);
		}

		if (cs_malloc(&osi.system_ca_file, cs_strlen(system_ca_file) + 1)) {
			cs_strncpy(osi.system_ca_file, system_ca_file,
					   cs_strlen(system_ca_file) + 1);
		}

		oscam_x509_crt trust_sys;
		oscam_ssl_cert_init(&trust_sys);

		int rsys = oscam_ssl_cert_parse_file(&trust_sys, system_ca_file);
		if (rsys == 0) {
			int vr = oscam_ssl_cert_verify(&crt, &trust_sys);
			if (vr == 0) {
				osi.cert_is_valid_system = true;
			}
		} else {
			cs_log("Error: unable to load CA bundle from %s", system_ca_file);
		}
		oscam_ssl_cert_free(&trust_sys);
	}

	if (osi.cert_is_valid_self && !osi.cert_is_valid_system)
	{
		if (!issuer_in_system_store(osi.cert_issuer))
			osi.cert_is_internal_ca = true;
	}

	// Public-key type
	char ptype[2 * SHA256_DIGEST_LENGTH];
	const int ptype_id = oscam_ssl_pk_get_type(oscam_ssl_cert_get_pubkey(&crt));
	snprintf(ptype, sizeof(ptype), "%d-bit %s Key",
			 (int)mbedtls_pk_get_bitlen(&crt.crt.pk),
			 (ptype_id == MBEDTLS_PK_RSA) ? "RSA" :
			 (ptype_id == MBEDTLS_PK_ECKEY) ? "ECDSA" : "Other");
	osi.pkey_type = cs_strdup(ptype);

	// ---- Clone the public key ----
	oscam_pk_context *pk = malloc(sizeof(*pk));
	if (!pk)
	{
		oscam_ssl_cert_free(&crt);
		return NULL;
	}

	const oscam_pk_context *pub = oscam_ssl_cert_get_pubkey(&crt);
	int rc = oscam_ssl_pk_clone(pk, pub);
	if (rc != 0)
	{
		char estr[128];
		oscam_ssl_strerror(ret, estr, sizeof(estr));
		cs_log("Error: failed to clone public key (rc=%d, %s)", rc, estr);
		free(pk);
		pk = NULL;
	}

	oscam_ssl_cert_free(&crt);
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
		oscam_ssl_pk_free(pubkey);
		free(pubkey);
	}

	return ret;
}

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
	mbedtls_x509_dn_gets(buf, sizeof(buf), dn);
	return cs_strdup(buf);
}

static void format_mbedtls_time(const mbedtls_x509_time *t, char *buf, size_t len)
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

static mbedtls_pk_context *verify_cert(void)
{
	mbedtls_x509_crt crt;
	mbedtls_x509_crt_init(&crt);
	if (mbedtls_x509_crt_parse(&crt, (const unsigned char*)config_cert,
							   strlen(config_cert) + 1) != 0)
	{
		cs_log("Error: unable to parse built-in certificate");
		return NULL;
	}

	// Version
	osi.cert_version = crt.version;

	// Validity
	format_mbedtls_time(&crt.valid_from,  osi.cert_valid_from, sizeof(osi.cert_valid_from));
	format_mbedtls_time(&crt.valid_to,	osi.cert_valid_to,   sizeof(osi.cert_valid_to));

	// Expiry check
	time_t now = time(NULL);
	struct tm t;
	memset(&t, 0, sizeof(t));   // prevents GCC uninitialized warning
	localtime_r(&now, &t);
	osi.cert_is_expired =
		(crt.valid_to.year  <  t.tm_year + 1900) ||
		(crt.valid_to.year == t.tm_year + 1900 && crt.valid_to.mon < t.tm_mon + 1);

	// Serial
	char serial_hex[128];
	mbedtls_x509_serial_gets(serial_hex, sizeof(serial_hex), &crt.serial);
	osi.cert_serial = cs_strdup(strtolower(serial_hex));

	// Fingerprint (SHA-1 of raw DER)
	unsigned char fp[20];
	SHA_CTX sctx;
	SHA1_Init(&sctx);
	SHA1_Update(&sctx, crt.raw.p, crt.raw.len);
	SHA1_Final(fp, &sctx);
	char fphex[41];
	hex_encode(fp, fphex, 20);
	osi.cert_fingerprint = cs_strdup(strtolower(fphex));

	// Subject / issuer
	osi.cert_subject = cert_dn_to_str(&crt.subject);
	osi.cert_issuer  = cert_dn_to_str(&crt.issuer);
	osi.cert_is_cacert = strcmp(osi.cert_subject, osi.cert_issuer) != 0;
	osi.cert_is_valid_self   = (strcmp(osi.cert_subject, osi.cert_issuer) == 0);
	osi.cert_is_valid_system = 1;

	// Public-key type
	char ptype[64];
	const mbedtls_pk_type_t ptype_id = mbedtls_pk_get_type(&crt.pk);
	snprintf(ptype, sizeof(ptype), "%d-bit %s Key",
			 (int)mbedtls_pk_get_bitlen(&crt.pk),
			 (ptype_id == MBEDTLS_PK_RSA) ? "RSA" :
			 (ptype_id == MBEDTLS_PK_ECDSA) ? "ECDSA" : "Other");
	osi.pkey_type = cs_strdup(ptype);

	// Copy pk context so caller can verify
	mbedtls_pk_context *pk = malloc(sizeof(*pk));
	if (pk) {
		int rc = oscam_ssl_pk_clone(pk, &crt.pk);
		if (rc != 0) {
			cs_log("Error: failed to clone public key (rc=%d)", rc);
			free(pk);
			pk = NULL;
		}
	}

	mbedtls_x509_crt_free(&crt);
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
					mbedtls_sha256_context ctx;
					mbedtls_sha256_init(&ctx);
					mbedtls_sha256_starts(&ctx, 0);
					mbedtls_sha256_update(&ctx, data, offset);
					mbedtls_sha256_update(&ctx, signature_end, file_size - end);
					mbedtls_sha256_finish(&ctx, arRetval.data = malloc(SHA256_DIGEST_LENGTH));
					arRetval.size = SHA256_DIGEST_LENGTH;
					mbedtls_sha256_free(&ctx);

					munmap(data, file_size);
				}
				close(fd);
			}
		}
		free(fi);
	}

	return arRetval;
}

static bool verifyBin(const char *binfile, mbedtls_pk_context *pubkey)
{
	osi.is_verified = false;
	DIGEST sign = { NULL, 0 };
	DIGEST hash = hashBinary(binfile, &sign);

	osi.sign_digest_size = sign.size;
	if (hash.data)
	{
		char shaVal[2 * hash.size + 1];
		hex_encode(hash.data, shaVal, hash.size);
		osi.hash_digest_size = hash.size;
		osi.hash_size = strlen(shaVal);
		osi.hash_sha256 = cs_strdup(strtolower(shaVal));

		if (pubkey && sign.data)
		{
			int ret = mbedtls_pk_verify(pubkey, MBEDTLS_MD_SHA256,
										hash.data, hash.size,
										sign.data, sign.size);
			osi.is_verified = (ret == 0);
		}

		free(hash.data);
	}
	if (sign.data) free(sign.data);
	return osi.is_verified;
}

bool init_signing_info(const char *binfile)
{
	mbedtls_pk_context *pubkey = NULL;
	memset(&osi, 0, sizeof(struct o_sign_info));

	// verify signing certificate and extract public key
	pubkey = verify_cert();

	// resolve binfile in PATH
	char *tmp = find_in_path(binfile);
	osi.binfile_exists = (tmp != NULL);
	snprintf(osi.resolved_binfile, sizeof(osi.resolved_binfile), "%s", tmp ? tmp : binfile);

	cs_log ("Binary		 = %s file %s%s",
			(osi.binfile_exists ? "Verifying" : "Unable to access"),
			osi.resolved_binfile,
			(osi.binfile_exists ? "..." : "!"));

	// verify binfile using public key
	bool ret = verifyBin(osi.resolved_binfile, pubkey);

	cs_log ("Signature	  = %s", (ret ? "Valid - Binary's signature was successfully verified using the built-in Public Key"
										: "Error: Binary's signature is invalid! Shutting down..."));

	if (pubkey)
	{
		cs_log("Certificate	= %s %s Certificate, %s %s",
				((osi.cert_is_valid_self || osi.cert_is_valid_system) ? "Trusted" : "Untrusted"),
				(osi.cert_is_cacert ? "CA" : "Self Signed"),
				(osi.cert_is_expired ? "expired since" : "valid until"),
				osi.cert_valid_to);
	}
	else
	{
		cs_log("Certificate	= Error: Built-in Public Key could not be extracted!");
	}

	if (tmp) free(tmp);
	if (pubkey) {
		mbedtls_pk_free(pubkey);
		free(pubkey);
	}

	return ret;
}

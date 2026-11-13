/*
 * Custom mbedTLS platform overrides for portable OSCam builds (mbedTLS 4.x).
 *
 * tf-psa-crypto/platform/platform_util.c already provides
 * mbedtls_zeroize_and_free, mbedtls_ms_time and mbedtls_platform_gmtime_r;
 * we only have to bring zeroize (overridden via MBEDTLS_PLATFORM_ZEROIZE_ALT
 * to avoid the glibc-2.25 dependency), our custom calloc/free/printf, the
 * entropy hardware_poll, and the platform setup/teardown stubs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
# include "mbedtls/memory_buffer_alloc.h"
#endif

#include "mbedtls/platform.h"
#include "mbedtls/platform_time.h"
#include "mbedtls/build_info.h"

/* ======================================================================
 * Platform zeroize (override via MBEDTLS_PLATFORM_ZEROIZE_ALT)
 *
 * Stock tf-psa-crypto enables explicit_bzero() based on the build host's
 * __GLIBC_MINOR__ — that introduces a GLIBC_2.25 runtime dependency on
 * the resulting binary even when cross-compiling for an older target.
 * Our volatile-pointer loop has the same security property (compiler
 * cannot dead-store-eliminate it) without any glibc symbol dependency.
 * ====================================================================== */
void mbedtls_platform_zeroize(void *buf, size_t len)
{
	if (buf == NULL || len == 0) return;
	volatile unsigned char *p = (volatile unsigned char *) buf;
	while (len--) { *p++ = 0; }
}

/* ======================================================================
 * Entropy source — always needed (custom hardware_poll for cross-builds)
 * ====================================================================== */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen);

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
	(void)data;

#if defined(__unix__) || defined(__linux__)
	{
		extern int open(const char *, int, ...);
		extern ssize_t read(int, void *, size_t);
		extern int close(int);

		int fd = open("/dev/urandom", 0);
		if (fd >= 0) {
			ssize_t got = read(fd, output, len);
			close(fd);
			if (got > 0) {
				if (olen) *olen = (size_t)got;
				return 0;
			}
		}
	}
#endif

	/* Fallback (weak) entropy */
	{
		uint64_t t = (uint64_t) time(NULL);
		uintptr_t sp = (uintptr_t) &t;
		uint64_t mixed = t ^ (sp << 13) ^ (sp >> 7);

		if (len > sizeof(mixed)) len = sizeof(mixed);
		memcpy(output, &mixed, len);
		if (olen) *olen = len;
		return 0;
	}
}

/* ======================================================================
 * Custom allocator / printf functions (always needed)
 * ====================================================================== */
int oscam_mbedtls_printf(const char *fmt, ...)
{
	va_list ap; va_start(ap, fmt);
	int rc = vfprintf(stdout, fmt, ap);
	va_end(ap);
	return rc;
}

int oscam_mbedtls_snprintf(char *buf, size_t buflen, const char *fmt, ...)
{
	va_list ap; va_start(ap, fmt);
	int rc = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	return rc;
}

void *oscam_mbedtls_calloc(size_t n, size_t size) { return calloc(n, size); }
void  oscam_mbedtls_free(void *p)                 { free(p); }

/* ======================================================================
 * Platform setup / teardown
 * ====================================================================== */
int mbedtls_platform_setup(mbedtls_platform_context *ctx)
{
	(void)ctx;
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
	static unsigned char mbedtls_static_heap[32 * 1024];
	mbedtls_memory_buffer_alloc_init(mbedtls_static_heap, sizeof(mbedtls_static_heap));
#endif
	return 0;
}

void mbedtls_platform_teardown(mbedtls_platform_context *ctx)
{
	(void)ctx;
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
	mbedtls_memory_buffer_alloc_free();
#endif
}

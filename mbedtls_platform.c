/*
 * Custom mbedTLS platform overrides for portable OSCam builds
 * - No dependency on versioned glibc symbols (e.g. explicit_bzero@GLIBC_*).
 * - Works on Linux (glibc/musl), macOS, and FreeBSD.
 * - Allows overriding printf and memory functions without pulling mbedtls/library/platform.c.
 *
 * Build assumptions (recommended):
 *   - You EXCLUDE: mbedtls/library/platform.c and mbedtls/library/platform_util.c
 *   - You ENABLE in your user config (mbedtls-config.h):
 *       #define MBEDTLS_PLATFORM_C
 *       #define MBEDTLS_PLATFORM_MEMORY
 *       #define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
 *
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
#if defined(MBEDTLS_DEBUG_C)
# include "mbedtls/debug.h"
#endif

#include "mbedtls/platform.h"
#include "mbedtls/platform_time.h"

/* ----------------------------------------------------------------------
 * Secure zeroization (we exclude platform_util.c, so we provide this)
 * -------------------------------------------------------------------- */
void mbedtls_platform_zeroize(void *buf, size_t len)
{
	volatile unsigned char *p = (volatile unsigned char *) buf;
	while (len--) { *p++ = 0; }
}

/* Some mbedTLS code calls this helper; provide it to avoid pulling
 * platform_util.c and to ensure secrets are scrubbed before free. */
void mbedtls_zeroize_and_free(void *ptr, size_t len)
{
	if (ptr == NULL) return;
	mbedtls_platform_zeroize(ptr, len);
	free(ptr);
}

/* ----------------------------------------------------------------------
 * Time helpers (portable, high-resolution when available)
 * -------------------------------------------------------------------- */
mbedtls_ms_time_t mbedtls_ms_time(void)
{
#if defined(CLOCK_REALTIME)
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
		return (mbedtls_ms_time_t)((ts.tv_sec * 1000ULL) + (ts.tv_nsec / 1000000ULL));
	}
#endif
	/* Fallback for older systems / environments */
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (mbedtls_ms_time_t)((tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000ULL));
}

struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *tt, struct tm *tm_buf)
{
	/* POSIX gmtime_r is available on Linux, FreeBSD, macOS */
	return gmtime_r(tt, tm_buf);
}

/* ----------------------------------------------------------------------
 * Minimal entropy source replacement for embedded / cross builds.
 * Provides a weak entropy source using time and stack data.
 * It’s NOT cryptographically secure, but sufficient to seed
 * mbedtls_ctr_drbg when true randomness is unavailable.
 * -------------------------------------------------------------------- */
/* Local prototype – avoids including mbedtls/entropy_poll.h */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen);

/* Portable entropy source for cross-builds (no glibc lock-in). */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
	(void)data;

	/* Try best source first, if available on the target (no glibc dependency). */
#if defined(__unix__) || defined(__linux__)
	/* Optional: /dev/urandom without glibc-specific calls */
	{
		int fd;
		ssize_t got;
		/* Use minimal headers to avoid portability issues */
		extern int open(const char *, int, ...);
		extern ssize_t read(int, void *, size_t);
		extern int close(int);

		/* O_RDONLY = 0 */
		fd = open("/dev/urandom", 0);
		if (fd >= 0) {
			got = read(fd, output, len);
			close(fd);
			if (got > 0) {
				if (olen) *olen = (size_t)got;
				return 0;
			}
		}
	}
#endif

	/* Fallback (weak) entropy: mix time and stack address */
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

/* ----------------------------------------------------------------------
 * Platform setup / teardown
 * -------------------------------------------------------------------- */
int mbedtls_platform_setup(mbedtls_platform_context *ctx)
{
	(void)ctx;

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
	static unsigned char mbedtls_static_heap[32 * 1024]; /* tune size */
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

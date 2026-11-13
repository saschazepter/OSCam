/*
 * Custom mbedTLS platform overrides for portable OSCam builds
 *
 * mbedTLS 4.x: platform_util.c provides zeroize, gmtime_r, ms_time etc.
 * We only provide: custom calloc/free/printf, hardware_poll, platform setup.
 * For mbedTLS 3.x: we still provide all platform functions.
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
 * Functions provided by platform_util.c in mbedTLS 4.x.
 * Only define these for mbedTLS 3.x builds (where we exclude platform_util.c).
 * ====================================================================== */
#if MBEDTLS_VERSION_NUMBER < 0x04000000

void mbedtls_platform_zeroize(void *buf, size_t len)
{
	volatile unsigned char *p = (volatile unsigned char *) buf;
	while (len--) { *p++ = 0; }
}

void mbedtls_zeroize_and_free(void *ptr, size_t len)
{
	if (ptr == NULL) return;
	mbedtls_platform_zeroize(ptr, len);
	free(ptr);
}

mbedtls_ms_time_t mbedtls_ms_time(void)
{
#if defined(CLOCK_REALTIME)
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
		return (mbedtls_ms_time_t)((ts.tv_sec * 1000ULL) + (ts.tv_nsec / 1000000ULL));
#endif
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (mbedtls_ms_time_t)((tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000ULL));
}

struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *tt, struct tm *tm_buf)
{
	return gmtime_r(tt, tm_buf);
}

#endif /* MBEDTLS_VERSION_NUMBER < 0x04000000 */

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

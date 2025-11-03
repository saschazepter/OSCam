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
 * If you include platform.c later, our weak symbols will be overridden by the strong ones.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>

#include "mbedtls/platform.h"
#include "mbedtls/platform_time.h"

/* ----------------------------------------------------------------------
 * Portable "weak" attribute for GCC/Clang (Linux, FreeBSD, macOS)
 * -------------------------------------------------------------------- */
#if !defined(WEAK)
# if defined(__GNUC__) || defined(__clang__)
#  define WEAK __attribute__((weak))
# else
#  define WEAK
# endif
#endif

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
 * Minimal printf / calloc / free wrappers
 * You can replace these with your own logging / allocator if desired.
 * -------------------------------------------------------------------- */
static int my_printf(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	/* Use stdout to mimic mbedtls default behavior */
	int ret = vfprintf(stdout, fmt, args);
	va_end(args);
	return ret;
}

static void *my_calloc(size_t n, size_t size)
{
	return calloc(n, size);
}

static void my_free(void *ptr)
{
	free(ptr);
}

/* ----------------------------------------------------------------------
 * Weak stubs for mbedtls_platform_set_* to avoid linking platform.c
 * If platform.c is ever linked, its strong symbols override these.
 * -------------------------------------------------------------------- */
WEAK int mbedtls_platform_set_printf(int (*printf_func)(const char *, ...))
{
	(void) printf_func;
	return 0; /* accept and ignore (we call our own in setup) */
}

WEAK int mbedtls_platform_set_calloc_free(void *(*calloc_func)(size_t, size_t),
											void (*free_func)(void *))
{
	(void) calloc_func;
	(void) free_func;
	return 0; /* accept and ignore (we call our own in setup) */
}

/* ----------------------------------------------------------------------
 * Setup / teardown
 * -------------------------------------------------------------------- */
int mbedtls_platform_setup(mbedtls_platform_context *ctx)
{
	(void) ctx;

	int ret = 0;

	/* Register our printf and memory hooks. Even if these weak functions
       are no-ops (because platform.c is linked and overrides them),
       calling them is harmless. */
	if (mbedtls_platform_set_printf(my_printf) != 0)
		ret = -1;

	if (mbedtls_platform_set_calloc_free(my_calloc, my_free) != 0)
		ret = -1;

	return ret;
}

void mbedtls_platform_teardown(mbedtls_platform_context *ctx)
{
	(void) ctx;
	/* Nothing to clean up */
}

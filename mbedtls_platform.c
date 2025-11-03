/*
 * Custom mbedTLS platform overrides for OSCam portable build
 * Eliminates strict dependency on glibc (e.g. explicit_bzero)
 * and allows control over memory / printf usage.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>

#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/platform_time.h"

/* --------------------------------------------------------------------
 * Secure zeroization replacement (avoids explicit_bzero@GLIBC_...)
 * ------------------------------------------------------------------*/
void mbedtls_platform_zeroize(void *buf, size_t len)
{
	volatile unsigned char *p = (volatile unsigned char *) buf;
	while (len--)
		*p++ = 0;
}

/* --------------------------------------------------------------------
 * Custom printf / calloc / free wrappers
 * ------------------------------------------------------------------*/
static int my_printf(const char *fmt, ...)
{
	va_list args;
	int ret;
	va_start(args, fmt);
	ret = vfprintf(stdout, fmt, args);
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

/* --- Secure zeroize + free replacement --- */
void mbedtls_zeroize_and_free(void *ptr, size_t len)
{
	if (ptr == NULL)
		return;

	volatile unsigned char *p = ptr;
	while (len--) *p++ = 0;

	free(ptr);
}

/* --- Millisecond time replacement --- */
mbedtls_ms_time_t mbedtls_ms_time(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (mbedtls_ms_time_t)((tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000ULL));
}

/* --- gmtime_r() wrapper --- */
struct tm *mbedtls_platform_gmtime_r(const mbedtls_time_t *tt, struct tm *tm_buf)
{
	return gmtime_r(tt, tm_buf);
}

/* --------------------------------------------------------------------
 * Register our replacements with mbedTLS at startup.
 * ------------------------------------------------------------------*/
int mbedtls_platform_set_printf(int (*printf_func)(const char *, ...));
int mbedtls_platform_set_calloc_free(void *(*calloc_func)(size_t, size_t),
									 void (*free_func)(void *));

int mbedtls_platform_setup(mbedtls_platform_context *ctx)
{
	(void) ctx;

	int ret = 0;

	if (mbedtls_platform_set_printf(my_printf) != 0)
		ret = -1;

	if (mbedtls_platform_set_calloc_free(my_calloc, my_free) != 0)
		ret = -1;

	return ret;
}

void mbedtls_platform_teardown(mbedtls_platform_context *ctx)
{
	(void) ctx;
}

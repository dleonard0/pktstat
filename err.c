/* David Leonard, 2006. Public domain */
#if HAVE_CONFIG_H
# include "config.h"
#endif

#if STDC_HEADERS
# include <stdio.h>
# include <stdarg.h>
# include <string.h>
#endif

#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#if HAVE_ERRNO_H
# include <errno.h>
#endif

#include "compat.h"

static void msg(const char *, int, const char *, va_list);

static void
msg(type, se, fmt, ap)
	const char *type;
	int se;
	const char *fmt;
	va_list ap;
{
	extern int errno;

	int errno_save = errno;
	fprintf(stderr, "%s: ", type);
	vfprintf(stderr, fmt, ap);
	if (se)
#if HAVE_STRERROR
	    fprintf(stderr, ": %s", strerror(errno_save));
#else
	    fprintf(stderr, ": error %d", errno_save);
#endif
	fprintf(stderr, "\n");
}

void
err(ec, fmt)
	int ec;
	const char *fmt;
{
	va_list ap;

	va_start(ap, fmt);
	msg("Error", 1, fmt, ap);
	va_end(ap);
	exit(ec);
}

void
errx(ec, fmt)
	int ec;
	const char *fmt;
{
	va_list ap;

	va_start(ap, fmt);
	msg("Error", 0, fmt, ap);
	va_end(ap);
	exit(ec);
}


void
warn(fmt)
	const char *fmt;
{
	va_list ap;

	va_start(ap, fmt);
	msg("Warning", 1, fmt, ap);
	va_end(ap);
}

void
warnx(fmt)
	const char *fmt;
{
	va_list ap;

	va_start(ap, fmt);
	msg("Warning", 0, fmt, ap);
	va_end(ap);
}

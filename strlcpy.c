/* David Leonard, 2006. Public domain. */
/* $Id$ */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include "compat.h"

size_t
strlcpy(dst, src, len)
	char *dst;
	const char *src;
	size_t len;
{
	size_t ret = 0;

	while (len > 1 && *src) {
	    *dst++ = *src++;
	    ret++;
	}
	if (len > 0)
	    *dst = 0;
	while (*src) {
	    ret++;
	    src++;
	}
	return ret + 1;
}

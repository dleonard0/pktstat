/* David Leonard, 2002. Public domain. */
/* $Id$ */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#if STDC_HEADERS
# include <stdio.h>
# include <string.h>
# include <ctype.h>
#endif
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "type.h"
#include "flow.h"
#include "tcp.h"

/*
 * Look for HTTP command words (e.g. GET, POST etc) and use it and the
 * following object argument as a description for the flow.
 */
void
tcp_http(f, data, end, toserver)
	struct flow *f;
	const char *data;
	const char *end;
	int toserver;
{
	const char *d;

#define startswith(data, text)	\
	(data + sizeof text - 1 <= end && \
	 memcmp(data, text, sizeof text - 1) == 0)

	/* Look for HTTP requests at the beginning of a packet */
	if (toserver && 
	    (startswith(data, "GET ") ||
	     startswith(data, "POST ") ||
	     startswith(data, "OPTIONS ") ||
	     startswith(data, "CONNECT ") ||
	     startswith(data, "HEAD ")))
	{
		/* Find the object of the request (usually a URI) */
		for (d = data; d < end && *d != ' '; d++)
			;
		if (d < end)
			d++;
		for (; d < end && *d != '\r' && *d != ' '
		    && *d != ';'; d++)
			;
		snprintf(f->desc, sizeof f->desc, "%.*s",
			(int)(d - data), data);
	}

	/* Record responses of form "HTTP/#.# ###" */
	if (!toserver &&
	    data + 12 <= end &&
	    memcmp(data, "HTTP/", 5) == 0 &&
	    isdigit(data[5]) &&
	    data[6] == '.' &&
	    isdigit(data[7]) &&
	    data[8] == ' ' &&
	    isdigit(data[9]) &&
	    isdigit(data[10]) &&
	    isdigit(data[11]))
	{
		if (isdigit(f->desc[0])) {
			/* Replace the existing code */
			f->desc[0] = data[9];
			f->desc[1] = data[10];
			f->desc[2] = data[11];
		} else {
			/* Insert the 3 digit result before the uri */
			char cp[DESCLEN];
			memcpy(cp, f->desc, sizeof cp);
			snprintf(f->desc, sizeof f->desc, "%c%c%c %.*s",
				data[9], data[10], data[11],
				(int)sizeof cp, cp);
		}
	}
}

/* David Leonard, 2002. Public domain. */
/* $Id$ */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include "flow.h"
#include "tcp.h"

void
tcp_http(f, data, end)
	struct flow *f;
	const char *data;
	const char *end;
{
	const char *d;

	if (memcmp(data, "GET ", 4) == 0 ||
	    memcmp(data, "POST ", 5) == 0 ||
	    memcmp(data, "CONNECT ", 8) == 0 ||
	    memcmp(data, "HEAD ", 5) == 0) {
		for (d = data; d < end && *d != ' '; d++)
			;
		if (d < end)
			d++;
		for (; d < end && *d != '\r' && *d != ' '
		    && *d != ';'; d++)
			;
		snprintf(f->desc, sizeof f->desc, "%.*s",
			d - data, data);
	}
}

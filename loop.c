/* David Leonard, 2002. Public domain. */
/* $Id$ */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "tag.h"

/* Used when the device's datalink type is DLT_LOOP */

const char *
loop_tag(p, end)
        const char *p;
	const char *end;
{
	u_int32_t af;
	static char tag[] = "loop af 0x----";

	memcpy(&af, p, sizeof af);
	p += sizeof af;

	switch (af) {
	case AF_INET:
		return ip_tag(p, end);
	case AF_INET6:
		return ip6_tag(p, end);
	default:
		snprintf(tag, sizeof tag, "loop af 0x%04x", af);
		return tag;
	}
}

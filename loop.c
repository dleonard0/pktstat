/* David Leonard, 2002. Public domain. */
/* $Id$ */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "tag.h"
#include "flow.h"

/*
 * Used when the device's datalink type is DLT_LOOP (loopback).
 * XXX Plenty more protocols could be handled here...
 */

const char *
loop_tag(p, end)
        const char *p;
	const char *end;
{
	u_int32_t af;
	static char tag[TAGLEN];

	memcpy(&af, p, sizeof af);
	p += sizeof af;

	switch (ntohl(af)) {
	case AF_INET:
		return ip_tag(p, end);
	case AF_INET6:
		return ip6_tag(p, end);
	default:
		snprintf(tag, sizeof tag, "loop af 0x%04x", af);
		return tag;
	}
}

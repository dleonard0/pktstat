/* David Leonard, 2002. Public domain. */
/* $Id$ */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#if STDC_HEADERS
# include <stdio.h>
# include <string.h>
#endif
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#if HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#include "compat.h"
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

#if defined(__FreeBSD__)
	switch (af) {
#else
	switch (ntohl(af)) {
#endif
	case AF_INET:
		return ip_tag(p, end);
#if HAVE_NETINET_IP6_H
	case AF_INET6:
		return ip6_tag(p, end);
#endif
	default:
		snprintf(tag, sizeof tag, "loop af 0x%04x", af);
		return tag;
	}
}

/* David Leonard, 2002. Public domain. */
/* $Id$ */
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "tag.h"

const char *
icmp_tag(p, end, ip)
	const char *p;
	const char *end;
	const struct ip *ip;
{
	const char *src, *dst;
	static char tag[256];
	struct icmp *icmp = (struct icmp *)p;

	src = ip_lookup(&ip->ip_src);
	dst = ip_lookup(&ip->ip_dst);
	switch (icmp->icmp_type) {
	case ICMP_ECHOREPLY:
		snprintf(tag, sizeof tag, "icmp echo-reply %s -> %s", src, dst);
		return tag;
	case ICMP_ECHO:
		snprintf(tag, sizeof tag, "icmp echo %s -> %s", src, dst);
		return tag;
	case ICMP_REDIRECT:
		snprintf(tag, sizeof tag, "icmp redirect %s -> %s", src, dst);
		return tag;
	default:
		snprintf(tag, sizeof tag, "icmp %02x/%02x %s -> %s",
			icmp->icmp_type, icmp->icmp_code, src, dst);
		return tag;
	}
}

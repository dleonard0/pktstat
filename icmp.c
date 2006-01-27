/* David Leonard, 2002. Public domain. */
/* $Id$ */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#if HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#if HAVE_NETINET_IP_H
# include <netinet/ip.h>
#endif
#if HAVE_NETINET_IP_ICMP_H
# include <netinet/ip_icmp.h>
#endif
#if HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#include "compat.h"
#include "tag.h"
#include "flow.h"

static char *unreachtab[16] = {
	"net", "host", "protocol", "port", "need-frag", "src-fail",
	"unknown-net", "unknown-host",
	"isolated", "prohib-net", "prohib-host", "tos-net", "tos-host",
	"filter-prohib", "host-prec", "prec-cutoff"
};

static char *redirecttab[4] = {
	"net", "host", "tos-net", "tos-host"
};

static char *typetab[] = {
/* 0*/	"echo", NULL, NULL, NULL, "sourcequench",
/* 5*/	NULL, "althostaddr", NULL, "echo", "routeradvert",
/*10*/	"routersolicit", "timxceed", "paramprob", "tstamp", "tstamp",
/*15*/	"info", "info", "addrmask", "addrmask", NULL,
/*20*/	NULL, NULL, NULL, NULL, NULL,
/*25*/	NULL, NULL, NULL, NULL, NULL,
/*30*/	"traceroute", "dataconverr", "mobile-redir", "ipv6-where", "ipv6-where",
/*35*/	"mobile-reg", "mobile-reg", NULL, NULL, "skip",
/*40*/	"photuris"
};

#define lengthof(a) (sizeof (a) / sizeof (a)[0])

const char *
icmp_tag(p, end, ip)
	const char *p;
	const char *end;
	const struct ip *ip;
{
	const char *src, *dst;
	static char tag[TAGLEN];
	struct icmp *icmp = (struct icmp *)p;

	src = ip_lookup(&ip->ip_src);
	dst = ip_lookup(&ip->ip_dst);
	switch (icmp->icmp_type) {
	case ICMP_REDIRECT:
		if (icmp->icmp_code >= lengthof(redirecttab))
			goto bad;
		snprintf(tag, sizeof tag, "icmp redirect %s %s -> %s",
			redirecttab[icmp->icmp_code], src, dst);
		return tag;
	case ICMP_UNREACH:
		if (icmp->icmp_code >= lengthof(unreachtab))
			goto bad;
		snprintf(tag, sizeof tag, "icmp unreach %s %s -> %s",
			unreachtab[icmp->icmp_code], src, dst);
		return tag;
	default:
	bad:
		if (icmp->icmp_type >= lengthof(typetab) ||
		    typetab[icmp->icmp_type] == NULL)
			snprintf(tag, sizeof tag, "icmp %u/%u %s -> %s",
				icmp->icmp_type, icmp->icmp_code, src, dst);
		else {
			snprintf(tag, sizeof tag, "icmp %s %s",
				typetab[icmp->icmp_type],
				tag_combine(src, dst));
		}
		return tag;
	}
}

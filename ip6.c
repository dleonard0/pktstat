/* David Leonard, 2002. Public domain. */
/* $Id$ */

/* Internet protocol version 6 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#if HAVE_PCAP_H
# include <pcap.h>
#endif
#if HAVE_NETDB_H
# include <netdb.h>
#endif
#if STDC_HEADERS
# include <string.h>
# include <stdlib.h>
#endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#if HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#if HAVE_NETINET_IP6_H
# include <netinet/ip6.h>
#endif
#if HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#include "compat.h"
#include "tag.h"
#include "flow.h"
#include "hash.h"
#include "main.h"
#include "display.h"

#ifndef IPV6_VERSION
# define IPV6_VERSION      0x60
# define IPV6_VERSION_MASK 0xf0
#endif

/* Compare two IPv6 addresses */
static int
in6addr_cmp(a, b)
	const void *a;
	const void *b;
{
	const struct in6_addr *ia = (const struct in6_addr *)a;
	const struct in6_addr *ib = (const struct in6_addr *)b;

	return memcmp(ia, ib, sizeof (struct in6_addr));
}

/* Compute a hash value of an IPv6 address */
static unsigned int
in6addr_hash(a)
	const void *a;
{
	const struct in6_addr *ia = (const struct in6_addr *)a;

	return hash_generic(ia, sizeof *ia);
}

static struct hash ip6_hash = {
	in6addr_cmp,		/* cmp */
	in6addr_hash,		/* hashfn */
	(free_t)free,		/* freaky */
	(free_t)free		/* freedata */
};

/* Look up an IP address */
const char *
ip6_lookup(addr)
	const struct in6_addr *addr;
{
	const char *result;
	static	int old_nflag = -1;
	static	int old_Fflag = -1;

	if (old_nflag != nflag || old_Fflag != Fflag) {
		hash_clear(&ip6_hash);
		old_nflag = nflag;
		old_Fflag = Fflag;
	}

	result = (const char *)hash_lookup(&ip6_hash, addr);
	if (result == NULL) {
		struct hostent *he;
		struct in6_addr *a2;
		const char *s;
		char *t;
		char buf[1024];

		if (nflag)
			he = NULL;
		else {
			display_message("resolving %s", 
			    inet_ntop(AF_INET6, addr, buf, sizeof buf));
			he = gethostbyaddr((char *)addr, sizeof *addr, 
			    AF_INET6);
			display_message("");
		}
		if (he == NULL)
			s = inet_ntop(AF_INET6, addr, buf, sizeof buf);
		else {
			if (!Fflag) {
				t = strchr(he->h_name, '.');
				if (t) *t = '\0';
			}
			s = he->h_name;
		}
		result = strdup(s);
		a2 = (struct in6_addr *)malloc(sizeof *addr);
		if (a2 == NULL)
			errx(1, "malloc");
		memcpy(a2, addr, sizeof *a2);
		hash_store(&ip6_hash, a2, result);
	}
	return result;
}

const char *
ip6_tag(p, end)
	const char *p;
	const char *end;
{
	const struct ip6_hdr *ip6;
	static char tag[TAGLEN];

	ip6 = (struct ip6_hdr *)p;
	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION) {
		snprintf(tag, sizeof tag, "ip6 version %u",
		    ip6->ip6_vfc & IPV6_VERSION_MASK);
		return tag;
	}
	switch (ip6->ip6_nxt) {
	case IPPROTO_TCP:
		return tcp_tag(p + sizeof *ip6, end, NULL, ip6);
	case IPPROTO_UDP:
		return udp_tag(p + sizeof *ip6, end, NULL, ip6);
	case IPPROTO_ICMPV6:
		/* XXX */
		snprintf(tag, sizeof tag, "icmp6 %s",
		    tag_combine(ip6_lookup(&ip6->ip6_src),
		    ip6_lookup(&ip6->ip6_dst)));
		return tag;
	default:
		snprintf(tag, sizeof tag, "ip6 %s proto %u",
		    tag_combine(ip6_lookup(&ip6->ip6_src),
		    ip6_lookup(&ip6->ip6_dst)), ip6->ip6_nxt);
		return tag;
	}
}

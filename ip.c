/* David Leonard, 2002. Public domain. */
/* $Id$ */

#include <pcap.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "tag.h"
#include "hash.h"

extern int nflag;

static int
inaddr_cmp(a, b)
	const void *a;
	const void *b;
{
	const struct in_addr *ia = (const struct in_addr *)a;
	const struct in_addr *ib = (const struct in_addr *)b;

	return memcmp(ia, ib, sizeof (struct in_addr));
}

static unsigned int
inaddr_hash(a)
	const void *a;
{
	const struct in_addr *ia = (const struct in_addr *)a;

	return ia->s_addr;
}

static struct hash ip_hash = { inaddr_cmp, inaddr_hash };

/* Look up an IP address */
const char *
ip_lookup(addr)
	const struct in_addr *addr;
{
	const char *result;

	result = (const char *)hash_lookup(&ip_hash, addr);
	if (result == NULL) {
		struct hostent *he;
		struct in_addr *a2;
		char *s;

		if (nflag)
			he = NULL;
		else
			he = gethostbyaddr((char *)addr, sizeof *addr, AF_INET);
		if (he == NULL)
			s = inet_ntoa(*addr);
		else {
			char *t = strchr(he->h_name, '.');
			if (t) *t = '\0';
			s = he->h_name;
		}
		result = strdup(s);
		a2 = (struct in_addr *)malloc(sizeof *addr);
		memcpy(a2, addr, sizeof *a2);
		hash_store(&ip_hash, a2, result);
	}
	return result;
}

const char *
ip_tag(p, end)
	const char *p;
	const char *end;
{
	const struct ip *ip;
	static char tag[256];
	int hlen;

	ip = (struct ip *)p;
	if (ip->ip_v != IPVERSION) {
		snprintf(tag, sizeof tag, "ip version %u", ip->ip_v);
		return tag;
	}
	hlen = ip->ip_hl << 2;
	switch(ip->ip_p) {
	case IPPROTO_TCP:
		return tcp_tag(p + hlen, p + ip->ip_len, ip);
	case IPPROTO_UDP:
		return udp_tag(p + hlen, p + ip->ip_len, ip);
	case IPPROTO_ICMP:
		return icmp_tag(p + hlen, p + ip->ip_len, ip);
	default:
		snprintf(tag, sizeof tag, "ip proto %x %s", ip->ip_p,
		    tag_combine(ip_lookup(&ip->ip_src),
		    ip_lookup(&ip->ip_dst)));
		return tag;
	}
}

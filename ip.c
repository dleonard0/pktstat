/* David Leonard, 2002. Public domain. */
/* $Id$ */

/* Internet protocol version 4 */

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
#include "main.h"
#include "display.h"

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

static struct hash ip_hash = {
	inaddr_cmp,	/* cmp */
	inaddr_hash,	/* hashfn */
	(free_t)free,	/* freekey */
	(free_t)free	/* freedata */
};

void
ip_reset()
{
	hash_clear(&ip_hash);
}

/* Look up an IP address */
const char *
ip_lookup(addr)
	const struct in_addr *addr;
{
	const char *result;
	static	int old_nflag = -1;
	static	int old_Fflag = -1;

	if (old_nflag != nflag || old_Fflag != Fflag) {
		ip_reset();
		old_nflag = nflag;
		old_Fflag = Fflag;
	}

	result = (const char *)hash_lookup(&ip_hash, addr);
	if (result == NULL) {
		struct hostent *he;
		struct in_addr *a2;
		char *s, *t;

		if (nflag)
			he = NULL;
		else {
			display_message("resolving %s", inet_ntoa(*addr));
			he = gethostbyaddr((char *)addr, sizeof *addr, AF_INET);
			display_message("");
		}
		if (he == NULL)
			s = inet_ntoa(*addr);
		else {
			if (!Fflag) {
				t = strchr(he->h_name, '.');
				if (t) *t = '\0';
			}
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
	const char *tcpend;
	static char tag[256];
	int hlen;

	ip = (struct ip *)p;
	if (ip->ip_v != IPVERSION) {
		snprintf(tag, sizeof tag, "ip version %u", ip->ip_v);
		return tag;
	}
	hlen = ip->ip_hl << 2;
	tcpend = p + ntohs(ip->ip_len);
	if (end < tcpend)
		tcpend = end;
	switch(ip->ip_p) {
	case IPPROTO_TCP:
		return tcp_tag(p + hlen, tcpend, ip, NULL);
	case IPPROTO_UDP:
		return udp_tag(p + hlen, tcpend, ip, NULL);
	case IPPROTO_ICMP:
		return icmp_tag(p + hlen, tcpend, ip);
	case IPPROTO_IGMP:
		snprintf(tag, sizeof tag, "igmp %s", 
		    tag_combine(ip_lookup(&ip->ip_src), ip_lookup(&ip->ip_dst))
		);
		return tag;
	default:
		snprintf(tag, sizeof tag, "ip proto %u %s", ip->ip_p,
		    tag_combine(ip_lookup(&ip->ip_src),
		    ip_lookup(&ip->ip_dst)));
		return tag;
	}
}

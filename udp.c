/* David Leonard, 2002. Public domain. */
/* $Id$ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#if defined(__linux__)
# define __FAVOR_BSD
#endif
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "tag.h"
#include "hash.h"
#include "main.h"
#include "display.h"

static int
udp_cmp(a, b)
	const void *a;
	const void *b;
{
	const u_int16_t*ia = (const u_int16_t*)a;
	const u_int16_t*ib = (const u_int16_t*)b;

	return *ia - *ib;
}

static unsigned int
udp_hash(a)
	const void *a;
{
	const u_int16_t*ia = (const u_int16_t*)a;

	return *ia;
}

static struct hash udp_hashtab = {
	udp_cmp,		/* cmp */
	udp_hash,		/* hashfn */
	(free_t)free,		/* freekey */
	(free_t)free		/* freedata */
};

void
udp_reset()
{
	hash_clear(&udp_hashtab);
}

/* Look up an IP address */
const char *
udp_lookup(port)
	u_int16_t port;
{
	const char *result;
	static int oldnflag = -1;

	if (oldnflag != nflag) {
		udp_reset();
		oldnflag = nflag;
	}

	result = (const char *)hash_lookup(&udp_hashtab, &port);
	if (result == NULL) {
		struct servent *se;
		u_int16_t *a2;
		char buf[32];

		if (nflag)
			se = NULL;
		else {
			display_message("resolving udp port %u", port);
			se = getservbyport(htons(port), "udp");
			display_message("");
		}
		if (se == NULL) {
			snprintf(buf, sizeof buf, "%u", port);
			result = buf;
		} else
			result = se->s_name;
		result = strdup(result);
		a2 = (u_int16_t *)malloc(sizeof (u_int16_t));
		*a2 = port;
		hash_store(&udp_hashtab, a2, result);
	}
	return result;
}

const char *
udp_tag(p, end, ip, ip6)
	const char *p;
	const char *end;
	const struct ip *ip;
	const struct ip6_hdr *ip6;
{
	static char src[32], dst[32];
	static char tag[256];
	struct udphdr *udp = (struct udphdr *)p;
	u_int16_t sport = ntohs(udp->uh_sport);
	u_int16_t dport = ntohs(udp->uh_dport);

	if (ip) {
		snprintf(src, sizeof src, "%s:%s", 
			ip_lookup(&ip->ip_src), udp_lookup(sport));
		snprintf(dst, sizeof dst, "%s:%s", 
			ip_lookup(&ip->ip_dst), udp_lookup(dport));
		snprintf(tag, sizeof tag, "udp %s", tag_combine(src, dst));
	}
	if (ip6) {
		snprintf(src, sizeof src, "%s:%s", 
			ip6_lookup(&ip6->ip6_src), udp_lookup(sport));
		snprintf(dst, sizeof dst, "%s:%s", 
			ip6_lookup(&ip6->ip6_dst), udp_lookup(dport));
		snprintf(tag, sizeof tag, "udp6 %s", tag_combine(src, dst));
	}

	return tag;
}


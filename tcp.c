/* David Leonard, 2002. Public domain. */
/* $Id$ */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "tag.h"
#include "hash.h"

extern int nflag;

static int
tcp_cmp(a, b)
	const void *a;
	const void *b;
{
	const u_int16_t*ia = (const u_int16_t*)a;
	const u_int16_t*ib = (const u_int16_t*)b;

	return *ia - *ib;
}

static unsigned int
tcp_hash(a)
	const void *a;
{
	const u_int16_t*ia = (const u_int16_t*)a;

	return *ia;
}

static struct hash tcp_hashtab = { tcp_cmp, tcp_hash };

/* Look up an IP address */
const char *
tcp_lookup(port)
	u_int16_t port;
{
	const char *result;

	result = (const char *)hash_lookup(&tcp_hashtab, &port);
	if (result == NULL) {
		struct servent *se;
		u_int16_t *a2;
		char buf[32];

		if (nflag)
			se = NULL;
		else
			se = getservbyport(port, "tcp");
		if (se == NULL) {
			snprintf(buf, sizeof buf, "%u", port);
			result = buf;
		} else
			result = se->s_name;
		result = strdup(result);
		a2 = (u_int16_t *)malloc(sizeof (u_int16_t));
		*a2 = port;
		hash_store(&tcp_hashtab, a2, result);
	}
	return result;
}

const char *
tcp_tag(p, end, ip)
	const char *p;
	const char *end;
	const struct ip *ip;
{
	static char src[32], dst[32];
	static char tag[256];
	struct tcphdr *tcp = (struct tcphdr *)p;

	snprintf(src, sizeof src, "%s:%s", 
		ip_lookup(&ip->ip_src), tcp_lookup(tcp->th_sport));
	snprintf(dst, sizeof src, "%s:%s", 
		ip_lookup(&ip->ip_dst), tcp_lookup(tcp->th_dport));
	snprintf(tag, sizeof tag, "tcp %s", tag_combine(src, dst));
	return tag;
}

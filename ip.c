/* David Leonard, 2002. Public domain. */
/* $Id$ */

/* Internet protocol version 4 */

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
#if HAVE_NETINET_IP_H
# include <netinet/ip.h>
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
#include "frag.h"

static int inaddr_cmp(const void *a, const void *b);
static unsigned int inaddr_hash(const void *a);
static const char *ip_fragment(const char *p, const char *end, 
		u_int16_t offset);
static const char *ip_pkt_tag(const char *p, const char *end);

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

static struct fragtab *ip_fragtab = NULL;

void
ip_reset()
{
	hash_clear(&ip_hash);
	if (ip_fragtab) {
		fragtab_free(ip_fragtab);
		ip_fragtab = NULL;
	}
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
#if HAVE_GETHOSTBYADDR
			display_message("resolving %s", inet_ntoa(*addr));
			he = gethostbyaddr((char *)addr, sizeof *addr, AF_INET);
			display_message("");
#else
			he = NULL;
#endif
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
		if (a2 == NULL)
			errx(1, "malloc");
		memcpy(a2, addr, sizeof *a2);
		hash_store(&ip_hash, a2, result);
	}
	return result;
}

/* Handle a fragment */
static const char *
ip_fragment(p, end, offset)
	const char *p;
	const char *end;
	u_int16_t offset;
{
	const struct ip *ip = (const struct ip *)p;
	struct ipfkey {
		struct in_addr src, dst;
		u_int16_t id;
	} ipfkey;
	u_int16_t next_offset;
	int paylen = ntohs(ip->ip_len) - (ip->ip_hl << 2);
	const char *tag;

	memcpy(&ipfkey.src, &ip->ip_src, sizeof ipfkey.src);
	memcpy(&ipfkey.dst, &ip->ip_dst, sizeof ipfkey.dst);
	memcpy(&ipfkey.id, &ip->ip_id, sizeof ipfkey.id);

	if (offset & IP_MF) {
		if (paylen & 7)
			return "ip fragments";	/* bad length */
		next_offset = (offset & IP_OFFMASK) + (paylen >> 3);
	} else
		next_offset = 0;

	if (ip_fragtab == NULL)
		ip_fragtab = fragtab_new(sizeof ipfkey, 1024);
	fragtab_put(ip_fragtab, &ipfkey, p, end - p, offset & IP_OFFMASK,
		next_offset);

	if ((offset & IP_OFFMASK) == 0)
		tag = ip_pkt_tag(p, end);
	else {
		size_t len;
		char *dp;
		dp = (char *)fragtab_get(ip_fragtab, &ipfkey, 0, &len);
		if (dp)
			tag = ip_pkt_tag(dp, dp + len);
		else
			tag = "ip fragments";	/* out of order! */
	}
		
if (!ip_fragtab) abort();
	if (fragtab_check(ip_fragtab, &ipfkey, 0, 0)) {
		fragtab_del(ip_fragtab, &ipfkey);
	}
	return tag;
}

static const char *
ip_pkt_tag(p, end)
	const char *p;
	const char *end;
{
	const struct ip *ip = (const struct ip *)p;
	const char *pktend;
	static char tag[TAGLEN];
	int hlen;

	pktend = p + ntohs(ip->ip_len);
	if (end < pktend)
		pktend = end;
	hlen = ip->ip_hl << 2;

	switch(ip->ip_p) {
	case IPPROTO_TCP:
		return tcp_tag(p + hlen, pktend, ip, NULL);
	case IPPROTO_UDP:
		return udp_tag(p + hlen, pktend, ip, NULL);
	case IPPROTO_ICMP:
		return icmp_tag(p + hlen, pktend, ip);
	case IPPROTO_IGMP:
		snprintf(tag, sizeof tag, "igmp %s", 
		    tag_combine(ip_lookup(&ip->ip_src), ip_lookup(&ip->ip_dst))
		);
		return tag;
	case IPPROTO_IPV6:	/* RFC1933 4.1.5 */
		snprintf(tag, sizeof tag, "ip %s", ip6_tag(p + hlen, end));
		/*
		 * XXX should we include the ipv4 encap src/dest in the tag??
		 * If we do, the tag looks cluttered... I think we are more
		 * interested in what the content of the data is, rather
		 * than how the data is encoded.
		 */
		return tag;
	default:
		snprintf(tag, sizeof tag, "ip proto %u %s", ip->ip_p,
		    tag_combine(ip_lookup(&ip->ip_src),
		    ip_lookup(&ip->ip_dst)));
		return tag;
	}
}

const char *
ip_tag(p, end)
	const char *p;
	const char *end;
{
	const struct ip *ip = (struct ip *)p;
	u_int16_t offset;
	static char tag[TAGLEN];

	if (ip->ip_v != IPVERSION) {
		snprintf(tag, sizeof tag, "ip version %u", ip->ip_v);
		return tag;
	}

	offset = ntohs(ip->ip_off);
	if ((offset & (IP_MF | IP_OFFMASK)) != 0)
		return ip_fragment(p, end, offset);

	return ip_pkt_tag(p, end);
}


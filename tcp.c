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
#include "flow.h"
#include "main.h"

static void link_ftp_eport(const char *, const char *, const char *, 
	const struct in_addr *);
static void link_ftp_port(const char *, const char *, const char *);

/* a hack to remember recent FTP port commands */
static struct {
    char ctltag[80];
    char datatag[80];
    struct in_addr addr;
    u_int16_t port;
} ftp;

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
			se = getservbyport(htons(port), "tcp");
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
	struct flow *f = NULL;
	u_int16_t sport = ntohs(tcp->th_sport);
	u_int16_t dport = ntohs(tcp->th_dport);

	snprintf(src, sizeof src, "%s:%s", 
		ip_lookup(&ip->ip_src), tcp_lookup(sport));
	snprintf(dst, sizeof src, "%s:%s", 
		ip_lookup(&ip->ip_dst), tcp_lookup(dport));
	snprintf(tag, sizeof tag, "tcp %s", tag_combine(src, dst));

	/* mark some flows as long-lived so we can preserve desc state */
	if ((tcp->th_flags & (TH_SYN|TH_FIN|TH_RST)) != 0) {
		f = findflow(tag);
		if ((tcp->th_flags & TH_SYN) != 0)
			f->dontdel = 1;
		if ((tcp->th_flags & (TH_FIN|TH_RST)) != 0) {
			f->dontdel = 0;	/* can reclaim now */
			/* f->desc[0] = '\0'; */ /* keep the url around */
		}
	}

	/* XXX HTTP */
	if (dport == 80 || dport == 8080 || dport == 3128) {
		const char *data = p + (tcp->th_off << 2);
		const char *d;
		if (memcmp(data, "GET ", 4) == 0 ||
		    memcmp(data, "POST ", 5) == 0 ||
		    memcmp(data, "HEAD ", 5) == 0) {
			if (!f)
				f = findflow(tag);
			for (d = data; d < end && *d != ' '; d++)
				;
			if (d < end)
				d++;
			for (; d < end && *d != '\r' && *d != ' ' 
			    && *d != ';'; d++)
				;
			snprintf(f->desc, sizeof f->desc, "%.*s",
				d - data, data);
	        }
	}

	/* XXX FTP - RFC2428 */
	if (dport == 21) {
		const char *data = p + (tcp->th_off << 2);
		const char *d;
		if (memcmp(data, "RETR ", 5) == 0 ||
		    memcmp(data, "STOR ", 5) == 0 ||
		    memcmp(data, "NLST ", 5) == 0 ||
		    memcmp(data, "ABOR ", 5) == 0 ||
		    memcmp(data, "LIST ", 5) == 0) {
			if (!f)
				f = findflow(tag);
			for (d = data; d < end && *d != '\r' && *d != '\n'; d++)
				;
			snprintf(f->desc, sizeof f->desc, "%.*s",
				 d - data, data);
			/* Copy the desc to the data flow if it is known */
			if (ftp.datatag[0] != '\0'  &&
			    strcmp(ftp.ctltag, tag) == 0)
			{
			    struct flow *f2 = findflow(ftp.datatag);
			    snprintf(f2->desc, sizeof f2->desc,
				"ftp-data: %.*s", d - data - 5, data + 5);
			    ftp.ctltag[0] = '\0';
			    ftp.datatag[0] = '\0';
			}
	        }
		if (memcmp(data, "PORT ", 5) == 0) 
			link_ftp_port(data + 5, tag, end);
		if (memcmp(data, "EPRT ", 5) == 0) 
			link_ftp_eport(data + 5, tag, end, &ip->ip_src);
	}

	if (sport == 21) {
	    const char *d = p + (tcp->th_off << 2);
	    if (memcmp(d, "227 ", 4) == 0) {
		while (d < end && *d != '(')
			d++;
		if (++d < end)
			link_ftp_port(d, tag, end);
	    }
	    else if (memcmp(d, "229 ", 4) == 0) {
		while (d < end && *d != '(')
			d++;
		if (++d < end)
			link_ftp_eport(d, tag, end, &ip->ip_src);
	    }
	}

	/* Try to complete an FTP association */
	if (ftp.datatag[0] == '\0' && ftp.ctltag[0] != '\0' && 
	     ip->ip_dst.s_addr == ftp.addr.s_addr && dport == ftp.port)
	{
		/* Complete association so that future descs are copied */
		strncpy(ftp.datatag, tag, sizeof ftp.datatag);
	}

	return tag;
}

/*
 * Parse and remember the port address so that we can associate it
 * back to the control flow
 */
static void
link_ftp_port(d, tag, end)
	const char *d;
	const char *tag;
	const char *end;
{
	union {
	    struct in_addr addr;
	    unsigned char a[4];
	} ua;
	union {
	    u_int16_t port;
	    unsigned char a[2];
	} up;
	char buf[256], *b;
	unsigned int v[6];

	for (b = buf; d < end && b < buf+1+sizeof buf && 
	    *d != ')' && *d != '\r';)
		*b++ = *d++;
	*b = '\0';

	if (sscanf(buf, "%u,%u,%u,%u,%u,%u", v+0,v+1,v+2,v+3,v+4,v+5) == 6)
	{
	    ua.a[0] = v[0];
	    ua.a[1] = v[1];
	    ua.a[2] = v[2];
	    ua.a[3] = v[3];
	    up.a[0] = v[4];
	    up.a[1] = v[5];
	    ftp.port = ntohs(up.port);
	    ftp.addr = ua.addr;
	    strncpy(ftp.ctltag, tag, sizeof ftp.ctltag);
	    ftp.datatag[0] = '\0';
	}
}


static void
link_ftp_eport(d, tag, end, defaddr)
	const char *d;
	const char *tag;
	const char *end;
	const struct in_addr *defaddr;
{
        struct in_addr addr;
	unsigned int port;
	char buf[256], *b;
	char delim;

	for (b = buf; d < end && b < buf+1+sizeof buf && 
	    *d != ')' && *d != '\r';)
		*b++ = *d++;
	*b = '\0';

	delim = buf[0];
	if (buf[1] == delim && buf[2] == delim && defaddr) {
		addr.s_addr = defaddr->s_addr;
		if (sscanf(buf + 3, "%u", &port) != 1)
			return;
		goto gotit;
	}

	if (buf[1] != '1' || buf[2] != delim)	/* only handle AF_INET */
		return;

	b = buf+3;
	while (*b && *b != delim)
		b++;
	if (!*b) return;
	*b++ = '\0';
	if (sscanf(b, "%u", &port) != 1)
		return;
	addr.s_addr = inet_addr(buf+3);
gotit:
	ftp.port = port;
	ftp.addr = addr;
	strncpy(ftp.ctltag, tag, sizeof ftp.ctltag);
	ftp.datatag[0] = '\0';
}

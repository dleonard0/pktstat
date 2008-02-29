/* David Leonard, 2002. Public domain. */
/* $Id$ */

/*
 * A flow is a grouped history of packets with some similarity.
 * Each flow is uniquely identified by a 'tag', which is
 * descriptive string. Some flows have extra descriptive
 * information, like FTP transferred file names. Flow data
 * structures are supposed to hang around for a while, even
 * if no packet activity in that flow has been seen.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#if STDC_HEADERS
# include  <string.h>
# include  <stdlib.h>
#endif
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "compat.h"
#include "flow.h"

int nflows = 0;
struct flow *flows;
static int maxflows = 0;

/* Generate a hash value for a tag */
static unsigned int
hash(tag)
	const char *tag;
{
	unsigned int result;

	for (result = 0; *tag; tag++) 
		result = (result << 1) ^ *tag;
	return result;
}

#define MAXFLOWS 1024

/* Find a flow by its tag */
struct flow *
findflow(tag)
	const char *tag;
{
	int i;
	unsigned int taghash = hash(tag);

	for (i = 0; i < nflows; i++)
		if (flows[i].taghash == taghash
		    && strcmp(flows[i].tag, tag) == 0)
			return &flows[i];
	if (nflows >= maxflows) {
		if (maxflows == 0) {
			maxflows = 8;
			flows = (struct flow *)malloc(maxflows * sizeof *flows);
		} else if (maxflows < MAXFLOWS) {
			if (maxflows * 2 <= MAXFLOWS)
			    maxflows *= 2;
			else 
			    maxflows = MAXFLOWS;
			flows = (struct flow *)realloc(flows,
			    maxflows * sizeof *flows);
		} else {
		    flow_del(&flows[nflows - 1]);
		}
		if (flows == NULL)
			errx(1, "malloc/realloc");	
	}
	flows[nflows].taghash = taghash;
	strlcpy(flows[nflows].tag, tag, sizeof flows[nflows].tag);
	flows[nflows].desc[0] = '\0';
	flows[nflows].octets = 0;
	flows[nflows].total_octets = 0;
	flows[nflows].packets = 0;
	flows[nflows].total_packets = 0;
	flows[nflows].keepalive = -1;
	flows[nflows].dontdel = 0;
	flows[nflows].udata = NULL;
	flows[nflows].freeudata = NULL;
	return &flows[nflows++];
}

/* Compare flows by the number of octets they have carried (reverse order) */
int
octetcmp(a, b)
	const void *a;
	const void *b;
{
	const struct flow *fa = (const struct flow *)a;
	const struct flow *fb = (const struct flow *)b;
	return -(fa->octets - fb->octets);
}

/* Compare flows by their tag */
int
tagcmp(a, b)
	const void *a;
	const void *b;
{
	const struct flow *fa = (const struct flow *)a;
	const struct flow *fb = (const struct flow *)b;
	return strcmp(fa->tag, fb->tag);
}

/* Compare flows by the time they were last seen (reverse order) */
int
lastcmp(a, b)
	const void *a;
	const void *b;
{
	const struct flow *fa = (const struct flow *)a;
	const struct flow *fb = (const struct flow *)b;
	if (fb->lastseen.tv_sec - fa->lastseen.tv_sec == 0)
		if (fb->lastseen.tv_usec - fa->lastseen.tv_usec == 0)
			return tagcmp(a, b);
		else
			return fb->lastseen.tv_usec - fa->lastseen.tv_usec;
	else
		return fb->lastseen.tv_sec - fa->lastseen.tv_sec;
}

/* Compare flows by their packet count (reverse order) */
int
packetcmp(a, b)
	const void *a;
	const void *b;
{
	const struct flow *fa = (const struct flow *)a;
	const struct flow *fb = (const struct flow *)b;
	return fa->packets - fb->packets;
}

/* Zero the octet count on all flows */
void
flow_zero()
{
	int i;

	for (i = 0; i < nflows; i++) {
		flows[i].octets = 0;
		flows[i].packets = 0;
	}
}

/* Remove a flow */
void
flow_del(f)
	struct flow *f;
{
	int i = f - flows;

	if (f->freeudata)
		(*f->freeudata)(f->udata);
	if (nflows > 1 && i != nflows -1) {
		memcpy(f, &flows[nflows-1], sizeof (struct flow));
	}
	nflows--;
}

void
flow_free()
{
	while (nflows)
	    flow_del(flows + nflows - 1);
	if (maxflows) {
	    free(flows);
	    maxflows = 0;
	}
}

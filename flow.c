/* David Leonard, 2002. Public domain. */
/* $Id$ */

#include <string.h>
#include <stdlib.h>
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
			maxflows = 128;
			flows = (struct flow *)malloc(maxflows * sizeof *flows);
		} else {
			maxflows *= 2;
			flows = (struct flow *)realloc(flows,
			    maxflows * sizeof *flows);
		}
	}
	flows[nflows].taghash = taghash;
	strncpy(flows[nflows].tag, tag, sizeof flows[nflows].tag);
	flows[nflows].desc[0] = '\0';
	flows[nflows].octets = 0;
	flows[nflows].total_octets = 0;
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

/* Zero the octet count on all flows */
void
flow_zero()
{
	int i;

	for (i = 0; i < nflows; i++)
		flows[i].octets = 0;
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

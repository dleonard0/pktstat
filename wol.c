/* David Leonard, 2004. Public domain. */
/* $Id$ */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#if STDC_HEADERS
# include <stdio.h>
# include <string.h>
#endif

#include "type.h"
#include "tag.h"
#include "flow.h"

#define MINLEN (6 + 6 * 16)
#define MACFMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MACVAL(p) \
		(unsigned char)((p)[0]), \
		(unsigned char)((p)[1]), \
		(unsigned char)((p)[2]), \
		(unsigned char)((p)[3]), \
		(unsigned char)((p)[4]), \
		(unsigned char)((p)[5])


/*
 * Wake-on-LAN (aka AMD Magic Packet) is an unusual packet pattern
 * that we detect early, before higher protocols. They can be broadcast
 * raw, or even routed, but for ethernet we assume the sender's MAC
 * is at the beginning.
 */
const char *
ether_wol(p, end, src)
	const char *p;
	const char *end;
	const char *src;
{
	static const unsigned char 
            magic[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
	    bad1[6] =  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	    bad2[6] =  { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        static char tag[TAGLEN];
	const char *q;

	for (q = p; q + MINLEN <= end; q++)  {
	    const char *b = q + 6;
	    if (memcmp(q, magic, 6) == 0 &&
		memcmp(b, b+(6*1), 6*1) == 0 &&
		memcmp(b, b+(6*2), 6*2) == 0 &&
		memcmp(b, b+(6*4), 6*4) == 0 &&
		memcmp(b, b+(6*8), 6*8) == 0 &&
		memcmp(b, bad1, 6) != 0 &&
		memcmp(b, bad2, 6) != 0)
	    {
		snprintf(tag, sizeof tag, 
		    "wol " MACFMT " -> " MACFMT,
		    MACVAL(src), MACVAL(b));
		return tag;
	    }
	}
	return NULL;
}

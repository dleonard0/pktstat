/* David Leonard, 2002. Public domain. */
/* $Id$ */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>

/*
#ifdef BSD
struct arphdr { int ignore; };
#endif
struct ifnet { int ignore; };

#include <sys/queue.h>
#include <netinet/in.h>
*/

#include <netipx/ipx.h>

#include "tag.h"

static struct {
	u_int8_t pt;
	const char *name;
} prototab[] = {
	{ IPXPROTO_RI,		"ripx" },
	{ IPXPROTO_PXP,		"pxp" },
	{ IPXPROTO_SPX,		"spx" },
	{ IPXPROTO_NCP,		"ncp" },
	{ IPXPROTO_NETBIOS,	"netbios" }
};
#define nproto (sizeof prototab / sizeof prototab[0])

const char *
ipx_tag(p, end)
	const char *p, *end;
{
	struct ipx h;
	static char tag[256];
	char src[64], dst[64], pt[64];
	int i;
	const char *ptname;

	memcpy(&h, p, sizeof h);
	snprintf(dst, sizeof src, "%s", ipx_ntoa(h.ipx_dna));
	snprintf(src, sizeof src, "%s", ipx_ntoa(h.ipx_sna));

	ptname = NULL;
	for (i = 0; i < sizeof prototab / sizeof prototab[0]; i++)
		if (prototab[i].pt == h.ipx_pt) {
			ptname = prototab[i].name;
			break;
		}
	if (!ptname) {
		snprintf(pt, sizeof pt, "%02x", h.ipx_pt);
		ptname = pt;
	}
	snprintf(tag, sizeof tag, "ipx %s %s -> %s", ptname, src, dst);
	return tag;
}

/* 
 * NOTES
 * - http://www.protocols.com/pbook/novel.htm
 * - 802.2 over IPX: RFC1132
 */

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

#if defined(__linux__)
#define IPXPROTO_UNKWN          IPX_TYPE_UNKNOWN
#define IPXPROTO_RI             IPX_TYPE_RIP
#define IPXPROTO_PXP            IPX_TYPE_SAP
#define IPXPROTO_SPX            IPX_TYPE_SPX
#define IPXPROTO_NCP            IPX_TYPE_NCP
#define IPXPROTO_NETBIOS        IPX_TYPE_PPROP
/* field name translations for 'struct ipxhdr' */
#define ipx_sum ipx_checksum
#define ipx_len	ipx_pktsize
#define ipx_tc	ipx_tctrl
#define ipx_pt	ipx_type
#define ipx_dna	ipx_dest
#define ipx_sna	ipx_source
#endif

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

#if defined(__linux__)
/* Convert ipx addr to string. (isn't there one in libc?) */
static const char *
ipx_ntoa(addr)
	ipx_address	addr;
{
	static char buf[] = "00000000:000000000000:0000";

	snprintf(buf, sizeof buf, 
		"%08lX:%02X%02X%02X%02X%02X%02X:%04X",
		(unsigned long) htonl(addr.net),
		addr.node[0], addr.node[1], addr.node[2],
		addr.node[3], addr.node[4], addr.node[5],
		htons(addr.sock));
	return buf;
}
#endif

const char *
ipx_tag(p, end)
	const char *p, *end;
{
#if defined(__linux__)
	struct ipxhdr h;
#else /* BSD */
	struct ipx h;
#endif
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

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
# if 1 /* linux is a dog's breakfast */
/* Because of the insanity of linux distros, we have to declare the
 * ipx header structure here. EVEN THOUGH THE KERNEL KNOWS IT.
 */
/* (these defines from OpenBSD <netipx/ipx.h>) */
#define IPXPROTO_UNKWN          0       /* Unknown */
#define IPXPROTO_RI             1       /* RIP Routing Information */
#define IPXPROTO_PXP            4       /* IPX Packet Exchange Protocol */
#define IPXPROTO_SPX            5       /* SPX Sequenced Packet */
#define IPXPROTO_NCP            17      /* NCP NetWare Core */
#define IPXPROTO_NETBIOS        20      /* Propagated Packet */
#define XXX     __attribute__((__packed__))
typedef struct {
	u_int32_t	net	XXX;
	u_int8_t	node[6] XXX;
	u_int16_t	sock	XXX;
} ipx_address, ipx_addr_t;
struct ipxhdr {
        u_int16_t       ipx_sum XXX;    /* Checksum */
        u_int16_t       ipx_len XXX;    /* Length, in bytes, including header */
        u_int8_t        ipx_tc  XXX;    /* Transport Control (i.e. hop count) */
        u_int8_t        ipx_pt  XXX;    /* Packet Type (i.e. lev 2 protocol) */
        ipx_addr_t      ipx_dna XXX;    /* Destination Network Address */
        ipx_addr_t      ipx_sna XXX;    /* Source Network Address */
};
# else /* linux is cool */
/*
 * kernel.org tarballs contain include/linux/ipx.h which only needs
 * these defines to make IPX header structures available.
 */
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
# endif /* the nightmare */
#endif /* linux */

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
/* Convert ipx addr to string. (why isn't there one in libc?) */
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

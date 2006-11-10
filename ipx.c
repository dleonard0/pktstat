/* David Leonard, 2002. Public domain. */
/* $Id$ */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#if STDC_HEADERS
# include <stdio.h>
# include <string.h>
#endif
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#if HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#if HAVE_NETIPX_IPX_H
# include <netipx/ipx.h>
#endif
#if HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#include "compat.h"
#include "tag.h"
#include "flow.h"

#ifndef IPXPROTO_UNKWN
# ifndef IPX_TYPE_UNKNOWN
/* (these defines from OpenBSD <netipx/ipx.h>) */
#  define IPXPROTO_UNKWN          0       /* Unknown */
#  define IPXPROTO_RI             1       /* RIP Routing Information */
#  define IPXPROTO_PXP            4       /* IPX Packet Exchange Protocol */
#  define IPXPROTO_SPX            5       /* SPX Sequenced Packet */
#  define IPXPROTO_NCP            17      /* NCP NetWare Core */
#  define IPXPROTO_NETBIOS        20      /* Propagated Packet */
#  define XXX     __attribute__((__packed__))
typedef struct {
	u_int32_t 	net		XXX;
	u_int8_t 	host[6] 	XXX;
	u_int16_t	port		XXX;
} ipx_address, ipx_addr_t;
struct ipxhdr {
        u_int16_t       ipx_sum XXX;    /* Checksum */
        u_int16_t       ipx_len XXX;    /* Length, in bytes, including header */
        u_int8_t        ipx_tc  XXX;    /* Transport Control (i.e. hop count) */
        u_int8_t        ipx_pt  XXX;    /* Packet Type (i.e. lev 2 protocol) */
        ipx_addr_t      ipx_dna XXX;    /* Destination Network Address */
        ipx_addr_t      ipx_sna XXX;    /* Source Network Address */
};
#  undef XXX
# else 
#  define IPXPROTO_UNKWN          IPX_TYPE_UNKNOWN
#  define IPXPROTO_RI             IPX_TYPE_RIP
#  define IPXPROTO_PXP            IPX_TYPE_SAP
#  define IPXPROTO_SPX            IPX_TYPE_SPX
#  define IPXPROTO_NCP            IPX_TYPE_NCP
#  define IPXPROTO_NETBIOS        IPX_TYPE_PPROP
/* field name translations for 'struct ipxhdr' */
#  define ipx_sum ipx_checksum
#  define ipx_len ipx_pktsize
#  define ipx_tc  ipx_tctrl
#  define ipx_pt  ipx_type
#  define ipx_dna ipx_dest
#  define ipx_sna ipx_source
# endif
#endif

static const char *my_ipx_ntoa(void *);

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

/*
 * Notes on the representation of IPX addresses
 * --------------------------------------------
 *
 * IPX addresses (unlike IP addresses) are essentially unstructured.
 * The format for display IPX addresses varies. Microsoft's WinSNMP parser
 * accepts one of '-', ':', '.' after the 8-digit hex net number.
 * (This is probably because RFC1298, section 2.4, describes just a raw string)
 *
 * Bowever, <http://netcert.tripod.com/ccna/internetworking/ipx.html>
 * gives '4a.0000.0c00.23fe' as an example. Novell themselves, in
 * <www.novell.com/documentation/lg/nw6p/ipx_enu/data/hvvqznoa.html>
 * give the example of 'FEDCBA98 1A2B3C5D7E9F 0453'.
 *
 * A discussion at <www.cs.helsinki.fi/linux/linux-kernel/2001-44/0742.html>
 * notes that ipx addresses look like hex floating point (ie xxx.xxx).
 * And a google-cached network course from boerner.net gives an example
 * IPX host address as '000008A2:0060973E97F3'.
 *
 * Cisco IOS reports IPX addresses in the 'dotted triplet' form,
 * with an example from a CCNA study guide given as '010a.0123.0123.0123'.
 * NetBSD's libc has an ipx_ntoa() that yields representations such as
 * '8A2H.00:60:97:3E:97:F3.65535'.
 *
 * Clearly, this is an insane and exciting world of mental trauma
 * that is as appealling as having a sharp pointy stick jabbed into your
 * eye. Because I am not that familiar with IPX, I would really
 * appreciate feedback/advice on this -- as long as the advice is 
 * NOT "let the user specify". I want to know what the best representation
 * to use for the expected users of pktstat would be. For now, I'll
 * use Cisco's representation, suffixed by a colon and the decimal port number.
 */
static const char *
my_ipx_ntoa(addr)
	void *addr;
{
	static char buf[] = "00000000.0000.0000.0000:0000";
	u_int32_t ipx_net;
	u_int8_t  ipx_host[6];
	u_int16_t ipx_port;

	memcpy(&ipx_net,  addr, 4);
	memcpy(&ipx_host, addr + 4, 6);
	memcpy(&ipx_port, addr + 10, 2);

	snprintf(buf, sizeof buf, 
		"%8lX.%02X%02X.%02X%02X.%02X%02X:%u",
		(unsigned long) ntohl(ipx_net),
		ipx_host[0], ipx_host[1], ipx_host[2],
		ipx_host[3], ipx_host[4], ipx_host[5],
		ntohs(ipx_port));
	return buf;
}

const char *
ipx_tag(p, end)
	const char *p, *end;
{
#if defined(__linux__)
	struct ipxhdr h;
#else /* BSD */
	struct ipx h;
#endif
	static char tag[TAGLEN];
	char src[TAGLEN], dst[TAGLEN], pt[TAGLEN];
	int i;
	const char *ptname;

	memcpy(&h, p, sizeof h);
	snprintf(dst, sizeof src, "%s", my_ipx_ntoa(&h.ipx_dna));
	snprintf(src, sizeof src, "%s", my_ipx_ntoa(&h.ipx_sna));

	ptname = NULL;
	for (i = 0; i < sizeof prototab / sizeof prototab[0]; i++)
		if (prototab[i].pt == h.ipx_pt) {
			ptname = prototab[i].name;
			break;
		}
	if (!ptname) {
		snprintf(pt, sizeof pt, "0x%02x", h.ipx_pt);
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

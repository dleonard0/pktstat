/* David Leonard, 2002. Public domain. */
/* $Id$ */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>

/* In order to avoid too many unneeded include files, we forge some types */
#ifdef BSD
struct arphdr { int ignore; };
#endif
struct ifnet { int ignore; };

#include <sys/queue.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#ifdef __linux__
#include <netinet/ether.h>
#endif

#include "tag.h"

static const char *llc_tag(const char *, const char *,
    const char *, const char *);
static const char *snap_tag(const char *, const char *);
static const char *ethertype(u_int16_t);

struct pppoe_header {
	u_int8_t	vertype;
	u_int8_t	code;
	u_int16_t	sessionid;
	u_int16_t	len;
};

/* Return the tag for an Ethernet II frame */

const char *
ether_tag(p, end)
        const char *p;
	const char *end;
{
	struct ether_header eh;
	struct pppoe_header ph;
	u_int16_t type;
	char src[] = "xx:xx:xx:xx:xx:xx";
	char dst[] = "xx:xx:xx:xx:xx:xx";

	memcpy(&eh, p, sizeof eh);	/* avoid bus alignment probs */

	/* In case someone wants the addrs: */
	snprintf(src, sizeof src, 
	    ether_ntoa((struct ether_addr *)&eh.ether_shost));
	snprintf(dst, sizeof dst, 
	    ether_ntoa((struct ether_addr *)&eh.ether_dhost));

	/* Skip any 802.1Q tag */
	type = ntohs(eh.ether_type);
	if (type == 0x8100) {
		memcpy(&eh.ether_type, p + 6 + 6 + 2 + 2, sizeof eh.ether_type);
		type = ntohs(eh.ether_type);
		p += 4;
	}
	p += ETHER_HDR_LEN;
	
	/*
	 * From IEEE Std 802.3 2000 edition:
	 *
	 * "3.2.6 Length/Type field
	 *  [...]
         *  a) If the value of this field is less than or equal to
         *  the value of maxValidFrame [0x5dc, from 4.2.7.1] then [it]
	 *  indicates the number of MAC client data octets contained in
         *  the subsequent data field of the frame {Length interpretation}.
	 *  
         *  b) If the value of this field is greater than or equal
         *  to 1536 decimal {equal to 0600 hexadecimal), then the
         *  Length/Type field indicates the nature of the MAC client
         *  protocol {Type interpretation}."
	 *
	 *  4.2.7.1 Common constants, types and variables
	 *  const
	 *    addressSize = [48 bits];
	 *    lengthOrTypeSize = 16;
	 *    crcSize = 32;
	 *    [...]
	 *    maxValidFrame = maxUntaggedFramSize - 
	 *      (2 * addressSize + lengthOrTypeSize + crcSize)/8;
	 *
	 *  4.4.2.1 [10Mb/s implementation]
	 *   maxUntaggedFrameSize = 1518 octets
	 *  [same for 100Mb/s and 1000Mb/s per sections 4.4.2.3 and 4]
	 * "
	 * Note: maxValidFrame = 1518-(2*48+16+32)/8 = 1500 = 0x05DC
	 */
	if (type <= 0x5DC)
		return llc_tag(p, end, src, dst);

	switch (type) {
	case ETHERTYPE_IP:
		return ip_tag(p, end);
#ifdef ETHERTYPE_IPV6
	case ETHERTYPE_IPV6:
		return ip6_tag(p, end);
#endif
#ifdef ETHERTYPE_PPPOE
	case ETHERTYPE_PPPOE:
		memcpy(&ph, p, sizeof ph);	/* avoid bus alignment probs */
		if (ph.code != 0)
			return "pppoe";
		return ppp_tag(p + sizeof ph, end);
#endif
	case 0x8137 /* ETHERTYPE_IPX */:
		return ipx_tag(p, end);
	default:
		return ethertype(type);
	}
}

/* 802.2 LLC SAP names */
static struct {
	u_int8_t	 sap;
	const char 	*name;
} saptab[] = {
	{ 0x00,	"null" },
	{ 0x06, "IP" },
	{ 0x42, "802.1d" },
	{ 0x7E, "X.25" },
	{ 0x80, "3Com" },
	{ 0xAA, "SNAP" },
	{ 0xBC, "Banyan" },
	{ 0xE0, "Novell" },
	{ 0xF4, "Lan Manager" },
	{ 0xFE, "CLNS" },
};

/* 802.2 LLC header */
static const char *
llc_tag(p, end, src, dst)
	const char *p, *end, *src, *dst;
{
	/* ANSI/IEEE Std 802.2 section 3.2 LLC PDU format */
	struct llc {
		u_int8_t  dsap, ssap;
		u_int8_t  control;
	} *h;
	char dsap_buf[5], ssap_buf[5];
	const char *dsap_name = NULL, *ssap_name = NULL;
	static char tag[80];

	int i;

	h = (struct llc *)p;

	/* "Raw" 802.3 */
	if (h->dsap == 0xff && h->ssap == 0xff)
		return ipx_tag(p + 14, end);

	p = p + sizeof h;

	if (p > end)
		return "llc short";

	/* Novell 802.3 with 802.2 headers */
	if (h->dsap == 0xe0 && h->ssap == 0xe0)
		return ipx_tag(p, end);

	/* TCP/IP over Novell */
	if (h->dsap == 0x06 && h->ssap == 0x06) 
		return ip_tag(p, end);

	/* Ethernet SNAP */
	if (h->dsap == 0xaa && h->ssap == 0xaa && h->control == 3) 
		return snap_tag(p, end);

	/* Convert the DSAP and SSAP fields to names */
	for (i = 0; i < sizeof saptab / sizeof saptab[0]; i++)
		if (saptab[i].sap == h->dsap) {
			dsap_name = saptab[i].name;
			break;
		}
	if (!dsap_name) {
		snprintf(dsap_buf, sizeof dsap_buf, "0x%02x", h->dsap);
		dsap_name = dsap_buf;
	}

	for (i = 0; i < sizeof saptab / sizeof saptab[0]; i++)
		if (saptab[i].sap == h->ssap) {
			ssap_name = saptab[i].name;
			break;
		}
	if (!ssap_name) {
		snprintf(ssap_buf, sizeof ssap_buf, "0x%02x", h->ssap);
		ssap_name = ssap_buf;
	}

	snprintf(tag, sizeof tag, "llc %s -> %s", ssap_name, dsap_name);
	return tag;
}

/* Ethertype names from RFC 1010 */
static struct {
	u_int16_t	type;
	const char	*name;
} ethertypetab[] = {
	{ 0x200,	"pup" },
	{ 0x600,	"idp" },
	{ 0x800,	"ip" },
	{ 0x801,	"x.75" },
	{ 0x802,	"nbs" },
	{ 0x803,	"ecma" },
	{ 0x804,	"chaos" },
	{ 0x805,	"x.25" },
	{ 0x806,	"arp" },
	{ 0x807,	"xns" },
	{ 0x81c,	"symbolics" },
	{ 0x81c,	"symbolics" },
	{ 0x1600,	"valid" },
	{ 0x5208,	"simnet" },
	{ 0x6001,	"mop" },
	{ 0x6002,	"mop" },
	{ 0x6003,	"decnet" },
	{ 0x6004,	"lat" },
	{ 0x6005,	"dec" },
	{ 0x6006,	"dec" },
	{ 0x8003,	"vln" },
	{ 0x8004,	"cronus" },
	{ 0x8005,	"hp" },
	{ 0x8006,	"nestar" },
	{ 0x8010,	"excelan" },
	{ 0x8035,	"rev-arp" },
	{ 0x8038,	"lanbridge" },
	{ 0x805b,	"svk" },
	{ 0x805c,	"svk" },
	{ 0x807c,	"merit" },
	{ 0x809b,	"appletalk" },
	{ 0x9000,	"loopback" },
};

static const char *
ethertype(type)
	u_int16_t type;
{
	int i;
	static char buf[40];

	for (i = 0; i < sizeof ethertypetab / sizeof ethertypetab[0]; i++)
		if (ethertypetab[i].type == type)
			return ethertypetab[i].name;
	snprintf(buf, sizeof buf, "ethertype 0x%04x", type);
	return buf;
}

/* 802.2 SNAP */
static const char *
snap_tag(p, end)
	const char *p, *end;
{
	struct snap {
		u_int8_t	oui[3];
		u_int8_t	type[2];
	} *snap;
	u_int16_t type;
	static char tag[80];

	snap = (struct snap *)p;
	p += sizeof snap;
	if (p > end)
		return "snap short";

	type = (snap->type[0] << 8) | snap->type[1];

	switch (type) {
	case ETHERTYPE_IP: 	/* RFC 1042 */
		return ip_tag(p, end);
	case 0x8137 /* ETHERTYPE_IPX */:
		return ipx_tag(p, end);
	}
	snprintf(tag, sizeof tag, 
		   "snap oui %02x.%02x.%02x %s",
		   snap->oui[0], snap->oui[1], snap->oui[2],
		   ethertype(type));
	return tag;
}

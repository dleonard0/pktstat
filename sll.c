/* David Leonard, 2003. Public domain. */
/* $Id$ */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#if STDC_HEADERS
# include <stdio.h>
#endif
#if HAVE_PCAP_H
# include <pcap.h>
#endif
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#include "compat.h"
#include "tag.h"
#include "flow.h"

#if defined(DLT_LINUX_SLL)

/*
 * libpcap for Linux provides synthetic framing for AF_PACKET sockets
 * (cf. SOCK_RAW) by prefixing data with a struct sll_header structure
 * derived from the AF_PACKET 'from' address structure.
 *
 * From libpcap/tcpdump's (private) "sll.h", we are told the 
 *
 *	"fake header includes:
 *	 a 2-byte 'packet type' which is one of:
 *		LINUX_SLL_HOST		[0] packet was sent to us
 *		LINUX_SLL_BROADCAST	[1] packet was broadcast
 *		LINUX_SLL_MULTICAST	[2] packet was multicast
 *		LINUX_SLL_OTHERHOST	[3] packet was sent to somebody else
 *		LINUX_SLL_OUTGOING	[4] packet was sent *by* us;
 *	 a 2-byte Ethernet protocol field;
 *	 a 2-byte link-layer type;
 *	 a 2-byte link-layer address length;
 *	 an 8-byte source link-layer address, whose actual length is
 *		specified by the previous value.
 *	 All fields except for the link-layer address are in network
 *	 byte order."
 *
 * This is misleading: the 'Ethernet protocol field' is actually last.
 * The 'Ethernet protocol field' also takes the same values as Linux's 
 * ETH_P_ values from <linux/if_ether.h>. Luckilly, these seem to be
 * the same as the standard ethernet protocol identifiers. The code below
 * may break if libpcap/linux-bpf.c or linux/if_ether.h change.
 */

#define SLL_ADDRLEN	8
struct sll_header {
	u_int16_t	sll_pkttype;
	u_int16_t	sll_hatype;
	u_int16_t	sll_halen;
	u_int8_t	sll_addr[SLL_ADDRLEN];
	u_int16_t	sll_protocol;
};

/* Return the tag for a Linux cooked socket packet */

const char *
sll_tag(p, end)
        const char *p;
	const char *end;
{
	struct sll_header *sll = (struct sll_header *)p;
	const char *tag;
	static char buf[TAGLEN];
	u_int16_t type;

	p += sizeof *sll;
	if (p > end)
		return "short sll";
	type = ntohs(sll->sll_protocol);

	tag = ether_tagx(type, p, end);
	if (tag)
		return tag;

	snprintf(buf, sizeof buf, "sll type 0x%04x hatype %04x",
		type, ntohs(sll->sll_hatype));
	return buf;
}

#endif /* defined(DLT_LINUX_SLL) */

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

#include "tag.h"

struct pppoe_header {
	u_int8_t	vertype;
	u_int8_t	code;
	u_int16_t	sessionid;
	u_int16_t	len;
};

/* Return the tag for an ethernet frame */

const char *
ether_tag(p, end)
        const char *p;
	const char *end;
{
	struct ether_header eh;
	struct pppoe_header ph;
	static char tag[80];

	memcpy(&eh, p, sizeof eh);	/* avoid bus alignment probs */

	switch (ntohs(eh.ether_type)) {
	case ETHERTYPE_IP:
		return ip_tag(p + ETHER_HDR_LEN, end);
#ifdef ETHERTYPE_IPV6
	case ETHERTYPE_IPV6:
		return ip6_tag(p + ETHER_HDR_LEN, end);
#endif
	case ETHERTYPE_ARP:
	case ETHERTYPE_REVARP:
		return "ether arp";
#ifdef ETHERTYPE_PPPOE
	case ETHERTYPE_PPPOE:
		p += ETHER_HDR_LEN;
		memcpy(&ph, p, sizeof ph);	/* avoid bus alignment probs */
		if (ph.code != 0)
			return "pppoe";
		return ppp_tag(p + sizeof ph, end);
#endif
	default:
		snprintf(tag, sizeof tag, "ether %02x",
		    ntohs(eh.ether_type));
		return tag;
	}
}

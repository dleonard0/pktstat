/* David Leonard, 2002. Public domain. */
/* $Id$ */
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
struct arphdr { int ignore; };
struct ifnet { int ignore; };
#include <sys/queue.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "tag.h"

const char *
ether_tag(p, end)
        const char *p;
	const char *end;
{
	struct ether_header eh;
	static char tag[80];

	memcpy(&eh, p, sizeof eh);	/* avoid bus alignment probs */

	switch (ntohs(eh.ether_type)) {
	case ETHERTYPE_IP:
		return ip_tag(p + ETHER_HDR_LEN, end);
	case ETHERTYPE_IPV6:
		return "ipv6";		/* XXX */

	case ETHERTYPE_ARP:
	case ETHERTYPE_REVARP:
		return "ether arp";
	case ETHERTYPE_PPPOE:
		return "ether pppoe";
	default:
		snprintf(tag, sizeof tag, "ether %02x",
		    ntohs(eh.ether_type));
		return tag;
	}
}

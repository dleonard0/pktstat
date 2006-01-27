/* David Leonard, 2002. Public domain. */
/* $Id$ */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#if HAVE_PCAP_H
# include <pcap.h>
#endif
#if HAVE_NET_PPP_DEFS_H
# include <net/ppp_defs.h>
#endif

#include "compat.h"
#include "tag.h"
#include "flow.h"

/* When the datalink type is DLT_PPP, we decode PPP-level packets */
const char *
ppp_tag(p, end)
	const char *p;
	const char *end;
{
	static char tag[TAGLEN];

	switch (PPP_PROTOCOL(p)) {

	/* higher level protocol encapsulation */
	case PPP_IP:
		return ip_tag(p + PPP_HDRLEN, end);
	case PPP_IPV6:
		return ip6_tag(p + PPP_HDRLEN, end);
	case PPP_IPX:
		return "ipx";		/* XXX - could decode further? */
	case PPP_AT:
		return "appletalk";	/* XXX - could decode further? */

	/* ppp private protocols */
	case PPP_IPCP:
		return "ppp-ipcp (IP negotiation)";
	case PPP_IPV6CP:
		return "ppp-ipv6cp (IPv6 negotiation)";
	case PPP_CCP:
		return "ppp-ccp (compression control)";
	case PPP_LCP:
		return "ppp-lcp (link control)";
	case PPP_PAP:
		return "ppp-pap (authentication)";
	case PPP_LQR:
		return "ppp-lqr (link quality)";
	case PPP_CHAP:
		return "ppp-chap (authentication)";
	case PPP_COMP:
		return "ppp-comp (comp/decompression fault)";
	default:
		snprintf(tag, sizeof tag, "ppp-0x%04x", PPP_PROTOCOL(p));
		return tag;
	}
}

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


/* Solaris */
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#if HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#if HAVE_NETINET_IP_H
# include <netinet/ip.h>
#endif
#if HAVE_SYS_PPP_SYS_H
# include <sys/stream.h>
# include <sys/vjcomp.h>
# include <sys/ppp_ioctl.h>
# include <sys/ppp_sys.h>
#endif

#include "compat.h"
#include "tag.h"
#include "flow.h"

#ifndef PPP_IP
# define PPP_IP          0x21    /* Internet Protocol */
# define PPP_IPV6        0x57    /* Internet Protocol Version 6 */
# define PPP_IPX         0x2b    /* Internetwork Packet Exchange */
# define PPP_AT          0x29    /* AppleTalk Protocol */
# define PPP_IPCP        0x8021  /* IP Control Protocol */
# define PPP_IPV6CP      0x8057  /* IPv6 Control Protocol */
# define PPP_CCP         0x80fd  /* Compression Control Protocol */
# define PPP_LCP         0xc021  /* Link Control Protocol */
# define PPP_PAP         0xc023  /* Password Authentication Protocol */
# define PPP_LQR         0xc025  /* Link Quality Report protocol */
# define PPP_CHAP        0xc223  /* Cryptographic Handshake Auth. Protocol */
# define PPP_COMP        0xfd    /* compressed packet */
#endif
#ifndef PPP_HDRLEN
# define PPP_HDRLEN 4
#endif
#ifndef PPP_PROTOCOL
# define PPP_PROTOCOL(p) ((((u_char *)(p))[2] << 8) + ((u_char *)(p))[3])
#endif

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
#if HAVE_NETINET_IP6_H
	case PPP_IPV6:
		return ip6_tag(p + PPP_HDRLEN, end);
#endif
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

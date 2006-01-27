/* David Leonard, 2002. Public domain. */
/* $Id$ */

/*
 * This compilation unit provides procedures for determining
 * the operational state of a network interface.
 * (ie if it is up, down, running or stopped.)
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#if STDC_HEADERS
# include <string.h>
#endif

#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#if HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#if HAVE_SYS_SOCKIO_H
# include <sys/sockio.h>
#endif
#if HAVE_NET_IF_H
# include <net/if.h>
#endif

#include "compat.h"
#include "ifc.h"

static int s = -1;
static char ifname[IFNAMSIZ];

/* Specify the interface name for future ifc_flags calls */
void
ifc_init(interface)
	const char *interface;
{
	/* Allocate a raw socket for later kernel queries on ifc state */
#if defined(AF_PACKET)
	s = socket(AF_PACKET, SOCK_RAW, 0);
#else
	s = socket(AF_ROUTE, SOCK_RAW, 0);
#endif
	if (s == -1)
		warn("socket");

	/* Record the current interface name */
	strlcpy(ifname, interface, sizeof ifname);
}

/* Fetch the flags from the interface */
int
ifc_flags()
{
	struct ifreq ifreq;

	if (s == -1)
		/* Assume the best! */
		return IFF_UP|IFF_RUNNING;

	/* Get our interface's operational flags */
	strlcpy(ifreq.ifr_name, ifname, sizeof ifreq.ifr_name);
	if (ioctl(s, SIOCGIFFLAGS, &ifreq) == -1)
		err(1, "SIOCGIFFLAGS");
	return ifreq.ifr_flags;
}

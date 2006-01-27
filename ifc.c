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

#include <err.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#if defined(BSD)
# include <sys/socket.h>
# include <sys/sockio.h>
#endif
#include <net/if.h>

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
	strncpy(ifname, interface, sizeof ifname);
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
	strncpy(ifreq.ifr_name, ifname, sizeof ifreq.ifr_name);
	if (ioctl(s, SIOCGIFFLAGS, &ifreq) == -1)
		err(1, "SIOCGIFFLAGS");
	return ifreq.ifr_flags;
}

/* David Leonard, 2002. Public domain. */
/* $Id$ */

/*
 * Read the state flags for an interface.
 */

#include <err.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#ifdef BSD
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
#if defined(AF_PACKET)
	s = socket(AF_PACKET, SOCK_RAW, 0);
#else
	s = socket(AF_ROUTE, SOCK_RAW, 0);
#endif
	if (s == -1)
		warn("socket");
	strncpy(ifname, interface, sizeof ifname);
}

/* Fetch the flags from the interface */
int
ifc_flags()
{
	struct ifreq ifreq;

	if (s == -1)
		return IFF_UP|IFF_RUNNING;
	strncpy(ifreq.ifr_name, ifname, sizeof ifreq.ifr_name);
	if (ioctl(s, SIOCGIFFLAGS, &ifreq) == -1)
		err(1, "SIOCGIFFLAGS");
	return ifreq.ifr_flags;
}

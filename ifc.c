/* David Leonard, 2002. Public domain. */
/* $Id$ */

/*
 * Read the state flags for an interface.
 */

#include <err.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>

#include "ifc.h"

static int s = -1;
static char ifname[IFNAMSIZ];

/* Specify the interface name for future ifc_flags calls */
void
ifc_init(interface)
	const char *interface;
{
	if ((s = socket(AF_ROUTE, SOCK_RAW, 0)) == -1)
		err(1, "socket");
	strncpy(ifname, interface, sizeof ifname);
}

/* Fetch the flags from the interface */
int
ifc_flags()
{
	struct ifreq ifreq;

	if (s == -1)
		return 0;

	strncpy(ifreq.ifr_name, ifname, sizeof ifreq.ifr_name);
	if (ioctl(s, SIOCGIFFLAGS, &ifreq) == -1)
		err(1, "SIOCGIFFLAGS");
	return ifreq.ifr_flags;
}

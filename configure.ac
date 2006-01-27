AC_INIT([pktstat],[1.8.0],[leonard@users.sourceforge.net])
AC_PREREQ(2.52)
AC_REVISION([$Id$])
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR(main.c)
AM_CONFIG_HEADER(config.h)

# checks for programs
AC_PROG_CC
AC_PROG_INSTALL

# checks for libraries
AC_SEARCH_LIBS(pcap_open_live, [pcap])
AC_SEARCH_LIBS(exp, [m])
AC_SEARCH_LIBS(tgoto, [termlib termcap curses ncurses ocurses])
AC_SEARCH_LIBS(initscr, [curses ncurses ocurses])

# checks for headers
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([sys/ioctl.h sys/param.h sys/queue.h sys/socket.h \
	sys/socket.h sys/sockio.h sys/time.h sys/types.h \
	stdio.h \
	ctype.h curses.h err.h errno.h inttypes.h math.h \
	arpa/inet.h \
	net/ppp_defs.h netdb.h \
	netinet/ether.h netinet/in.h netinet/in_systm.h \
	netinet/tcp.h netinet/udp.h \
	netipx/ipx.h \
	pcap.h poll.h string.h termios.h unistd.h])

AC_CHECK_HEADERS([net/if.h netinet/if_ether.h netinet/ip_icmp.h], [], [],
[#include <stdio.h>
#if STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# if HAVE_STLIB_H
#  include <stdlib.h>
# endif
#endif
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#if HAVE_SYS_QUEUE_H
# include <sys/queue.h>
#endif
])

AC_CHECK_HEADERS([netinet/ip6.h netinet/ip.h], [], [],
[#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
])

AC_HEADER_TIOCGWINSZ

# checks for types
AC_TYPE_SIGNAL
# AC_CHECK_TYPES(struct foo)

# checks for structures
# checks for compiler characteristics
AC_C_BIGENDIAN     #-- defines WORDS_BIGENDIAN
AC_C_CONST
AC_CHECK_SIZEOF(unsigned short)
AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned long)

# checks for library functions
AC_FUNC_MEMCMP
AC_CHECK_FUNC([exp],,
	[AC_MSG_WARN([Could not find exp(): load averages will be disabled])])
AC_CHECK_FUNC([pcap_open_live],,
	[AC_MSG_ERROR([Cannot proceed without a packet capture library])])
AC_CHECK_FUNC([initscr],,
	[AC_MSG_ERROR([Cannot proceed without a screen display library])])

# checks for system services
# checks for programs

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

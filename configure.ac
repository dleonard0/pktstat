AC_INIT([pktstat],[1.8.5],[leonard@users.sourceforge.net])
AC_REVISION([$Id$])
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR(main.c)
AM_CONFIG_HEADER(config.h)

## -- fix brokenness with automake-1.4
#AC_SUBST(PACKAGE,[$PACKAGE_NAME])
#AC_SUBST(VERSION,[$PACKAGE_VERSION])

# checks for programs
AC_PROG_CC
AC_PROG_INSTALL

# checks for libraries
AC_SEARCH_LIBS(socket, [socket])	dnl for Solaris
AC_SEARCH_LIBS(gethostbyname, [nsl])	dnl for Solaris
AC_SEARCH_LIBS(pcap_open_live, [pcap])
AC_SEARCH_LIBS(exp, [m])
AC_SEARCH_LIBS(tgoto, [termlib termcap curses ncurses ocurses])
AC_SEARCH_LIBS(initscr, [curses ncurses ocurses])
AC_SEARCH_LIBS(nanosleep, [posix4])

# checks for headers
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([sys/ioctl.h sys/param.h sys/queue.h \
	sys/socket.h sys/sockio.h sys/types.h sys/signal.h \
	ncurses.h curses.h err.h errno.h inttypes.h math.h \
	arpa/inet.h \
	net/ppp_defs.h sys/ppp_sys.h netdb.h \
	netinet/ether.h netinet/in.h netinet/in_systm.h \
	netinet/tcp.h netinet/udp.h \
	netipx/ipx.h \
	pcap.h poll.h string.h termios.h unistd.h])

AC_CHECK_HEADERS([net/if.h netinet/if_ether.h netinet/ip.h \
		  netinet/ip_icmp.h netinet/ip6.h ], [], [],
[
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
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
#if HAVE_NET_IF_H
# include <net/if.h>
#endif
#if HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#if HAVE_NETINET_IP_H
# include <netinet/ip.h>
#endif
])

AC_HEADER_TIOCGWINSZ

# checks for types
AC_TYPE_SIGNAL
AC_TYPE_SIZE_T
AC_CHECK_TYPE(struct timeval)

# checks for structures
# checks for compiler characteristics
AC_C_BIGENDIAN     #-- defines WORDS_BIGENDIAN
AC_C_CONST
AC_C_VOLATILE
AC_CHECK_SIZEOF(unsigned short)
AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned long)
AC_CHECK_SIZEOF(unsigned long long)

# checks for library functions
AC_FUNC_MEMCMP
AC_CHECK_FUNC([exp],,
	[AC_MSG_WARN([Could not find exp(): load averages will be disabled])])
AC_CHECK_FUNC([pcap_open_live],,
	[AC_MSG_ERROR([Cannot proceed without a packet capture library])])
AC_CHECK_FUNCS([initscr],,
	[AC_MSG_ERROR([Cannot proceed without a screen display library])])
AC_CHECK_FUNCS([fopen fgets ferror fclose snprintf sscanf],,
	[AC_MSG_ERROR([Cannot proceed without stdio functions])])
AC_CHECK_FUNCS([err errx warnx warn],,[AC_LIBOBJ(err)])
AC_CHECK_FUNCS([strlcpy],,[AC_LIBOBJ(strlcpy)])
AC_CHECK_FUNCS([getenv qsort poll gettimeofday atexit nanosleep signal])
AC_CHECK_FUNCS([getservbyport gethostbyaddr inet_addr resizeterm])

# checks for system services
# checks for programs

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

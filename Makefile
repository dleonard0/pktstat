# David Leonard, 2002. Public domain.
# $Id$

# Common makefile component.
# See GNUmakefile or BSDmakefile for gmake or (b)make specific rules.
# For other systems, feel free to hack at this or those files to make
# it compile.
# (and yes, I have heard of configure)

PROG=	pktstat
SRCS=	main.c flow.c display.c hash.c resize.c ifc.c abbrev.c
HDRS=	display.h flow.h hash.h main.h resize.h tag.h ifc.h abbrev.h
SRCS+=	ether.c ppp.c loop.c sll.c
SRCS+=	ip.c tcp.c udp.c icmp.c ip6.c ipx.c
SRCS+=	tcp_http.c tcp_x11.c tcp_sup.c
HDRS+=	tcp.h machendian.h
LDADD=	-lpcap -lcurses -lm
CFLAGS=	-ggdb

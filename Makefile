# David Leonard, 2002. Public domain.
# $Id$

# Common makefile component.
# See GNUmakefile or BSDmakefile for gmake or (b)make specific rules.
# For other systems, feel free to hack at this or those files to make
# it compile.
# (and yes, I have heard of configure)

PREFIX?=        /usr/local
TRUEPREFIX?=    ${PREFIX}
BINDIR=         ${TRUEPREFIX}/bin
MANDIR=         ${TRUEPREFIX}/man/cat

PROG=		pktstat
SRCS=		main.c flow.c display.c hash.c resize.c ifc.c abbrev.c tag.c \
		frag.c \
		ether.c ppp.c loop.c sll.c \
		ip.c tcp.c udp.c icmp.c ip6.c ipx.c \
		tcp_http.c tcp_x11.c wol.c
#SRCS+=		tcp_sup.c

LDADD=		-lpcap -lcurses -lm
CPPFLAGS=       -I/usr/include/pcap
#CFLAGS=        -Wall -ggdb

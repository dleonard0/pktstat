# $Id$
PROG=	pktstat
SRCS=	main.c flow.c display.c hash.c resize.c
SRCS+=	ether.c ppp.c ip.c tcp.c udp.c icmp.c
LDADD=	-lpcap -lcurses
.include <bsd.prog.mk>

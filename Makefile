# $Id$
PROG=	tcpstat
SRCS=	main.c flow.c display.c hash.c
SRCS+=	ether.c ppp.c ip.c tcp.c udp.c icmp.c
LDADD=	-lpcap -lcurses
NOMAN=
.include <bsd.prog.mk>

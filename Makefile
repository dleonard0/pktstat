# $Id$
PROG=	pktstat
SRCS=	main.c flow.c display.c hash.c resize.c
HDRS=	display.h flow.h hash.h main.h resize.h tag.h
SRCS+=	ether.c ppp.c ip.c tcp.c udp.c icmp.c
SRCS+=	ip6.c
SRCS+=	tcp_http.c tcp_x11.c
HDRS+=	tcp.h
LDADD=	-lpcap -lcurses
.include <bsd.prog.mk>

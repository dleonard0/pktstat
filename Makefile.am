# David Leonard, 2006. Public domain.
# $Id$

AUTOMAKE_OPTIONS= foreign

bin_PROGRAMS=	pktstat
man_MANS=	pktstat.1

pktstat_SOURCES=        abbrev.c display.c ether.c flow.c frag.c hash.c    \
                        icmp.c ifc.c ip.c ip6.c ipx.c loop.c main.c ppp.c  \
                        resize.c sll.c tag.c tcp.c tcp_http.c tcp_x11.c    \
                        udp.c wol.c                                        \
                        abbrev.h display.h flow.h frag.h hash.h ifc.h      \
                        machendian.h main.h resize.h tag.h tcp.h type.h


EXTRA_DIST=	ChangeLog NEWS README AUTHORS COPYING pktstat.spec

ChangeLog:
	cd $(srcdir) && svn2cl -o ChangeLog


# David Leonard, 2006. Public domain.
# $Id$

AUTOMAKE_OPTIONS= foreign

PATH_PKTSTATRC=	$(sysconfdir)/pktstatrc
AM_CPPFLAGS=	-DPATH_PKTSTATRC=\"$(PATH_PKTSTATRC)\"

bin_PROGRAMS=	pktstat
man_MANS=	pktstat.1

pktstat_SOURCES=	abbrev.c display.c ether.c flow.c frag.c hash.c
pktstat_SOURCES+=	icmp.c ifc.c ip.c ip6.c ipx.c loop.c main.c ppp.c
pktstat_SOURCES+=	resize.c sll.c tag.c tcp.c tcp_http.c tcp_x11.c
pktstat_SOURCES+=	tcp_smtp.c
pktstat_SOURCES+=	udp.c wol.c
pktstat_SOURCES+=	abbrev.h compat.h display.h flow.h frag.h hash.h
pktstat_SOURCES+=	ifc.h machendian.h main.h resize.h tag.h tcp.h
pktstat_SOURCES+=	type.h
pktstat_SOURCES+=	xx_malloc.c
pktstat_LDADD=		@LIBOBJS@

EXTRA_DIST=	NEWS README COPYING pktstat.spec pktstat.spec.in
EXTRA_DIST+=	pktstat.1.in
CLEANFILES=	pktstat.1

pktstat.1: pktstat.1.in
	sed -e 's,@PATH_PKTSTATRC\@,$(PATH_PKTSTATRC),g' \
		< $(srcdir)/pktstat.1.in >$@
	
dist-hook: 
	test ! -d $(srcdir)/.svn || \
	(cd $(srcdir) && svn2cl --stdout) > $(distdir)/ChangeLog

pktstat.spec: pktstat.spec.in
	sed -e 's,@PACKAGE_VERSION@,$(PACKAGE_VERSION),g' \
		< $(srcdir)/pktstat.spec.in >$@

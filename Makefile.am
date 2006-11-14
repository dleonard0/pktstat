# David Leonard, 2006. Public domain.
# $Id$

AUTOMAKE_OPTIONS= foreign

PATH_PKTSTATRC=	$(sysconfdir)/pktstatrc
AM_CPPFLAGS=	-DPATH_PKTSTATRC=\"$(PATH_PKTSTATRC)\"

bin_PROGRAMS=	pktstat
man_MANS=	pktstat.1

pktstat_SOURCES=        abbrev.c display.c ether.c flow.c frag.c hash.c    \
                        icmp.c ifc.c ip.c ip6.c ipx.c loop.c main.c ppp.c  \
                        resize.c sll.c tag.c tcp.c tcp_http.c tcp_x11.c    \
                        udp.c wol.c                                        \
                        abbrev.h compat.h display.h flow.h frag.h hash.h   \
			ifc.h machendian.h main.h resize.h tag.h tcp.h     \
			type.h
pktstat_LDADD=		@LIBOBJS@

EXTRA_DIST=	NEWS README COPYING pktstat.spec \
		pktstat.1.in
CLEANFILES=	pktstat.1

pktstat.1: pktstat.1.in
	sed -e 's,@PATH_PKTSTATRC\@,$(PATH_PKTSTATRC),g' \
		< $(srcdir)/pktstat.1.in >$@
	
dist-hook: 
	test ! -d $(srcdir)/.svn || \
	(cd $(srcdir) && svn2cl --stdout) > $(distdir)/ChangeLog


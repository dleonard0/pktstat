# David Leonard, 2002. Public domain.
# $Id$

include Makefile

#-- simulate the essential parts of BSD's /usr/share/mk/bsd.prog.mk

OBJS?=		${SRCS:.c=.o}
MAN?=		${PROG}.cat1
INSTALL?=	install
NROFF?=		nroff -Tascii -mandoc

all: ${PROG} ${MAN}

${PROG}: ${OBJS}
	${LINK.c} -o $@ ${OBJS} ${LDADD}

${MAN}: ${MAN:.cat1=.1}
	${NROFF} $^ > $@

install:
	${INSTALL} -m 555 ${PROG} ${BINDIR}/
ifndef NOMAN
	${INSTALL} -m 444 ${MAN} ${MANDIR}1/${MAN:.cat1=.0}
endif

clean:
	rm -f ${PROG} ${MAN} ${OBJS}


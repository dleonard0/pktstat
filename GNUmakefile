# David Leonard, 2002. Public domain.
# $Id$

# Glue for non-BSD systems, that have GNU's make (gmake)

include Makefile

#-- simulate the essential parts of BSD's bsd.prog.mk

OBJS=	${SRCS:.c=.o}
MAN=	${PROG}.cat1
CFLAGS=	-I/usr/include/pcap
PREFIX?=/usr/local
BINDIR=	${PREFIX}/bin
MANDIR=	${PREFIX}/man

all: ${PROG} ${MAN}

${PROG}: ${OBJS}
	${LINK.c} -o $@ ${OBJS} ${LDADD}

${MAN}: ${MAN:.cat1=.1}
	nroff -mandoc $^ > $@

install:
	install -m 555 ${PROG} ${BINDIR}/
	install -m 444 ${MAN} ${MANDIR}/cat1/${MAN:.cat1=.0}

clean:
	rm -f ${PROG} ${MAN} ${OBJS}


# $Id$
# Glue for non-BSD systems

include Makefile

OBJS=	${SRCS:.c=.o}
MAN=	${PROG}.cat1

all: ${PROG} ${MAN}

${PROG}: ${OBJS}
	${LINK.c} -o $@ ${OBJS} ${LDADD}

${MAN}: ${MAN:.cat1=.1}
	nroff -man -Tascii $^ > $@

install:
	@echo "GNUmakefile: install rule not written - please fix me"; exit 1

clean:
	rm -f ${PROG} ${MAN} ${OBJS}


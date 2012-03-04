/* David Leonard, 2002. Public domain. */
/* $Id: tcp_http.c 1193 2007-08-30 10:33:24Z d $ */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#if STDC_HEADERS
# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <ctype.h>
#endif
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "type.h"
#include "flow.h"
#include "tcp.h"
#include "compat.h"

#define CR  '\r'
#define LF  '\n'

struct smtp_state {
	int in_data;		    /* true while client sends DATA */
	int in_header;		    /* true in DATA's headers */
	char line[2048];	    /* buffer for data sent to server */
	int line_len;		    /* length of line read so far */
	enum { sLINE, sEXPECT_LF, sENCRYPTED } state;
	char to_addr[512];	    /* RCPT TO: */
	char from_addr[512];	    /* MAIL FROM: */
};

/* Returns pointer to string after prefix, or NULL if no match */
const char *
strip_prefix(s, prefix)
	const char *s;
	const char *prefix;
{
	while (*prefix)
	    if (*s++ != *prefix++)
		return 0;
	return s;
}

/* Normalize a line by uppercasing the command word(s), and stripping
 * and collapsing whitespace */
static void
normalize_line(line)
	char *line;
{
	char *s, *p;
	int has_colon;

	s = p = line;
	/* Skip leading whitespace */
	while (*s == ' ' || *s == '\t')
	    s++;
	/* Collapse whitespace */
	while (*s && *s != ':') {
	    if (*s == ' ' || *s == '\t') {
		while (*s == ' ' || *s == '\t')
		    s++;
		*p++ = ' ';
	    } else {
		*p++ = *s++;
	    }
	}
	/* Remove whitespace before a colon */
	if (*s == ':' && p > line && p[-1] == ' ')
	    p--;
	if (*s == ':') {
	    *p++ = *s++;
	    has_colon = 1;
	} else
	    has_colon = 0;
	/* Remove whitespace after colon */
	while (*s == ' ' || *s == '\t')
	    s++;
	/* Copy the rest of the line, collapsing whitespace */
	while (*s) {
	    if (*s == ' ' || *s == '\t') {
		while (*s == ' ' || *s == '\t')
		    s++;
		*p++ = ' ';
	    } else
		*p++ = *s++;
	}
	/* Strip trailing whitespace */
	if (p > line && p[-1] == ' ')
	    p--;
	*p = 0;

	/* Uppercase the first word, unless there is a colon in which case
	 * we uppercase to the colon */
	for (s = line; *s && *s != (has_colon ? ':' : ' '); s++)
	    if (*s != ' ')
		*s = toupper(*s);
}

/* Normalize an email address
 *   u@h    -> u@h
 *   N<u@h> -> u@h
 */

static void
normalize_addr(line)
	char *line;
{
	char *s, *t, *u;

	/* Search for the opening angle bracket */
	for (s = line; *s; s++)
	    if (*s == '<')
		break;
	if (!*s)
	    return; /* no '<' */
	s++;	    /* skip '<' */

	/* Check that there is a closing bracket */
	for (u = s; *u; u++)
	    if (*u == '>')
		break;
	if (*u != '>')
	    return; /* no '>' */

	for (t = line; s < u; t++,s++)
	    *t = *s;
	*t = 0;
}

static void
smtp_line(f, line)
	struct flow *f;
	const char *line;
{
	struct smtp_state *state;
	const char *s;
	int addr_changed = 0;
FILE*log;

	state = (struct smtp_state *)f->udata;

if ((log = fopen("/tmp/smtp.log", "a")))
   fprintf(log, "smpt_line [%s]\n", line);

	if (state->in_data) {
	    if (strcmp(line, ".") == 0) {
		state->in_data = 0;
		state->from_addr[0] = 0;
		state->to_addr[0] = 0;
	    } else if (state->in_header) {
		if (!*line)
		    state->in_header = 0;
#if 0
		/* Tag the Subject: line inside DATA */
		else if ((line[0] == 'S' || line[0] == 's') &&
		         (line[1] == 'U' || line[1] == 'u') &&
		         (line[2] == 'B' || line[2] == 'b') &&
		         (line[3] == 'J' || line[3] == 'j') &&
		         (line[4] == 'E' || line[4] == 'e') &&
		         (line[5] == 'C' || line[5] == 'c') &&
		         (line[6] == 'T' || line[6] == 't') &&
		         line[7] == ':')
		    snprintf(f->desc, sizeof f->desc, "%s", line);
#endif
	    }
	} else {
	    /* Normalize the command line */
	    normalize_line(line);
if (log)fprintf(log, "normalized to [%s]\n", line);
	    if ((s = strip_prefix(line, "MAIL FROM:"))) {
		snprintf(state->from_addr, sizeof state->from_addr, "%s", s);
		normalize_addr(state->from_addr);
		addr_changed = 1;
if (log)fprintf(log, "from_addr = [%s]\n", state->from_addr);
	    }
	    else if ((s = strip_prefix(line, "RCPT TO:"))) {
		snprintf(state->to_addr, sizeof state->to_addr, "%s", s);
		normalize_addr(state->to_addr);
		addr_changed = 1;
if (log)fprintf(log, "to_addr = [%s]\n", state->to_addr);
	    }
	    else if (strcmp(line, "DATA") == 0) {
		state->in_data = 1;
		state->in_header = 1;
	    }
	    else if (strcmp(line, "STARTTLS") == 0) {
		state->state = sENCRYPTED;
		snprintf(f->desc, sizeof f->desc, "STARTTLS");
	    }

	    if ((addr_changed || 
	         strcmp(line, "QUIT") == 0 ||
		 strcmp(line, "DATA") == 0) && 
		(*state->from_addr && *state->to_addr)) 
	    {
		snprintf(f->desc, sizeof f->desc, "%s -> %s", 
		    state->from_addr, state->to_addr);
	    } else {
		if (strcmp(line, "QUIT") != 0)
		    snprintf(f->desc, sizeof f->desc, "%s", line);
	    }
if (log)fprintf(log, "set desc to: [%s]\n", f->desc);
	}

if (log)fclose(log);
}

/*
 * Look for simple SMTP (RFC 2822) commands.
 */
void
tcp_smtp(f, data, end, toserver)
	struct flow *f;
	const char *data;
	const char *end;
	int toserver;
{
	const char *d;
	struct smtp_state *state;

	if (!toserver)
	    return;

	if (!f->udata) {
	    /* Initialize state */
	    state = (struct smtp_state *)malloc(sizeof *state);
	    if (!state)
		errx(1, "malloc");
	    memset(state, 0, sizeof *state);
	    f->udata = state;
	    f->freeudata = free;
	    state->line_len = 0;
	    state->state = sLINE;
	    state->to_addr[0] = 0;
	    state->from_addr[0] = 0;
	} else
	    state = (struct smtp_state *)f->udata;

	/* Extract data, line by line */
	for (d = data; d < end; d++) 
	    switch (state->state) {
            case sENCRYPTED:
                /* Don't bother */
                d = end - 1;
                break;

	    case sLINE:
		if (*d == CR) {
		    state->state = sEXPECT_LF;
		} else {
		    if (state->line_len < sizeof state->line - 1)
			state->line[state->line_len++] = *d;
		    /*state->state = sLINE;*/
		}
		break;
	    case sEXPECT_LF:
		if (*d == LF) {
		    state->line[state->line_len] = 0;
		    smtp_line(f, state->line);
		    state->line_len = 0;
		    state->state = sLINE;
		} else if (*d == CR) {
		    state->line_len = 0;
		    /*state->state = sEXPECT_LF;*/
		} else {
		    state->line[0] = *d;
		    state->line_len = 1;
		    state->state = sLINE;
		}
		break;
	    }
}

/* David Leonard, 2002. Public domain. */
/* $Id$ */

/* EXPERIMENTAL - seems to be buggy */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <err.h>
#include <sys/types.h>
#include <sys/time.h>

#include "machendian.h"
#include "flow.h"
#include "tcp.h"

/* From supmsg.h */
#define MSGGOAWAY       (-1)
#define MSGSIGNON       (101)
#define MSGSIGNONACK    (102)
#define MSGSETUP        (103)
#define MSGSETUPACK     (104)
#define MSGLOGIN        (105)
#define MSGLOGACK       (106)
#define MSGCRYPT        (107)
#define MSGCRYPTOK      (108)
#define MSGREFUSE       (109)
#define MSGLIST         (110)
#define MSGNEED         (111)
#define MSGDENY         (112)
#define MSGSEND         (113)
#define MSGRECV         (114)
#define MSGDONE         (115)
#define MSGXPATCH       (117)
#define MSGCOMPRESS     (118)
#define FSETUPOK        (999)
#define FSETUPHOST      (998)
#define FSETUPSAME      (997)
#define FSETUPOLD       (996)
#define FSETUPBUSY      (995)
#define FSETUPRELEASE   (994)
#define FLOGOK          (989)
#define FLOGNG          (988)
#define FDONESUCCESS    (979)
#define FDONEDONTLOG    (978)
#define FDONESRVERROR   (977)
#define FDONEUSRERROR   (976)
#define FDONEGOAWAY     (975)

#define VALIDMSG(m)	(((m) > 100 && (m) <130) || ((m) > 960 && (m) < 1000))

#define ENDCOUNT (-1)                   /* end of message marker */
#define NULLCOUNT (-2)                  /* used for sending NULL pointer */

static struct msginfo {
	int	msgcode;
	const char *name;
	const char *arghint;
} msginfo[] = {
	{ MSGGOAWAY,	"goaway",	NULL	},
	{ MSGSIGNON,	"signon",	NULL	},
	{ MSGSIGNONACK,	"signonack",	NULL	},
	{ MSGSETUP,	"setup",	NULL	},
	{ MSGSETUPACK,	"setupack",	NULL	},
	{ MSGLOGIN,	"login",	NULL	},
	{ MSGLOGACK,	"logack",	NULL	},
	{ MSGCRYPT,	"crypt",	NULL	},
	{ MSGCRYPTOK,	"cryptok",	NULL	},
	{ MSGREFUSE,	"refuse",	NULL	},
	{ MSGLIST,	"list",		NULL	},
	{ MSGNEED,	"need",		NULL	},
	{ MSGDENY,	"deny",		NULL	},
	{ MSGSEND,	"send",		NULL	},
	{ MSGRECV,	"recv",		NULL	},
	{ MSGDONE,	"done",		NULL	},
	{ MSGXPATCH,	"xpatch",	NULL	},
	{ MSGCOMPRESS,	"compress",	NULL	},
	{ FSETUPOK,	"setup-ok",	NULL	},
	{ FSETUPHOST,	"setup-host",	NULL	},
	{ FSETUPSAME,	"setup-same",	NULL	},
	{ FSETUPOLD,	"setup-old",	NULL	},
	{ FSETUPBUSY,	"setup-busy",	NULL	},
	{ FSETUPRELEASE,"setup-release",NULL	},
	{ FLOGOK,	"log-ok",	NULL	},
	{ FLOGNG,	"log-ng",	NULL	},
	{ FDONESUCCESS,	"done-success",	NULL	},
	{ FDONEDONTLOG,	"done-dontlog",	NULL	},
	{ FDONESRVERROR,"done-srverror",NULL	},
	{ FDONEUSRERROR,"done-usrerror",NULL	},
	{ FDONEGOAWAY,	"done-goaway",	NULL	},
	{ 0, NULL, NULL }
};

struct supstate {
	int		needswap;
	union {
		u_int32_t i;
		char	  b[4];
	} word;
	int	wordleft;
	int	argleft;	/* bytes of argument left to read */
	enum state_e {
		STATE_BAD,
		STATE_INIT,
		STATE_MSGCODE,	/* wait for msg code */
		STATE_ARGLEN,	/* wait for arg len or end */
		STATE_ARGDATA,	/* wait for next byte of arg data */
	} state;		/* state after wordleft or skipleft reaches 0 */

	/* We hold the first 64 bytes of any argument */
	u_int32_t msg;
	int	nargs;
	struct arg {
		int isnull;
		int len;
		char data[64];
	} arg[64], 
	  overarg[16]; /* Excess args overwrite each other */
};

#define U16(v)	(state->needswap ? swap16(v) : (v))
#define U32(v)	(state->needswap ? swap32(v) : (v))
#define ARG(i) \
	((i) < 64 ? &state->arg[i] \
		  : &state->overarg[((i)-64) % 16])

static const char *
quotename(arg)
	struct arg *arg;
{
	static char buf[1024];
	static const char hex[] = "0123456789abcdef";
	int i, j;

	if (arg->isnull)
		return "null";

	for (i=j=0; i < arg->len && j < sizeof buf - 5; i++) {
		char c = arg->data[i];
		if (c == '\\') {
			buf[j++] = '\\';
			buf[j++] = '\\';
		} else if (c == '\n') {
			buf[j++] = '\\';
			buf[j++] = 'n';
		} else if (c == 0) {
			buf[j++] = '\\';
			buf[j++] = '0';
		} else if (c >= ' ' && c <= '~') {
			buf[j++] = c;
		} else {
			buf[j++] = '\\';
			buf[j++] = 'x';
			buf[j++] = hex[c >> 4 & 0xf];
			buf[j++] = hex[c >> 0 & 0xf];
		}
	}
	buf[j] = '\0';
	return buf;
}

static void
setdesc(f, state)
	struct flow *f;
	struct supstate *state;
{
	struct msginfo *mi;
	int pos = 0, i, j;

	if (state->msg == 0)
		return;
	if (state->msg == MSGLIST) {
		int i = state->nargs & ~3;
		if (i == state->nargs && i)
			i -= 4;
		snprintf(f->desc, sizeof f->desc, 
			"list (%s)", quotename(ARG(i)));
		return;
	}
	if (state->msg == MSGRECV) {
		snprintf(f->desc, sizeof f->desc, 
			"recv %s", quotename(ARG(0)));
		return;
	}

	/* Generic case */
	for (mi = msginfo; ; mi++)
		if (!mi->name)
			return;
		else if (mi->msgcode == state->msg)
			break;

	pos += snprintf(f->desc + pos, sizeof f->desc - pos, 
		"%s", mi->name);

/*
	if (state->argleft)
		pos += snprintf(f->desc + pos, sizeof f->desc - pos, 
			" {%d}", state->argleft);
*/

	for (i = 0; i < state->nargs && i < 64 && pos+9 < sizeof f->desc; i++) {
	    if (state->arg[i].isnull)
		pos += snprintf(f->desc + pos, sizeof f->desc - pos, 
			" -");
	    else if (state->arg[i].len == 4) {
		u_int32_t value;
		memcpy(&value, state->arg[i].data, sizeof value);
		pos += snprintf(f->desc + pos, sizeof f->desc - pos, 
			" %d", U32(value));
	    } else 
		pos += snprintf(f->desc + pos, sizeof f->desc - pos, 
			" %s", quotename(&state->arg[i]));
	}
}

/*
 * Watch the sup client stream, looking for commands
 */
void
tcp_sup(f, data, end, isclient)
	struct flow *f;
	const char *data;
	const char *end;
	int isclient;
{
	struct supstate *state;
	struct supstate *states;
	enum state_e curstate = STATE_BAD, nextstate = STATE_BAD;
	u_int32_t word;
	struct arg *arg;

	if (data == end)
		return;

	states = (struct supstate *)f->udata;
	if (state == NULL) {
		states = (struct supstate *)malloc(2*sizeof (struct supstate));
		if (states == NULL)
			errx(1, "malloc");
		f->udata = state;
		f->freeudata = free;
		states[0].state = STATE_INIT;
		states[0].argleft = 0;
		states[0].wordleft = 4;
		states[0].msg = 0;
		states[0].nargs = 0;
		states[0].arg[0].len = 0;

		states[1].state = STATE_MSGCODE;
		states[1].argleft = 0;
		states[1].wordleft = 4;
		states[1].msg = 0;
		states[1].nargs = 0;
		states[1].arg[0].len = 0;
	}

	state = &states[isclient ? 0 : 1];

    again:

	if (state->state == STATE_BAD) {
		f->desc[0] = '\0';
		return;
	}

	arg = ARG(state->nargs);

	/* Read in the args  */
	while (state->argleft > 0) {
		if (data >= end) {
			setdesc(f, state);
			return;
		}

		state->argleft--;
		arg->data[arg->len] = *data;
		arg->len++;
		data++;
	}

	/* Read in an integer word */
	while (state->wordleft > 0) {
		if (data >= end) {
			setdesc(f, state);
			return;
		}

		state->wordleft--;
		state->word.b[3-state->wordleft] = *data++;
	}

	curstate = state->state;
	nextstate = STATE_BAD;	/* default */
	word = state->word.i;

	switch (curstate) {
	case STATE_INIT:
		nextstate = STATE_MSGCODE;
		state->wordleft = 4;
		state->msg = 0;
		if (word == 0x01020304) {
			state->needswap = 0;
			break;
		}
		if (word == 0x04030201) {
			state->needswap = 1;
			break;
		}
		if (!VALIDMSG(word))
			state->needswap = 1;
		if (!VALIDMSG(U32(word))) {
			nextstate = STATE_BAD;
			break;
		}
		/* FALLTHROUGH */

	case STATE_MSGCODE:
		state->msg = U32(word);
		if (state->msg == MSGGOAWAY) {
			nextstate = STATE_BAD;
			break;
		}
		state->nargs = 0;
		arg = ARG(state->nargs);
		arg->len = 0;
		arg->isnull = 0;
		nextstate = STATE_ARGLEN;
		state->wordleft = 4;
		break;

	case STATE_ARGLEN:
		if (U32(word) == ENDCOUNT) {
			nextstate = STATE_MSGCODE;
			state->wordleft = 4;
			break;
		}
		if (U32(word) != NULLCOUNT) {
			nextstate = STATE_ARGDATA;
			state->argleft = U32(word);
			break;
		}
		arg->isnull = 1;
		/* Fallthru */

	case STATE_ARGDATA:
		state->nargs++;
		arg = ARG(state->nargs);
		arg->len = 0;
		arg->isnull = 0;
		nextstate = STATE_ARGLEN;
		state->wordleft = 4;
		break;
	}

	state->state = nextstate;
	goto again;
}

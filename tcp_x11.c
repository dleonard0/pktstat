/* David Leonard, 2002. Public domain. */
/* $Id$ */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <machine/endian.h>
#include "flow.h"
#include "tcp.h"

/* From Xproto.h: */

struct xConnClientPrefix {
	u_int8_t	byteOrder;
#define BE	'B'
#define LE	'l'
	u_int8_t	pad;
	u_int16_t	majorVersion, minorVersion;
	u_int16_t	nbytesAuthProto;
	u_int16_t	nbytesAuthString;
	u_int16_t	pad2;
};

#define U16(v)	(state->byteorder == BE ? betoh16(v) : letoh16(v))
#define U32(v)	(state->byteorder == BE ? betoh32(v) : letoh32(v))

struct xChangePropertyReq {
	u_int8_t	reqType;
#define X_ChangeProperty 18 
	u_int8_t	mode;
	u_int16_t	length;	/* number of 32-bit words */
	u_int32_t	window;
	u_int32_t	property;
#define XA_WM_COMMAND	34
	u_int32_t	type;
#define XA_STRING	31
	u_int8_t	format;	/* bits per element */
	u_int8_t	pad[3];
	u_int32_t	nUnits;
};

struct x11state {
	char	byteorder;
	int	skipbytes;
};

void
tcp_x11(f, data, end)
	struct flow *f;
	const char *data;
	const char *end;
{
	struct x11state *state;
	const struct xChangePropertyReq *req;

	if (data == end)
		return;

	state = (struct x11state *)f->udata;
	if (state == NULL) {
		const struct xConnClientPrefix *p;
		state = (struct x11state *)malloc(sizeof (struct x11state));
		f->udata = state;
		f->freeudata = free;
		p = (const struct xConnClientPrefix *)data;
		state->byteorder = p->byteOrder;
		state->skipbytes = (sizeof *p) +  U16(p->nbytesAuthProto)
		    + U16(p->nbytesAuthString);
		state->skipbytes = (state->skipbytes + 3) & ~3; /* eek! */
	}

	while (1) {
		if (state->skipbytes >= (end - data)) {
			state->skipbytes -= (end - data);
			return;
		}

		data += state->skipbytes;
		state->skipbytes = 0;

		/*
		 * Look for a WM_COMMAND property being set to a
		 * string, and save its list as the description
		 */
		req = (const struct xChangePropertyReq *)data;

		if (req->reqType == X_ChangeProperty
		    && U32(req->property) == XA_WM_COMMAND
		    && U32(req->type) == XA_STRING
		    && req->format == 8)
		{
			const char *cmd = (const char *)(req + 1);
			int len = U32(req->nUnits);
			int i;
			if (len > 0 && cmd[len-1] == '\0')
				len--;
			for (i = 0; i < sizeof f->desc - 1 && i < len; i++)
				if (cmd[i])
					f->desc[i] = cmd[i];
				else
					f->desc[i] = ' ';
			f->desc[i] = '\0';
		}
		state->skipbytes = U16(req->length) * 4;
	}
}

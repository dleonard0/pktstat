/* David Leonard, 2002. Public domain. */
/* $Id$ */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <err.h>
#include <sys/types.h>
#include <sys/time.h>

#include "machendian.h"
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

struct xReq {
	u_int8_t	reqType;
#define X_ChangeProperty 18 
	u_int8_t	data0;
	u_int16_t	length;	/* number of 32-bit words */
};

struct xChangePropertyReq {
	u_int8_t	reqType;
	u_int8_t	mode;
	u_int16_t	length;	/* number of 32-bit words */
	u_int32_t	window;
	u_int32_t	property;
#define XA_WM_COMMAND	34
#define XA_WM_NAME	39
#define XA_WM_CLASS	67
	u_int32_t	type;
#define XA_STRING	31
	u_int8_t	format;	/* bits per element */
	u_int8_t	pad[3];
	u_int32_t	nUnits;
};

struct x11state {
	char	byteorder;
	int	goodness;
};

/*
 * Watch the X11 protocol carefully and look for string atom changes.
 * Typically the WM_NAME, WM_CLASS or WM_COMMAND atoms contain a good
 * description of the activity that's causing the traffic.
 */
void
tcp_x11(f, data, end)
	struct flow *f;
	const char *data;
	const char *end;
{
	struct x11state *state;

	if (data == end)
		return;

	state = (struct x11state *)f->udata;

	if (state == NULL) {
		const struct xConnClientPrefix *p;
		state = (struct x11state *)malloc(sizeof (struct x11state));
		if (state == NULL)
			errx(1, "malloc");
		f->udata = state;
		f->freeudata = free;
		p = (const struct xConnClientPrefix *)data;
		state->byteorder = p->byteOrder;
		state->goodness = 0;
		/* Unlikely to have the WM props in the first pkt */
		return;
	}

	while (data + sizeof (struct xReq) <= end) {
		const struct xReq *xr = (const struct xReq *)data;
		const struct xChangePropertyReq *chp =
			(const struct xChangePropertyReq *)data;
		const char *nextdata = data + 4 * U16(xr->length);

		/* 
		 * Look for a change to a WM_NAME or WM_COMMAND atom
		 */
		if (xr->reqType == X_ChangeProperty
		    && data + sizeof *chp < end
		    && U32(chp->type) == XA_STRING
		    && chp->format == 8)
		{
			const char *cmd = data + sizeof *chp;
			int i, len = U32(chp->nUnits);
			int goodness;
			u_int32_t property = U32(chp->property);

			/* We prefer some properties over others */
			goodness = 
			    property == XA_WM_COMMAND ? 2 :
			    property == XA_WM_NAME ? 1 : 
			    property == XA_WM_CLASS ? 0 : 
				-1;

			if (goodness > state->goodness)
			{
			    if (len > 0 && cmd[len-1] == '\0')
				len--;
			    for (i = 0; i < sizeof f->desc - 1 && i < len; i++)
				if (cmd[i])
					f->desc[i] = cmd[i];
				else
					f->desc[i] = ' ';
			    f->desc[i] = '\0';
			    state->goodness = goodness;
			}
		}

		if (nextdata <= data)
			break;			/* hmm, avoid going backwards */
		data = nextdata;
	}
}

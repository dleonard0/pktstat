/* David Leonard, 2002. Public domain. */
/* $Id$ */

#include <stdio.h>
#include <stdlib.h>
#include <curses.h>
#include <stdarg.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <net/if.h>

#include "display.h"
#include "flow.h"
#include "main.h"
#include "resize.h"
#include "ifc.h"

#define BITS(r)	(Bflag ? (r) : (r) * NBBY)
#define BPSS	(Bflag ? "Bps" : "bps")
#define BS	(Bflag ? "B" : "b")

static unsigned long total_octets = 0;
static double total_time = 0;
static double maxbps = -1;
static double minbps = -1;
static const char *display_device, *display_filter;
static volatile int resize_needed = 0;

static
const char *
mega(x, fmt)
	double x;
	const char *fmt;
{
	static char buf[80];
	static char suffix[] = " kMGTPE";
	int i;
	int len;

	i = 0;
	while (x >= 1000 && suffix[i]) {
		x /= 1000.0;
		i++;
	}
	snprintf(buf, sizeof buf - 1, fmt, x);
	len = strlen(buf);
	if (suffix[i] != ' ')
		buf[len++] = suffix[i];
	buf[len] = '\0';
	return buf;
}

static const char *
days(td)
	double td;
{
	static char buf[80];
	unsigned long t = td;

#define Mn	60
#define Hr	(60*60)
#define Dy	(24*60*60)

	if (t < Mn) {
		snprintf(buf, sizeof buf, "%lds", t);
		return buf;
	}
	if (t < Hr) {
		snprintf(buf, sizeof buf, "%ldm%02lds",
			t / Mn,
			(t % Mn) / 1
		);
		return buf;
	}
	if (t < Dy) {
		snprintf(buf, sizeof buf, "%ldh%02ldm%02lds",
			t / Hr,
			(t % Hr) / Mn,
			((t % Hr) % Mn) / 1
		);
		return buf;
	}
	snprintf(buf, sizeof buf, "%ldd%02ldh%02ldm%02lds",
		t / Dy,
		(t % Dy) / Hr,
		((t % Dy) % Hr) / Mn,
		(((t % Dy) % Hr) % Mn) / 1
	);
	return buf;
}

void
display_open(device, filter)
	const char *device, *filter;
{
	display_device = device;
	display_filter = filter;
	initscr();
	cbreak();
	noecho();
	nodelay(stdscr, TRUE);
	resize_init(&resize_needed);
	ifc_init(device);
}

void
display_close()
{
	endwin();
}

void
display_update(period)
	double period;
{
	int i, flags;
	unsigned long sum;
	double bps = 0;
	int maxx, maxy, y, x;
	int redraw_needed = 0;
	int clearflows = 0;

	if (resize_needed) {
		resize();
		redraw_needed = 1;
	}

	switch (getch()) {
	case ('L'&0x3f):		/* control-L to redraw */
		redraw_needed = 1;
		break;
	case 'q':			/* q for quit */
		exit(0);
	case 't':			/* toggle -t */
		tflag = !tflag;
		break;
	case 'T':			/* toggle -T */
		Tflag = !Tflag;
		break;
	case 'n':			/* toggle -n */
		nflag = !nflag;
		clearflows = 1;
		break;
	case 'b': case 'B':		/* toggle -B */
		Bflag = !Bflag;
		break;
	case 'f': case 'F':		/* toggle -F */
		Fflag = !Fflag;
		clearflows = 1;
		break;
	case 'r':			/* reset stats */
		total_octets = 0;
		total_time = 0;
		maxbps = -1;
		minbps = -1;
		break;
	case ERR:
	default:
		break;	
	}

	if (redraw_needed) {
		erase();
		redrawwin(stdscr); 
		refresh();
	}

	move(0,0);

	getmaxyx(stdscr, maxy, maxx);

	/* sort the flows by their packet octet count */
	qsort(flows, nflows, sizeof (struct flow), tflag ? octetcmp : tagcmp);

	sum = 0;
	for (i = 0; i < nflows; i++)
		sum += flows[i].octets;

	total_octets += sum;
	total_time += period;

	printw("interface: %s ", display_device);

	flags = ifc_flags();
	if ((flags & IFF_UP) == 0) {
		int oattr = attron(A_REVERSE);
		printw("down");
		attrset(oattr);
		printw(" ");
	}

	if ((flags & IFF_RUNNING) == 0)
		printw("(not running) ");

	if (Tflag)
		printw("   total: %s%s (%s)", 
		    mega(BITS((double)total_octets), "%.1f"),
		    BS, days(total_time));
	clrtoeol();
	printw("\n");
	if (display_filter)
		printw("filter: %s\n", display_filter);

	if (period > 0.5) {
		bps = sum / period;
		if (minbps < 0 || bps < minbps)
			minbps = bps;
		if (maxbps < 0 || bps > maxbps)
			maxbps = bps;
		printw("cur: %-6s ", mega(BITS(bps), "%.1f"));
	}
	if (total_time > 0)
		printw("avg: %-6s ", 
			mega(BITS(total_octets / total_time), "%.1f"));
	if (minbps >= 0)
		printw("min: %-6s ",
			mega(BITS(minbps), "%.1f"));
	if (maxbps >= 0)
		printw("max: %-6s ", 
			mega(BITS(maxbps), "%.1f"));
	clrtoeol();
	printw("%s\n", BPSS);

#define LLEN	(13 + (Tflag ? 7 : 0))

	printw("\n");
	attron(A_UNDERLINE); printw("%6s", BPSS);
	attrset(A_NORMAL); printw(" ");
	attron(A_UNDERLINE); printw("%4s", "%");
	attrset(A_NORMAL); printw(" ");
	if (Tflag) {
		attron(A_UNDERLINE); printw("%6s", BS);
		attrset(A_NORMAL); printw(" ");
	}
	attron(A_UNDERLINE); printw("%-*s", maxx - LLEN, "desc");
	attrset(A_NORMAL); printw("\n");

	clrtobot();
	for (i = 0; i < nflows; i++) {
		getyx(stdscr, y, x);
		if (y >= maxy - 2)
			break;
		if (flows[i].octets == 0 && flows[i].keepalive == 0)
			continue;
		if (flows[i].octets == 0)
			attron(A_DIM);
		else if (flows[i].keepalive < kflag)
			attron(A_BOLD);
		if (flows[i].octets)
			printw("%6s %3d%% ",
				mega(BITS(flows[i].octets / period), "%5.1f"),
				(int)(100 * flows[i].octets / period / maxbps));
		else
			printw("%6s %4s ", "", "");
		if (Tflag)
			printw("%6s ", 
				mega((double)BITS(flows[i].total_octets),
				     "%5.1f"));
		printw("%.*s\n", maxx - LLEN, flows[i].tag);
		if (flows[i].desc[0] != '\0') {
			printw("%6s %4s ", "", "");
			if (Tflag)
				printw("%6s ", "");
			addch(ACS_LLCORNER);
			printw(" %.*s\n", maxx - LLEN - 2, flows[i].desc);
		}
		attrset(A_NORMAL);
	}
	for (i = 0; i < nflows; i++)
		if (flows[i].octets > 0)
			flows[i].keepalive = kflag;
		else if (flows[i].keepalive > 0) {
			flows[i].keepalive--;
			if (flows[i].keepalive <= 0 && !flows[i].dontdel) {
				flow_del(&flows[i]);
				i--;	/* cause new flow slips in */
			}
		}

	refresh();

	/* If tag names will change, we need to reset everything */
	if (clearflows)
		while (nflows)
			flow_del(flows);
}

void
display_message(const char *fmt, ...)
{
	int maxy, maxx;
	char *buf;
	va_list ap;

	if (resize_needed)
		resize();

	getmaxyx(stdscr, maxy, maxx);
	buf = alloca(maxx);

	va_start(ap, fmt);
	vsnprintf(buf, maxx - 2, fmt, ap);
	va_end(ap);

	move(maxy - 1, 0);
	clrtoeol();
	addstr(buf);

	refresh();
}

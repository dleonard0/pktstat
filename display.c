/* David Leonard, 2002. Public domain. */
/* $Id$ */

#include <stdio.h>
#include <stdlib.h>
#include <curses.h>
#include <sys/types.h>

#include "display.h"
#include "flow.h"
#include "main.h"
#include "resize.h"

#define BPS(r)	(Bflag ? (r) : (r) * NBBY)
#define BPSS	(Bflag ? "Bps" : "bps")

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
	int i;
	unsigned long sum;
	double bps = 0;
	int maxx, maxy, y, x;
	int redraw_needed = 0;

	if (resize_needed) {
		resize();
		redraw_needed = 1;
	}

	switch (getch()) {
	case ('L'&0x3f):	/* control-L */
		redraw_needed = 1;
		break;
	case 'q':
		exit(0);
	case 't':
		tflag = !tflag;
		break;
	case 'n':
		nflag = !nflag;
		while (nflows)
			flow_del(flows);	/* because tags change */
		break;
	case 'b':
	case 'B':
		Bflag = !Bflag;
		break;
	case ERR:		/* no key */
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
	printw("device: %s\n", display_device);
	if (display_filter)
		printw("filter: %s\n", display_filter);

	/* sort the flows by their packet octet count */
	qsort(flows, nflows, sizeof (struct flow), tflag ? octetcmp : tagcmp);

	sum = 0;
	for (i = 0; i < nflows; i++)
		sum += flows[i].octets;

	total_octets += sum;
	total_time += period;

	if (period > 0.5) {
		bps = sum / period;
		if (minbps < 0 || bps < minbps)
			minbps = bps;
		if (maxbps < 0 || bps > maxbps)
			maxbps = bps;
		printw("cur: %-6s ", mega(BPS(bps), "%.1f"));
	}
	if (total_time > 0)
		printw("avg: %-6s ", 
			mega(BPS(total_octets / total_time), "%.1f"));
	if (minbps >= 0)
		printw("min: %-6s ",
			mega(BPS(minbps), "%.1f"));
	if (maxbps >= 0)
		printw("max: %-6s ", 
			mega(BPS(maxbps), "%.1f"));
	printw("%s\n", BPSS);

	printw("\n");
	attron(A_UNDERLINE); printw("%6s", BPSS);
	attrset(A_NORMAL); printw(" ");
	attron(A_UNDERLINE); printw("%4s", "%");
	attrset(A_NORMAL); printw(" ");
	attron(A_UNDERLINE); printw("%-*s", maxx - 15, "desc");
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
				mega(BPS(flows[i].octets / period), "%5.1f"),
				(int)(100 * flows[i].octets / period / maxbps));
		else
			printw("%6s %4s ", "", "");
		printw("%.*s\n", maxx - 13, flows[i].tag);
		if (flows[i].desc[0] != '\0') {
			printw("%6s %4s ", "", "");
			addch(ACS_LLCORNER);
			printw(" %.*s\n", maxx - 13 - 2, flows[i].desc);
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
}

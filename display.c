/* David Leonard, 2002. Public domain. */
/* $Id$ */
#include <stdio.h>
#include <stdlib.h>
#include <curses.h>

#include "display.h"
#include "flow.h"

static unsigned long total_octets = 0;
static double total_time = 0;
static double maxbps = -1;
static double minbps = -1;
static const char *display_device, *display_filter;

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

	erase();

	switch (getch()) {
	case ('L'&0x3f):	/* control-L */
		clear(); 
		break;
	case 'q':
		exit(0);
	case ERR:		/* no key */
	default:
		break;	
	}

	getmaxyx(stdscr, maxy, maxx);
	printw("device: %s\n", display_device);
	if (display_filter)
		printw("filter: %s\n", display_filter);

	if (period == 0) 
		return;

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
		printw("cur %-8.1f ", bps);
	}
	if (total_octets)
		printw("avg %-8.1f", total_octets / total_time);
	printw("min %-8.1f max %-8.1f\n", minbps, maxbps);
	printw("\n");

	for (i = 0; i < nflows; i++) {
		getyx(stdscr, y, x);
		if (y >= maxy - 2)
			break;
		if (flows[i].octets == 0 && flows[i].keepalive == 0)
			continue;
		if (flows[i].octets == 0)
			attron(A_DIM);
		else if (flows[i].keepalive < keepalive)
			attron(A_BOLD);
		printw("%8.1f bps %3d%% %s\n",
			flows[i].octets / period,
			(int)(100 * flows[i].octets / period / maxbps),
			/* (int)(flows[i].octets * 100 / sum), */
			flows[i].tag);
		if (flows[i].desc[0] != '\0')
		printw("%8s            %s\n", "", flows[i].desc);
		attrset(A_NORMAL);
	}
	for (i = 0; i < nflows; i++)
		if (flows[i].octets > 0)
			flows[i].keepalive = keepalive;
		else if (flows[i].keepalive > 0) {
			flows[i].keepalive--;
			if (flows[i].keepalive <= 0 && !flows[i].dontdel) {
				flow_del(&flows[i]);
				i--;	/* cause new flow slips in */
			}
		}

	refresh();
}
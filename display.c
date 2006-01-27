/* David Leonard, 2002. Public domain. */
/* $Id$ */

/*
 * This compilation unit uses curses to display the current
 * list of active tags on the screen. It also handles keystroke
 * input to make changes to flag settings.
 * And, although this is not the right place for it, all
 * the averages are computed here.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <curses.h>
#include <stdarg.h>
#include <math.h>
#include <err.h>
#include <time.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <net/if.h>

#include "display.h"
#include "flow.h"
#include "main.h"
#include "resize.h"
#include "ifc.h"
#include "tag.h"

#undef MIN
#undef MAX
#define MIN(a,b)	((a) < (b) ? (a) : (b))
#define MAX(a,b)	((a) > (b) ? (a) : (b))

#ifndef NBBY
# define NBBY 8	/* Number of bits per byte */
#endif

#define BITS(r)	(Bflag ? (r) : (r) * NBBY)
#define BPSS	(Bflag ? "Bps" : "bps")
#define BS	(Bflag ? "B" : "b")

static unsigned long total_octets = 0;
static double total_time = 0;
static double maxbps = -1;
static double minbps = -1;
static const char *display_device, *display_filter;
static int display_opened = 0;
static volatile int resize_needed = 0;
#if HAVE_EXP
static double avg[3] = { 0.0, 0.0, 0.0 };
static double avg_pkt[3] = { 0.0, 0.0, 0.0 };
#endif
static int showhelp = 0;
static int wasdown = 0;

static unsigned long total_packets = 0;
static double maxpps = -1;
static double minpps = -1;

static const char *mega(double, const char *);
static const char *days(double);
static void printhelp(void);

/* Return SI unit representation for number x, e.g (3000,"%.1f") -> "3.0k" */
static
const char *
mega(x, fmt)
	double x;
	const char *fmt;
{
	static char buf[1024];	/* XXX - arbitrary size */
	static char suffix[] = " kMGTPE";
	int i;
	int len;

	i = 0;
	while (x >= 999.95 && suffix[i]) {
		x /= 1000.0;
		i++;
	}
	if (!suffix[i]) {
		x /= 0.0;	/* IEEE Inf */
		i = 0;		/* no unit */
	}
	snprintf(buf, sizeof buf - 1, fmt, x);
	len = strlen(buf);
	if (i)
		buf[len++] = suffix[i];
	buf[len] = '\0';
	return buf;
}

/* Return human-friendly time expression, eg in days, weeks, hours etc. */
static const char *
days(td)
	double td;
{
	static char buf[1024];	/* XXX - arbitrary size */
	unsigned long t = td;

	static const int Mn = 60;
	static const int Hr = 60 * 60;
	static const int Dy = 24 * 60 * 60;

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

/* Prepare the display using curses */
void
display_open(device, filter)
	const char *device, *filter;
{

	display_device = device;
	display_filter = filter;
	initscr();
	cbreak();
	noecho();
	scrollok(stdscr, FALSE);
	nodelay(stdscr, TRUE);
	display_opened = 1;
	resize_init(&resize_needed);
	ifc_init(device);		/* XXX shouldn't be here */
}

/* Close the display */
void
display_close()
{
	if (display_opened)
		endwin();
	display_opened = 0;
}

/* Update the display, sorting and drawing all the computed tags */
void
display_update(period)
	double period;
{
	int i, flags;
	unsigned long sum;
	double bps = 0;
	int maxx, maxy, y, x;
	int maxi;
	int redraw_needed = 0;
	int clearflows = 0;
	unsigned long sum_packets;
	double pps = 0;

	if (resize_needed) {
		resize();
		redraw_needed = 1;
	}

	getmaxyx(stdscr, maxy, maxx);

	/* Handle keystroke since the last screen update */
	switch (getch()) {
	case ('L'&0x3f):		/* control-L to redraw */
		redraw_needed = 1;
		break;
	case 'q':			/* q for quit */
		exit(0);
	case 't':			/* toggle -t */
		tflag = !tflag;
		if (tflag)
			lflag = 0;
		break;
	case 'l':			/* toggle -l */
		lflag = !lflag;
		if (lflag)
			tflag = 0;
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
	case 'p':			/* toggle -p */
		pflag = !pflag;
		break;
	case 'f': case 'F':		/* toggle -F */
		Fflag = !Fflag;
		clearflows = 1;
		break;
	case 'r':			/* reset stats */
		total_octets = 0;
		total_packets = 0;
		total_time = 0;
		maxbps = -1;
		minbps = -1;
		maxpps = -1;
		minpps = -1;
		period = 0;
		while (nflows)		/* clear flows now */
			flow_del(flows);
#if HAVE_EXP
		for (i = 0; i < 3; i++)	/* clear averages */
			avg[i] = avg_pkt[i] = 0;
#endif
		ip_reset();
		udp_reset();
		tcp_reset();
		break;
	case '?':			/* show help line */
		if (showhelp > 0)
			showhelp = 0;
		else
			showhelp = 1;
		break;
	case ERR:			/* no key */
		break;
	default:			/* unknown key */
		break;	
	}

	if (redraw_needed)
		clearok(curscr, TRUE);

	move(0,0);

	/* sort the flows by their packet octet count */
	qsort(flows, nflows, sizeof (struct flow), 
		lflag ? lastcmp 
		      : tflag ? (pflag ? packetcmp : octetcmp)
			      : tagcmp);

	/* Compute total number of octets we have just seen go by */
	sum = 0;
	sum_packets = 0;
	for (i = 0; i < nflows; i++) {
		sum += flows[i].octets;
		sum_packets += flows[i].packets;
	}

	/* Keep track of totals for the -T flag */
	total_octets += sum;
	total_packets += sum_packets;
	total_time += period;

	/* Print information about the interface */
	printw("interface: %s ", display_device);

	flags = ifc_flags();
	if ((flags & IFF_UP) == 0) {
		static char since[27];
		int oattr = attron(A_REVERSE);
		printw("down");
		attrset(oattr);
		if (!wasdown) {
			time_t now = time(0);
			char *c = ctime(&now);
			memcpy(since, c, 24);
			since[24] = '\0';
			beep();
			wasdown = 1;
		}
		printw(" (since %s) ", since);
	} else
		wasdown = 0;

	if ((flags & IFF_RUNNING) == 0)
		printw("(not running) ");

	if (Tflag)
		printw("   total: %s%s (%s)", mega(
		    pflag ? total_packets : (double)BITS(total_octets), "%.1f"),
		    pflag ? "p" : BS, days(total_time));
	clrtoeol();
	printw("\n");

	/* Compute minimum and maximum octet rates */
	if (period > 0) {
		bps = sum / period;
		if (minbps < 0 || bps < minbps)
			minbps = bps;
		if (maxbps < 0 || bps > maxbps)
			maxbps = bps;
		pps = sum_packets / period;
		if (minpps < 0 || pps < minpps)
			minpps = pps;
		if (maxpps < 0 || pps > maxpps)
			maxpps = pps;

#if HAVE_EXP
		/* Compute the 1, 5 and 15 minute average packet/bit rates */
		for (i = 0; i < 3; i++) {
			static double T[3] = { 60, 5 * 60, 15 * 60 };
			double eT = exp(-period / T[i]);
			avg[i] = avg[i] * eT + bps * (1.0 - eT);
			avg_pkt[i] = avg_pkt[i] * eT + pps * (1.0 - eT);
		}
#endif
	}

	if (!Tflag) {
#if HAVE_EXP
		/* Display simple load average */
		printw("load averages: ");
		printw("%s ", mega(pflag ? avg_pkt[0] : BITS(avg[0]), "%.1f"));
		printw("%s ", mega(pflag ? avg_pkt[1] : BITS(avg[1]), "%.1f"));
		printw("%s ", mega(pflag ? avg_pkt[2] : BITS(avg[2]), "%.1f"));
#endif
	} else {
		/* Display sophisticated load averages for the -T flag */
		if (period > 0) {
			printw("cur: %s ", mega(pflag ? pps : BITS(bps),
			    "%.1f"));
			if (mflag > 0)
				printw("(%u%%) ", (int)(100.0 * bps / mflag));
			else if (maxbps > 0)
				printw("(%u%%) ", (int)(100.0 * bps / maxbps));
		}
#if HAVE_EXP
		printw("[%s ", mega(pflag ? avg_pkt[0] : BITS(avg[0]),
		    "%.1f"));
		printw("%s ", mega(pflag ? avg_pkt[1] : BITS(avg[1]),
		    "%.1f"));
		printw("%s] ", mega(pflag ? avg_pkt[1] : BITS(avg[2]),
		    "%.1f"));
#endif
		if (minbps >= 0)
			printw("min: %s ",
				mega(pflag ? minpps : BITS(minbps), "%.1f"));
		if (!pflag && mflag > 0) {
			printw("max: ");
			attron(A_UNDERLINE);
			printw("%s", mega(BITS(mflag), "%.1f"));
			attrset(A_NORMAL);
			if (maxbps > mflag)
				printw(" (%s)", mega(BITS(maxbps), "%.1f"));
			printw(" ");
		} else if (maxbps >= 0)
			printw("max: %s ", 
				mega(pflag ? maxpps : BITS(maxbps), "%.1f"));
		if (total_time > 0) {
			printw("avg: %s ", mega(
			    (pflag ? total_packets : BITS(total_octets)) /
			    total_time, "%.1f"));
		}
	}
	printw("%s", pflag ? "pps" : BPSS);
	clrtoeol();

	/* Print information about the filter (if any) */
	move(2, 0);
	if (display_filter)
		printw("filter: %s", display_filter);
	clrtoeol();
	move(3, 0);

/* Computing the indent for tag descripions now */
#define LLEN	(13 + (Tflag ? 7 : 0) - (pflag ? 5 : 0))

	/* Print the heading row */
	attron(A_UNDERLINE); printw("%6s", pflag ? "pps" : BPSS);
	attrset(A_NORMAL); printw(" ");
	if (!pflag) {
		attron(A_UNDERLINE); printw("%4s", "%");
		attrset(A_NORMAL); printw(" ");
	}
	if (Tflag) {
		attron(A_UNDERLINE); printw("%6s", pflag ? "p" : BS);
		attrset(A_NORMAL); printw(" ");
	}
	attron(A_UNDERLINE); printw("%-*s", 
		MIN(maxx - LLEN, 
		    MAX(sizeof flows->desc + 2, sizeof flows->tag) - 1),
		"desc");
	attrset(A_NORMAL); 
	clrtoeol();
	printw("\n");

	clrtobot();

	maxi = nflows;
	for (i = 0; i < nflows; i++) {

		/* Handle going off the bottom of the screen */
		getyx(stdscr, y, x);
		if (y >= maxy - 2) {
			maxi = i + 10;
			break;
		}

		/* Ignore flows that have stopped for a while */
		if (!lflag && flows[i].octets == 0 && flows[i].keepalive <= 0)
			continue;

		/* Dim flows that have paused */
		if (flows[i].octets == 0)
			attron(A_DIM);
		/* Embolden flows that have started up again */
		else if (flows[i].keepalive < kflag)
			attron(A_BOLD);

		/* Print the bitrate of active flows */
		if (flows[i].octets && period > 0) {
			printw("%6s ", mega(
			    (pflag ? flows[i].packets : BITS(flows[i].octets)) /
			    period, "%5.1f"));
			if (!pflag) printw("%3d%% ", 
			    (int)(100.0 * (flows[i].octets / period / 
					   (mflag>0 ? mflag : maxbps))));
		} else {
			printw("%6s ", "");
			if (!pflag) printw("%4s ", "");
		}

		/* Show a flow's total bit history with the -T flag */
		if (Tflag)
			printw("%6s ", 
				mega((double) (pflag 
				    ? flows[i].total_packets
				    : BITS(flows[i].total_octets)),
				    "%5.1f"));

		/* Finally, the flow's name */
		printw("%.*s\n", MIN(maxx - LLEN, sizeof flows[i].tag - 1),
		    flows[i].tag);

		/* On a new line, show the flow's description, if it has one */
		if (flows[i].desc[0] != '\0') {
			printw("%6s ", "");
			if (!pflag) printw("%4s ", "");
			if (Tflag)
				printw("%6s ", "");
			/* Show a right angle if the connection is live */
			if (flows[i].dontdel)
				addch(ACS_LLCORNER);
			else
				addch('-');
			printw(" %.*s\n", MIN(maxx - LLEN - 2, 
			    sizeof flows[i].desc - 1), flows[i].desc);
		}
		attrset(A_NORMAL);
	}

	if (showhelp) {
		move(maxy - 1, 0);
		printhelp();
	}

	/* Flush output to the screen */
	refresh();

	/* Decrement keepalive counter for flows that have paused. */
	for (i = 0; i < nflows; i++) {
		if (flows[i].octets > 0) {
			flows[i].keepalive = kflag;
			continue;
		}
		if (flows[i].keepalive > 0)
			flows[i].keepalive -= period;
		if ((!lflag || i >= maxi) && flows[i].keepalive <= 0 && !flows[i].dontdel) {
			flow_del(&flows[i]);
			i--;	/* because a new flow slips in */
		}
	}


	/* If tag names are about to change, we need to reset everything */
	if (clearflows)
		while (nflows)
			flow_del(flows);
}

/* Display an informational message at the bottom of the screen */
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
	if (buf[0])
		addstr(buf);
	else if (showhelp)
		printhelp();

	refresh();
}

/* Print the help text */
static void
printhelp()
{
	static struct helplabel {
		int	*flagp;
		const char *name;
	} helplabels[] = {
		{ &tflag, "top" },
		{ &lflag, "last" },
		{ &nflag, "numeric" },
		{ &Bflag, "Byte" },
		{ &pflag, "packet" },
		{ &Fflag, "FQDN" },
		{ &Tflag, "Total" },
		{ NULL,   "reset" },
		{ NULL,   "quit" },
		{ NULL,   "?help" },
	};
#define nhelplabels (sizeof helplabels / sizeof helplabels[0])

	struct helplabel *h;

	for (h = helplabels; h < helplabels + nhelplabels; h++) {
		attrset(A_UNDERLINE);
		if (h->flagp && *h->flagp)
			attron(A_REVERSE);
		printw("%c", h->name[0]);
		attroff(A_UNDERLINE);
		printw((char *)h->name + 1);
		attrset(0);
		printw(" ");
	}
	printw(" - pktstat %s", version);
}

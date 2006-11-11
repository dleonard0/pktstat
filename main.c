/* David Leonard, 2002. Public domain. */
/* $Id$ */

/*
 * The main module. Here we process command line arguments, and
 * interface pcap to our tag and flow display modules.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#if STDC_HEADERS
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
#endif
#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#if HAVE_ERRNO_H
# include <errno.h>
#endif

#if HAVE_PCAP_H
# include <pcap.h>
#endif
#if HAVE_POLL_H
# include <poll.h>
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

#include "compat.h"
#include "main.h"
#include "tag.h"
#include "flow.h"
#include "display.h"
#include "abbrev.h"

/* Flags set by command-line options */
int Bflag = 0;
int cflag = 0;
int Eflag = 0;
int Fflag = 0;
int kflag = 10;
int lflag = 0;
double mflag = 0;
int nflag = 0;
int pflag = 0;
int Pflag = 0;
int tflag = 0;
int Tflag = 0;
int wflag = 5;

/* Current release version */
char version[] = PACKAGE_VERSION;

/* The system time when the current packet capture cycle started */
static struct timeval starttime;

#if !defined(timersub)
#define timersub(tvp, uvp, vvp)                                         \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
                if ((vvp)->tv_usec < 0) {                               \
                        (vvp)->tv_sec--;                                \
                        (vvp)->tv_usec += 1000000;                      \
                }                                                       \
        } while (0)
#endif

/*
 * Receive a packet from libpcap and determine its category tag.
 * This is called directly from libpcap.
 */
static void
upcall_from_pcap(context, hdr, data)
	u_char *context;
	const struct pcap_pkthdr *hdr;
	const u_char *data;
{
	const char *tag;
	const char *(*fn)(const char *, const char *) =
		(const char *(*)(const char *, const char *))context;
	struct flow *flow;

	/* 'Tag' this packet. ie identify it in a human-readable way */
	tag = abbrev_tag((*fn)((const char *)data, 
		(const char *)data + hdr->caplen));

	/* Find which tracked flow the packet belongs to and account it */
	flow = findflow(tag);
	flow->octets += hdr->len;
	flow->total_octets += hdr->len;
	flow->lastseen = starttime;
	flow->packets++;
	flow->total_packets++;
}

/* main */
int
main(argc, argv)
	int argc;
	char *argv[];
{
	int ch;
	extern int optind;
	extern char *optarg;
	pcap_t *p;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *interface = NULL;
	int error = 0;
	int datalink_type;
	const char *(*fn)(const char *, const char *);
	int i;
	int snaplen = 1500;
	char *expr = NULL;
	int exprlen;
	int blankAflag = 0;

	/* Process command line options */
	while ((ch = getopt(argc, argv, "A:a:BcEFi:k:lm:npPtTw:")) != -1)
		switch (ch) {
		case 'A':
			if (strcmp(optarg, "none") == 0)
				blankAflag = 1;
			else
				abbrev_add_file(optarg, 0);
			break;
		case 'a':
			abbrev_add(optarg);
			break;
		case 'B':
			Bflag = 1;		/* bps/Bps flag */
			break;
		case 'c':
			cflag = 1;		/* no-combine */
			break;
		case 'E':
			Eflag = 1;		/* XXX undocumented - ignore errors from pcap */
			break;
		case 'F':
			Fflag = 1;		/* full hostname */
			break;
		case 'i':
			interface = optarg;	/* interface */
			break;
		case 'k':
			kflag = atoi(optarg);	/* keep-on-screen time */
			break;
		case 'l':
			if (tflag) {
				warnx("-l incompatible with -t");
				error = 1;
			}
			lflag = 1;		/* 'last' mode */
			break;
		case 'm':
			mflag = atof(optarg) / 8.0;	/* maxbps */
			if (mflag <= 0) {
				warnx("invalid argument to -m");
				error = 1;
			}
			break;
		case 'n':
			nflag = 1;		/* no-lookup */
			break;
		case 'p':
			pflag = 1;		/* show packets, not bits */
			break;
		case 'P':
			Pflag = 1;		/* no promiscuous mode */
			break;
		case 't':
			if (lflag) {
				warnx("-t incompatible with -l");
				error = 1;
			}
			tflag = 1;		/* 'top' mode */
			break;
		case 'T':
			Tflag = 1;		/* total column */
			break;
		case 'w':
			wflag = atoi(optarg);	/* wait time */
			break;
		default:
			error = 1;
		}

	/* Handle usage errors */
	if (error) {
		fprintf(stderr, "pktstat version %s\n", VERSION);
		fprintf(stderr, "usage: %s"
		    " [-BcFlnpPtT] [-i interface]"
		    " [-k keeptime] [-m maxbps] [-w wait]"
		    " [-a abbrev] [-A file]"
		    " [filter-expr]\n",
		    argv[0]);
		exit(1);
	}

	/* Open the interface */
	if (interface == NULL)
		interface = pcap_lookupdev(errbuf);
	if (!interface) 
		errx(1, "pcap_lookupdev: %s", errbuf);
	p = pcap_open_live(interface, snaplen, Pflag ? 0 : 1, 0, errbuf);
	if (!p) 
		errx(1, "%s", errbuf);

	/* XXX should drop privileges here before opening files */
	/* if (issetugid()) seteuid(getuid()); */

	/* Use default abbreviations if nothing specified */
	if (!blankAflag)
		abbrev_add_default_files();

	/* Determine the datalink type */
	datalink_type = pcap_datalink(p);
	switch (datalink_type) {
	case DLT_PPP:
		fn = ppp_tag;
		break;
	case DLT_EN10MB:
		fn = ether_tag;
		break;
#if defined(DLT_LINUX_SLL)
	case DLT_LINUX_SLL:
		fn = sll_tag;
		break;
#endif
#if defined(DLT_LOOP)
	case DLT_LOOP:
		fn = loop_tag;
		break;
#endif
	case DLT_RAW:
		fn = ip_tag;
		break;
	default:
		errx(1, "unknown datalink type %d", datalink_type);
	}

	/* Add a filter expression */
	if (optind < argc) {
		struct bpf_program bpfprog = { 0, 0 };
		bpf_u_int32 net, mask;

		/* Allocate storage for the expression */
		exprlen = 0;
		for (i = optind; i < argc; i++)
			exprlen += strlen(argv[i]) + 1;
		expr = malloc(exprlen);
		if (expr == NULL)
			errx(1, "malloc");

		/* Concatenate the remaining command line args into a string */
		*expr = '\0';
		exprlen = 0;
		for (i = optind; i < argc; i++) {
			int len = strlen(argv[i]);
			memcpy(expr + exprlen, argv[i], len);
			exprlen += len;
			if (i != argc - 1)
				expr[exprlen++] = ' ';
		}
		expr[exprlen++] = '\0';

		/* Compile and install the filter expression */
		if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1)
			errx(1, "%s: %s", interface, errbuf);
		if (pcap_compile(p, &bpfprog, expr, 1, mask) == -1)
			errx(1, "pcap_compile: %s", pcap_geterr(p));
		if (pcap_setfilter(p, &bpfprog) == -1)
			errx(1, "pcap_setfilter: %s", pcap_geterr(p));
	}

	/* Initialise the counters and display */
	if (gettimeofday(&starttime, NULL) == -1)
		err(1, "gettimeofday");
	display_open(interface, expr);
	atexit(display_close);
	flow_zero();
	display_update(0);

	/* Dump and display the packets */
	for (;;) {
		struct timeval diff, now;
		double period;
		char errmsg[1024];	/* XXX - arbitrary size */
		int error = 0;
		int cnt;
		struct pollfd pfd[2];

		/* Wait for something to happen */
		pfd[0].fd = pcap_fileno(p);
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		pfd[1].fd = STDIN_FILENO;
		pfd[1].events = POLLIN;
		pfd[1].revents = 0;
		if (poll(pfd, 2, wflag * 1000) == -1) {
			if (errno != EINTR) 
				err(1, "poll");
		}

		/* Handle packet arrivals */
		if (pfd[0].revents) {
			cnt = pcap_dispatch(p, -1, upcall_from_pcap,
				(u_char *)fn);
			if (cnt == -1) {
				snprintf(errmsg, sizeof errmsg, pcap_geterr(p));
				error = 1;
			}
		}

		/* Figure out how much time we were blocked for */
		if (gettimeofday(&now, NULL) == -1)
			err(1, "gettimeofday");
		timersub(&now, &starttime, &diff);
		period = diff.tv_sec + diff.tv_usec * 1e-6;

		/* Update the flow display if the delay period has passed */
		if (period >= wflag || pfd[1].revents) {
			display_update(period);
			starttime = now;
			flow_zero();
		}

		/* Display pcap errors as soon as we can */
		if (error) {
			int t = (wflag - period) * 1000000;
			struct timespec ts;

			if (!Eflag) {
				display_close();
				errx(1, "%s", errmsg);
			}

			display_message(errmsg);
			if (t) {
				/* sleep for the rest of the period */
				ts.tv_sec = t / 1000000;
				ts.tv_nsec = t % 1000000;
				nanosleep(&ts, NULL);
			}
		}
	}

	pcap_close(p);
	exit(0);
}

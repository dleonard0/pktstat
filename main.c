/* David Leonard, 2002. Public domain. */
/* $Id$ */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <pcap.h>
#include <poll.h>
#include <sys/time.h>

#include "main.h"
#include "tag.h"
#include "flow.h"
#include "display.h"
#include "abbrev.h"

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

#define VERSION "1.7.2r.t20030817"
char version[] = VERSION;

/* When the packet capture interval started */
static struct timeval starttime;

/* Receive a packet from libpcap and determine its category tag */
static void
handler(context, hdr, data)
	u_char *context;
	const struct pcap_pkthdr *hdr;
	const u_char *data;
{
	const char *tag;
	const char *(*fn)(const char *, const char *) =
		(const char *(*)(const char *, const char *))context;
	struct flow *flow;

	tag = abbrev_tag((*fn)(data, data + hdr->caplen));
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
	u_char *fn;
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
		fn = (u_char *)ppp_tag;
		break;
	case DLT_EN10MB:
		fn = (u_char *)ether_tag;
		break;
#if defined(DLT_LINUX_SLL)
	case DLT_LINUX_SLL:
		fn = (u_char *)sll_tag;
		break;
#endif
#if defined(DLT_LOOP)
	case DLT_LOOP:
		fn = (u_char *)loop_tag;
		break;
#endif
	case DLT_RAW:
		fn = (u_char *)ip_tag;
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

		if (pfd[0].revents) {
			cnt = pcap_dispatch(p, -1, handler, fn);
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

		/* Update the display if the -w period has passed */
		if (period >= wflag || pfd[1].revents) {
			display_update(period);
			starttime = now;
			flow_zero();
		}

		/* Display pcap errors */
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

/* Combine source and dest to make a combined tag unless -c flag given */
const char *
tag_combine(src, dst)
	const char *src;
	const char *dst;
{
	static char buf[TAGLEN];
	static char buf2[TAGLEN];
	const char *res;

	if (cflag) {
		snprintf(buf, sizeof buf, "%s -> %s", src, dst);
		res = abbrev_tag(buf);
	} else {
		snprintf(buf, sizeof buf, "%s <-> %s", src, dst);
		res = abbrev_tag(buf);
		if (res == buf) {
			snprintf(buf2, sizeof buf2, "%s <-> %s", dst, src);
			res = abbrev_tag(buf2);
			if (res == buf2)
				if (strcmp(src, dst) < 0)
					res = buf;
		}
	}
	return res;
}

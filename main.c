/* David Leonard, 2002. Public domain. */
/* $Id$ */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <pcap.h>
#include <sys/time.h>

#include "main.h"
#include "tag.h"
#include "flow.h"
#include "display.h"

int Bflag = 0;
int cflag = 0;
int Fflag = 0;
int kflag = 10;
int nflag = 0;
int tflag = 0;
int Tflag = 0;
int wflag = 5;

#define VERSION "1.6.1"

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

	tag = (*fn)(data, data + hdr->caplen);
	flow = findflow(tag);
	flow->octets += hdr->len;
	flow->total_octets += hdr->len;
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
	struct timeval start;
	int i;
	int snaplen = 1500;
	char *expr = NULL;
	int exprlen;

	/* Process command line options */
	while ((ch = getopt(argc, argv, "BcFi:k:ntTw:")) != -1)
		switch (ch) {
		case 'B':
			Bflag = 1;		/* bps/Bps flag */
			break;
		case 'c':
			cflag = 1;		/* no-combine */
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
		case 'n':
			nflag = 1;		/* no-lookup */
			break;
		case 't':
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
		    " [-BcFntT] [-i interface]"
		    " [-k keepcount] [-w wait] [filter-expr]\n",
		    argv[0]);
		exit(1);
	}

	/* Open the interface */
	if (interface == NULL)
		interface = pcap_lookupdev(errbuf);
	if (!interface) 
		errx(1, "pcap_lookupdev: %s", errbuf);
	p = pcap_open_live(interface, snaplen, 1, wflag * 1000, errbuf);
	if (!p) 
		errx(1, "%s", errbuf);

	/* Determine the datalink type */
	datalink_type = pcap_datalink(p);
	switch (datalink_type) {
	case DLT_PPP:
		fn = (u_char *)ppp_tag;
		break;
	case DLT_EN10MB:
		fn = (u_char *)ether_tag;
		break;
	case DLT_LOOP:
		fn = (u_char *)loop_tag;
		break;
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
	if (gettimeofday(&start, NULL) == -1)
		err(1, "gettimeofday");
	display_open(interface, expr);
	atexit(display_close);
	flow_zero();
	display_update(0);

	/* Dump and display the packets */
	for (;;) {
		struct timeval now, diff;
		double period;

		if (pcap_dispatch(p, 0, handler, fn) == -1)
			errx(1, "%s", pcap_geterr(p));

		/* Figure out how long how much time it really took */
		if (gettimeofday(&now, NULL) == -1)
			err(1, "gettimeofday");
		timersub(&now, &start, &diff);
		period = diff.tv_sec + diff.tv_usec * 1e-6;

		/* Update the display if the -w period has passed */
		if (period >= wflag) {
			display_update(period);
			start = now;
			flow_zero();
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
	static char buf[80];
	if (cflag) 
		snprintf(buf, sizeof buf, "%s -> %s", src, dst);
	else if (strcmp(src, dst) < 0)
		snprintf(buf, sizeof buf, "%s <-> %s", src, dst);
	else
		snprintf(buf, sizeof buf, "%s <-> %s", dst, src);
	return buf;
}

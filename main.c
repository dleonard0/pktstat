/* David Leonard, 2002. Public domain. */
/* $Id$ */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <pcap.h>
#include <sys/time.h>

#include "tag.h"
#include "flow.h"
#include "display.h"

static int cflag = 0;
int keepalive = 10;
int tflag = 0;
int nflag = 0;

const char *version = "1.0";

/* Receive a packet and determine its category tag */
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
	int waitsec = 5;
	int datalink_type;
	u_char *fn;
	struct timeval start;
	int i;
	int snaplen = 96;
	char *expr = NULL;
	int exprlen;

	/* Process command line options */
	while ((ch = getopt(argc, argv, "ci:k:ntw:")) != -1)
		switch (ch) {
		case 'c':
			cflag = 1;
			break;
		case 'i':
			interface = optarg;
			break;
		case 'k':
			keepalive = atoi(optarg);
			break;
		case 'n':
			nflag = 1;
			break;
		case 't':
			tflag = 1;
			break;
		case 'w':
			waitsec = atoi(optarg);
			break;
		default:
			error = 1;
		}

	/* Handle usage errors */
	if (error) {
		fprintf(stderr, "pktstat version %s\n", version);
		fprintf(stderr, 
		    "usage: %s [-c] [-k keepalive]"
		    " [-w wait] [-i interface] [filter-expr]\n",
		    argv[0]);
		exit(1);
	}

	/* Open the interface */
	if (interface == NULL)
		interface = pcap_lookupdev(errbuf);
	if (!interface) 
		errx(1, "pcap_lookupdev: %s", errbuf);
	p = pcap_open_live(interface, snaplen, 1, waitsec * 1000, errbuf);
	if (!p) 
		errx(1, "%s: %s", interface, errbuf);

	/* Determine the datalink type */
	datalink_type = pcap_datalink(p);
	switch (datalink_type) {
	case DLT_PPP:
		fn = (u_char *)ppp_tag;
		break;
	case DLT_EN10MB:
		fn = (u_char *)ether_tag;
		break;
	default:
		errx(1, "unknown datalink type %d", datalink_type);
	}

	/* Add a filter expression */
	if (optind < argc) {
		struct bpf_program bpfprog = { 0, 0 };
		bpf_u_int32 net, mask;

		exprlen = 0;
		for (i = optind; i < argc; i++)
			exprlen += strlen(argv[i]) + 1;
		expr = malloc(exprlen);
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
		if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1)
			errx(1, "%s: %s", interface, errbuf);
		if (pcap_compile(p, &bpfprog, expr, 1, mask) == -1)
			errx(1, "pcap_compile: %s", pcap_geterr(p));
		if (pcap_setfilter(p, &bpfprog) == -1)
			errx(1, "pcap_setfilter: %s", pcap_geterr(p));
	}

	/* Dump and display the packets */
	if (gettimeofday(&start, NULL) == -1)
		err(1, "gettimeofday");
	display_open(interface, expr);
	atexit(display_close);
	flow_zero();
	display_update(0);
	for (;;) {
		struct timeval now, diff;
		double period;

		if (pcap_dispatch(p, 0, handler, fn) == -1) {
			errx(1, "%s", pcap_geterr(p));
		}
		if (gettimeofday(&now, NULL) == -1)
			err(1, "gettimeofday");
		timersub(&now, &start, &diff);
		period = diff.tv_sec + diff.tv_usec * 1e-6;
		if (period >= waitsec) {
			display_update(period);
			start = now;
			flow_zero();
		}
	}

	pcap_close(p);
	exit(0);
}

/* Combine source and dest to make a combined tag if required */
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

/* David Leonard, 2002. Public domain. */
/* $Id$ */

extern int oneflag;	/* Writing one cycle to stdout */
extern int Bflag;	/* Show bytes instead of bits */
extern int cflag;	/* Keep pkt classes separate (no-combine) */
extern int Eflag;	/* Ignore errors from pcap (not documented) */
extern int Fflag;	/* Show full hostnames (not just first part of FQDN) */
extern int kflag;	/* 'Keep' time in seconds. */
extern int lflag;	/* last mode; keeps seen classes on screen */
extern double mflag;	/* fixed interface maximum in bps (0 means auto) */
extern int nflag;	/* no DNS lookups */
extern int pflag;	/* show packet count instead of bit/byte count */
extern int Pflag;	/* Disables promiscuous mode */
extern int tflag;	/* 'top' mode; sort display by bandwidth/packet count */
extern int Tflag;	/* Show totals */
extern int wflag;	/* wait time between refresh in seconds */

extern char version[];

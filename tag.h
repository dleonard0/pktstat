/* David Leonard, 2002. Public domain. */
/* $Id$ */

/*
 * Tag functions return a string tag depending on the packet payload.
 * The string represents a display category.
 */

extern int combine;

struct ip;
struct in_addr;

const char *ppp_tag(const char *, const char *);
const char *ether_tag(const char *, const char *);
const char *ip_tag(const char *, const char *);
const char *tcp_tag(const char *, const char *, const struct ip *);
const char *udp_tag(const char *, const char *, const struct ip *);
const char *icmp_tag(const char *, const char *, const struct ip *);

const char *tag_combine(const char *, const char *);

const char *ip_lookup(const struct in_addr *);


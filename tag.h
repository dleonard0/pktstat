/* David Leonard, 2002. Public domain. */
/* $Id$ */

/*
 * Tag functions return a string tag depending on the packet payload.
 * The string represents a display category.
 */

extern int combine;

struct ip;
struct in_addr;
struct in6_addr;
struct ip6_hdr;

const char *ppp_tag(const char *, const char *);
const char *ether_tag(const char *, const char *);
const char *loop_tag(const char *, const char *);
const char *sll_tag(const char *, const char *);

const char *ip_tag(const char *, const char *);
const char *ip6_tag(const char *, const char *);

const char *ip_lookup(const struct in_addr *);
const char *ip6_lookup(const struct in6_addr *);

const char *tcp_tag(const char *, const char *, const struct ip *, const struct ip6_hdr *);
const char *udp_tag(const char *, const char *, const struct ip *, const struct ip6_hdr *);
const char *icmp_tag(const char *, const char *, const struct ip *);

const char *ipx_tag(const char *, const char *);

const char *tag_combine(const char *, const char *);

/* Ethernet-like tagging - returns NULL on unknown type */
const char *ether_tagx(u_int16_t type, const char *p, const char *end);

/* Reset hostname and port lookups */
void ip_reset(void);
void tcp_reset(void);
void udp_reset(void);

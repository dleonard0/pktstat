/* David Leonard, 2002. Public domain. */
/* $Id$ */

/*
 * Tag functions return a string tag depending on the packet payload.
 * The string represents a display category.
 * The design philosophy here is that the tags should be short enough
 * and descriptive enough not to overwhelm an operator on a relatively
 * quiet business network, with the presumption that if the operator
 * is interested enough, they can always run tcpdump to look closer.
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

/* Ethernet-like tagging helper */
const char *ether_tagx(u_int16_t type, const char *p, const char *end);

/* Flush hostname and port lookup caches */
void ip_reset(void);
void tcp_reset(void);
void udp_reset(void);

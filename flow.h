/* David Leonard, 2002. Public domain. */
/* $Id$ */

#include <sys/time.h>

#define TAGLEN	1024
#define DESCLEN (TAGLEN - 2)

struct flow {
	char		tag[TAGLEN];
	char		desc[DESCLEN];
	unsigned int	taghash;
	uint64_t	octets;
	uint64_t	total_octets;
	uint64_t	packets;
	uint64_t	total_packets;
	double		keepalive;
	int		dontdel;
	unsigned long	seq[2];		/* seq no for TCP */
	void		*udata;
	void		(*freeudata)(void *);
	struct timeval	lastseen;
};

extern int nflows;
extern struct flow *flows;

struct flow *findflow(const char *tag);
void	     flow_zero(void);
void	     flow_del(struct flow *);
void	     flow_free(void);

int	     octetcmp(const void *, const void *);
int	     tagcmp(const void *, const void *);
int	     lastcmp(const void *, const void *);
int	     packetcmp(const void *, const void *);

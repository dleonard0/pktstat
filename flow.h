/* David Leonard, 2002. Public domain. */
/* $Id$ */

struct flow {
	char		tag[80];
	unsigned int	taghash;
	unsigned long	octets;
	int		keepalive;
};

extern int nflows;
extern struct flow *flows;

struct flow *findflow(const char *tag);
void	     flow_zero(void);
void	     flow_del(struct flow *);

int	     octetcmp(const void *, const void *);
int	     tagcmp(const void *, const void *);

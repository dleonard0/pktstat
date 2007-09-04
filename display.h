/* David Leonard, 2002. Public domain. */
/* $Id$ */

extern int keepalive;
extern int tflag;

void	display_open(const char *device, const char *filter);
void	display_close(void);
void	display_update(double period);
void	batch_update(double period);
void	display_message(const char *msg, ...);

/* David Leonard, 2002. Public domain. */
/* $Id$ */

void tcp_x11(struct flow *f, const char *data, const char *end);
void tcp_http(struct flow *f, const char *data, const char *end, int toserver);
void tcp_sup(struct flow *f, const char *data, const char *end, int isclient);

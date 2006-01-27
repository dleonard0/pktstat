/* David Leonard, 2002. Public domain. */
/* $Id$ */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#if STDC_HEADERS
# include <stdio.h>
# include <string.h>
#endif
#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "main.h"
#include "tag.h"
#include "flow.h"
#include "abbrev.h"

/*
 * Combine source and dest to make a combined tag unless -c flag given
 * What combining means is that we sometimes have flows which are not
 * uni-directional. So we convert a->b and b->a tags to get a<->b. The left and
 * right sides are ordered lexicographically, so that we get only a<->b and
 * not also b<->a.
 * XXX the ordering should be biased to have the local host/net on the left
 * of combined flows.
 */
const char *
tag_combine(src, dst)
	const char *src;
	const char *dst;
{
	static char buf[TAGLEN];
	static char buf2[TAGLEN];
	const char *res;

	if (cflag) {
		snprintf(buf, sizeof buf, "%s -> %s", src, dst);
		res = abbrev_tag(buf);
	} else {
		snprintf(buf, sizeof buf, "%s <-> %s", src, dst);
		res = abbrev_tag(buf);
		if (res == buf) {
			/* The abbreviations could match a reverse combine: */
			snprintf(buf2, sizeof buf2, "%s <-> %s", dst, src);
			res = abbrev_tag(buf2);
			if (res == buf2)
				if (strcmp(src, dst) < 0)
					res = buf;
		}
	}
	return res;
}

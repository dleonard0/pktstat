/* 2006, David Leonard. Public domain */
#if HAVE_CONFIG_H
# include <config.h>
#endif

#include "compat.h"

int
memcmp(pa, pb, len)
	void *pa, *pb;
	size_t len;
{
	unsigned char *a = (unsigned char *)pa;
	unsigned char *b = (unsigned char *)pb;

	while (len--)
	    if (*a == *b)
	    	a++, b++;
	    else 
	   	return *a < *b ? -1 : 1;
	return 0;
}



#include "type.h"

#if DEBUG_MALLOC
#include <stdlib.h>
#include <string.h>
void *xx_malloc(size_t, const char *, int);
void *xx_realloc(void *, size_t, const char *, int);
void xx_free(void *);
char *xx_strdup(const char *s, const char *, int);
#define malloc(sz)      xx_malloc(sz,__FILE__,__LINE__)
#define realloc(ptr,sz) xx_realloc(ptr,sz,__FILE__,__LINE__)
#define free            xx_free
#define strdup(s)       xx_strdup(s,__FILE__,__LINE__)
#endif

#if !HAVE_MEMCMP
int memcmp(const void *, const void *, size_t);
#endif

#if HAVE_ERR_H
# include <err.h>
#else
# if !HAVE_ERR
void err(int, const char *, ...);
void errx(int, const char *, ...);
void warn(const char *, ...);
void warnx(const char *, ...);
# endif
#endif


#if !HAVE_STRNCPY
size_t strlcpy(char *, const char *, size_t);
#endif

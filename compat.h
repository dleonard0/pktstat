
#include "type.h"

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

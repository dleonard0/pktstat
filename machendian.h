/* David Leonard, 2004. Public domain. */
/* $Id$ */

/*
 * Machine-dependent types and endian conversion.
 *
 * The following macros convert from specific to native endianness:
 *
 *	swap16(x)	swap32(x)
 *
 *	letoh16(x)	letoh32(x)
 *	betoh16(x)	betoh32(x)
 *	htole16(x)	htole32(x)
 *	htobe16(x)	htobe32(x)
 *
 * These integer types should also be defined after include this file:
 *
 *	u_int8_t	int8_t
 *	u_int16_t	int16_t
 *	u_int32_t	int32_t
 *
 * The Berkeley socket macros ntohs, ntohl, htons, htonl are assumed to
 * work on 16 (?to?s) and 32 (?to?l) bit integers.
 */

#include <sys/types.h>
#include <sys/param.h>
#if defined(BSD)
# include <sys/endian.h>
# if defined(be16toh) && !defined(betoh16)
   /* Sigh. FreeBSD just has to be different. */
#  define betoh16(x) be16toh(x)
#  define betoh32(x) be32toh(x)
#  define letoh16(x) le16toh(x)
#  define letoh32(x) le32toh(x)
#  define swap32(x)  bswap32(x)
# endif
#endif

#if defined(__linux__) || defined(__FreeBSD_kernel__)
# include <endian.h>
# include <byteswap.h>
# define swap16(x) bswap_16(x)
# define swap32(x) bswap_32(x)
# if defined(WORDS_BIGENDIAN)
#  define letoh16(x)	swap16(x)
#  define letoh32(x)	swap32(x)
#  define betoh16(x)	(x)
#  define betoh32(x)	(x)
# else
#  define letoh16(x)	(x)
#  define letoh32(x)	(x)
#  define betoh16(x)	swap16(x)
#  define betoh32(x)	swap32(x)
# endif
#endif

/*
 * The following macros convert from specific to native endianness:
 *
 *	swap16(x)	swap32(x)
 *
 *	letoh16(x)	letoh32(x)
 *	betoh16(x)	betoh32(x)
 *	htole16(x)	htole32(x)
 *	htobe16(x)	htobe32(x)
 *
 * These integer types should also be defined:
 *
 *	u_int8_t	int8_t
 *	u_int16_t	int16_t
 *	u_int32_t	int32_t
 *
 */

#include <sys/types.h>
#include <sys/param.h>
#if defined(BSD)
# include <sys/endian.h>
#endif

#if defined(__linux__)
# include <endian.h>
# include <byteswap.h>
# define swap16(x) bswap_16(x)
# define swap32(x) bswap_32(x)
# ifdef WORDS_BIGENDIAN
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

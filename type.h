/* David Leonard, 2004. Public domain. */
/* $Id$ */

/*
 * Machine-dependent types and endian conversion defined here:
 *
 *      u_int8_t
 *      u_int16_t
 *      u_int32_t
 *
 * The following macros swap bytes in a 16-bit or 32-bit value:
 *
 *	swap16(x)	swap32(x)
 *
 * The following macros convert from specific to native endianness:
 *
 *	letoh16(x)	letoh32(x)
 *	betoh16(x)	betoh32(x)
 *	htole16(x)	htole32(x)
 *	htobe16(x)	htobe32(x)
 */

/* Try to obtain faster swap macros if possible */
#if HAVE_BYTESWAP_H
# include <byteswap.h>
#endif
#if HAVE_ENDIAN_H
# include <endian.h>
#endif

#if !defined(swap16) || !defined(swap32)
# undef swap16
# define swap16(x)   (uint16_t)( ((uint16_t)(x) & 0x00ff << 8) \
		               | ((uint16_t)(x) & 0xff00 >> 8) )
# undef swap32	     
# define swap32(x)   (uint32_t)( ((uint32_t)(x) & 0x000000ff << 24) \
		               | ((uint32_t)(x) & 0x0000ff00 <<  8) \
		               | ((uint32_t)(x) & 0x00ff0000 >>  8) \
		               | ((uint32_t)(x) & 0xff000000 >> 24) )
#endif

#if HAVE_INTTYPES_H
# include <inttypes.h>
# define u_int8_t uint8_t
# define u_int16_t uint16_t
# define u_int32_t uint32_t
# define u_int64_t uint64_t
#elif HAVE_STDINT_H
# include <stdint.h>
#else
typedef unsigned char u_int8_t;
# if SIZEOF_UNSIGNED_SHORT == 2
typedef unsigned short u_int16_t;
# elif SIZEOF_UNSIGNED_INT == 2
typedef unsigned int   u_int16_t;
# else
#  error "Don't know what type to use for u_int16_t"
# endif
# if SIZEOF_UNSIGNED_INT == 4
typedef unsigned int   u_int32_t;
# elif SIZEOF_UNSIGNED_LONG == 4
typedef unsigned long  u_int32_t;
# else
#  error "Don't know what type to use for u_int32_t"
# endif
# if SIZEOF_UNSIGNED_INT == 8
typedef unsigned int   u_int64_t;
# elif SIZEOF_UNSIGNED_LONG == 8
typedef unsigned long  u_int64_t;
# elif SIZEOF_UNSIGNED_LONG_LONG == 8
typedef unsigned long long u_int64_t;
# else
#  error "Don't know what type to use for u_int64_t"
# endif
#endif

#undef letoh16
#undef letoh32
#undef betoh16
#undef betoh32
#undef htole16
#undef htole32
#undef htobe16
#undef htobe32
#if WORDS_BIGENDIAN
# define letoh16(x) swap16(x)
# define letoh32(x) swap32(x)
# define betoh16(x) (x)
# define betoh32(x) (x)
#else /* little endian */
# define letoh16(x) (x)
# define letoh32(x) (x)
# define betoh16(x) swap16(x)
# define betoh32(x) swap32(x)
#endif
#define htole16(x) letoh16(x)
#define htole32(x) letoh32(x)
#define htobe16(x) betoh16(x)
#define htobe32(x) betoh32(x)

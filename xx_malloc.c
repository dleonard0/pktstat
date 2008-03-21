
/*
 * Simple wrappers around malloc/realloc/free so I can see
 * how much memory has been allocated by which functions
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#if DEBUG_MALLOC

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

struct place;

/* A header kept at the front of every allocation */
struct header {
    unsigned int magic;
#define HEADER_MAGIC 0x3117deed
#define FREED_MAGIC  0xdeed3117
    struct header *next, **prevp;
    struct place *place;
    size_t size;
};

/* A list head for each file:lineno onto which we chain every header */
struct place {
    struct place *next;
    const char *file;
    int lineno;
    struct header *head;
    unsigned int allocs, reallocs, frees;
    size_t size;
};

/* List of known places */
static struct place *places;

/* A flag to say that the atexit handler has been registered */
static int registered;

/* Convert a malloc pointer to a header */
static void *
ptr_from_hdr(struct header *h)
{
    if (!h) 
	return (void *)0;
    return (void *)(h + 1);
}

/* Convert a header to a malloc pointer */
static struct header *
hdr_from_ptr(void *p)
{
    if (!p)
	return (struct header *)0;
    return (struct header *)p - 1;
}

/* Returns at most the right-most len characters of s */
static const char *
right(const char *s, int len)
{
    int slen = strlen(s);
    return slen < len ? s : s + slen - len;
}

/* Dump a summary of allocations */
static void
dump()
{
    struct place *p;

    printf("%-25s %8s %8s %8s %8s\n", "Location", "#alloc", 
	"#realloc", "#free", "unfreed");
    for (p = places; p; p = p->next)
	printf("%20.20s:%-4d %8u %8u %8u %8u\n", right(p->file, 20),
	    p->lineno, p->allocs, p->reallocs, p->frees, p->size);
}

static struct place *
find_place(const char *file, int lineno)
{
    struct place **p, *np;

    if (!registered) {
	registered = 1;
	atexit(dump);
    }

    for (p = &places; *p; p = &((*p)->next)) {
	int cmp = strcmp(file, (*p)->file);
	if (cmp < 0)
	    continue;
	if (cmp > 0)
	    break;
	if ((*p)->lineno == lineno)
	    return *p;
	if ((*p)->lineno > lineno)
	    break;
    }
    np = (struct place *)malloc(sizeof (struct place));

    np->file = file;
    np->lineno = lineno;
    np->head = (struct header *)0;
    np->allocs = 0;
    np->reallocs = 0;
    np->frees = 0;
    np->size = 0;

    np->next = *p;
    *p = np;
    return np;
}

/* Remove a header from its place */
static void
header_remove(struct header *h)
{
    *h->prevp = h->next;
    if (h->next)
	h->next->prevp = h->prevp;
}

/* Insert a header into its place list */
static void
header_insert(struct header *h, struct place *place)
{
    h->next = place->head;
    h->prevp = &place->head;
    if (h->next)
	h->next->prevp = &h->next;
    h->place = place;
}

/* Checks the magic */
static void
check_magic(struct header *h)
{
    if (h) {
	assert(h->magic != FREED_MAGIC);
	assert(h->magic == HEADER_MAGIC);
    }
}

/* Wrap malloc() */
void *
xx_malloc(size_t sz, const char *file, int lineno)
{
    struct header *h;
    struct place *place;
    
    h = (struct header *)malloc(sizeof (struct header) + sz);
    if (h) {
	place = find_place(file, lineno);
	header_insert(h, place);
	h->magic = HEADER_MAGIC;
	h->size = sz;
	place->size += sz;
	place->allocs++;
    }
    return ptr_from_hdr(h);
}

/* Wrap realloc() */
void *
xx_realloc(void *ptr, size_t sz, const char *file, int lineno)
{
    struct header *h;
    struct place *place;

    check_magic(hdr_from_ptr(ptr));
    h = (struct header *)realloc(hdr_from_ptr(ptr), 
	    sizeof (struct header) + sz);
    if (h) {
	if (h->next)
	    h->next->prevp = &h->next;
	*h->prevp = h;
	h->place->size -= h->size;
	h->place->reallocs++;

	/* Move h onto a new place */
	place = find_place(file, lineno);
	if (place != h->place) {
	    header_remove(h);
	    header_insert(h, place);
	}

	place->size += sz;
	h->size = sz;
	place->allocs++;
    }
    return ptr_from_hdr(h);
}

/* Wrap strdup() */
char *
xx_strdup(const char *s, const char *file, int lineno)
{
    size_t sz;
    char *s2;

    sz = strlen(s) + 1;
    s2 = xx_malloc(sz, file, lineno);
    memcpy(s2, s, sz);
    return s2;
}

/* Wrap free() */
void
xx_free(void *ptr)
{
    struct header *h = hdr_from_ptr(ptr);
    check_magic(h);
    if (h) {
	header_remove(h);
	h->place->size -= h->size;
	h->place->frees++;
	h->magic = FREED_MAGIC;
	memset(h + 1, 0xd0, h->size);
    }
    free(h);
}

#endif

#if TEST_MAIN
#include "compat.h"
int main()
{
    char *a,*b,*c[10];
    int i;

    a = malloc(1024);
    b = malloc(2048);
    b = realloc(b, 4096);
    for (i = 0; i < 10; i++)
	c[i] = malloc(279);

    free(a);
    free(b);
    for (i = 0; i < 10; i++)
	free(c[i]);
}
#endif

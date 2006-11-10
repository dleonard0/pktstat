/*
 * Fragment storage.
 *
 * Fragments are stored in keyed buckets.
 * A packet bucket is an ordered list of unique, indexed packets,
 * intended for eventual reassembly into a complete packet.
 * It is up to the caller to free a bucket when it is
 * no longer needed. Very old buckets are deleted automatically.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#if STDC_HEADERS
# include <stdlib.h>
# include <string.h>
#endif

#include "compat.h"

#define LIST_REMOVE(o, pfx) do {				\
	if ((*(o)->pfx##_prevp = (o)->pfx##_next) != NULL)	\
	    (o)->pfx##_next->pfx##_prevp = (o)->pfx##_prevp;	\
    /*  (o)->pfx##_prevp = NULL; */				\
    /*  (o)->pfx##_next  = NULL; */				\
    } while (0)

#define LIST_INSERT(o, headp, pfx) do {				\
	(o)->pfx##_prevp = (headp);				\
	if (((o)->pfx##_next = *(headp)) != NULL)		\
	    (o)->pfx##_next->pfx##_prevp = &(o)->pfx##_next;	\
	*(headp) = (o);						\
    } while (0)

#define LIST_NEXT(o, pfx) ((o)->pfx##_next)
#define LIST_DECL(t, pfx)	t *pfx##_next, **pfx##_prevp

struct frag {
	u_int32_t	index, next_index;
	LIST_DECL(struct frag, ordered);
	size_t		datalen;
};
#define FRAG_DATA(f)	((char *)((f)+1))

struct bucket {
	LIST_DECL(struct bucket, hash);
	struct bucket	*lru_fwd, *lru_back;	
	struct frag	*first_frag;
};
#define BUCKET_KEY(b)	((char *)((b)+1))

#define HASHLEN		257

struct fragtab {
	int		keylen;
	int		availbuckets;
	struct bucket	*lru_first, *lru_last;
	struct bucket	*buckets[HASHLEN];
};

/* Prototypes */
static unsigned int hash(const void *key, int keylen);
static void bucket_lru_remove(struct fragtab *fragtab, struct bucket *bucket);
static void bucket_lru_insert(struct fragtab *fragtab, struct bucket *bucket);
static void frag_delete(struct frag *frag);
static struct frag **frag_find(struct frag **fragp, u_int32_t index);
static struct bucket **bucket_find(struct fragtab *fragtab, const void *key);
static void bucket_create(struct fragtab *fragtab, const void *key, 
		struct bucket **dest);
static void frag_create(struct fragtab *fragtab, const void *data,
	size_t datalen, u_int32_t index, u_int32_t next_index,
	struct frag **dest);
static void bucket_delete(struct fragtab *fragtab, struct bucket *bucket);

/* Compute a hash index from a key string */
static unsigned int
hash(key, keylen)
	const void *key;
	int keylen;
{
	unsigned int h = 0;
	unsigned char *p;

	for (p = (unsigned char *)key; keylen; keylen--, p++)
		h = (h << 1) ^ *p;
	return h % HASHLEN;
}

/* Remove a bucket from the lru list */
static void
bucket_lru_remove(fragtab, bucket)
	struct fragtab *fragtab;
	struct bucket *bucket;
{

	if (bucket->lru_back)
		bucket->lru_back->lru_fwd = bucket->lru_fwd;
	else
		fragtab->lru_first = bucket->lru_fwd;
	if (bucket->lru_fwd)
		bucket->lru_fwd->lru_back = bucket->lru_back;
	else
		fragtab->lru_last = bucket->lru_back;
}

/* Place a (removed) bucket at the front of the lru list */
static void
bucket_lru_insert(fragtab, bucket)
	struct fragtab *fragtab;
	struct bucket *bucket;
{
	if (fragtab->lru_first) {
		bucket->lru_fwd = fragtab->lru_first;
		fragtab->lru_first->lru_back = bucket;
		fragtab->lru_first = bucket;
		bucket->lru_back = NULL;
	} else {
		fragtab->lru_first = bucket;
		fragtab->lru_last = bucket;
		bucket->lru_fwd = NULL;
		bucket->lru_back = NULL;
	}
}

/* Unlink and deallocate a fragment */
static void
frag_delete(frag)
	struct frag *frag;
{
	LIST_REMOVE(frag, ordered);
	free(frag);
}

/*
 * Returns a pointer to where the fragment of the given index
 * should be.
 */
static struct frag **
frag_find(fragp, index)
	struct frag **fragp;
	u_int32_t index;
{
	while (*fragp && (*fragp)->index < index)
		fragp = &LIST_NEXT(*fragp, ordered);
	return fragp;
}

/*
 * Searches a chain in the hashtable for the bucket with the given key.
 * Returns the end of the chain, if not found.
 */
static struct bucket **
bucket_find(fragtab, key)
	struct fragtab *fragtab;
	const void *key;
{
	struct bucket **bucketp;
	unsigned int keyhash;

	keyhash = hash(key, fragtab->keylen);
	bucketp = &fragtab->buckets[keyhash];
	while (*bucketp && memcmp(BUCKET_KEY(*bucketp), key, 
	    fragtab->keylen) != 0)
		bucketp = &LIST_NEXT(*bucketp, hash);
	return bucketp;
}

/* Create and insert a new bucket */
static void
bucket_create(fragtab, key, dest)
	struct fragtab *fragtab;
	const void *key;
	struct bucket **dest;
{
	struct bucket *bucket;
	size_t size;

	size = sizeof (struct bucket) + fragtab->keylen;
	bucket = (struct bucket *)malloc(size);
	if (!bucket)
		errx(1, "malloc");
	bucket->first_frag = NULL;
	memcpy(BUCKET_KEY(bucket), key, fragtab->keylen);

	LIST_INSERT(bucket, dest, hash);

	bucket_lru_insert(fragtab, bucket);
	fragtab->availbuckets--;
}

/* Create and insert a new fragment. */
static void
frag_create(fragtab, data, datalen, index, next_index, dest)
	struct fragtab *fragtab;
	const void *data;
	size_t datalen;
	u_int32_t index, next_index;
	struct frag **dest;
{
	size_t size;
	struct frag* frag;

	size = sizeof (struct fragtab) + datalen;
	frag = (struct frag *)malloc(size);
	if (!frag)
		errx(1, "malloc");
	frag->index = index;
	frag->next_index = next_index;
	frag->datalen = datalen;
	memcpy(FRAG_DATA(frag), data, datalen);

	LIST_INSERT(frag, dest, ordered);
}

/* Delete a bucket and all the fragments it contains */
static void
bucket_delete(fragtab, bucket)
	struct fragtab *fragtab;
	struct bucket *bucket;
{
	while (bucket->first_frag)
		frag_delete(bucket->first_frag);
	bucket_lru_remove(fragtab, bucket);

	LIST_REMOVE(bucket, hash);
	free(bucket);
	fragtab->availbuckets++;
}

/*
 * Allocate an empty fragment table
 */
struct fragtab *
fragtab_new(keylen, maxbuckets)
	int keylen, maxbuckets;
{
	struct fragtab *fragtab;
	int i;

	fragtab = (struct fragtab *)malloc(sizeof (struct fragtab));
	if (!fragtab)
		errx(1, "malloc");
	fragtab->keylen = keylen;
	fragtab->availbuckets = maxbuckets;
	fragtab->lru_first = NULL;
	fragtab->lru_last = NULL;
	for (i = 0; i < HASHLEN; i++)
		fragtab->buckets[i] = NULL;
	return fragtab;
}

/*
 * Put a new fragment into the right bucket. A bucket is created
 * if there isnt one for the fragment already. The bucket is moved
 * to the young end of the lru list. 
 */
void
fragtab_put(fragtab, key, data, datalen, index, next_index)
	struct fragtab *fragtab;
	const void *key;
	const void *data;
	size_t datalen;
	u_int32_t index, next_index;
{
	struct bucket **bucketp, *bucket;
	struct frag **fragp;

	bucketp = bucket_find(fragtab, key);
	if (!*bucketp) {
		if (fragtab->availbuckets < 0) 
			bucket_delete(fragtab, fragtab->lru_last);
		bucket_create(fragtab, key, bucketp);
	} else if (fragtab->lru_first != *bucketp) {
		/* Move to young end of list */
		bucket_lru_remove(fragtab, *bucketp);
		bucket_lru_insert(fragtab, *bucketp);
	}
	bucket = *bucketp;

	fragp = frag_find(&bucket->first_frag, index);
	if (*fragp && (*fragp)->index == index)
		frag_delete(*fragp);
	frag_create(fragtab, data, datalen, index, next_index, fragp);
}

/*
 * Return the data associated with a fragment at the given index,
 * or return NULL if it doesn't exist yet.
 */
const void *
fragtab_get(fragtab, key, index, datalenp)
	struct fragtab *fragtab;
	const void *key;
	u_int32_t index;
	size_t *datalenp;
{
	struct bucket *bucket;
	struct frag *frag;

	bucket = *bucket_find(fragtab, key);
	if (bucket) {
		frag = *frag_find(&bucket->first_frag, index);
		if (frag && frag->index == index) {
			*datalenp = frag->datalen;
			return FRAG_DATA(frag);
		}
	}
	return NULL;
}

/*
 * Delete all fragments with the given key
 */
void
fragtab_del(fragtab, key)
	struct fragtab *fragtab;
	const void *key;
{
	struct bucket *bucket;

	bucket = *bucket_find(fragtab, key);
	if (bucket)
		bucket_delete(fragtab, bucket);
}

/*
 * Return true if all the fragments of the bucket exist;
 * ie each fragment's next_index is equal to the next fragment's index
 */
int
fragtab_check(fragtab, key, first_index, last_index)
	struct fragtab *fragtab;
	const void *key;
	u_int32_t first_index, last_index;
{
	struct bucket *bucket;
	struct frag *frag;

	bucket = *bucket_find(fragtab, key);
	if (bucket) {
	    frag = bucket->first_frag;
	    if (frag && frag->index == first_index)
		for (; frag; frag = LIST_NEXT(frag, ordered)) {
		    if (LIST_NEXT(frag, ordered) == NULL) {
			if (frag->next_index == last_index)
			    /* at last fragment and it is last expected index */
			    return 1;
		    } else if (frag->next_index != 
			LIST_NEXT(frag, ordered)->index) {
			/* missing fragments */
			break;
		    }
		}
	}
	return 0;
}

/*
 * Destroy all storage associated with the fragment table
 */
void
fragtab_free(fragtab)
	struct fragtab *fragtab;
{
	int i;

	for (i = 0; i < HASHLEN; i++)
	    while (fragtab->buckets[i])
		bucket_delete(fragtab, fragtab->buckets[i]);
	free(fragtab);
}

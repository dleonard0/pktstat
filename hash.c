/* David Leonard, 2002. Public domain. */
/* $Id$ */

#include <stdlib.h>
#include "hash.h"

struct hashelt {
	struct hashelt *next;
	const void *key;
	const void *data;
};

static struct hashelt **
find(h, key)
	struct hash *h;
	const void *key;
{
	unsigned int hash = (*h->hashfn)(key);
	struct hashelt **he;

	for (he = &h->list[hash % HASHSZ]; *he; he = &(*he)->next)
		if ((*h->cmp)(key, (*he)->key) == 0)
			break;
	return he;
}

/* Find the data associated with a key. Returns 0 if not found. */
const void *
hash_lookup(h, key)
	struct hash *h;
	const void *key;
{
	struct hashelt **he = find(h, key);

	if (*he)
		return (*he)->data;
	else
		return (void *)0;
}

/*
 * Store a key and data in the hash table. The key & data pointers
 * are now owned by the hash table. They will be freed later during
 * hash_del() or hash_clear() using the freedata and freekey function
 * pointers.
 */
void
hash_store(h, key, data)
	struct hash *h;
	const void *key;
	const void *data;
{
	struct hashelt **he = find(h, key);
	struct hashelt *e;

	if (*he) {
		if (h->freedata)
			(*h->freedata)((*he)->data);
		if (h->freekey)
			(*h->freekey)((*he)->key);
		e = *he;
	} else {
		e = (struct hashelt *)malloc(sizeof (struct hashelt));
		e->next = *he;
		*he = e;
	}
	(*he)->key = key;
	(*he)->data = data;
}

/* Free a hashed value */
void
hash_del(h, key)
	struct hash *h;
	const void *key;
{
	struct hashelt **he = find(h, key);

	if (*he) {
		struct hashelt *e = *he;
		*he = (*he)->next;
		if (h->freekey)
			(*h->freekey)(e->key);
		if (h->freedata)
			(*h->freedata)(e->key);
		free(e);
	}
}

/* Free all the values stored in a hash table */
void
hash_clear(h)
	struct hash *h;
{
	int i;

	for (i = 0; i < HASHSZ; i++)
		while (h->list[i]) {
			struct hashelt *he = h->list[i];
			h->list[i] = he->next;
			if (h->freekey)
				(*h->freekey)(he->key);
			if (h->freedata)
				(*h->freedata)(he->data);
			free((void *)he);
		}
}

/* A generic hashing function for binary data */
unsigned int
hash_generic(data, sz)
	void *data;
	size_t sz;
{
	unsigned int hash = 0;
	const unsigned char *p = (const unsigned char *)data;
	int i;

	for (i = 0; i < sz; i ++)
		hash = (hash << 4) ^ *p++;
	return hash;
}

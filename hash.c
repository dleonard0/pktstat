/* David Leonard, 2002. Public domain. */
/* $Id$ */
#include <stdlib.h>
#include "hash.h"

struct hashelt {
	struct hashelt *next;
	const void *key;
	const void *data;
};

const void *
hash_lookup(h, key)
	struct hash *h;
	const void *key;
{
	unsigned int hash = (*h->hashfn)(key);
	struct hashelt *he;

	for (he = h->list[hash % HASHSZ]; he; he = he->next)
		if ((*h->cmp)(key, he->key) == 0)
			return he->data;
	return (void *)0;
}

void
hash_store(h, key, data)
	struct hash *h;
	const void *key;
	const void *data;
{
	unsigned int hash = (*h->hashfn)(key);
	struct hashelt *he;

	he = (struct hashelt *)malloc(sizeof (struct hashelt));
	he->key = key;
	he->data = data;
	he->next = h->list[hash % HASHSZ];
	h->list[hash % HASHSZ] = he;
}

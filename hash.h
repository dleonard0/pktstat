/* David Leonard, 2002. Public domain. */
/* $Id$ */

#undef offsetof
#define offsetof(t,f)	((int)(&(((t *)0)->f)))

#define HASHSZ	237

struct hashelt;
struct hash {
	int		(*cmp)(const void *key1, const void *key2);
	unsigned int	(*hashfn)(const void *key);
	void		(*freekey)(const void *key);
	void		(*freedata)(const void *data);
	struct hashelt *list[HASHSZ];
};

const void *hash_lookup(struct hash *, const void *key);
void hash_store(struct hash *, const void *key, const void *data);
void hash_clear(struct hash *);
unsigned int hash_generic(void *, size_t);

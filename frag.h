
/*
 * Fragment storage.
 *
 * Fragments are stored in keyed buckets.
 * A bucket is an ordered list of unique, indexed packets.
 * It is up to the caller to free a bucket when it is
 * no longer needed. Very old buckets are deleted automatically.
 * It is up to the caller to reassemble. A simple LRU ejection
 * scheme is used.
 */

struct fragtab;

struct fragtab *fragtab_new(int keylen, int maxbuckets);
void   fragtab_put(struct fragtab *ft, const void *key, const void *data, 
			size_t datalen, u_int32_t index, u_int32_t next_index);
void * fragtab_get(struct fragtab *ft, const void *key, u_int32_t index, 
			size_t *datalenp);
void   fragtab_del(struct fragtab *ft, const void *key);
void   fragtab_free(struct fragtab *ft);
int    fragtab_check(struct fragtab *fragtab, const void *key, 
			u_int32_t first_index, u_int32_t last_index);

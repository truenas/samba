/*
 * tdb_freelist_size() merges free records that are next to each other.
 * It must hold the freelist write lock to do that. In a read-only
 * traverse it must only count.
 */
#include "../common/tdb_private.h"
#include "../common/io.c"
#include "../common/tdb.c"
#include "../common/lock.c"
#include "../common/freelist.c"
#include "../common/traverse.c"
#include "../common/transaction.c"
#include "../common/error.c"
#include "../common/open.c"
#include "../common/check.c"
#include "../common/hash.c"
#include "../common/mutex.c"
#include "tap-interface.h"
#include <stdlib.h>
#include "logging.h"

#define DBNAME "freelist-merge-lock.tdb"
#define NUM_KEYS 10

static const struct tdb_methods *orig_methods;
static struct tdb_methods checked_methods;
static unsigned num_writes, num_unlocked_writes;

static int checked_write(struct tdb_context *tdb, tdb_off_t off,
			 const void *buf, tdb_len_t len)
{
	struct tdb_lock_type *lck = find_nestlock(tdb, lock_offset(-1));

	num_writes += 1;
	if ((lck == NULL) || (lck->ltype != F_WRLCK)) {
		num_unlocked_writes += 1;
	}
	return orig_methods->tdb_write(tdb, off, buf, len);
}

static TDB_DATA string_key(const char *s)
{
	return (TDB_DATA) { .dptr = discard_const_p(uint8_t, s),
			    .dsize = strlen(s) };
}

static tdb_off_t key_offset(struct tdb_context *tdb, const char *key)
{
	TDB_DATA k = string_key(key);
	uint32_t hash = tdb->hash_fn(&k);
	struct tdb_record rec;
	tdb_off_t off;

	off = tdb_find_lock_hash(tdb, k, hash, F_RDLCK, &rec);
	if (off != 0) {
		tdb_unlock(tdb, BUCKET(hash), F_RDLCK);
	}
	return off;
}

/*
 * Delete the records from the right. tdb_free() merges a record only
 * with the record on its left, and that one is still in use. This
 * leaves free records next to each other.
 */
static struct tdb_context *open_free_neighbours(void)
{
	struct tdb_context *tdb;
	char keys[NUM_KEYS][16];
	tdb_off_t offsets[NUM_KEYS];
	uint8_t buf[100];
	unsigned i, j;

	unlink(DBNAME);
	tdb = tdb_open_ex(DBNAME, 1, TDB_DEFAULT, O_RDWR|O_CREAT, 0600,
			  &taplogctx, NULL);
	ok1(tdb != NULL);

	memset(buf, 'x', sizeof(buf));
	ok1(tdb_store(tdb, string_key("keep"),
		      (TDB_DATA) { .dptr = buf, .dsize = sizeof(buf) },
		      TDB_INSERT) == 0);
	for (i = 0; i < NUM_KEYS; i++) {
		snprintf(keys[i], sizeof(keys[i]), "key%u", i);
		ok1(tdb_store(tdb, string_key(keys[i]),
			      (TDB_DATA) { .dptr = buf, .dsize = sizeof(buf) },
			      TDB_INSERT) == 0);
		offsets[i] = key_offset(tdb, keys[i]);
		ok1(offsets[i] != 0);
	}
	for (i = 0; i < NUM_KEYS; i++) {
		unsigned right = 0;

		for (j = 0; j < NUM_KEYS; j++) {
			if (offsets[j] > offsets[right]) {
				right = j;
			}
		}
		ok1(tdb_delete(tdb, string_key(keys[right])) == 0);
		offsets[right] = 0;
	}
	return tdb;
}

static int count_freelist(struct tdb_context *tdb, TDB_DATA key,
			  TDB_DATA data, void *private_data)
{
	int *count = private_data;

	*count = tdb_freelist_size(tdb);
	return 0;
}

int main(int argc, char *argv[])
{
	struct tdb_context *tdb;
	int before, count;

	plan_tests(2 * (3 * NUM_KEYS + 2) + 9);

	tdb = open_free_neighbours();
	orig_methods = tdb->methods;
	checked_methods = *tdb->methods;
	checked_methods.tdb_write = checked_write;

	before = tdb_freelist_size_no_merge(tdb);
	tdb->methods = &checked_methods;
	ok1(tdb_freelist_size(tdb) > 0);
	tdb->methods = orig_methods;
	ok(num_writes > 0, "tdb_freelist_size() merged nothing");
	ok(num_unlocked_writes == 0,
	   "%u of %u writes without the freelist write lock",
	   num_unlocked_writes, num_writes);
	count = tdb_freelist_size_no_merge(tdb);
	ok(count < before, "%d free records after merging, %d before",
	   count, before);
	ok1(tdb_check(tdb, NULL, NULL) == 0);
	tdb_close(tdb);

	tdb = open_free_neighbours();
	before = tdb_freelist_size_no_merge(tdb);
	num_writes = 0;
	count = -1;
	tdb->methods = &checked_methods;
	ok1(tdb_traverse_read(tdb, count_freelist, &count) == 1);
	tdb->methods = orig_methods;
	ok(count == before,
	   "tdb_freelist_size() in tdb_traverse_read() returned %d, "
	   "expected %d", count, before);
	ok1(num_writes == 0);
	ok1(tdb_check(tdb, NULL, NULL) == 0);
	tdb_close(tdb);

	diag("done");
	return exit_status();
}

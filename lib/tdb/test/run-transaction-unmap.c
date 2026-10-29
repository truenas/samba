/*
 * A transaction that makes the file larger maps the larger file. Commit
 * and cancel must unmap all of it, not only the old size.
 */
#include "../common/tdb_private.h"

static struct {
	void *addr;
	size_t len;
} mappings[16];
static unsigned num_mappings, bad_munmaps;

static void *tracked_mmap(void *addr, size_t len, int prot, int flags,
			  int fd, off_t offset)
{
	void *ptr = mmap(addr, len, prot, flags, fd, offset);

	if (ptr != MAP_FAILED) {
		if (num_mappings == ARRAY_SIZE(mappings)) {
			abort();
		}
		mappings[num_mappings].addr = ptr;
		mappings[num_mappings].len = len;
		num_mappings += 1;
	}
	return ptr;
}

static int tracked_munmap(void *addr, size_t len)
{
	unsigned i;

	for (i = 0; i < num_mappings; i++) {
		if (mappings[i].addr == addr) {
			break;
		}
	}
	if (i == num_mappings) {
		bad_munmaps += 1;
	} else {
		if (mappings[i].len != len) {
			bad_munmaps += 1;
		}
		num_mappings -= 1;
		mappings[i] = mappings[num_mappings];
	}
	return munmap(addr, len);
}

#define mmap tracked_mmap
#define munmap tracked_munmap

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

#define DBNAME "transaction-unmap.tdb"

static TDB_DATA string_key(const char *s)
{
	return (TDB_DATA) { .dptr = discard_const_p(uint8_t, s),
			    .dsize = strlen(s) };
}

static int store_len(struct tdb_context *tdb, const char *key, size_t len)
{
	TDB_DATA data = { .dptr = calloc(len, 1), .dsize = len };
	int ret = -1;

	if (data.dptr != NULL) {
		ret = tdb_store(tdb, string_key(key), data, TDB_REPLACE);
		free(data.dptr);
	}
	return ret;
}

int main(int argc, char *argv[])
{
	struct tdb_context *tdb;
	tdb_off_t recovery_head, head;
	tdb_len_t size;
	TDB_DATA data;

	plan_tests(26);
	unlink(DBNAME);
	tdb = tdb_open_ex(DBNAME, 2, TDB_NOSYNC, O_RDWR|O_CREAT, 0600,
			  &taplogctx, NULL);
	ok1(tdb != NULL);

	/* This commit creates the recovery area that the next one reuses */
	ok1(tdb_transaction_start(tdb) == 0);
	ok1(store_len(tdb, "a", 100) == 0);
	ok1(tdb_transaction_commit(tdb) == 0);
	ok1(tdb_ofs_read(tdb, TDB_RECOVERY_HEAD, &recovery_head) == 0);
	ok1(recovery_head != 0);

	ok1(tdb_transaction_start(tdb) == 0);
	size = tdb->map_size;
	ok1(store_len(tdb, "b", 200000) == 0);
	ok1(tdb->map_size > size);
	ok1(tdb_transaction_commit(tdb) == 0);
	ok1(tdb_ofs_read(tdb, TDB_RECOVERY_HEAD, &head) == 0);
	ok(head == recovery_head, "recovery area moved, not testing its reuse");
	ok(bad_munmaps == 0, "%u munmap() with the wrong length", bad_munmaps);

	ok1(tdb_transaction_start(tdb) == 0);
	ok(bad_munmaps == 0, "%u munmap() with the wrong length", bad_munmaps);
	size = tdb->map_size;
	ok1(store_len(tdb, "c", 400000) == 0);
	ok1(tdb->map_size > size);
	ok1(tdb_transaction_cancel(tdb) == 0);

	tdb_close(tdb);
	ok(bad_munmaps == 0, "%u munmap() with the wrong length", bad_munmaps);
	ok(num_mappings == 0, "%u mappings left after tdb_close()",
	   num_mappings);

	tdb = tdb_open_ex(DBNAME, 0, TDB_NOSYNC, O_RDWR, 0600,
			  &taplogctx, NULL);
	ok1(tdb != NULL);
	data = tdb_fetch(tdb, string_key("b"));
	ok1(data.dsize == 200000);
	free(data.dptr);
	ok1(!tdb_exists(tdb, string_key("c")));
	ok1(tdb_check(tdb, NULL, NULL) == 0);
	tdb_close(tdb);
	ok1(bad_munmaps == 0);
	ok1(num_mappings == 0);

	diag("done");
	return exit_status();
}

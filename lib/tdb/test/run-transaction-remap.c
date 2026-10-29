/*
 * A transaction start must keep the map if the file size did not
 * change. It must remap after TDB_NOMMAP is added or removed, and after
 * another process makes the file larger.
 */
#include "../common/tdb_private.h"

static unsigned num_mmaps, num_munmaps;

static void *counted_mmap(void *addr, size_t len, int prot, int flags,
			  int fd, off_t offset)
{
	void *ptr = mmap(addr, len, prot, flags, fd, offset);

	if (ptr != MAP_FAILED) {
		num_mmaps += 1;
	}
	return ptr;
}

static int counted_munmap(void *addr, size_t len)
{
	num_munmaps += 1;
	return munmap(addr, len);
}

#define mmap counted_mmap
#define munmap counted_munmap

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
#include <sys/types.h>
#include <sys/wait.h>
#include "logging.h"

#define DBNAME "transaction-remap.tdb"

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

static int grower(int from)
{
	struct tdb_context *tdb;
	char c;

	if (read(from, &c, 1) != 1) {
		return 1;
	}
	tdb = tdb_open_ex(DBNAME, 0, TDB_NOSYNC, O_RDWR, 0600,
			  &taplogctx, NULL);
	if (tdb == NULL) {
		diag("grower: open failed: %s", strerror(errno));
		return 1;
	}
	if (store_len(tdb, "big", 200000) != 0) {
		diag("grower: store failed: %s", tdb_errorstr(tdb));
		return 1;
	}
	tdb_close(tdb);
	return 0;
}

int main(int argc, char *argv[])
{
	struct tdb_context *tdb;
	unsigned mmaps, munmaps;
	int to_grower[2];
	struct stat st;
	TDB_DATA data;
	pid_t pid;
	int status;

	plan_tests(25);
	unlink(DBNAME);
	ok1(pipe(to_grower) == 0);

	/* Fork before opening: a process can't open a tdb twice */
	pid = fork();
	if (pid == 0) {
		close(to_grower[1]);
		exit(grower(to_grower[0]));
	}
	close(to_grower[0]);

	tdb = tdb_open_ex(DBNAME, 2, TDB_NOSYNC, O_RDWR|O_CREAT, 0600,
			  &taplogctx, NULL);
	ok1(tdb != NULL);
	ok1(store_len(tdb, "a", 100) == 0);
	ok1(tdb->map_ptr != NULL);

	mmaps = num_mmaps;
	munmaps = num_munmaps;
	ok1(tdb_transaction_start(tdb) == 0);
	ok1(tdb_transaction_cancel(tdb) == 0);
	ok((num_mmaps == mmaps) && (num_munmaps == munmaps),
	   "a transaction start remapped the unchanged file");

	tdb_add_flags(tdb, TDB_NOMMAP);
	ok1(tdb_transaction_start(tdb) == 0);
	ok(tdb->map_ptr == NULL, "still mapped after adding TDB_NOMMAP");
	ok1(num_munmaps == munmaps + 1);
	ok1(tdb_transaction_cancel(tdb) == 0);
	data = tdb_fetch(tdb, string_key("a"));
	ok1(data.dsize == 100);
	free(data.dptr);

	tdb_remove_flags(tdb, TDB_NOMMAP);
	ok1(tdb_transaction_start(tdb) == 0);
	ok(tdb->map_ptr != NULL, "not mapped after removing TDB_NOMMAP");
	ok1(num_mmaps == mmaps + 1);
	ok1(tdb_transaction_cancel(tdb) == 0);

	ok1(write(to_grower[1], "x", 1) == 1);
	ok1(waitpid(pid, &status, 0) == pid);
	ok(WIFEXITED(status) && (WEXITSTATUS(status) == 0),
	   "the other process could not grow the file");
	munmaps = num_munmaps;
	ok1(tdb_transaction_start(tdb) == 0);
	ok1((fstat(tdb->fd, &st) == 0) && (tdb->map_size == st.st_size));
	ok(num_munmaps == munmaps + 1, "no remap after the file grew");
	ok1(tdb_transaction_cancel(tdb) == 0);
	data = tdb_fetch(tdb, string_key("big"));
	ok1(data.dsize == 200000);
	free(data.dptr);

	ok1(tdb_check(tdb, NULL, NULL) == 0);
	tdb_close(tdb);
	close(to_grower[1]);

	diag("done");
	return exit_status();
}

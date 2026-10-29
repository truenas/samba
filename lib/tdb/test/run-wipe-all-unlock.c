/*
 * tdb_wipe_all() must release its allrecord lock when it fails. Make it
 * fail: point the recovery head past the end of the file while we hold
 * the allrecord lock. Our lock stops the tdb_lockall() in tdb_wipe_all()
 * from checking the recovery area first.
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
#include <sys/types.h>
#include <sys/wait.h>
#include "logging.h"

#define DBNAME "wipe-all-unlock.tdb"

static TDB_DATA string_key(const char *s)
{
	return (TDB_DATA) { .dptr = discard_const_p(uint8_t, s),
			    .dsize = strlen(s) };
}

static int locker(int from)
{
	struct tdb_context *tdb;
	char c;

	if (read(from, &c, 1) != 1) {
		return 1;
	}
	tdb = tdb_open_ex(DBNAME, 0, TDB_DEFAULT, O_RDWR, 0600,
			  &taplogctx, NULL);
	if (tdb == NULL) {
		diag("locker: open failed: %s", strerror(errno));
		return 1;
	}
	if (tdb_lockall_nonblock(tdb) != 0) {
		diag("locker: tdb_lockall_nonblock failed: %s",
		     tdb_errorstr(tdb));
		return 1;
	}
	tdb_unlockall(tdb);
	tdb_close(tdb);
	return 0;
}

int main(int argc, char *argv[])
{
	struct tdb_context *tdb;
	tdb_off_t recovery_head, bad_head;
	int to_locker[2];
	pid_t pid;
	int ret, status;

	plan_tests(16);
	unlink(DBNAME);
	ok1(pipe(to_locker) == 0);

	/* Fork before opening: a process can't open a tdb twice */
	pid = fork();
	if (pid == 0) {
		close(to_locker[1]);
		exit(locker(to_locker[0]));
	}
	close(to_locker[0]);

	tdb = tdb_open_ex(DBNAME, 2, TDB_DEFAULT, O_RDWR|O_CREAT, 0600,
			  &taplogctx, NULL);
	ok1(tdb != NULL);
	ok1(tdb_store(tdb, string_key("key"), string_key("data"),
		      TDB_INSERT) == 0);

	ok1(tdb_lockall(tdb) == 0);
	ok1(tdb_ofs_read(tdb, TDB_RECOVERY_HEAD, &recovery_head) == 0);
	bad_head = tdb->map_size + 4096;
	ok1(tdb_ofs_write(tdb, TDB_RECOVERY_HEAD, &bad_head) == 0);

	suppress_logging = true;
	ret = tdb_wipe_all(tdb);
	suppress_logging = false;
	ok1(ret == -1);
	ok(tdb->allrecord_lock.count == 1,
	   "allrecord lock count %u after the failed wipe, expected 1",
	   tdb->allrecord_lock.count);

	ok1(tdb_ofs_write(tdb, TDB_RECOVERY_HEAD, &recovery_head) == 0);
	ok1(tdb_unlockall(tdb) == 0);

	ok1(write(to_locker[1], "x", 1) == 1);
	ok1(waitpid(pid, &status, 0) == pid);
	ok(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	   "the other process could not lock the tdb");

	ok1(tdb_wipe_all(tdb) == 0);
	ok1(!tdb_exists(tdb, string_key("key")));
	ok1(tdb_check(tdb, NULL, NULL) == 0);
	tdb_close(tdb);
	close(to_locker[1]);

	diag("done");
	return exit_status();
}

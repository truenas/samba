/*
 * The owner of a chain mutex is killed while another process waits for
 * it, blocking or polling with tdb_chainlock_nonblock(). The waiter must
 * get the chain (robust mutex, EOWNERDEAD) and the db must stay usable.
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
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "logging.h"

#define DBNAME "mutex-die-waiter.tdb"
#define TDB_FLAGS (TDB_INCOMPATIBLE_HASH|TDB_MUTEX_LOCKING)

static TDB_DATA key = { .dptr = discard_const_p(uint8_t, "chain"),
			.dsize = 5 };
static TDB_DATA val = { .dptr = discard_const_p(uint8_t, "after"),
			.dsize = 5 };

static int holder(int to)
{
	struct tdb_context *tdb;
	char c = 0;

	tdb = tdb_open_ex(DBNAME, 0, TDB_FLAGS, O_RDWR|O_CREAT, 0600,
			  &taplogctx, NULL);
	if ((tdb == NULL) || (tdb_chainlock(tdb, key) != 0)) {
		diag("holder: open or chainlock failed");
		return 1;
	}
	if (write(to, &c, 1) != 1) {
		return 1;
	}
	/* Hold the chain until we are killed */
	for (;;) {
		pause();
	}
	return 1;
}

static int waiter(bool poll, int to)
{
	struct tdb_context *tdb;
	char c = 0;
	int ret;

	tdb = tdb_open_ex(DBNAME, 0, TDB_FLAGS, O_RDWR, 0600,
			  &taplogctx, NULL);
	if (tdb == NULL) {
		diag("waiter: open failed: %s", strerror(errno));
		return 1;
	}
	if (write(to, &c, 1) != 1) {
		return 1;
	}
	if (poll) {
		while ((ret = tdb_chainlock_nonblock(tdb, key)) != 0) {
			usleep(1000);
		}
	} else {
		ret = tdb_chainlock(tdb, key);
	}
	if (ret != 0) {
		diag("waiter: chainlock failed: %s", tdb_errorstr(tdb));
		return 1;
	}
	if (tdb_store(tdb, key, val, TDB_REPLACE) != 0) {
		diag("waiter: store failed: %s", tdb_errorstr(tdb));
		return 1;
	}
	tdb_chainunlock(tdb, key);
	tdb_close(tdb);
	return 0;
}

static void run_case(bool poll)
{
	struct tdb_context *tdb;
	int from_h[2], from_w[2];
	pid_t h, w;
	int status;
	char c;
	TDB_DATA got;

	diag("waiter %s", poll ? "polls with tdb_chainlock_nonblock" :
	     "blocks in tdb_chainlock");

	unlink(DBNAME);
	ok1(pipe(from_h) == 0);
	ok1(pipe(from_w) == 0);

	h = fork();
	if (h == 0) {
		close(from_h[0]);
		exit(holder(from_h[1]));
	}
	close(from_h[1]);
	ok1(read(from_h[0], &c, 1) == 1);

	w = fork();
	if (w == 0) {
		close(from_w[0]);
		exit(waiter(poll, from_w[1]));
	}
	close(from_w[1]);
	ok1(read(from_w[0], &c, 1) == 1);

	/* Let the waiter get stuck on the chain, then kill the owner */
	usleep(200000);
	ok1(kill(h, SIGKILL) == 0);
	ok1(waitpid(h, &status, 0) == h);

	/* The waiter must finish */
	alarm(30);
	ok1(waitpid(w, &status, 0) == w);
	alarm(0);
	ok(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	   "waiter failed, status 0x%x", status);

	tdb = tdb_open_ex(DBNAME, 0, TDB_FLAGS, O_RDWR, 0600, &taplogctx,
			  NULL);
	ok1(tdb);
	got = tdb_fetch(tdb, key);
	ok1(got.dsize == val.dsize && memcmp(got.dptr, val.dptr, 5) == 0);
	free(got.dptr);
	ok1(tdb_check(tdb, NULL, NULL) == 0);
	tdb_close(tdb);
	close(from_h[0]);
	close(from_w[0]);
}

int main(int argc, char *argv[])
{
	plan_tests(24);

	if (!tdb_runtime_check_for_robust_mutexes()) {
		skip(1, "No robust mutex support");
		return exit_status();
	}

	run_case(false);
	run_case(true);

	diag("done");
	return exit_status();
}

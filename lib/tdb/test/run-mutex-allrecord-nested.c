/*
 * A process holds a chain lock twice (nested) while another one runs
 * tdb_lockall(), which takes the allrecord mutex and then waits for that
 * chain. When the first process now locks a second chain, it must see it
 * already holds a chain and not queue behind the allrecord locker, or
 * both wait for each other.
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
#include <poll.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "logging.h"

#define DBNAME "mutex-allrecord-nested.tdb"
#define HASH_SIZE 31
#define TDB_FLAGS (TDB_INCOMPATIBLE_HASH|TDB_MUTEX_LOCKING|TDB_CLEAR_IF_FIRST)

static char key1_buf[16], key2_buf[16];
static TDB_DATA key1, key2;

/* Two keys in different chains. TDB_INCOMPATIBLE_HASH selects jenkins. */
static void find_keys(void)
{
	unsigned i;

	strlcpy(key1_buf, "key0", sizeof(key1_buf));
	key1 = (TDB_DATA) { .dptr = (uint8_t *)key1_buf, .dsize = 4 };
	for (i = 1; ; i++) {
		snprintf(key2_buf, sizeof(key2_buf), "key%u", i);
		key2 = (TDB_DATA) { .dptr = (uint8_t *)key2_buf,
				    .dsize = strlen(key2_buf) };
		if ((tdb_jenkins_hash(&key1) % HASH_SIZE) !=
		    (tdb_jenkins_hash(&key2) % HASH_SIZE)) {
			break;
		}
	}
}

static int nested_locker(int from, int to)
{
	struct tdb_context *tdb;
	char c = 0;
	int i;

	tdb = tdb_open_ex(DBNAME, HASH_SIZE, TDB_FLAGS, O_RDWR|O_CREAT, 0600,
			  &taplogctx, NULL);
	if (tdb == NULL) {
		diag("nested_locker: open failed: %s", strerror(errno));
		return 1;
	}
	if ((tdb_chainlock(tdb, key1) != 0) ||
	    (tdb_chainlock(tdb, key1) != 0)) {
		diag("nested_locker: chainlock failed");
		return 1;
	}
	if ((write(to, &c, 1) != 1) || (read(from, &c, 1) != 1)) {
		return 1;
	}

	/* Wait for tdb_lockall() to take the allrecord mutex */
	for (i = 0; i < 10000; i++) {
		volatile short *l = &tdb->mutexes->allrecord_lock;
		if (*l != F_UNLCK) {
			break;
		}
		usleep(1000);
	}
	if (i == 10000) {
		diag("nested_locker: tdb_lockall() did not start");
		return 1;
	}
	/* Let it get stuck on our chain */
	usleep(100000);

	if (tdb_chainlock(tdb, key2) != 0) {
		diag("nested_locker: second chainlock failed");
		return 1;
	}
	tdb_chainunlock(tdb, key2);
	tdb_chainunlock(tdb, key1);
	tdb_chainunlock(tdb, key1);
	tdb_close(tdb);
	return (write(to, &c, 1) == 1) ? 0 : 1;
}

static int allrecord_locker(int from, int to)
{
	struct tdb_context *tdb;
	char c = 0;

	tdb = tdb_open_ex(DBNAME, HASH_SIZE, TDB_FLAGS, O_RDWR|O_CREAT, 0600,
			  &taplogctx, NULL);
	if (tdb == NULL) {
		diag("allrecord_locker: open failed: %s", strerror(errno));
		return 1;
	}
	if ((write(to, &c, 1) != 1) || (read(from, &c, 1) != 1)) {
		return 1;
	}
	if (tdb_lockall(tdb) != 0) {
		diag("allrecord_locker: tdb_lockall failed");
		return 1;
	}
	tdb_unlockall(tdb);
	tdb_close(tdb);
	return 0;
}

int main(int argc, char *argv[])
{
	int to_l[2], from_l[2], to_a[2], from_a[2];
	struct pollfd pfd;
	pid_t l, a;
	int status, ret;
	char c = 0;

	plan_tests(12);

	if (!tdb_runtime_check_for_robust_mutexes()) {
		skip(1, "No robust mutex support");
		return exit_status();
	}

	unlink(DBNAME);
	find_keys();
	ok1(pipe(to_l) == 0);
	ok1(pipe(from_l) == 0);
	ok1(pipe(to_a) == 0);
	ok1(pipe(from_a) == 0);

	l = fork();
	if (l == 0) {
		close(to_l[1]); close(from_l[0]);
		close(to_a[0]); close(to_a[1]); close(from_a[0]); close(from_a[1]);
		exit(nested_locker(to_l[0], from_l[1]));
	}
	close(to_l[0]);
	close(from_l[1]);
	ok1(read(from_l[0], &c, 1) == 1);

	a = fork();
	if (a == 0) {
		close(to_a[1]); close(from_a[0]);
		close(to_l[1]); close(from_l[0]);
		exit(allrecord_locker(to_a[0], from_a[1]));
	}
	close(to_a[0]);
	close(from_a[1]);
	ok1(read(from_a[0], &c, 1) == 1);

	ok1(write(to_a[1], &c, 1) == 1);
	ok1(write(to_l[1], &c, 1) == 1);

	/* The nested locker must get through, a deadlock leaves it stuck */
	pfd = (struct pollfd) { .fd = from_l[0], .events = POLLIN };
	ret = poll(&pfd, 1, 10000);
	if (ret != 1) {
		kill(l, SIGKILL);
		kill(a, SIGKILL);
		waitpid(l, &status, 0);
		waitpid(a, &status, 0);
		fail("deadlock: nested chain lock holder waited for "
		     "tdb_lockall()");
	}
	ok1(read(from_l[0], &c, 1) == 1);

	ok1(waitpid(l, &status, 0) == l);
	ok1(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ok1(waitpid(a, &status, 0) == a);
	ok1(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	diag("done");
	return exit_status();
}

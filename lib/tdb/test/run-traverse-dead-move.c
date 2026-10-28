/*
 * A traverse sits on record A while another process deletes A and
 * stores key K of the chain before A's. The store must not reuse A's dead
 * record for K: moved into K's chain it would take the traverse into a
 * chain it has not locked and lose record B behind A.
 *
 * Case 1: the freelist is free, A must stay in its chain.
 * Case 2: a third process holds the freelist, so the store steals dead
 *         records from other chains.
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

#define DBNAME "traverse-dead-move.tdb"
#define HASH_SIZE 32

static char key_a[16], key_b[16], key_k[16];

static TDB_DATA string_key(const char *s)
{
	return (TDB_DATA) { .dptr = discard_const_p(uint8_t, s),
			    .dsize = strlen(s) };
}

/*
 * A and B in one chain (not the first), K in the chain before it.
 * TDB_INCOMPATIBLE_HASH selects the jenkins hash.
 */
static void find_keys(void)
{
	unsigned i, chain_a = 0;
	bool have_a = false, have_b = false, have_k = false;
	char buf[16];

	for (i = 0; !(have_a && have_b && have_k); i++) {
		TDB_DATA k;
		unsigned chain;

		snprintf(buf, sizeof(buf), "key%u", i);
		k = string_key(buf);
		chain = tdb_jenkins_hash(&k) % HASH_SIZE;
		if (!have_a) {
			if (chain != 0) {
				strlcpy(key_a, buf, sizeof(key_a));
				chain_a = chain;
				have_a = true;
			}
		} else if (!have_b && (chain == chain_a)) {
			strlcpy(key_b, buf, sizeof(key_b));
			have_b = true;
		} else if (!have_k && (chain == chain_a - 1)) {
			strlcpy(key_k, buf, sizeof(key_k));
			have_k = true;
		}
	}
}

static int store_string(struct tdb_context *tdb, const char *key, size_t len)
{
	uint8_t buf[128];

	memset(buf, 'x', sizeof(buf));
	return tdb_store(tdb, string_key(key),
			 (TDB_DATA) { .dptr = buf, .dsize = len }, TDB_REPLACE);
}

static int writer(int tdb_flags, int from, int to)
{
	struct tdb_context *tdb;
	char c;

	if (read(from, &c, 1) != 1) {
		return 1;
	}
	tdb = tdb_open_ex(DBNAME, HASH_SIZE, tdb_flags, O_RDWR, 0600,
			  &taplogctx, NULL);
	if (tdb == NULL) {
		diag("writer: open failed: %s", strerror(errno));
		return 1;
	}
	if (tdb_delete(tdb, string_key(key_a)) != 0) {
		diag("writer: delete failed: %s", tdb_errorstr(tdb));
		return 1;
	}
	if (store_string(tdb, key_k, 50) != 0) {
		diag("writer: store failed: %s", tdb_errorstr(tdb));
		return 1;
	}
	tdb_close(tdb);
	return (write(to, &c, 1) == 1) ? 0 : 1;
}

static int freelist_holder(int tdb_flags, int from, int to)
{
	struct tdb_context *tdb;
	char c;

	if (read(from, &c, 1) != 1) {
		return 1;
	}
	tdb = tdb_open_ex(DBNAME, HASH_SIZE, tdb_flags, O_RDWR, 0600,
			  &taplogctx, NULL);
	if ((tdb == NULL) || (tdb_lock(tdb, -1, F_WRLCK) != 0)) {
		diag("holder: open or freelist lock failed");
		return 1;
	}
	if ((write(to, &c, 1) != 1) || (read(from, &c, 1) != 1)) {
		return 1;
	}
	tdb_unlock(tdb, -1, F_WRLCK);
	tdb_close(tdb);
	return 0;
}

struct trav_state {
	int to_writer, from_writer, to_holder;
	unsigned seen_b;
};

static int trav_fn(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data,
		   void *private_data)
{
	struct trav_state *s = private_data;
	char c = 0;

	if ((key.dsize == strlen(key_b)) &&
	    (memcmp(key.dptr, key_b, key.dsize) == 0)) {
		s->seen_b += 1;
	}
	if ((key.dsize != strlen(key_a)) ||
	    (memcmp(key.dptr, key_a, key.dsize) != 0)) {
		return 0;
	}
	/* Sitting on A: let the writer delete A and store K */
	if (write(s->to_writer, &c, 1) != 1) {
		return -1;
	}
	if (s->to_holder != -1) {
		/* Let the writer find the freelist busy, then free it */
		usleep(200000);
		if (write(s->to_holder, &c, 1) != 1) {
			return -1;
		}
	}
	if (read(s->from_writer, &c, 1) != 1) {
		return -1;
	}
	return 0;
}

static void run_case(int tdb_flags, bool hold_freelist)
{
	struct tdb_context *tdb;
	struct trav_state s = { .to_holder = -1 };
	int to_w[2], from_w[2], to_h[2], from_h[2];
	pid_t w, h = -1;
	int ret, status;
	char c = 0;

	diag("%s, %s", (tdb_flags & TDB_MUTEX_LOCKING) ? "mutex" : "fcntl",
	     hold_freelist ? "freelist held (steal)" : "freelist free");

	unlink(DBNAME);
	find_keys();
	ok1(pipe(to_w) == 0);
	ok1(pipe(from_w) == 0);
	ok1(pipe(to_h) == 0);
	ok1(pipe(from_h) == 0);

	/* Fork before opening: a process can't open a tdb twice */
	w = fork();
	if (w == 0) {
		close(to_w[1]); close(from_w[0]);
		close(to_h[0]); close(to_h[1]); close(from_h[0]); close(from_h[1]);
		exit(writer(tdb_flags, to_w[0], from_w[1]));
	}
	if (hold_freelist) {
		h = fork();
		if (h == 0) {
			close(to_h[1]); close(from_h[0]);
			close(to_w[0]); close(to_w[1]);
			close(from_w[0]); close(from_w[1]);
			exit(freelist_holder(tdb_flags, to_h[0], from_h[1]));
		}
	}
	/* A child that dies now shows up as EOF on our end */
	close(to_w[0]); close(from_w[1]); close(to_h[0]); close(from_h[1]);

	tdb = tdb_open_ex(DBNAME, HASH_SIZE, tdb_flags, O_RDWR|O_CREAT, 0600,
			  &taplogctx, NULL);
	ok1(tdb);

	/* Stored last, A comes first in the chain, B after it */
	ok1(store_string(tdb, key_b, 100) == 0);
	ok1(store_string(tdb, key_a, 100) == 0);

	if (hold_freelist) {
		ok1(write(to_h[1], &c, 1) == 1);
		ok1(read(from_h[0], &c, 1) == 1);
		s.to_holder = to_h[1];
	}
	s.to_writer = to_w[1];
	s.from_writer = from_w[0];

	ret = tdb_traverse_read(tdb, trav_fn, &s);
	ok(ret == 2, "traverse returned %d records, expected 2", ret);
	ok(s.seen_b == 1, "traverse saw %s %u times, expected once",
	   key_b, s.seen_b);

	ok1(waitpid(w, &status, 0) == w);
	ok1(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	if (hold_freelist) {
		ok1(waitpid(h, &status, 0) == h);
		ok1(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}
	ok1(tdb_check(tdb, NULL, NULL) == 0);
	tdb_close(tdb);

	close(to_w[1]); close(from_w[0]); close(to_h[1]); close(from_h[0]);
}

int main(int argc, char *argv[])
{
	int flags = TDB_VOLATILE|TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH;

	plan_tests(40);

	run_case(flags, false);
	run_case(flags, true);

	if (tdb_runtime_check_for_robust_mutexes()) {
		run_case(flags|TDB_MUTEX_LOCKING, false);
		run_case(flags|TDB_MUTEX_LOCKING, true);
	} else {
		skip(1, "No robust mutex support");
	}

	diag("done");
	return exit_status();
}

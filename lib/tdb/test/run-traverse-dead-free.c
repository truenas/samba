/*
 * A traverse sits on record A while another process deletes A and then
 * frees the dead records of A's chain: without TDB_VOLATILE the delete
 * trims them at once, with it a store too big for A purges the chain
 * on its way to the freelist. A must stay where it is, the traverse has
 * to continue from it to record B.
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

#define DBNAME "traverse-dead-free.tdb"
#define HASH_SIZE 32

static char key_a[16], key_b[16], key_c[16];

static TDB_DATA string_key(const char *s)
{
	return (TDB_DATA) { .dptr = discard_const_p(uint8_t, s),
			    .dsize = strlen(s) };
}

/* Three keys of one chain. TDB_INCOMPATIBLE_HASH selects jenkins. */
static void find_keys(void)
{
	unsigned i, chain_a = 0, found = 0;
	char buf[16];

	for (i = 0; found < 3; i++) {
		TDB_DATA k;
		unsigned chain;

		snprintf(buf, sizeof(buf), "key%u", i);
		k = string_key(buf);
		chain = tdb_jenkins_hash(&k) % HASH_SIZE;
		if (found == 0) {
			strlcpy(key_a, buf, sizeof(key_a));
			chain_a = chain;
			found = 1;
		} else if (chain == chain_a) {
			strlcpy((found == 1) ? key_b : key_c, buf, 16);
			found += 1;
		}
	}
}

static int store_string(struct tdb_context *tdb, const char *key, size_t len)
{
	uint8_t buf[256];

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
	if ((tdb_flags & TDB_VOLATILE) &&
	    (store_string(tdb, key_c, 200) != 0)) {
		diag("writer: store failed: %s", tdb_errorstr(tdb));
		return 1;
	}
	tdb_close(tdb);
	return (write(to, &c, 1) == 1) ? 0 : 1;
}

struct trav_state {
	int to_writer, from_writer;
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
	/* Sitting on A: let the writer delete A and free dead records */
	if ((write(s->to_writer, &c, 1) != 1) ||
	    (read(s->from_writer, &c, 1) != 1)) {
		return -1;
	}
	return 0;
}

static void run_case(int tdb_flags)
{
	struct tdb_context *tdb;
	struct trav_state s = { 0 };
	int to_w[2], from_w[2];
	pid_t w;
	int ret, status;

	diag("%s, %s", (tdb_flags & TDB_MUTEX_LOCKING) ? "mutex" : "fcntl",
	     (tdb_flags & TDB_VOLATILE) ? "volatile" : "not volatile");

	unlink(DBNAME);
	find_keys();
	ok1(pipe(to_w) == 0);
	ok1(pipe(from_w) == 0);

	/* Fork before opening: a process can't open a tdb twice */
	w = fork();
	if (w == 0) {
		close(to_w[1]);
		close(from_w[0]);
		exit(writer(tdb_flags, to_w[0], from_w[1]));
	}
	close(to_w[0]);
	close(from_w[1]);

	tdb = tdb_open_ex(DBNAME, HASH_SIZE, tdb_flags, O_RDWR|O_CREAT, 0600,
			  &taplogctx, NULL);
	ok1(tdb);

	/* Stored last, A comes first in the chain, B after it */
	ok1(store_string(tdb, key_b, 100) == 0);
	ok1(store_string(tdb, key_a, 20) == 0);

	s.to_writer = to_w[1];
	s.from_writer = from_w[0];
	ret = tdb_traverse_read(tdb, trav_fn, &s);
	ok(ret == 2, "traverse returned %d records, expected 2", ret);
	ok(s.seen_b == 1, "traverse saw %s %u times, expected once",
	   key_b, s.seen_b);

	ok1(waitpid(w, &status, 0) == w);
	ok1(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ok1(tdb_check(tdb, NULL, NULL) == 0);
	tdb_close(tdb);
	close(to_w[1]);
	close(from_w[0]);
}

int main(int argc, char *argv[])
{
	int flags = TDB_CLEAR_IF_FIRST|TDB_INCOMPATIBLE_HASH;

	plan_tests(36);

	run_case(flags);
	run_case(flags|TDB_VOLATILE);

	if (tdb_runtime_check_for_robust_mutexes()) {
		run_case(flags|TDB_MUTEX_LOCKING);
		run_case(flags|TDB_MUTEX_LOCKING|TDB_VOLATILE);
	} else {
		skip(1, "No robust mutex support");
	}

	diag("done");
	return exit_status();
}

#include "replace.h"
#include "system/filesys.h"
#include "replace-test.h"

#define SUBDIR "subdir"
#define TESTDIR "testdir"
#define SYMLINK "symlink"
#define SUBDIR2 "subdir2"

static bool remove_if_exists(const char *path, int (*rmfn) (const char *))
{
	int error;
	struct stat st;

	error = stat(path, &st);
	if (error) {
		if (errno == ENOENT) {
			return true;
		}
		fprintf(stderr, "%s: stat() failed: %s\n",
			TESTDIR, strerror(errno));
		return false;
	}

	error = rmfn(path);
	if (error) {
		fprintf(stderr, "%s: failed to remove path: %s\n",
			path, strerror(errno));
		return false;
	}

	return true;
}

static bool cleanup(void)
{
	if (!remove_if_exists(TESTDIR "/" SYMLINK, unlink)) {
		return false;
	}

	if (!remove_if_exists(TESTDIR, rmdir)) {
		return false;
	}

	if (!remove_if_exists(SUBDIR "/" SUBDIR2, rmdir)) {
		return false;
	}

	if (!remove_if_exists(SUBDIR, rmdir)) {
		return false;
	}

	return true;
}

static bool setup(void)
{
	int error;

	error = mkdir(TESTDIR, 0700);
	if (error) {
		fprintf(stderr, "%s: mkdir() failed: %s\n",
			TESTDIR, strerror(errno));
		return false;
	}

	error = mkdir(SUBDIR, 0700);
	if (error) {
		fprintf(stderr, "%s: mkdir() failed: %s\n",
			SUBDIR, strerror(errno));
		return false;
	}

	error = mkdir(SUBDIR "/" SUBDIR2, 0700);
	if (error) {
		fprintf(stderr, "%s: mkdir() failed: %s\n",
			SUBDIR "/" SUBDIR2, strerror(errno));
		return false;
	}

	error = symlink("../" SUBDIR, TESTDIR "/" SYMLINK);
	if (error) {
		fprintf(stderr, "symlink() failed: %s\n",
			strerror(errno));
		return false;
	}

	return true;
}

static int do_openat2(int dirfd, const char *path, int resolve)
{
	struct open_how how = {
		.flags = O_DIRECTORY,
		.resolve = resolve
	};

	return openat2(dirfd, path, &how, sizeof(how));
}


static bool open_symlink_nofollow_fail(int dirfd)
{
	int ret;

	ret = do_openat2(
		dirfd,
		TESTDIR "/" SYMLINK "/" SUBDIR2,
		RESOLVE_NO_SYMLINKS
	);
	if ((ret == -1) && (errno == ELOOP)) {
		return true;
	} else if (ret == -1) {
		fprintf(stderr, "RESOLVE_NO_SYMLINKS: openat2() "
			"unexpected error: %s\n",
			strerror(errno));
		return false;
	}

	close(ret);
	fprintf(stderr, "unexpected success whilst trying to resolve path "
		"containing an intermediate symlink\n");
	return false;
}

int test_openat2_impl(void)
{
	int dirfd, ret = -1;

	if (!cleanup()) {
		fprintf(stderr, "cleanup failed\n");
		return -1;
	}

	if (!setup()) {
		fprintf(stderr, "setup failed\n");
		return -1;
	}

	dirfd = open(".", O_DIRECTORY);
	if (dirfd == -1) {
		fprintf(stderr, "failed to open dirfd: %s\n", strerror(errno));
		return -1;
	}

	printf("test: openat2_symlink_nofollow_eloop\n");
	if (!open_symlink_nofollow_fail(dirfd)) {
		goto error_out;
	}
	printf("success: openat2_symlink_nofollow_eloop\n");
	ret = 0;

error_out:
	close(dirfd);
	cleanup();
	return ret;
}

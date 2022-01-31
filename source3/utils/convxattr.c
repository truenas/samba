/*
   Unix SMB/CIFS implementation.
   Copyright (C) iXsystems 2021

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "system/filesys.h"
#include "string_replace.h"
#include <popt.h>
#include <fts.h>

#ifdef HAVE_JANSSON
#include <jansson.h>
#include "audit_logging.h" /* various JSON helpers */
#include "auth/common_auth.h"
#define JS_MAJ_VER      0
#define JS_MIN_VER      1
#endif /* HAVE_JANSSON */

#define STREAM_MARKER_COMPAT		"user.SAMBA_COMPAT"
#define STREAM_SUFFIX			":$DATA"

static struct encoding_config {
	struct char_mappings **mappings;
	enum vfs_translate_direction direction;
	char *config;
} enc;

static struct rename_xattr_state {
	TALLOC_CTX *mem_ctx;
	int skip;
	int force;
	int verbose;
	int test;
	int no_xdev;
	int do_chdir;
	char *stream_prefix;
	char *new_prefix;
	bool streams_xattr_compat;
	char *action;
	char *suffix_op;
#ifdef HAVE_JANSSON
	struct json_object jsfile;
	struct json_object jsxattrs;
	struct json_object jsentry;
#endif
	bool (*fn)(FTSENT *entry, const char *xattr_name);
} state;

static ssize_t get_xattr_list(FTSENT *entry,
			      char **xatbuf)
{
	ssize_t sizeret = -1;
	char *names = NULL;

	sizeret = listxattr(entry->fts_accpath, NULL, 0);
	if (sizeret == -1) {
		d_fprintf(stderr, "%s: listxattr() failed: %s\n",
			  entry->fts_accpath, strerror(errno));
		return sizeret;
	}

	names = talloc_array(state.mem_ctx, char, sizeret);
	if (names == NULL) {
		d_fprintf(stderr, "%s: listxattr() failed: memory error\n",
			  entry->fts_accpath);
		return -1;
	}

	sizeret = listxattr(entry->fts_accpath, names, sizeret);
	if (sizeret == -1) {
		d_fprintf(stderr, "%s: listxattr() failed: %s\n",
			  entry->fts_accpath, strerror(errno));
		return sizeret;
	}

	*xatbuf = names;
	return sizeret;
}

static bool has_stream_suffix(const char *xat)
{
	size_t offset;

	offset = strlen(xat) - strlen(STREAM_SUFFIX);
	if (strequal(xat + offset, STREAM_SUFFIX)) {
		return true;
	}

	return false;
}

/*
 * Check what need to be done regarding ":DATA$" suffix
 * Returns 0 if no change required, 1 if it should be added, -1 if removed.
 */
static int check_stream_suffix(const char *xat)
{
	int rv = 0;
	bool has_suffix;

	switch(state.suffix_op[0]){
	case 'a':
		has_suffix = has_stream_suffix(xat);
		rv = has_suffix ? 0 : 1;
		break;
	case 'r':
		has_suffix = has_stream_suffix(xat);
		rv = has_suffix ? -1 : 0;
		break;
	case 'i':
	default:
		break;
	}
	return rv;
}


static bool move_xattr(FTSENT *entry, const char *old_name, const char *new_name)
{
	bool rv = true;
	ssize_t len;
	char *xatbuf = NULL;
	int ret, flags = XATTR_CREATE;

	len = getxattr(entry->fts_accpath, old_name, NULL, 0);
	if (len < 0) {
		if (errno == ENOATTR) {
			return true;
		}
		d_fprintf(stderr, "%s: getxattr [%s] failed: %s\n",
			  entry->fts_accpath, old_name, strerror(errno));
		return false;
	}

	xatbuf = talloc_zero_array(state.mem_ctx, char, len);
	if (xatbuf == NULL) {
		d_fprintf(stderr, "%s: getxattr [%s] failed: memory error\n",
			  entry->fts_accpath, old_name);
		return false;
	}

	len = getxattr(entry->fts_accpath, old_name, xatbuf, len);
	if (len < 0) {
		d_fprintf(stderr, "%s: getxattr [%s] failed: %s\n",
			  entry->fts_accpath, old_name, strerror(errno));
		rv = false;
		goto done;
	}

	if (state.force) {
		flags = 0;
	}

	ret = setxattr(entry->fts_accpath, new_name, xatbuf, len, flags);
	if (ret != 0) {
		d_fprintf(stderr, "%s: setxattr [%s] failed: %s\n",
			  entry->fts_accpath, new_name, strerror(errno));
		rv = false;
		goto done;
	}

	ret = removexattr(entry->fts_accpath, old_name);
	if (ret == -1) {
		d_fprintf(stderr, "%s: removexattr [%s] failed: %s\n",
			  entry->fts_accpath, old_name, strerror(errno));
		rv = false;
		goto done;
	}

done:
	TALLOC_FREE(xatbuf);
	return rv;
}

/*
 * Perform conversion of between fruit:encoding = private and
 * fruit:encoding = native.
 */
static bool apply_encoding(const char *prefix, char **name_in)
{
	char *to_check = NULL, *tmp_name = NULL, *name_out = NULL;
	NTSTATUS status;
	bool suffix;

	if (enc.mappings == NULL) {
		return true;
	}

	suffix = has_stream_suffix(*name_in);
	to_check = talloc_strdup(state.mem_ctx, *name_in + strlen(prefix));
	if (to_check == NULL) {
		d_fprintf(stderr, "memory_error");
		return false;
	}

	if (suffix) {
		size_t l = strlen(to_check);
		to_check[l - strlen(STREAM_SUFFIX)] = '\0';
	}

	status = string_replace_allocate(NULL,
					 to_check,
					 enc.mappings,
					 to_check,
					 &tmp_name,
					 enc.direction);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(to_check);
		return false;
	}

	name_out = talloc_asprintf(state.mem_ctx,
				   "%s%s%s",
				   prefix,
				   tmp_name,
				   suffix ? ":$DATA" : "");
	if (name_out == NULL) {
		d_fprintf(stderr, "memory_error");
		TALLOC_FREE(to_check);
		return false;
	}

	TALLOC_FREE(to_check);
	TALLOC_FREE(*name_in);
	*name_in = name_out;

	return true;
}

static char *get_prefix(const char *xattr_name)
{
	size_t old_len, new_len;

	old_len = strlen(state.stream_prefix);
	new_len = strlen(state.new_prefix);

	/*
	 * Prefix is reducing in length.
	 * Overlap is not possible.
	 */
	if (old_len > new_len) {
		return state.new_prefix;
	}

	/*
	 * If for example, we're changing prefix from
	 * "user." to "user.DosStream." and hit an
	 * xattr that already contains "user.DosStream." in
	 * its name, then we should skip it. Otherwise
	 * new name will be "user.DosStream.DosStream".
	 */
	if (strncmp(xattr_name, state.new_prefix, new_len) == 0) {
		return state.stream_prefix;
	}

	return state.new_prefix;
}

static bool move_prefix(FTSENT *entry,
			const char *xattr_name)
{
	bool ok = true;
	char *new_name = NULL, *prefix = NULL;
	int suffix_op;

	/* 1 means add, -1 means remove, 0 ignore */
	suffix_op = check_stream_suffix(xattr_name);

	prefix = get_prefix(xattr_name);

	new_name = talloc_asprintf(state.mem_ctx,
				   suffix_op == 1 ? "%s%s:DATA" : "%s%s",
				   prefix,
				   xattr_name + strlen(state.stream_prefix));

	if (new_name == NULL) {
		d_fprintf(stderr, "memory error\n");
		return false;
	}

	if (suffix_op == -1) {
		size_t offset;
		offset = strlen(new_name) - strlen(STREAM_SUFFIX);
		new_name[offset] = '\0';
	}

	ok = apply_encoding(prefix, &new_name);

	/* Target and destination are same. Skip xattr ops */
	if (strequal(xattr_name, new_name)) {
		goto done;
	}

	if (!state.test) {
		ok = move_xattr(entry, xattr_name, new_name);
		if (!ok) {
			TALLOC_FREE(new_name);
			return false;
		}
	}

done:
	if (state.verbose) {
#ifdef HAVE_JANSSON
		int error;
		error = json_add_string(&state.jsentry, "result", new_name);
		if (error) {
			d_fprintf(stderr, "%s: failed to add %s->%s\n",
				  entry->fts_accpath, xattr_name, new_name);
		}
#else
		d_printf(" -> [%s]", new_name);
#endif
	}
	TALLOC_FREE(new_name);

	return true;
}

static bool add_byte_to_xattr(FTSENT *entry,
			      const char *xattr_name)
{
	ssize_t len;
	char *xatbuf = NULL;
	int ret;

	if (state.test) {
		return true;
	}

	len = getxattr(entry->fts_accpath, xattr_name, NULL, 0);
	if (len < 0) {
		if (errno == ENOATTR) {
			return true;
		}
		d_fprintf(stderr, "%s: getxattr [%s] failed: %s\n",
			 entry->fts_accpath, xattr_name, strerror(errno));
		return false;
	}

	xatbuf = talloc_array(state.mem_ctx, char, len + 1);
	if (xatbuf == NULL) {
		d_fprintf(stderr, "%s: getxattr [%s] failed: memory error\n",
			 entry->fts_accpath, xattr_name);
	}

	len = getxattr(entry->fts_accpath, xattr_name, xatbuf, len);
	if (len < 0) {
		d_fprintf(stderr, "%s: getxattr [%s] failed: %s\n",
			 entry->fts_accpath, xattr_name, strerror(errno));
		TALLOC_FREE(xatbuf);
		return false;
	}

	xatbuf[len] = '\0';

	ret = setxattr(entry->fts_accpath, xattr_name, &xatbuf, len + 1, XATTR_REPLACE);
	if (ret != 0) {
		d_fprintf(stderr, "%s: setxattr [%s] failed: %s\n",
			  entry->fts_accpath, xattr_name, strerror(errno));
		TALLOC_FREE(xatbuf);
		return false;
	}

	TALLOC_FREE(xatbuf);
	return true;
}

static bool rm_byte_from_xattr(FTSENT *entry,
			       const char *xattr_name)
{
	ssize_t len;
	char *xatbuf = NULL;
	int ret;

	if (state.test) {
		return true;
	}

	len = getxattr(entry->fts_accpath, xattr_name, NULL, 0);
	if (len < 0) {
		if (errno == ENOATTR) {
			return true;
		}
		d_fprintf(stderr, "%s: getxattr [%s] failed: %s\n",
			  entry->fts_accpath, xattr_name, strerror(errno));
		return false;
	}

	xatbuf = talloc_array(state.mem_ctx, char, len);
	if (xatbuf == NULL) {
		d_fprintf(stderr, "%s: getxattr [%s] failed: memory error\n",
			  entry->fts_accpath, xattr_name);
	}

	len = getxattr(entry->fts_accpath, xattr_name, xatbuf, len);
	if (len < 0) {
		d_fprintf(stderr, "%s: getxattr [%s] failed: %s\n",
			 entry->fts_accpath, xattr_name, strerror(errno));
		TALLOC_FREE(xatbuf);
		return false;
	}

	ret = setxattr(entry->fts_accpath, xattr_name, &xatbuf, len - 1, XATTR_REPLACE);
	if (ret != 0) {
		d_fprintf(stderr, "%s: setxattr [%s] failed: %s\n",
			  entry->fts_accpath, xattr_name, strerror(errno));
		TALLOC_FREE(xatbuf);
		return false;
	}

	return true;
}

static bool name_is_included(const char *xattr_name)
{
	static const char * const prohibited_ea_names[] = {
		SAMBA_POSIX_INHERITANCE_EA_NAME,
		SAMBA_XATTR_DOS_ATTRIB,
		SAMBA_XATTR_MARKER,
		STREAM_MARKER_COMPAT,
		NULL
	};

	int i;
	char *prefix = state.stream_prefix;

	for (i = 0; prohibited_ea_names[i]; i++) {
		if (strequal( prohibited_ea_names[i], xattr_name)) {
			return false;
		}
	}

	if (strncmp(xattr_name, prefix, strlen(prefix)) != 0) {
		return false;
	}

	return true;
}

static int iter_xattr_names(FTSENT *entry,
			    char *xattr_names,
			    ssize_t names_size)
{
	char *p = NULL;

	for (p = xattr_names; p - xattr_names < names_size; p += strlen(p)+1) {
		bool ok;
		ok = name_is_included(p);
		if (!ok) {
			continue;
		}

		if (state.verbose) {
#ifdef HAVE_JANSSON
			int error;
			state.jsentry = json_new_object();
			if (json_is_invalid(&state.jsentry)) {
				d_fprintf(stderr, "JSON error\n");
				return -1;
			}
			error = json_add_string(&state.jsentry, "name", p);
			if (error) {
				d_fprintf(stderr, "JSON error\n");
				return -1;
			}
#else
			d_printf("\txattr: [%s] ", p);
#endif
		}

		ok = state.fn(entry, p);
		if (!ok) {
			return -1;
		}
		if (state.verbose) {
#ifdef HAVE_JANSSON
			int error;
			error = json_add_object(&state.jsxattrs, NULL, &state.jsentry);
			if (error) {
				d_fprintf(stderr, "JSON error\n");
				return -1;
			}
			/* json_decref on state.jsxattrs.root will free entry memory */
			state.jsentry = (struct json_object) {
				.root = NULL,
				.valid = false,
			};
#else
			d_printf("\n");
#endif
		}
        }

	return 0;
}

static int set_streams_xattr_sentinel(FTSENT *entry)
{
	ssize_t len;
	char marker[1];

	if (state.test) {
		return 0;
	}

	len = getxattr(entry->fts_accpath, STREAM_MARKER_COMPAT, marker, 1);
	if (len == 1) {
		char expected[1] = { state.streams_xattr_compat ? '\0' : '1' };

		if (strcmp(marker, expected) != 0) {
			d_fprintf(stderr, "%s: xattrs already transformed.\n",
				  entry->fts_accpath);
			return -EINVAL;
		}
	}
	else if ((len == -1) && (errno != ENODATA)) {
		d_fprintf(stderr, "%s: expected return when getting compat marker.",
			  entry->fts_accpath);
		return -1;
	}

	marker[0] = state.streams_xattr_compat ? '1' : '\0';

	len = setxattr(entry->fts_accpath, STREAM_MARKER_COMPAT, &marker, 1, 0);
	if (len != 0) {
		d_fprintf(stderr, "%s: failed to set compat marker: %s.",
			  entry->fts_accpath, strerror(errno));
		return -1;
	}

	return 0;
}

#ifdef HAVE_JANSSON
static int json_alloc(void)
{
	state.jsfile = json_new_object();
	if (json_is_invalid(&state.jsfile)) {
		printf("alloc_failed\n");
		return -1;
	}

	state.jsxattrs = json_new_array();
	if (json_is_invalid(&state.jsxattrs)) {
		json_free(&state.jsfile);
		printf("alloc_failed\n");
		return -1;
	}

	return 0;
}

static void json_dealloc(void)
{
	json_free(&state.jsfile);
	json_free(&state.jsxattrs);

	if (json_is_invalid(&state.jsentry)) {
		return;
	}
	json_free(&state.jsentry);
}
#endif /* HAVE_JANSSON */

static int handle_file(FTS *ftsp,
		       FTSENT *entry)
{
	ssize_t len;
	int error;
	char *namelist = NULL;
#ifdef HAVE_JANSSON
	char *jsoutput = NULL;

	if (state.verbose) {
		error = json_alloc();
		if (error) {
			return -1;
		}
		error = json_add_string(&state.jsfile, "file", entry->fts_accpath);
		if (error) {
			goto done;
		}
		if (state.do_chdir) {
			error = json_add_int(&state.jsfile, "depth", entry->fts_level);
			if (error) {
				goto done;
			}
		}
	}
#else
	if (state.verbose) {
		d_printf("%s\n", entry->fts_accpath);
	}
#endif

	error = set_streams_xattr_sentinel(entry);
	if (error == -EINVAL) {
		if (!state.skip) {
			goto done;
		}
	}
	else if (error) {
		goto done;
	}

	len = get_xattr_list(entry, &namelist);
	if (len == -1) {
		error = -1;
		goto done;
	}

	error = iter_xattr_names(entry, namelist, len);
	if (error) {
		d_fprintf(stderr, "%s: iter_xattr_names() failed.\n",
			  entry->fts_accpath);
		goto done;
	}

#ifdef HAVE_JANSSON
	if (state.verbose) {
		error = json_add_object(&state.jsfile,
					"xattrs",
					&state.jsxattrs);
		if (error) {
			goto done;
		}
		jsoutput = json_to_string(state.mem_ctx, &state.jsfile);
		if (jsoutput == NULL) {
			error = -ENOMEM;
			goto done;
		}
		d_printf("%s\n", jsoutput);
		TALLOC_FREE(jsoutput);
	}
#endif

done:
#if HAVE_JANSSON
	if (state.verbose) {
		json_dealloc();
	}
#endif /* HAVE_JANSSON */
	return error;
}

static int do_fts_walk(char **paths)
{
	FTS *ftsp = NULL;
	FTSENT *entry = NULL;
	int error = 0;
	int fts_flags = FTS_PHYSICAL;

	if (state.no_xdev) {
		fts_flags |= FTS_XDEV;
	}

	if (!state.do_chdir) {
		fts_flags |= FTS_NOCHDIR;
	}

	ftsp = fts_open(paths, fts_flags, NULL);
	while ((entry = fts_read(ftsp)) != NULL) {
		switch (entry->fts_info) {
		case FTS_D:
		case FTS_F:
			error = handle_file(ftsp, entry);
			if (error) {
				return error;
			}
			break;
		case FTS_ERR:
			d_fprintf(stderr, "%s: fts_read() error: %s\n",
				  entry->fts_path, strerror(entry->fts_errno));
			return -1;
		}
	}

	return error;
}

#ifdef HAVE_JANSSON
static int dump_params_json(char **paths)
{
	int error, i;
	char *path = NULL;
	char *jsoutput = NULL;

	error = json_alloc();
	if (error) {
		return -1;
	}

	error = json_add_version(&state.jsfile, JS_MAJ_VER, JS_MIN_VER);
	if (error) {
		goto done;
	}

	error = json_add_string(&state.jsfile, "action", state.action);
	if (error) {
		goto done;
	}

	error = json_add_bool(&state.jsfile, "verbose", state.verbose);
	if (error) {
		goto done;
	}

	error = json_add_bool(&state.jsfile, "chdir", state.do_chdir);
	if (error) {
		goto done;
	}

	error = json_add_bool(&state.jsfile, "no-xdev", state.no_xdev);
	if (error) {
		goto done;
	}

	error = json_add_bool(&state.jsfile, "force", state.force);
	if (error) {
		goto done;
	}

	error = json_add_bool(&state.jsfile, "test", state.test);
	if (error) {
		goto done;
	}

	error = json_add_string(&state.jsfile, "prefix_old",
				state.stream_prefix);
	if (error) {
		goto done;
	}

	error = json_add_string(&state.jsfile, "prefix_new",
				state.new_prefix);
	if (error) {
		goto done;
	}

	error = json_add_string(&state.jsfile, "suffix_op",
				state.suffix_op);
	if (error) {
		goto done;
	}

	error = json_add_string(&state.jsfile, "fruit_encoding",
				enc.config);
	if (error) {
		goto done;
	}

	for (i = 0, path = paths[i]; path; i++, path = paths[i]) {
		struct json_object entry;

		entry = json_new_object();
		if (json_is_invalid(&entry)) {
			goto done;
		}

		error = json_add_string(&entry, "path", path);
		if (error) {
			json_free(&entry);
			goto done;
		}
		error = json_add_object(&state.jsxattrs, NULL, &entry);
		if (error) {
			goto done;
		}
	}

	error = json_add_object(&state.jsfile, "targets", &state.jsxattrs);
	if (error) {
		goto done;
	}

	jsoutput = json_to_string(state.mem_ctx, &state.jsfile);
	if (jsoutput == NULL) {
		goto done;
	}
	d_printf("%s\n", jsoutput);
	TALLOC_FREE(jsoutput);

done:
	json_dealloc();
	return error;
}
#endif /* HAVE_JANSSON */

static const char **get_mapping_list(void)
{
	char **mappings = NULL;

	mappings = str_list_make_v3(state.mem_ctx, macos_string_replace_map, NULL);
	if (mappings == NULL) {
		d_fprintf(stderr, "Failed to convert string mapping to list\n");
	}

	return discard_const_p(const char *, mappings);
}

static int load_encoding_mappings(void)
{
	const char **mappings = NULL;
	mappings = get_mapping_list();
	if (mappings == NULL) {
		d_fprintf(stderr, "Failed to convert string mapping to list\n");
		return -1;
	}

	enc.mappings = string_replace_init_map(state.mem_ctx, mappings);
	if (enc.mappings == NULL) {
		d_fprintf(stderr, "Failing to initialize MacOS encoding info\n");
		return -1;
	}

	return 0;
}

static int validate_encoding_op(void)
{
	int rv = -1;

	if (enc.config == NULL) {
		enc.config = talloc_strdup(state.mem_ctx, "ignore");
		return 0;
	}

	if (strequal(enc.config, "private")) {
		enc.direction = vfs_translate_to_windows;
		rv = load_encoding_mappings();
	}
	else if (strequal(enc.config, "native")) {
		enc.direction = vfs_translate_to_unix;
		rv = load_encoding_mappings();
	}
	else if (strequal(enc.config, "ignore")) {
		rv = 0;
	} else {
		d_fprintf(stderr, "Unknown encoding config: %s\n", enc.config);
	}

	return rv;
}

static int validate_suffix_op(void)
{
	int rv = -1;

	if (state.suffix_op == NULL) {
		d_fprintf(stderr,
			  "Suffix operation must be specified during move op.");
		return -1;
	}

	if (strequal(state.suffix_op, "append")) {
		rv = 0;
	}
	else if (strequal(state.suffix_op, "remove")) {
		rv = 0;
	}
	else if (strequal(state.suffix_op, "ignore")) {
		rv = 0;
	} else {
		d_fprintf(stderr, "Unknown suffix op: %s\n", state.suffix_op);
	}

	return rv;
}

static int validate_prefix(const char *prefix)
{
	const char *last_char = &prefix[strlen(prefix) -1];

	if (strcmp(last_char, ".") != 0) {
		d_fprintf(stderr, "Prefix [%s] is not terminated with a '.'\n",
			  state.new_prefix);
		return -1;
	}

	if (strncmp(prefix, "user.", 5) != 0) {
		d_fprintf(stderr, "Prefix [%s] does not start with \"user.\"\n",
			  state.new_prefix);
		return -1;
	}

	return 0;
}

static int load_action(void)
{
	int error;

	if (state.action == NULL) {
		d_fprintf(stderr, "Action is required.");
		return -1;
	}

	error = validate_prefix(state.stream_prefix);
	if (error) {
		return error;
	}

	if (strequal(state.action, "add")) {
		state.fn = add_byte_to_xattr;
	}
	else if (strequal(state.action, "rem")) {
		state.fn = rm_byte_from_xattr;
	}
	else if (strequal(state.action, "mv")) {
		error = validate_suffix_op();
		if (error) {
			return error;
		}
		error = validate_encoding_op();
		if (error) {
			return error;
		}
		error = validate_prefix(state.new_prefix);
		if (error) {
			return error;
		}
		state.fn = move_prefix;
	} else {
		d_fprintf(stderr, "Unknown action: %s\n", state.action);
		return -1;
	}
	return 0;
}

int main(int argc, const char *argv[])
{
	int c;
	const char *path = NULL;
	char **paths = NULL;
	int i = 0;

	poptContext pc = NULL;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{
			.longName   = "stream-prefix",
			.shortName  = 'p',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &state.stream_prefix,
			.val        = 'p',
			.descrip    = "Extended attribute prefix for streams. "
				      "Specified actions will only be performed "
				      "on extended attributes that start with this prefix",
		},
		{
			.longName   = "new-prefix",
			.shortName  = 'n',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &state.new_prefix,
			.val        = 'n',
			.descrip    = "New extended attribute prefix for streams "
				      "used during \"mv\" actions. During the action, "
				      "the prefix specified by the \"stream prefix\" "
				      "parameter is replaced with the prefix specified "
				      "by this parameter.",
		},
		{
			.longName   = "action",
			.shortName  = 'a',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &state.action,
			.val        = 'a',
			.descrip    = "xattr operation to perform. Only one action "
				      "may be specified. Supported actions are add, rem, mv",
		},
		{
			.longName   = "encoding",
			.shortName  = 'e',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &enc.config,
			.val        = 'e',
			.descrip    = "Encoding style. Choices are \"native\", \"private\", "
				      "and \"ignore\". Default is to ignore (no encoding "
				      "changes).",
		},
		{
			.longName   = "verbose",
			.shortName  = 'v',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &state.verbose,
			.val        = 'v',
			.descrip    = "print files and xattrs where op performed. If "
				      "Samba was compiled with JSON support, then "
				      "new-line separated detailed information about "
				      "the operatoin and result will be printed to stdout.",
		},
		{
			.longName   = "test",
			.shortName  = 't',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &state.test,
			.val        = 't',
			.descrip    = "Perform a trial run for the specified operation. "
				      "No on-disk changes will be made. Implies verbose. "
		},
		{
			.longName   = "no-xdev",
			.shortName  = 'x',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &state.no_xdev,
			.val        = 'x',
			.descrip    = "Perform a trial run for the specified operation. "
				      "No on-disk changes will be made. Implies verbose. "
		},
		{
			.longName   = "skip",
			.shortName  = 's',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &state.skip,
			.val        = 's',
			.descrip    = "skip files that are already converted",
		},
		{
			.longName   = "force",
			.shortName  = 'f',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &state.force,
			.val        = 'f',
			.descrip    = "overwrite existing xattrs when moving prefixes",
		},
		{
			.longName   = "do-chdir",
			.shortName  = 'c',
			.argInfo    = POPT_ARG_NONE,
			.arg        = &state.do_chdir,
			.val        = 'c',
			.descrip    = "Allow changing of directory during traversal.",
		},
		{
			.longName   = "suffix-op",
			.shortName  = 'z',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &state.suffix_op,
			.val        = 'z',
			.descrip    = "Controls behavior regarding \":$DATA\" suffix "
				      "during \"mv\" action. Options are: "
				      "\"append\", \"remove\", \"ignore\". There is "
				      "no default.",
		},
		POPT_TABLEEND
	};
	TALLOC_CTX *frame = talloc_stackframe();
	const char *s = NULL;
	int ret = 0;

	if (getuid() != 0) {
		d_printf("%s only works as root!\n", argv[0]);
		ret = 1;
		goto done;
	}

	state.mem_ctx = frame;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptSetOtherOptionHelp(pc,
		"-a ACTION PATH [PATH ...] \n\n"
		"\tSupported actions: \"add\", \"rem\", \"mv\"\n"
		"\t\tadd: add single zero byte to xattr data\n"
		"\t\trem: remove last byte from xattr data\n"
		"\t\tmv: change prefix for xattrs from \"stream-prefix\" "
		"to \"new-prefix\". New prefix must begin with \"user.\"\n"
	);

	while ((c = poptGetNextOpt(pc)) != -1) {
		switch (c) {
		case 't':
			state.verbose = true;
			break;
		case 'z':
			s = poptGetOptArg(pc);
			state.suffix_op = talloc_strdup(frame, s);
			break;
		case 'n':
			s = poptGetOptArg(pc);
			state.new_prefix = talloc_strdup(frame, s);
			break;
		case 'e':
			s = poptGetOptArg(pc);
			enc.config = talloc_strdup(frame, s);
			break;
		case 'p':
			s = poptGetOptArg(pc);
			state.stream_prefix = talloc_strdup(frame, s);
			break;
		case 'a':
			s = poptGetOptArg(pc);
			state.action = talloc_strdup(frame, s);
			break;
		}
	}

	if (state.stream_prefix == NULL) {
		state.stream_prefix = talloc_strdup(frame, SAMBA_XATTR_DOSSTREAM_PREFIX);
		if (state.stream_prefix == NULL) {
			ret = -1;
			goto done;
		}
	}

	ret = load_action();
	if (ret != 0) {
		poptPrintUsage(pc, stderr, 0);
		ret = 1;
		goto done;
	}

	if (poptPeekArg(pc) == NULL) {
		poptPrintUsage(pc, stderr, 0);
		ret = 1;
		goto done;
	}

	paths = talloc_zero_array(frame, char *, 1);
	if (paths == NULL) {
		d_fprintf(stderr, "memory error\n");
		ret = 1;
		goto done;
	}

	while ((path = poptGetArg(pc)) != NULL) {
		paths[i] = talloc_strdup(frame, path);
		i++;
		paths = talloc_realloc(frame, paths, char *, i + 1);
		paths[i] = NULL;
	}

#ifdef HAVE_JANSSON
	ret = dump_params_json(paths);
	if (ret != 0) {
		d_printf("Failed to print JSON parameters\n");
	}
#endif
	ret = do_fts_walk(paths);

done:
	poptFreeContext(pc);

	TALLOC_FREE(frame);
	return ret;
}

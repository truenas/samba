/*
   Unix SMB/CIFS implementation.

   TrueNAS SMB auditing (vfs_truenas_audit) torture tests.

   Each test performs SMB2 operations and checks the records the module wrote
   for them. smbtorture must run on the server: the share needs
   "truenas_audit:backend = debug", the truenas_audit debug class a log file of
   its own ("log level = 1 truenas_audit:1@<path>"), and the path is passed
   with --option=torture:audit_log=<path>; without it the tests are skipped.
   Records are attributed by the session and tree ids in their svc_data.

   The filter tests also need --option=torture:audit_ignored_share=<share>
   (ignore_list matches the user) and --option=torture:audit_watched_share=
   <share> (watch_list and ignore_list both match).

   Copyright (C) iXsystems 2026

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
#include "lib/cmdline/cmdline.h"
#include "auth/credentials/credentials.h"

#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/smb/smbXcli_base.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_ioctl.h"

#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smbtorture.h"
#include "torture/smb2/proto.h"
#include "torture/smb2/oplock_break_handler.h"
#include "torture/truenas/proto.h"

#ifdef HAVE_JANSSON
#include <jansson.h>

struct tn_audit_ids {
	uint64_t session_id;
	uint32_t tcon_id;
};

struct tn_audit_rec {
	char *event;
	char *user;
	char *service;
	bool success;
	json_t *data;		/* the parsed event_data */
};

struct tn_audit_recs {
	size_t num;
	struct tn_audit_rec *rec;
};

/* Matches any stream, as opposed to NULL for the base file */
#define TN_AUDIT_ANY_STREAM ((const char *)-1)

static const char *tn_audit_log_path(struct torture_context *tctx)
{
	return torture_setting_string(tctx, "audit_log", NULL);
}

#define TN_AUDIT_REQUIRE_LOG(tctx) do { \
	if (tn_audit_log_path(tctx) == NULL) { \
		torture_skip(tctx, "requires an audited share and " \
			     "--option=torture:audit_log=<path>"); \
	} \
} while (0)

static struct tn_audit_ids tn_audit_ids(struct smb2_tree *tree)
{
	return (struct tn_audit_ids) {
		.session_id = smb2cli_session_current_id(
			tree->session->smbXcli),
		.tcon_id = smb2cli_tcon_current_id(tree->smbXcli),
	};
}

static off_t tn_audit_mark(struct torture_context *tctx)
{
	struct stat st;

	if (stat(tn_audit_log_path(tctx), &st) != 0) {
		return 0;
	}
	return st.st_size;
}

static const char *tn_audit_path(TALLOC_CTX *mem_ctx, const char *smb_name)
{
	char *path = talloc_strdup(mem_ctx, smb_name);

	if (path != NULL) {
		string_replace(path, '\\', '/');
	}
	return path;
}

static int tn_audit_recs_destructor(struct tn_audit_recs *recs)
{
	size_t i;

	for (i = 0; i < recs->num; i++) {
		json_decref(recs->rec[i].data);
	}
	return 0;
}

/* svc_data and event_data are JSON documents stored as strings */
static json_t *tn_audit_load_member(json_t *root, const char *key)
{
	const char *s = json_string_value(json_object_get(root, key));
	json_error_t err;

	if (s == NULL) {
		return NULL;
	}
	return json_loads(s, 0, &err);
}

static bool tn_audit_member_is(json_t *obj, const char *key, const char *value)
{
	const char *s = json_string_value(json_object_get(obj, key));

	return (s != NULL) && (strcmp(s, value) == 0);
}

/* False if malformed; rec->data is NULL for another session or tree */
static bool tn_audit_parse_rec(TALLOC_CTX *mem_ctx,
			       const char *line,
			       struct tn_audit_ids ids,
			       struct tn_audit_rec *rec,
			       const char **why)
{
	static const char *keys[] = {
		"aid", "vers", "time", "addr", "user", "sess", "svc",
		"event", "success", "svc_data", "event_data",
	};
	char session_id[21], tcon_id[11];
	json_t *root = NULL, *svc = NULL, *data = NULL;
	json_error_t err;
	char *dump = NULL;
	bool ok = false;
	size_t i;

	*rec = (struct tn_audit_rec) { 0 };

	root = json_loads(line, 0, &err);
	if (!json_is_object(root)) {
		*why = "record is not a JSON object";
		goto done;
	}
	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		if (json_object_get(root, keys[i]) == NULL) {
			*why = talloc_asprintf(mem_ctx, "record lacks \"%s\"",
					       keys[i]);
			goto done;
		}
	}
	svc = tn_audit_load_member(root, "svc_data");
	data = tn_audit_load_member(root, "event_data");
	if (!json_is_object(svc) || !json_is_object(data)) {
		*why = "svc_data or event_data is not a JSON object";
		goto done;
	}

	dump = json_dumps(data, 0);
	if ((dump == NULL) || (strstr(dump, ".::TMPNAME:") != NULL)) {
		*why = "record names a temporary name of smbd";
		goto done;
	}

	ok = true;

	snprintf(session_id, sizeof(session_id), "%" PRIu64, ids.session_id);
	snprintf(tcon_id, sizeof(tcon_id), "%" PRIu32, ids.tcon_id);
	if (!tn_audit_member_is(svc, "session_id", session_id) ||
	    !tn_audit_member_is(svc, "tcon_id", tcon_id)) {
		goto done;
	}

	rec->event = talloc_strdup(mem_ctx,
		json_string_value(json_object_get(root, "event")));
	rec->user = talloc_strdup(mem_ctx,
		json_string_value(json_object_get(root, "user")));
	rec->service = talloc_strdup(mem_ctx,
		json_string_value(json_object_get(svc, "service")));
	rec->success = json_is_true(json_object_get(root, "success"));
	rec->data = data;
	data = NULL;
done:
	free(dump);
	json_decref(data);
	json_decref(svc);
	json_decref(root);
	return ok;
}

/* Records since @start for @ids; all records since must be well-formed */
static bool tn_audit_collect(struct torture_context *tctx,
			     off_t start,
			     struct tn_audit_ids ids,
			     struct tn_audit_recs **precs)
{
	const char *path = tn_audit_log_path(tctx);
	struct tn_audit_recs *recs = NULL;
	char *buf = NULL, *line = NULL, *saveptr = NULL;
	struct stat st;
	size_t len, got = 0;
	int fd;

	recs = talloc_zero(tctx, struct tn_audit_recs);
	torture_assert(tctx, recs != NULL, "talloc");
	talloc_set_destructor(recs, tn_audit_recs_destructor);
	*precs = recs;

	fd = open(path, O_RDONLY);
	torture_assert(tctx, fd != -1,
		       talloc_asprintf(tctx, "open %s: %s", path,
				       strerror(errno)));
	if (fstat(fd, &st) != 0) {
		close(fd);
		torture_fail(tctx, "fstat of the audit log failed");
	}
	if (st.st_size < start) {
		close(fd);
		torture_fail(tctx, "the audit log shrank, was it rotated? "
			     "(set \"max log size = 0\")");
	}
	len = st.st_size - start;

	buf = talloc_array(recs, char, len + 1);
	if (buf == NULL) {
		close(fd);
		torture_fail(tctx, "talloc");
	}
	while (got < len) {
		ssize_t n = pread(fd, buf + got, len - got, start + got);

		if (n <= 0) {
			break;
		}
		got += n;
	}
	close(fd);
	buf[got] = '\0';

	for (line = strtok_r(buf, "\n", &saveptr);
	     line != NULL;
	     line = strtok_r(NULL, "\n", &saveptr)) {
		struct tn_audit_rec rec;
		const char *why = NULL;

		line += strspn(line, " \t");
		if (*line != '{') {
			continue;
		}
		torture_assert(tctx,
			       tn_audit_parse_rec(recs, line, ids, &rec, &why),
			       talloc_asprintf(tctx, "%s: %s", why, line));
		if (rec.data == NULL) {
			continue;
		}

		recs->rec = talloc_realloc(recs, recs->rec,
					   struct tn_audit_rec, recs->num + 1);
		if (recs->rec == NULL) {
			json_decref(rec.data);
			torture_fail(tctx, "talloc");
		}
		recs->rec[recs->num++] = rec;
	}

	return true;
}

static void tn_audit_dump(struct torture_context *tctx,
			  const struct tn_audit_recs *recs)
{
	size_t i;

	if (recs == NULL) {
		return;
	}
	torture_comment(tctx, "%zu audit records for the test's tree:\n",
			recs->num);
	for (i = 0; i < recs->num; i++) {
		char *data = json_dumps(recs->rec[i].data, JSON_SORT_KEYS);

		torture_comment(tctx, "  [%zu] %s %s %s\n", i,
				recs->rec[i].event,
				recs->rec[i].success ? "ok" : "FAIL",
				data != NULL ? data : "?");
		free(data);
	}
}

/* Stream names are logged with or without the ":$DATA" type */
static bool tn_audit_stream_is(const char *logged, const char *stream)
{
	size_t llen = strlen(logged), slen = strlen(stream);
	const size_t tlen = strlen(":$DATA");

	if ((llen > tlen) && strequal(logged + llen - tlen, ":$DATA")) {
		llen -= tlen;
	}
	if ((slen > tlen) && strequal(stream + slen - tlen, ":$DATA")) {
		slen -= tlen;
	}
	return (llen == slen) && (strncasecmp_m(logged, stream, llen) == 0);
}

/*
 * Whether event_data[key] names @path (any path if NULL) and @stream: NULL for
 * the base file, TN_AUDIT_ANY_STREAM for any stream.
 */
static bool tn_audit_names(const struct tn_audit_rec *rec,
			   const char *key,
			   const char *path,
			   const char *stream)
{
	json_t *f = json_object_get(rec->data, key);
	const char *s = NULL;

	if (!json_is_object(f)) {
		return false;
	}
	if (path != NULL) {
		const char *p = json_string_value(json_object_get(f, "path"));

		if ((p == NULL) || !strequal(p, path)) {
			return false;
		}
	}
	s = json_string_value(json_object_get(f, "stream"));
	if (stream == TN_AUDIT_ANY_STREAM) {
		return s != NULL;
	}
	if (stream == NULL) {
		return s == NULL;
	}
	return (s != NULL) && tn_audit_stream_is(s, stream);
}

/*
 * Index of the first record from @from on of @event (any if NULL) for the file
 * @path (any if NULL) and @stream (see tn_audit_names()), or -1.
 */
static ssize_t tn_audit_find(const struct tn_audit_recs *recs,
			     ssize_t from,
			     const char *event,
			     const char *path,
			     const char *stream)
{
	ssize_t i;

	for (i = MAX(from, 0); i < (ssize_t)recs->num; i++) {
		const struct tn_audit_rec *rec = &recs->rec[i];

		if ((event != NULL) && !strequal(rec->event, event)) {
			continue;
		}
		if (((path != NULL) || (stream != NULL)) &&
		    !tn_audit_names(rec, "file", path, stream)) {
			continue;
		}
		return i;
	}
	return -1;
}

static size_t tn_audit_count(const struct tn_audit_recs *recs,
			     const char *event,
			     const char *path,
			     const char *stream)
{
	size_t n = 0;
	ssize_t i = -1;

	while ((i = tn_audit_find(recs, i + 1, event, path, stream)) != -1) {
		n++;
	}
	return n;
}

/* event_data[k1][k2], or event_data[k1] if k2 is NULL, as a string */
static const char *tn_audit_str(const struct tn_audit_rec *rec,
				const char *k1,
				const char *k2)
{
	json_t *v = json_object_get(rec->data, k1);

	if (k2 != NULL) {
		v = json_object_get(v, k2);
	}
	return json_string_value(v);
}

static bool tn_audit_str_is(const struct tn_audit_rec *rec,
			    const char *k1,
			    const char *k2,
			    const char *value)
{
	const char *s = tn_audit_str(rec, k1, k2);

	return (s != NULL) && (strcmp(s, value) == 0);
}

/* A hex string of event_data[k1][k2] as a number, 0 if missing */
static uint32_t tn_audit_hex(const struct tn_audit_rec *rec,
			     const char *k1,
			     const char *k2)
{
	const char *s = tn_audit_str(rec, k1, k2);

	return (s != NULL) ? strtoul(s, NULL, 16) : 0;
}

static const char *tn_audit_handle(const struct tn_audit_rec *rec,
				   const char *key)
{
	return json_string_value(json_object_get(
		json_object_get(json_object_get(rec->data, key), "handle"),
		"value"));
}

static bool tn_audit_same_handle(const struct tn_audit_rec *a,
				 const struct tn_audit_rec *b)
{
	const char *ha = tn_audit_handle(a, "file");
	const char *hb = tn_audit_handle(b, "file");

	return (ha != NULL) && (hb != NULL) && (strcmp(ha, hb) == 0);
}

static bool tn_audit_ops_are(const struct tn_audit_rec *rec,
			     const char *read_cnt,
			     const char *read_bytes,
			     const char *write_cnt,
			     const char *write_bytes)
{
	return tn_audit_str_is(rec, "operations", "read_cnt", read_cnt) &&
	       tn_audit_str_is(rec, "operations", "read_bytes", read_bytes) &&
	       tn_audit_str_is(rec, "operations", "write_cnt", write_cnt) &&
	       tn_audit_str_is(rec, "operations", "write_bytes", write_bytes);
}

static ssize_t tn_audit_find_setattr(const struct tn_audit_recs *recs,
				     ssize_t from,
				     const char *attr_type)
{
	ssize_t i = from - 1;

	while ((i = tn_audit_find(recs, i + 1, "SET_ATTR", NULL, NULL)) != -1) {
		if (tn_audit_str_is(&recs->rec[i], "attr_type", NULL,
				    attr_type)) {
			return i;
		}
	}
	return -1;
}

static size_t tn_audit_count_setattr(const struct tn_audit_recs *recs,
				     const char *attr_type)
{
	size_t n = 0;
	ssize_t i = -1;

	while ((i = tn_audit_find_setattr(recs, i + 1, attr_type)) != -1) {
		n++;
	}
	return n;
}

/* A fresh, empty directory for a test */
static bool tn_audit_setup(struct torture_context *tctx,
			   struct smb2_tree *tree,
			   const char *dname)
{
	struct smb2_handle h;
	NTSTATUS status;

	smb2_deltree(tree, dname);
	status = torture_smb2_testdir(tree, dname, &h);
	torture_assert_ntstatus_ok(tctx, status, "create test directory");
	smb2_util_close(tree, h);
	return true;
}

static NTSTATUS tn_audit_create(struct smb2_tree *tree,
				TALLOC_CTX *mem_ctx,
				const char *fname,
				uint32_t access,
				uint32_t disposition,
				uint32_t options,
				struct smb2_handle *h)
{
	struct smb2_create cr;
	NTSTATUS status;

	ZERO_STRUCT(cr);
	cr.in.desired_access = access;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.create_disposition = disposition;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	cr.in.create_options = options;
	cr.in.fname = fname;

	status = smb2_create(tree, mem_ctx, &cr);
	if (NT_STATUS_IS_OK(status)) {
		*h = cr.out.file.handle;
	}
	return status;
}

/* A file (or stream) holding @len zero bytes */
static bool tn_audit_make_file(struct torture_context *tctx,
			       struct smb2_tree *tree,
			       const char *fname,
			       size_t len)
{
	struct smb2_handle h;
	uint8_t *buf = NULL;
	NTSTATUS status;
	bool ret = true;

	status = tn_audit_create(tree, tctx, fname, SEC_RIGHTS_FILE_ALL,
				 NTCREATEX_DISP_OVERWRITE_IF, 0, &h);
	torture_assert_ntstatus_ok(tctx, status,
				   talloc_asprintf(tctx, "create %s", fname));
	if (len > 0) {
		buf = talloc_zero_array(tctx, uint8_t, len);
		torture_assert_goto(tctx, buf != NULL, ret, done, "talloc");
		status = smb2_util_write(tree, h, buf, 0, len);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
			talloc_asprintf(tctx, "write %s", fname));
	}
done:
	smb2_util_close(tree, h);
	return ret;
}

static void tn_audit_basic_info(union smb_setfileinfo *s,
				struct smb2_handle h,
				NTTIME create_time,
				NTTIME write_time,
				uint32_t attrib)
{
	ZERO_STRUCTP(s);
	s->basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION;
	s->basic_info.in.file.handle = h;
	s->basic_info.in.create_time = create_time;
	s->basic_info.in.write_time = write_time;
	s->basic_info.in.attrib = attrib;
}

static void tn_audit_rename_info(union smb_setfileinfo *s,
				 struct smb2_handle h,
				 const char *new_name)
{
	ZERO_STRUCTP(s);
	s->rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	s->rename_information.in.file.handle = h;
	s->rename_information.in.new_name = new_name;
}

/* Everyone:Full, inheritable: a DACL ixnas maps without loss */
static struct security_descriptor *tn_audit_world_sd(TALLOC_CTX *mem_ctx)
{
	return security_descriptor_dacl_create(mem_ctx, 0, NULL, NULL,
		dom_sid_string(mem_ctx, &global_sid_World),
		SEC_ACE_TYPE_ACCESS_ALLOWED, SEC_STD_ALL | SEC_FILE_ALL,
		SEC_ACE_FLAG_OBJECT_INHERIT | SEC_ACE_FLAG_CONTAINER_INHERIT,
		NULL);
}

#define TN_AUDIT_WORLD_SDDL ";;;WD)"

/* Tree connect and disconnect; DISCONNECT has the tree's counts */
static bool test_tn_audit_connect(struct torture_context *tctx,
				  struct smb2_tree *tree0)
{
	const char *fname = "tn_audit_connect.dat";
	const char *share = torture_setting_string(tctx, "share", NULL);
	const char *user = cli_credentials_get_username(
		samba_cmdline_get_creds());
	struct smb2_tree *tree = NULL;
	struct tn_audit_recs *recs = NULL;
	struct tn_audit_ids ids;
	struct smb2_handle h;
	struct smb2_read rd;
	uint8_t buf[100] = { 0 };
	ssize_t c, d;
	NTSTATUS status;
	off_t start;
	bool ret = true;
	size_t i;

	TN_AUDIT_REQUIRE_LOG(tctx);
	smb2_util_unlink(tree0, fname);

	start = tn_audit_mark(tctx);
	torture_assert(tctx, torture_smb2_connection(tctx, &tree), "connect");
	ids = tn_audit_ids(tree);

	/* one each of create, write, read and close; the file goes on close */
	status = tn_audit_create(tree, tctx, fname, SEC_RIGHTS_FILE_ALL,
				 NTCREATEX_DISP_CREATE,
				 NTCREATEX_OPTIONS_DELETE_ON_CLOSE, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create");
	status = smb2_util_write(tree, h, buf, 0, sizeof(buf));
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "write");
	ZERO_STRUCT(rd);
	rd.in.file.handle = h;
	rd.in.length = sizeof(buf);
	status = smb2_read(tree, tctx, &rd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "read");
	status = smb2_util_close(tree, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "close");
	status = smb2_tdis(tree);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "tdis");

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}

	torture_assert_goto(tctx, recs->num > 0, ret, done,
			    "no records for the tree");
	for (i = 0; i < recs->num; i++) {
		torture_assert_goto(tctx,
				    strequal(recs->rec[i].user, user) &&
				    strequal(recs->rec[i].service, share),
				    ret, done,
				    "record for another user or share");
	}

	c = tn_audit_find(recs, 0, "CONNECT", NULL, NULL);
	torture_assert_goto(tctx, c == 0, ret, done,
			    "the first record must be the CONNECT");
	torture_assert_goto(tctx, recs->rec[c].success, ret, done,
			    "CONNECT not successful");
	torture_assert_goto(tctx,
			    json_is_object(json_object_get(recs->rec[c].data,
							   "unix_token")),
			    ret, done, "CONNECT lacks the unix token");

	torture_assert_goto(tctx,
			    tn_audit_find(recs, 0, "UNLINK", fname, NULL) != -1,
			    ret, done, "no UNLINK for the delete on close");

	d = tn_audit_find(recs, 0, "DISCONNECT", NULL, NULL);
	torture_assert_goto(tctx, d == (ssize_t)recs->num - 1, ret, done,
			    "the last record must be the DISCONNECT");
	torture_assert_goto(tctx,
			    tn_audit_str_is(&recs->rec[d], "operations",
					    "create", "1") &&
			    tn_audit_str_is(&recs->rec[d], "operations",
					    "close", "1") &&
			    tn_audit_str_is(&recs->rec[d], "operations",
					    "read", "1") &&
			    tn_audit_str_is(&recs->rec[d], "operations",
					    "write", "1"),
			    ret, done,
			    "DISCONNECT must count one create, close, read and "
			    "write");

done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	TALLOC_FREE(tree);
	smb2_util_unlink(tree0, fname);
	return ret;
}

/* Only the first write within rw_log_interval is logged, CLOSE has totals */
static bool test_tn_audit_file_io(struct torture_context *tctx,
				  struct smb2_tree *tree)
{
	const char *dname = "tn_audit_io";
	const char *fname = "tn_audit_io\\file.dat";
	const char *path = tn_audit_path(tctx, fname);
	const uint32_t access = SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA |
				SEC_FILE_READ_ATTRIBUTE;
	struct tn_audit_ids ids = tn_audit_ids(tree);
	struct tn_audit_recs *recs = NULL;
	struct smb2_handle h;
	struct smb2_read rd;
	uint8_t buf[1000];
	ssize_t c, w, r, cl;
	NTSTATUS status;
	off_t start;
	bool ret = true;

	TN_AUDIT_REQUIRE_LOG(tctx);
	torture_assert(tctx, tn_audit_setup(tctx, tree, dname), "setup");
	memset(buf, 'a', sizeof(buf));

	start = tn_audit_mark(tctx);
	status = tn_audit_create(tree, tctx, fname, access,
				 NTCREATEX_DISP_CREATE, 0, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "create");
	status = smb2_util_write(tree, h, buf, 0, sizeof(buf));
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "write");
	status = smb2_util_write(tree, h, buf, sizeof(buf), sizeof(buf));
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "write 2");
	ZERO_STRUCT(rd);
	rd.in.file.handle = h;
	rd.in.length = sizeof(buf);
	status = smb2_read(tree, tctx, &rd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "read");
	status = smb2_util_close(tree, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "close");

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}

	c = tn_audit_find(recs, 0, "CREATE", path, NULL);
	torture_assert_goto(tctx, c != -1, ret, done, "no CREATE");
	torture_assert_goto(tctx, recs->rec[c].success, ret, done,
			    "CREATE not successful");
	torture_assert_goto(tctx,
			    tn_audit_str_is(&recs->rec[c], "result",
					    "value_parsed", "SUCCESS"),
			    ret, done, "CREATE result");
	torture_assert_goto(tctx,
			    tn_audit_hex(&recs->rec[c], "parameters",
					 "DesiredAccess") == access,
			    ret, done, "CREATE DesiredAccess");
	torture_assert_goto(tctx,
			    tn_audit_str_is(&recs->rec[c], "parameters",
					    "CreateDisposition", "CREATE"),
			    ret, done, "CREATE CreateDisposition");
	torture_assert_goto(tctx,
			    tn_audit_str_is(&recs->rec[c], "file_type", NULL,
					    "FILE"),
			    ret, done, "CREATE file_type");

	torture_assert_int_equal_goto(tctx,
				      tn_audit_count(recs, "WRITE", path, NULL),
				      1, ret, done,
				      "WRITE records (the second write is "
				      "within rw_log_interval)");
	torture_assert_int_equal_goto(tctx,
				      tn_audit_count(recs, "READ", path, NULL),
				      1, ret, done, "READ records");
	w = tn_audit_find(recs, c, "WRITE", path, NULL);
	r = tn_audit_find(recs, c, "READ", path, NULL);
	cl = tn_audit_find(recs, c, "CLOSE", path, NULL);
	torture_assert_goto(tctx,
			    (w != -1) && (r != -1) && (cl > w) && (cl > r),
			    ret, done,
			    "expected CREATE, then WRITE and READ, then CLOSE");
	torture_assert_goto(tctx,
			    tn_audit_ops_are(&recs->rec[cl], "1", "1000",
					     "2", "2000"),
			    ret, done, "CLOSE totals of the handle");
	torture_assert_goto(tctx,
			    tn_audit_same_handle(&recs->rec[c], &recs->rec[cl]),
			    ret, done, "CREATE and CLOSE handles differ");

done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	smb2_deltree(tree, dname);
	return ret;
}

/* Failed opens are recorded with their status */
static bool test_tn_audit_open_failures(struct torture_context *tctx,
					struct smb2_tree *tree)
{
	const char *dname = "tn_audit_fail";
	const char *missing = "tn_audit_fail\\missing.dat";
	const char *fname = "tn_audit_fail\\file.dat";
	struct tn_audit_ids ids = tn_audit_ids(tree);
	struct tn_audit_recs *recs = NULL;
	struct smb2_handle h;
	ssize_t c;
	NTSTATUS status;
	off_t start;
	bool ret = true;

	TN_AUDIT_REQUIRE_LOG(tctx);
	torture_assert(tctx, tn_audit_setup(tctx, tree, dname), "setup");
	torture_assert(tctx, tn_audit_make_file(tctx, tree, fname, 0),
		       "make file");

	start = tn_audit_mark(tctx);
	status = tn_audit_create(tree, tctx, missing, SEC_FILE_READ_DATA,
				 NTCREATEX_DISP_OPEN, 0, &h);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_OBJECT_NAME_NOT_FOUND,
					   ret, done, "open missing file");
	/* SEC_FLAG_SYSTEM_SECURITY requires SeSecurityPrivilege */
	status = tn_audit_create(tree, tctx, fname,
				 SEC_FLAG_SYSTEM_SECURITY | SEC_FILE_READ_DATA,
				 NTCREATEX_DISP_OPEN, 0, &h);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_PRIVILEGE_NOT_HELD,
					   ret, done, "open for the SACL");

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}

	c = tn_audit_find(recs, 0, "CREATE", tn_audit_path(tctx, missing),
			  NULL);
	torture_assert_goto(tctx, c != -1, ret, done,
			    "no CREATE for the missing file");
	torture_assert_goto(tctx,
			    !recs->rec[c].success &&
			    tn_audit_str_is(&recs->rec[c], "result",
					    "value_parsed",
					    "NT_STATUS_OBJECT_NAME_NOT_FOUND"),
			    ret, done, "result of opening the missing file");

	c = tn_audit_find(recs, 0, "CREATE", tn_audit_path(tctx, fname),
			  NULL);
	torture_assert_goto(tctx, c != -1, ret, done,
			    "no CREATE for the open for the SACL");
	torture_assert_goto(tctx,
			    !recs->rec[c].success &&
			    tn_audit_str_is(&recs->rec[c], "result",
					    "value_parsed",
					    "NT_STATUS_PRIVILEGE_NOT_HELD"),
			    ret, done, "result of opening for the SACL");

	torture_assert_int_equal_goto(tctx,
				      tn_audit_count(recs, "CLOSE", NULL, NULL),
				      0, ret, done,
				      "failed opens have nothing to close");

done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	smb2_deltree(tree, dname);
	return ret;
}

/* mkdir's rename from a temporary name is not logged */
static bool test_tn_audit_mkdir_rmdir(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	const char *dname = "tn_audit_mkdir";
	const char *sub = "tn_audit_mkdir\\sub";
	const char *path = tn_audit_path(tctx, sub);
	struct tn_audit_ids ids = tn_audit_ids(tree);
	struct tn_audit_recs *recs = NULL;
	struct smb2_handle h;
	ssize_t c, u, cl;
	NTSTATUS status;
	off_t start;
	bool ret = true;

	TN_AUDIT_REQUIRE_LOG(tctx);
	torture_assert(tctx, tn_audit_setup(tctx, tree, dname), "setup");

	start = tn_audit_mark(tctx);
	status = tn_audit_create(tree, tctx, sub, SEC_RIGHTS_DIR_ALL,
				 NTCREATEX_DISP_CREATE,
				 NTCREATEX_OPTIONS_DIRECTORY, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "mkdir");
	smb2_util_close(tree, h);
	status = smb2_util_rmdir(tree, sub);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "rmdir");

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}

	c = tn_audit_find(recs, 0, "CREATE", path, NULL);
	torture_assert_goto(tctx, c != -1, ret, done, "no CREATE for mkdir");
	torture_assert_goto(tctx,
			    recs->rec[c].success &&
			    tn_audit_str_is(&recs->rec[c], "file_type", NULL,
					    "DIRECTORY") &&
			    tn_audit_str_is(&recs->rec[c], "parameters",
					    "CreateDisposition", "CREATE"),
			    ret, done, "CREATE for mkdir");
	torture_assert_int_equal_goto(tctx,
				      tn_audit_count(recs, "RENAME", NULL,
						     NULL),
				      0, ret, done,
				      "mkdir must not be recorded as a rename");

	u = tn_audit_find(recs, c, "UNLINK", path, NULL);
	torture_assert_goto(tctx, u != -1, ret, done, "no UNLINK for rmdir");
	torture_assert_goto(tctx,
			    recs->rec[u].success &&
			    tn_audit_str_is(&recs->rec[u], "file", "type",
					    "DIRECTORY"),
			    ret, done, "UNLINK for rmdir");
	cl = tn_audit_find(recs, u, "CLOSE", path, NULL);
	torture_assert_goto(tctx, cl != -1, ret, done,
			    "no CLOSE after the rmdir");

done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	smb2_deltree(tree, dname);
	return ret;
}

/* The stream opens smbd makes for an open with DELETE are not logged */
static bool test_tn_audit_delete_streams(struct torture_context *tctx,
					 struct smb2_tree *tree)
{
	const char *dname = "tn_audit_ads";
	const char *fname = "tn_audit_ads\\file.dat";
	const char *path = tn_audit_path(tctx, fname);
	struct tn_audit_ids ids = tn_audit_ids(tree);
	struct tn_audit_recs *recs = NULL;
	ssize_t c, u;
	NTSTATUS status;
	off_t start;
	bool ret = true;

	TN_AUDIT_REQUIRE_LOG(tctx);
	torture_assert(tctx, tn_audit_setup(tctx, tree, dname), "setup");
	torture_assert(tctx,
		       tn_audit_make_file(tctx, tree, fname, 10) &&
		       tn_audit_make_file(tctx, tree,
					  "tn_audit_ads\\file.dat:s1", 10) &&
		       tn_audit_make_file(tctx, tree,
					  "tn_audit_ads\\file.dat:s2", 10),
		       "make file with streams");

	start = tn_audit_mark(tctx);
	status = smb2_util_unlink(tree, fname);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "unlink");

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}

	c = tn_audit_find(recs, 0, "CREATE", path, NULL);
	torture_assert_goto(tctx, c != -1, ret, done, "no CREATE");
	torture_assert_goto(tctx,
			    recs->rec[c].success &&
			    (tn_audit_hex(&recs->rec[c], "parameters",
					  "DesiredAccess") & SEC_STD_DELETE),
			    ret, done, "CREATE with DELETE access");
	u = tn_audit_find(recs, c, "UNLINK", path, NULL);
	torture_assert_goto(tctx, u != -1, ret, done, "no UNLINK");
	torture_assert_goto(tctx,
			    recs->rec[u].success &&
			    tn_audit_str_is(&recs->rec[u], "file", "type",
					    "REGULAR"),
			    ret, done, "UNLINK");
	torture_assert_int_equal_goto(tctx,
				      tn_audit_count(recs, NULL, NULL,
						     TN_AUDIT_ANY_STREAM),
				      0, ret, done,
				      "the streams smbd opens for the delete "
				      "must not be recorded");

done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	smb2_deltree(tree, dname);
	return ret;
}

/* smbd setting an already set archive bit after a rename is not logged */
static bool test_tn_audit_rename(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	const char *dname = "tn_audit_rename";
	const char *src = "tn_audit_rename\\src.dat";
	const char *dst = "tn_audit_rename\\dst.dat";
	struct tn_audit_ids ids = tn_audit_ids(tree);
	struct tn_audit_recs *recs = NULL;
	union smb_setfileinfo s;
	struct smb2_handle h;
	ssize_t rn;
	NTSTATUS status;
	off_t start;
	bool ret = true;

	TN_AUDIT_REQUIRE_LOG(tctx);
	torture_assert(tctx, tn_audit_setup(tctx, tree, dname), "setup");
	torture_assert(tctx, tn_audit_make_file(tctx, tree, src, 10),
		       "make file");

	start = tn_audit_mark(tctx);
	status = torture_smb2_open(tree, src, SEC_STD_DELETE, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "open");
	tn_audit_rename_info(&s, h, dst);
	status = smb2_setinfo_file(tree, &s);
	smb2_util_close(tree, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "rename");

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}

	rn = tn_audit_find(recs, 0, "RENAME", NULL, NULL);
	torture_assert_goto(tctx, rn != -1, ret, done, "no RENAME");
	torture_assert_goto(tctx,
			    recs->rec[rn].success &&
			    tn_audit_names(&recs->rec[rn], "src_file",
					   tn_audit_path(tctx, src), NULL) &&
			    tn_audit_names(&recs->rec[rn], "dst_file",
					   tn_audit_path(tctx, dst), NULL) &&
			    tn_audit_str_is(&recs->rec[rn], "src_file", "type",
					    "REGULAR"),
			    ret, done, "RENAME source and destination");
	torture_assert_int_equal_goto(tctx,
				      tn_audit_count(recs, "SET_ATTR", NULL,
						     NULL),
				      0, ret, done,
				      "the archive bit smbd sets after the "
				      "rename must not be recorded");

done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	smb2_deltree(tree, dname);
	return ret;
}

/* Setting attributes only: a DOSMODE record, no TIMESTAMP record */
static bool test_tn_audit_set_attributes(struct torture_context *tctx,
					 struct smb2_tree *tree)
{
	const char *dname = "tn_audit_attr";
	const char *fname = "tn_audit_attr\\file.dat";
	struct tn_audit_ids ids = tn_audit_ids(tree);
	struct tn_audit_recs *recs = NULL;
	union smb_setfileinfo s;
	struct smb2_handle h;
	ssize_t d;
	NTSTATUS status;
	off_t start;
	bool ret = true;

	TN_AUDIT_REQUIRE_LOG(tctx);
	torture_assert(tctx, tn_audit_setup(tctx, tree, dname), "setup");
	torture_assert(tctx, tn_audit_make_file(tctx, tree, fname, 0),
		       "make file");

	start = tn_audit_mark(tctx);
	status = torture_smb2_open(tree, fname,
				   SEC_FILE_READ_ATTRIBUTE |
				   SEC_FILE_WRITE_ATTRIBUTE, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "open");
	tn_audit_basic_info(&s, h, 0, 0, FILE_ATTRIBUTE_HIDDEN);
	status = smb2_setinfo_file(tree, &s);
	smb2_util_close(tree, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"set attributes");

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}

	d = tn_audit_find_setattr(recs, 0, "DOSMODE");
	torture_assert_goto(tctx, d != -1, ret, done, "no DOSMODE record");
	torture_assert_goto(tctx,
			    recs->rec[d].success &&
			    tn_audit_names(&recs->rec[d], "file",
					   tn_audit_path(tctx, fname), NULL) &&
			    (tn_audit_hex(&recs->rec[d], "dosmode", NULL) &
			     FILE_ATTRIBUTE_HIDDEN),
			    ret, done, "DOSMODE record");
	torture_assert_int_equal_goto(tctx,
				      tn_audit_count_setattr(recs, "TIMESTAMP"),
				      0, ret, done,
				      "setting attributes only must not "
				      "record a timestamp change");

done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	smb2_deltree(tree, dname);
	return ret;
}

/* Setting timestamps only: a TIMESTAMP record, no DOSMODE record */
static bool test_tn_audit_set_times(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	const char *dname = "tn_audit_times";
	const char *fname = "tn_audit_times\\file.dat";
	struct tn_audit_ids ids = tn_audit_ids(tree);
	struct tn_audit_recs *recs = NULL;
	union smb_setfileinfo s;
	struct smb2_handle h;
	NTTIME btime, mtime;
	json_t *ts = NULL;
	ssize_t t;
	NTSTATUS status;
	off_t start;
	bool ret = true;

	TN_AUDIT_REQUIRE_LOG(tctx);
	torture_assert(tctx, tn_audit_setup(tctx, tree, dname), "setup");
	torture_assert(tctx, tn_audit_make_file(tctx, tree, fname, 0),
		       "make file");
	unix_to_nt_time(&btime, 1577934245);	/* 2020-01-02 */
	unix_to_nt_time(&mtime, 1609470245);	/* 2021-01-01 */

	start = tn_audit_mark(tctx);
	status = torture_smb2_open(tree, fname,
				   SEC_FILE_READ_ATTRIBUTE |
				   SEC_FILE_WRITE_ATTRIBUTE, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "open");
	tn_audit_basic_info(&s, h, btime, mtime, 0);
	status = smb2_setinfo_file(tree, &s);
	smb2_util_close(tree, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "set times");

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}

	t = tn_audit_find_setattr(recs, 0, "TIMESTAMP");
	torture_assert_goto(tctx, t != -1, ret, done, "no TIMESTAMP record");
	ts = json_object_get(recs->rec[t].data, "ts");
	torture_assert_goto(tctx,
			    recs->rec[t].success &&
			    tn_audit_names(&recs->rec[t], "file",
					   tn_audit_path(tctx, fname), NULL) &&
			    (json_object_get(ts, "btime") != NULL) &&
			    (json_object_get(ts, "mtime") != NULL),
			    ret, done, "TIMESTAMP record with btime and mtime");
	torture_assert_int_equal_goto(tctx,
				      tn_audit_count_setattr(recs, "DOSMODE"),
				      0, ret, done,
				      "setting the create time must not "
				      "record a DOS attribute change");

done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	smb2_deltree(tree, dname);
	return ret;
}

/* smbd restoring a client-set write time after writes is not logged */
static bool test_tn_audit_sticky_write_time(struct torture_context *tctx,
					    struct smb2_tree *tree)
{
	const char *dname = "tn_audit_sticky";
	const char *fname = "tn_audit_sticky\\file.dat";
	struct tn_audit_ids ids = tn_audit_ids(tree);
	struct tn_audit_recs *recs = NULL;
	union smb_setfileinfo s;
	struct smb2_handle h;
	NTTIME mtime;
	ssize_t t;
	NTSTATUS status;
	off_t start;
	bool ret = true;
	int i;

	TN_AUDIT_REQUIRE_LOG(tctx);
	torture_assert(tctx, tn_audit_setup(tctx, tree, dname), "setup");
	status = tn_audit_create(tree, tctx, fname, SEC_RIGHTS_FILE_ALL,
				 NTCREATEX_DISP_CREATE, 0, &h);
	torture_assert_ntstatus_ok(tctx, status, "create");
	unix_to_nt_time(&mtime, 1609470245);

	start = tn_audit_mark(tctx);
	tn_audit_basic_info(&s, h, 0, mtime, 0);
	status = smb2_setinfo_file(tree, &s);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"set write time");
	for (i = 0; i < 3; i++) {
		status = smb2_util_write(tree, h, "x", i, 1);
		torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
						"write");
	}
	status = smb2_util_close(tree, h);
	ZERO_STRUCT(h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "close");

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}

	torture_assert_int_equal_goto(tctx,
				      tn_audit_count_setattr(recs, "TIMESTAMP"),
				      1, ret, done,
				      "smbd restoring the write time after "
				      "each write must not be recorded");
	t = tn_audit_find_setattr(recs, 0, "TIMESTAMP");
	torture_assert_goto(tctx,
			    json_object_get(json_object_get(recs->rec[t].data,
							    "ts"),
					    "mtime") != NULL,
			    ret, done, "TIMESTAMP record with mtime");

done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	if (!smb2_util_handle_empty(h)) {
		smb2_util_close(tree, h);
	}
	smb2_deltree(tree, dname);
	return ret;
}

/* Setting a DACL: a SET_ACL record with the descriptor in SDDL */
static bool test_tn_audit_set_acl(struct torture_context *tctx,
				  struct smb2_tree *tree)
{
	const char *dname = "tn_audit_acl";
	const char *fname = "tn_audit_acl\\file.dat";
	struct tn_audit_ids ids = tn_audit_ids(tree);
	struct tn_audit_recs *recs = NULL;
	union smb_setfileinfo s;
	struct smb2_handle h;
	const char *sddl = NULL;
	ssize_t c, a;
	NTSTATUS status;
	off_t start;
	bool ret = true;

	TN_AUDIT_REQUIRE_LOG(tctx);
	torture_assert(tctx, tn_audit_setup(tctx, tree, dname), "setup");
	torture_assert(tctx, tn_audit_make_file(tctx, tree, fname, 0),
		       "make file");

	start = tn_audit_mark(tctx);
	/* No WRITE_OWNER: ixnas would deny the open, see truenas_acl.c */
	status = tn_audit_create(tree, tctx, fname,
				 SEC_STD_READ_CONTROL | SEC_STD_WRITE_DAC,
				 NTCREATEX_DISP_OPEN, 0, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "open");
	ZERO_STRUCT(s);
	s.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	s.set_secdesc.in.file.handle = h;
	s.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	s.set_secdesc.in.sd = tn_audit_world_sd(tctx);
	status = smb2_setinfo_file(tree, &s);
	smb2_util_close(tree, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "set DACL");

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}

	c = tn_audit_find(recs, 0, "CREATE", tn_audit_path(tctx, fname),
			  NULL);
	torture_assert_goto(tctx, c != -1, ret, done, "no CREATE");
	a = tn_audit_find(recs, c, "SET_ACL", NULL, NULL);
	torture_assert_goto(tctx, a != -1, ret, done, "no SET_ACL");
	sddl = tn_audit_str(&recs->rec[a], "sd", NULL);
	torture_assert_goto(tctx,
			    recs->rec[a].success &&
			    tn_audit_same_handle(&recs->rec[a],
						 &recs->rec[c]) &&
			    (tn_audit_hex(&recs->rec[a], "secinfo", NULL) ==
			     SECINFO_DACL) &&
			    (sddl != NULL) &&
			    (strstr(sddl, TN_AUDIT_WORLD_SDDL) != NULL),
			    ret, done, "SET_ACL record");

done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	smb2_deltree(tree, dname);
	return ret;
}

static NTSTATUS tn_audit_create_sd(struct smb2_tree *tree,
				   TALLOC_CTX *mem_ctx,
				   const char *fname,
				   uint32_t disposition,
				   uint32_t options,
				   struct smb2_handle *h)
{
	struct smb2_create cr;
	NTSTATUS status;

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA |
			       SEC_STD_READ_CONTROL;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.create_disposition = disposition;
	cr.in.create_options = options;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	cr.in.fname = fname;
	cr.in.sec_desc = tn_audit_world_sd(mem_ctx);

	status = smb2_create(tree, mem_ctx, &cr);
	if (NT_STATUS_IS_OK(status)) {
		*h = cr.out.file.handle;
	}
	return status;
}

static bool tn_audit_has_world_sd(const struct tn_audit_rec *rec)
{
	const char *sddl = tn_audit_str(rec, "sd", NULL);

	return (sddl != NULL) && (strstr(sddl, TN_AUDIT_WORLD_SDDL) != NULL);
}

/* Whether rec[c + 1] is the SET_ACL of the SD sent with the CREATE rec[c] */
static bool tn_audit_is_create_acl(const struct tn_audit_recs *recs,
				   ssize_t c)
{
	const struct tn_audit_rec *rec = NULL;
	const char *path = NULL, *name = NULL;

	if ((c < 0) || ((size_t)c + 1 >= recs->num)) {
		return false;
	}
	rec = &recs->rec[c + 1];
	path = tn_audit_str(&recs->rec[c], "file", "path");
	name = tn_audit_str(rec, "file", "name");

	return strequal(rec->event, "SET_ACL") && rec->success &&
	       (path != NULL) && (name != NULL) && strequal(path, name) &&
	       (tn_audit_str(rec, "file", "type") != NULL) &&
	       (tn_audit_hex(rec, "secinfo", NULL) & SECINFO_DACL) &&
	       tn_audit_has_world_sd(rec);
}

/* An SD smbd applies from a CREATE is logged as SET_ACL right after it */
static bool test_tn_audit_create_with_sd(struct torture_context *tctx,
					 struct smb2_tree *tree)
{
	const char *dname = "tn_audit_sd";
	const char *fname = "tn_audit_sd\\file.dat";
	const char *sub = "tn_audit_sd\\dir";
	const char *fpath = tn_audit_path(tctx, fname);
	struct tn_audit_ids ids = tn_audit_ids(tree);
	struct tn_audit_recs *recs = NULL;
	struct smb2_handle h;
	ssize_t c1, c2, cd;
	NTSTATUS status;
	off_t start;
	bool ret = true;

	TN_AUDIT_REQUIRE_LOG(tctx);
	torture_assert(tctx, tn_audit_setup(tctx, tree, dname), "setup");

	start = tn_audit_mark(tctx);
	status = tn_audit_create_sd(tree, tctx, fname, NTCREATEX_DISP_CREATE,
				    0, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create file with SD");
	smb2_util_close(tree, h);
	status = tn_audit_create_sd(tree, tctx, fname, NTCREATEX_DISP_OPEN_IF,
				    0, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open the existing file with SD");
	smb2_util_close(tree, h);
	status = tn_audit_create_sd(tree, tctx, sub, NTCREATEX_DISP_CREATE,
				    NTCREATEX_OPTIONS_DIRECTORY, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create directory with SD");
	smb2_util_close(tree, h);

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}

	c1 = tn_audit_find(recs, 0, "CREATE", fpath, NULL);
	c2 = tn_audit_find(recs, c1 + 1, "CREATE", fpath, NULL);
	cd = tn_audit_find(recs, 0, "CREATE", tn_audit_path(tctx, sub), NULL);
	torture_assert_goto(tctx, (c1 != -1) && (c2 != -1) && (cd != -1),
			    ret, done, "CREATE records");
	torture_assert_goto(tctx,
			    recs->rec[c1].success && recs->rec[c2].success &&
			    recs->rec[cd].success &&
			    tn_audit_has_world_sd(&recs->rec[c1]) &&
			    tn_audit_has_world_sd(&recs->rec[c2]) &&
			    tn_audit_has_world_sd(&recs->rec[cd]),
			    ret, done, "CREATE records with the SD");

	torture_assert_goto(tctx, tn_audit_is_create_acl(recs, c1), ret, done,
			    "SET_ACL right after the CREATE of the file");
	torture_assert_goto(tctx, tn_audit_is_create_acl(recs, cd), ret, done,
			    "SET_ACL right after the CREATE of the directory");
	torture_assert_int_equal_goto(tctx,
		tn_audit_count(recs, "SET_ACL", NULL, NULL), 2, ret, done,
		"opening the existing file must not record a SET_ACL");

done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	smb2_deltree(tree, dname);
	return ret;
}

/* FSCTL_SET_SPARSE is an FSCTL record, without a SET_ATTR */
static bool test_tn_audit_fsctl_sparse(struct torture_context *tctx,
				       struct smb2_tree *tree)
{
	const char *dname = "tn_audit_fsctl";
	const char *fname = "tn_audit_fsctl\\file.dat";
	struct tn_audit_ids ids = tn_audit_ids(tree);
	struct tn_audit_recs *recs = NULL;
	union smb_ioctl io;
	struct smb2_handle h;
	uint8_t set_sparse = 0xff;
	ssize_t f;
	NTSTATUS status;
	off_t start;
	bool ret = true;

	TN_AUDIT_REQUIRE_LOG(tctx);
	torture_assert(tctx, tn_audit_setup(tctx, tree, dname), "setup");
	status = tn_audit_create(tree, tctx, fname, SEC_RIGHTS_FILE_ALL,
				 NTCREATEX_DISP_CREATE, 0, &h);
	torture_assert_ntstatus_ok(tctx, status, "create");

	start = tn_audit_mark(tctx);
	ZERO_STRUCT(io);
	io.smb2.level = RAW_IOCTL_SMB2;
	io.smb2.in.file.handle = h;
	io.smb2.in.function = FSCTL_SET_SPARSE;
	io.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;
	io.smb2.in.out.data = &set_sparse;
	io.smb2.in.out.length = sizeof(set_sparse);
	status = smb2_ioctl(tree, tctx, &io.smb2);
	smb2_util_close(tree, h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"FSCTL_SET_SPARSE");

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}

	f = tn_audit_find(recs, 0, "FSCTL", tn_audit_path(tctx, fname), NULL);
	torture_assert_goto(tctx, f != -1, ret, done, "no FSCTL record");
	torture_assert_goto(tctx,
			    recs->rec[f].success &&
			    tn_audit_str_is(&recs->rec[f], "function",
					    "parsed", "SPARSE"),
			    ret, done, "FSCTL record");
	torture_assert_int_equal_goto(tctx,
				      tn_audit_count(recs, "SET_ATTR", NULL,
						     NULL),
				      0, ret, done,
				      "the sparse attribute set by the FSCTL "
				      "must not be recorded separately");

done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	smb2_deltree(tree, dname);
	return ret;
}

/* Server side copy: OFFLOAD_READ of the source, OFFLOAD_WRITE of the target */
static bool test_tn_audit_copychunk(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	const char *dname = "tn_audit_copy";
	const char *src = "tn_audit_copy\\src.dat";
	const char *dst = "tn_audit_copy\\dst.dat";
	struct tn_audit_ids ids = tn_audit_ids(tree);
	struct tn_audit_recs *recs = NULL;
	struct smb2_handle hs = {{0}}, hd = {{0}};
	struct req_resume_key_rsp key;
	struct srv_copychunk_copy cc;
	struct srv_copychunk_rsp cc_rsp;
	enum ndr_err_code ndr_ret;
	union smb_ioctl io;
	ssize_t o;
	NTSTATUS status;
	off_t start;
	bool ret = true;

	TN_AUDIT_REQUIRE_LOG(tctx);
	torture_assert(tctx, tn_audit_setup(tctx, tree, dname), "setup");
	torture_assert(tctx,
		       tn_audit_make_file(tctx, tree, src, 4096) &&
		       tn_audit_make_file(tctx, tree, dst, 0),
		       "make files");
	status = torture_smb2_open(tree, src, SEC_FILE_READ_DATA |
				   SEC_FILE_READ_ATTRIBUTE, &hs);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "open src");
	status = torture_smb2_open(tree, dst, SEC_RIGHTS_FILE_ALL, &hd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "open dst");

	start = tn_audit_mark(tctx);
	ZERO_STRUCT(io);
	io.smb2.level = RAW_IOCTL_SMB2;
	io.smb2.in.file.handle = hs;
	io.smb2.in.function = FSCTL_SRV_REQUEST_RESUME_KEY;
	io.smb2.in.max_output_response = 32;
	io.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;
	status = smb2_ioctl(tree, tctx, &io.smb2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"FSCTL_SRV_REQUEST_RESUME_KEY");
	ndr_ret = ndr_pull_struct_blob(&io.smb2.out.out, tctx, &key,
			(ndr_pull_flags_fn_t)ndr_pull_req_resume_key_rsp);
	torture_assert_goto(tctx, ndr_ret == NDR_ERR_SUCCESS, ret, done,
			    "ndr_pull_req_resume_key_rsp");

	ZERO_STRUCT(cc);
	memcpy(cc.source_key, key.resume_key, ARRAY_SIZE(cc.source_key));
	cc.chunk_count = 1;
	cc.chunks = talloc_zero_array(tctx, struct srv_copychunk, 1);
	torture_assert_goto(tctx, cc.chunks != NULL, ret, done, "talloc");
	cc.chunks[0].length = 4096;

	ZERO_STRUCT(io);
	io.smb2.level = RAW_IOCTL_SMB2;
	io.smb2.in.file.handle = hd;
	io.smb2.in.function = FSCTL_SRV_COPYCHUNK;
	io.smb2.in.max_output_response = sizeof(struct srv_copychunk_rsp);
	io.smb2.in.flags = SMB2_IOCTL_FLAG_IS_FSCTL;
	ndr_ret = ndr_push_struct_blob(&io.smb2.in.out, tctx, &cc,
			(ndr_push_flags_fn_t)ndr_push_srv_copychunk_copy);
	torture_assert_goto(tctx, ndr_ret == NDR_ERR_SUCCESS, ret, done,
			    "ndr_push_srv_copychunk_copy");
	status = smb2_ioctl(tree, tctx, &io.smb2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"FSCTL_SRV_COPYCHUNK");
	ndr_ret = ndr_pull_struct_blob(&io.smb2.out.out, tctx, &cc_rsp,
			(ndr_pull_flags_fn_t)ndr_pull_srv_copychunk_rsp);
	torture_assert_goto(tctx, ndr_ret == NDR_ERR_SUCCESS, ret, done,
			    "ndr_pull_srv_copychunk_rsp");
	torture_assert_int_equal_goto(tctx, cc_rsp.total_bytes_written, 4096,
				      ret, done, "bytes copied");

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}

	o = tn_audit_find(recs, 0, "OFFLOAD_READ", tn_audit_path(tctx, src),
			  NULL);
	torture_assert_goto(tctx, (o != -1) && recs->rec[o].success,
			    ret, done, "OFFLOAD_READ of the source");
	o = tn_audit_find(recs, 0, "OFFLOAD_WRITE", tn_audit_path(tctx, dst),
			  NULL);
	torture_assert_goto(tctx, (o != -1) && recs->rec[o].success,
			    ret, done, "OFFLOAD_WRITE of the target");

done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	if (!smb2_util_handle_empty(hs)) {
		smb2_util_close(tree, hs);
	}
	if (!smb2_util_handle_empty(hd)) {
		smb2_util_close(tree, hd);
	}
	smb2_deltree(tree, dname);
	return ret;
}

/* I/O on a stream counts once */
static bool test_tn_audit_stream_io(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	const char *dname = "tn_audit_sio";
	const char *fname = "tn_audit_sio\\file.dat";
	const char *sname = "tn_audit_sio\\file.dat:data";
	const char *path = tn_audit_path(tctx, fname);
	struct tn_audit_ids ids = tn_audit_ids(tree);
	struct tn_audit_recs *recs = NULL;
	struct smb2_handle h;
	struct smb2_read rd;
	uint8_t buf[2048];
	ssize_t c, cl;
	NTSTATUS status;
	off_t start;
	bool ret = true;

	TN_AUDIT_REQUIRE_LOG(tctx);
	torture_assert(tctx, tn_audit_setup(tctx, tree, dname), "setup");
	torture_assert(tctx, tn_audit_make_file(tctx, tree, fname, 0),
		       "make file");
	memset(buf, 'b', sizeof(buf));

	start = tn_audit_mark(tctx);
	status = tn_audit_create(tree, tctx, sname, SEC_RIGHTS_FILE_ALL,
				 NTCREATEX_DISP_CREATE, 0, &h);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"create stream");
	status = smb2_util_write(tree, h, buf, 0, sizeof(buf));
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "write");
	ZERO_STRUCT(rd);
	rd.in.file.handle = h;
	rd.in.length = sizeof(buf);
	status = smb2_read(tree, tctx, &rd);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "read");
	smb2_util_close(tree, h);

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}

	c = tn_audit_find(recs, 0, "CREATE", path, ":data:$DATA");
	torture_assert_goto(tctx, (c != -1) && recs->rec[c].success,
			    ret, done, "CREATE of the stream");
	cl = tn_audit_find(recs, c, "CLOSE", path, ":data:$DATA");
	torture_assert_goto(tctx, cl != -1, ret, done, "no CLOSE");
	torture_assert_goto(tctx,
			    tn_audit_ops_are(&recs->rec[cl], "1", "2048",
					     "1", "2048"),
			    ret, done, "CLOSE totals of the stream handle");

done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	smb2_deltree(tree, dname);
	return ret;
}

/* The handle placeholder for the operations following a related CREATE */
static const struct smb2_handle tn_audit_related = {
	.data = { UINT64_MAX, UINT64_MAX },
};

/* Compound CREATE, WRITE, CLOSE */
static bool test_tn_audit_compound_write(struct torture_context *tctx,
					 struct smb2_tree *tree)
{
	const char *dname = "tn_audit_cwrite";
	const char *fname = "tn_audit_cwrite\\file.dat";
	const char *path = tn_audit_path(tctx, fname);
	struct tn_audit_ids ids = tn_audit_ids(tree);
	struct tn_audit_recs *recs = NULL;
	struct smb2_request *req[3];
	struct smb2_create cr;
	struct smb2_write wr;
	struct smb2_close cl;
	ssize_t c, w, x;
	NTSTATUS status;
	off_t start;
	bool ret = true;

	TN_AUDIT_REQUIRE_LOG(tctx);
	torture_assert(tctx, tn_audit_setup(tctx, tree, dname), "setup");

	start = tn_audit_mark(tctx);
	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_RIGHTS_FILE_ALL;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	cr.in.create_disposition = NTCREATEX_DISP_CREATE;
	cr.in.fname = fname;

	smb2_transport_compound_start(tree->session->transport, 3);
	req[0] = smb2_create_send(tree, &cr);
	smb2_transport_compound_set_related(tree->session->transport, true);
	ZERO_STRUCT(wr);
	wr.in.file.handle = tn_audit_related;
	wr.in.data = data_blob_talloc_zero(tctx, 1024);
	req[1] = smb2_write_send(tree, &wr);
	ZERO_STRUCT(cl);
	cl.in.file.handle = tn_audit_related;
	req[2] = smb2_close_send(tree, &cl);

	status = smb2_create_recv(req[0], tree, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "CREATE");
	status = smb2_write_recv(req[1], &wr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "WRITE");
	status = smb2_close_recv(req[2], &cl);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "CLOSE");

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}

	c = tn_audit_find(recs, 0, "CREATE", path, NULL);
	w = tn_audit_find(recs, c, "WRITE", path, NULL);
	x = tn_audit_find(recs, w, "CLOSE", path, NULL);
	torture_assert_goto(tctx, (c != -1) && (w != -1) && (x != -1),
			    ret, done, "expected CREATE, WRITE, CLOSE");
	torture_assert_goto(tctx,
			    tn_audit_ops_are(&recs->rec[x], "0", "0",
					     "1", "1024"),
			    ret, done, "CLOSE totals");

done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	smb2_deltree(tree, dname);
	return ret;
}

/* Compound CREATE, SET_INFO (attributes), CLOSE */
static bool test_tn_audit_compound_setinfo(struct torture_context *tctx,
					   struct smb2_tree *tree)
{
	const char *dname = "tn_audit_cset";
	const char *fname = "tn_audit_cset\\file.dat";
	const char *path = tn_audit_path(tctx, fname);
	struct tn_audit_ids ids = tn_audit_ids(tree);
	struct tn_audit_recs *recs = NULL;
	struct smb2_request *req[3];
	union smb_setfileinfo s;
	struct smb2_create cr;
	struct smb2_close cl;
	ssize_t c, d, x;
	NTSTATUS status;
	off_t start;
	bool ret = true;

	TN_AUDIT_REQUIRE_LOG(tctx);
	torture_assert(tctx, tn_audit_setup(tctx, tree, dname), "setup");
	torture_assert(tctx, tn_audit_make_file(tctx, tree, fname, 0),
		       "make file");

	start = tn_audit_mark(tctx);
	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
			       SEC_FILE_WRITE_ATTRIBUTE;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN;
	cr.in.fname = fname;

	smb2_transport_compound_start(tree->session->transport, 3);
	req[0] = smb2_create_send(tree, &cr);
	smb2_transport_compound_set_related(tree->session->transport, true);
	tn_audit_basic_info(&s, tn_audit_related, 0, 0, FILE_ATTRIBUTE_HIDDEN);
	req[1] = smb2_setinfo_file_send(tree, &s);
	ZERO_STRUCT(cl);
	cl.in.file.handle = tn_audit_related;
	req[2] = smb2_close_send(tree, &cl);

	status = smb2_create_recv(req[0], tree, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "CREATE");
	status = smb2_setinfo_recv(req[1]);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "SET_INFO");
	status = smb2_close_recv(req[2], &cl);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "CLOSE");

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}

	c = tn_audit_find(recs, 0, "CREATE", path, NULL);
	d = tn_audit_find_setattr(recs, c, "DOSMODE");
	x = tn_audit_find(recs, d, "CLOSE", path, NULL);
	torture_assert_goto(tctx, (c != -1) && (d != -1) && (x != -1),
			    ret, done, "expected CREATE, SET_ATTR, CLOSE");
	torture_assert_goto(tctx,
			    tn_audit_hex(&recs->rec[d], "dosmode", NULL) &
			    FILE_ATTRIBUTE_HIDDEN,
			    ret, done, "DOSMODE record");
	torture_assert_int_equal_goto(tctx,
				      tn_audit_count_setattr(recs, "TIMESTAMP"),
				      0, ret, done,
				      "setting attributes only must not "
				      "record a timestamp change");

done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	smb2_deltree(tree, dname);
	return ret;
}

/* Compound CREATE, SET_INFO (rename), CLOSE */
static bool test_tn_audit_compound_rename(struct torture_context *tctx,
					  struct smb2_tree *tree)
{
	const char *dname = "tn_audit_cren";
	const char *src = "tn_audit_cren\\src.dat";
	const char *dst = "tn_audit_cren\\dst.dat";
	struct tn_audit_ids ids = tn_audit_ids(tree);
	struct tn_audit_recs *recs = NULL;
	struct smb2_request *req[3];
	union smb_setfileinfo s;
	struct smb2_create cr;
	struct smb2_close cl;
	ssize_t c, rn, x;
	NTSTATUS status;
	off_t start;
	bool ret = true;

	TN_AUDIT_REQUIRE_LOG(tctx);
	torture_assert(tctx, tn_audit_setup(tctx, tree, dname), "setup");
	torture_assert(tctx, tn_audit_make_file(tctx, tree, src, 10),
		       "make file");

	start = tn_audit_mark(tctx);
	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_STD_DELETE | SEC_FILE_READ_ATTRIBUTE;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN;
	cr.in.fname = src;

	smb2_transport_compound_start(tree->session->transport, 3);
	req[0] = smb2_create_send(tree, &cr);
	smb2_transport_compound_set_related(tree->session->transport, true);
	tn_audit_rename_info(&s, tn_audit_related, dst);
	req[1] = smb2_setinfo_file_send(tree, &s);
	ZERO_STRUCT(cl);
	cl.in.file.handle = tn_audit_related;
	req[2] = smb2_close_send(tree, &cl);

	status = smb2_create_recv(req[0], tree, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "CREATE");
	status = smb2_setinfo_recv(req[1]);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "rename");
	status = smb2_close_recv(req[2], &cl);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "CLOSE");

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}

	c = tn_audit_find(recs, 0, "CREATE", tn_audit_path(tctx, src), NULL);
	rn = tn_audit_find(recs, c, "RENAME", NULL, NULL);
	x = tn_audit_find(recs, rn, "CLOSE", NULL, NULL);
	torture_assert_goto(tctx, (c != -1) && (rn != -1) && (x != -1),
			    ret, done, "expected CREATE, RENAME, CLOSE");
	torture_assert_goto(tctx,
			    recs->rec[rn].success &&
			    tn_audit_names(&recs->rec[rn], "src_file",
					   tn_audit_path(tctx, src), NULL) &&
			    tn_audit_names(&recs->rec[rn], "dst_file",
					   tn_audit_path(tctx, dst), NULL),
			    ret, done, "RENAME source and destination");

done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	smb2_deltree(tree, dname);
	return ret;
}

/* An open deferred for an oplock break is logged once */
static bool test_tn_audit_oplock_break(struct torture_context *tctx,
				       struct smb2_tree *tree1,
				       struct smb2_tree *tree2)
{
	const char *dname = "tn_audit_oplock";
	const char *fname = "tn_audit_oplock\\file.dat";
	const char *path = tn_audit_path(tctx, fname);
	struct tn_audit_ids ids = tn_audit_ids(tree2);
	struct tn_audit_recs *recs = NULL;
	struct smb2_handle h1 = {{0}}, h2 = {{0}};
	struct smb2_create cr;
	ssize_t c;
	NTSTATUS status;
	off_t start;
	bool ret = true;

	TN_AUDIT_REQUIRE_LOG(tctx);
	torture_assert(tctx, tn_audit_setup(tctx, tree1, dname), "setup");
	torture_assert(tctx, tn_audit_make_file(tctx, tree1, fname, 10),
		       "make file");

	tree1->session->transport->oplock.handler = torture_oplock_ack_handler;
	tree1->session->transport->oplock.private_data = tree1;
	torture_reset_break_info(tctx, &break_info);

	ZERO_STRUCT(cr);
	cr.in.desired_access = SEC_RIGHTS_FILE_ALL;
	cr.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	cr.in.share_access = NTCREATEX_SHARE_ACCESS_MASK;
	cr.in.create_disposition = NTCREATEX_DISP_OPEN;
	cr.in.oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
	cr.in.fname = fname;
	status = smb2_create(tree1, tctx, &cr);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"open with batch oplock");
	h1 = cr.out.file.handle;
	torture_assert_int_equal_goto(tctx, cr.out.oplock_level,
				      SMB2_OPLOCK_LEVEL_BATCH, ret, done,
				      "batch oplock granted");

	start = tn_audit_mark(tctx);
	status = tn_audit_create(tree2, tctx, fname, SEC_FILE_READ_DATA,
				 NTCREATEX_DISP_OPEN, 0, &h2);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"second open");
	torture_wait_for_oplock_break(tctx);
	torture_assert_int_equal_goto(tctx, break_info.count, 1, ret, done,
				      "the second open must break the oplock");

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}

	torture_assert_int_equal_goto(tctx,
		tn_audit_count(recs, "CREATE", path, NULL), 1, ret, done,
		"the deferred open must be recorded once");
	c = tn_audit_find(recs, 0, "CREATE", path, NULL);
	torture_assert_goto(tctx, recs->rec[c].success, ret, done,
			    "the recorded open must be the successful one");

done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	tree1->session->transport->oplock.handler = NULL;
	if (!smb2_util_handle_empty(h2)) {
		smb2_util_close(tree2, h2);
	}
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree1, h1);
	}
	smb2_deltree(tree1, dname);
	return ret;
}

/* Create and remove a file on a fresh connection to @share */
static bool tn_audit_on_share(struct torture_context *tctx,
			      const char *share,
			      const char *fname,
			      off_t *start,
			      struct tn_audit_ids *ids)
{
	struct smb2_tree *tree = NULL;
	NTSTATUS status;
	bool ret = true;

	*start = tn_audit_mark(tctx);
	torture_assert(tctx, torture_smb2_con_share(tctx, share, &tree),
		       talloc_asprintf(tctx, "connect to %s", share));
	*ids = tn_audit_ids(tree);

	ret = tn_audit_make_file(tctx, tree, fname, 10);
	torture_assert_goto(tctx, ret, ret, done, "make file");
	status = smb2_util_unlink(tree, fname);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "unlink");
	status = smb2_tdis(tree);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "tdis");
done:
	TALLOC_FREE(tree);
	return ret;
}

/* A user that truenas_audit:ignore_list matches is not audited */
static bool test_tn_audit_ignore_list(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	const char *share = torture_setting_string(tctx,
						   "audit_ignored_share", NULL);
	struct tn_audit_recs *recs = NULL;
	struct tn_audit_ids ids;
	off_t start;
	bool ret = true;

	TN_AUDIT_REQUIRE_LOG(tctx);
	if (share == NULL) {
		torture_skip(tctx, "requires "
			     "--option=torture:audit_ignored_share=<share>");
	}

	ret = tn_audit_on_share(tctx, share, "tn_audit_ignored.dat",
				&start, &ids);
	torture_assert(tctx, ret, "operations on the ignored share");

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}
	torture_assert_int_equal_goto(tctx, recs->num, 0, ret, done,
				      "a user on the ignore list must not "
				      "be audited");
done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	return ret;
}

/* The watch list takes precedence over the ignore list */
static bool test_tn_audit_watch_list(struct torture_context *tctx,
				     struct smb2_tree *tree)
{
	const char *share = torture_setting_string(tctx,
						   "audit_watched_share", NULL);
	const char *fname = "tn_audit_watched.dat";
	struct tn_audit_recs *recs = NULL;
	struct tn_audit_ids ids;
	off_t start;
	bool ret = true;

	TN_AUDIT_REQUIRE_LOG(tctx);
	if (share == NULL) {
		torture_skip(tctx, "requires "
			     "--option=torture:audit_watched_share=<share>");
	}

	ret = tn_audit_on_share(tctx, share, fname, &start, &ids);
	torture_assert(tctx, ret, "operations on the watched share");

	ret = tn_audit_collect(tctx, start, ids, &recs);
	if (!ret) {
		goto done;
	}
	torture_assert_goto(tctx,
			    (tn_audit_find(recs, 0, "CONNECT", NULL,
					   NULL) != -1) &&
			    (tn_audit_find(recs, 0, "CREATE", fname,
					   NULL) != -1) &&
			    (tn_audit_find(recs, 0, "UNLINK", fname,
					   NULL) != -1),
			    ret, done,
			    "a user on the watch list must be audited even "
			    "if also on the ignore list");
done:
	if (!ret) {
		tn_audit_dump(tctx, recs);
	}
	return ret;
}
#endif /* HAVE_JANSSON */

void torture_truenas_audit_suite(struct torture_suite *suite)
{
	struct torture_suite *audit = torture_suite_create(suite, "audit");

#ifdef HAVE_JANSSON
	torture_suite_add_1smb2_test(audit, "connect",
				     test_tn_audit_connect);
	torture_suite_add_1smb2_test(audit, "file_io",
				     test_tn_audit_file_io);
	torture_suite_add_1smb2_test(audit, "open_failures",
				     test_tn_audit_open_failures);
	torture_suite_add_1smb2_test(audit, "mkdir_rmdir",
				     test_tn_audit_mkdir_rmdir);
	torture_suite_add_1smb2_test(audit, "delete_streams",
				     test_tn_audit_delete_streams);
	torture_suite_add_1smb2_test(audit, "rename",
				     test_tn_audit_rename);
	torture_suite_add_1smb2_test(audit, "set_attributes",
				     test_tn_audit_set_attributes);
	torture_suite_add_1smb2_test(audit, "set_times",
				     test_tn_audit_set_times);
	torture_suite_add_1smb2_test(audit, "sticky_write_time",
				     test_tn_audit_sticky_write_time);
	torture_suite_add_1smb2_test(audit, "set_acl",
				     test_tn_audit_set_acl);
	torture_suite_add_1smb2_test(audit, "create_with_sd",
				     test_tn_audit_create_with_sd);
	torture_suite_add_1smb2_test(audit, "fsctl_sparse",
				     test_tn_audit_fsctl_sparse);
	torture_suite_add_1smb2_test(audit, "copychunk",
				     test_tn_audit_copychunk);
	torture_suite_add_1smb2_test(audit, "stream_io",
				     test_tn_audit_stream_io);
	torture_suite_add_1smb2_test(audit, "compound_write",
				     test_tn_audit_compound_write);
	torture_suite_add_1smb2_test(audit, "compound_setinfo",
				     test_tn_audit_compound_setinfo);
	torture_suite_add_1smb2_test(audit, "compound_rename",
				     test_tn_audit_compound_rename);
	torture_suite_add_2smb2_test(audit, "oplock_break",
				     test_tn_audit_oplock_break);
	torture_suite_add_1smb2_test(audit, "ignore_list",
				     test_tn_audit_ignore_list);
	torture_suite_add_1smb2_test(audit, "watch_list",
				     test_tn_audit_watch_list);
#endif

	audit->description = talloc_strdup(audit,
		"vfs_truenas_audit records of SMB2 operations");
	torture_suite_add_suite(suite, audit);
}

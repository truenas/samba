/* 
   Unix SMB/CIFS implementation.

   SMB2 create test suite

   Copyright (C) Andrew Tridgell 2008
   
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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/smb/smbXcli_base.h"
#include "torture/torture.h"
#include "torture/util.h"
#include "torture/smb2/proto.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"

#include "system/filesys.h"
#include "auth/credentials/credentials.h"
#include "lib/cmdline/cmdline.h"
#include "librpc/gen_ndr/security.h"
#include "lib/events/events.h"

#define FNAME "test_create.dat"
#define DNAME "smb2_open"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) Incorrect status %s - should be %s\n", \
			 __location__, nt_errstr(status), nt_errstr(correct)); \
		return false; \
	}} while (0)

#define CHECK_EQUAL(v, correct) do { \
	if (v != correct) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) Incorrect value for %s 0x%08llx - " \
		        "should be 0x%08llx\n", \
			 __location__, #v, \
		        (unsigned long long)v, \
		        (unsigned long long)correct); \
		return false;					\
	}} while (0)

#define CHECK_TIME(t, field) do { \
	time_t t1, t2; \
	finfo.all_info.level = RAW_FILEINFO_ALL_INFORMATION; \
	finfo.all_info.in.file.handle = h1; \
	status = smb2_getinfo_file(tree, tctx, &finfo); \
	CHECK_STATUS(status, NT_STATUS_OK); \
	t1 = t & ~1; \
	t2 = nt_time_to_unix(finfo.all_info.out.field) & ~1; \
	if (abs(t1-t2) > 2) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) wrong time for field %s  %s - %s\n", \
			__location__, #field, \
			timestring(tctx, t1), \
			timestring(tctx, t2)); \
		dump_all_info(tctx, &finfo); \
		ret = false; \
	}} while (0)

#define CHECK_NTTIME(t, field) do { \
	NTTIME t2; \
	finfo.all_info.level = RAW_FILEINFO_ALL_INFORMATION; \
	finfo.all_info.in.file.handle = h1; \
	status = smb2_getinfo_file(tree, tctx, &finfo); \
	CHECK_STATUS(status, NT_STATUS_OK); \
	t2 = finfo.all_info.out.field; \
	if (llabs((int64_t)(t-t2)) > 20000) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) wrong time for field %s  %s - %s\n", \
		       __location__, #field, \
		       nt_time_string(tctx, t), \
		       nt_time_string(tctx, t2)); \
		dump_all_info(tctx, &finfo); \
		ret = false; \
	}} while (0)

#define CHECK_ALL_INFO(v, field) do { \
	finfo.all_info.level = RAW_FILEINFO_ALL_INFORMATION; \
	finfo.all_info.in.file.handle = h1; \
	status = smb2_getinfo_file(tree, tctx, &finfo); \
	CHECK_STATUS(status, NT_STATUS_OK); \
	if ((v) != (finfo.all_info.out.field)) { \
	       torture_result(tctx, TORTURE_FAIL, \
			"(%s) wrong value for field %s  0x%x - 0x%x\n", \
			__location__, #field, (int)v,\
			(int)(finfo.all_info.out.field)); \
		dump_all_info(tctx, &finfo); \
		ret = false; \
	}} while (0)

#define CHECK_VAL(v, correct) do { \
	if ((v) != (correct)) { \
		torture_result(tctx, TORTURE_FAIL, \
			"(%s) wrong value for %s  0x%x - should be 0x%x\n", \
		       __location__, #v, (int)(v), (int)correct); \
		ret = false; \
	}} while (0)

#define SET_ATTRIB(sattrib) do { \
	union smb_setfileinfo sfinfo; \
	ZERO_STRUCT(sfinfo.basic_info.in); \
	sfinfo.basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION; \
	sfinfo.basic_info.in.file.handle = h1; \
	sfinfo.basic_info.in.attrib = sattrib; \
	status = smb2_setinfo_file(tree, &sfinfo); \
	if (!NT_STATUS_IS_OK(status)) { \
		torture_comment(tctx, \
		    "(%s) Failed to set attrib 0x%x on %s\n", \
		       __location__, (unsigned int)(sattrib), fname); \
	}} while (0)

/*
  test some interesting combinations found by gentest
 */
static bool test_create_gentest(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_create io;
	NTSTATUS status;
	uint32_t access_mask, file_attributes_set;
	uint32_t ok_mask, not_supported_mask, invalid_parameter_mask;
	uint32_t not_a_directory_mask, unexpected_mask;
	union smb_fileinfo q;

	ZERO_STRUCT(io);
	io.in.desired_access     = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes    = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.share_access = 
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options = 0;
	io.in.fname = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.in.create_options = 0xF0000000;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	io.in.create_options = 0;

	io.in.file_attributes = FILE_ATTRIBUTE_DEVICE;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	io.in.file_attributes = FILE_ATTRIBUTE_VOLUME;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	io.in.create_disposition = NTCREATEX_DISP_OPEN;
	io.in.file_attributes = FILE_ATTRIBUTE_VOLUME;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);
	
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.desired_access = 0x08000000;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	io.in.desired_access = 0x04000000;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);

	io.in.file_attributes = 0;
	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.desired_access     = SEC_FLAG_MAXIMUM_ALLOWED;
	ok_mask = 0;
	not_supported_mask = 0;
	invalid_parameter_mask = 0;
	not_a_directory_mask = 0;
	unexpected_mask = 0;
	{
		int i;
		for (i=0;i<32;i++) {
			io.in.create_options = (uint32_t)1<<i;
			if (io.in.create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE) {
				continue;
			}
			status = smb2_create(tree, tctx, &io);
			if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
				not_supported_mask |= 1<<i;
			} else if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
				invalid_parameter_mask |= 1<<i;
			} else if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_A_DIRECTORY)) {
				not_a_directory_mask |= 1<<i;
			} else if (NT_STATUS_EQUAL(status, NT_STATUS_OK)) {
				ok_mask |= 1<<i;
				status = smb2_util_close(tree, io.out.file.handle);
				CHECK_STATUS(status, NT_STATUS_OK);
			} else {
				unexpected_mask |= 1<<i;
				torture_comment(tctx,
				    "create option 0x%08x returned %s\n",
				    1<<i, nt_errstr(status));
			}
		}
	}
	io.in.create_options = 0;

	CHECK_EQUAL(ok_mask,                0x00efcf7e);
	CHECK_EQUAL(not_a_directory_mask,   0x00000001);
	CHECK_EQUAL(not_supported_mask,     0x00102080);
	CHECK_EQUAL(invalid_parameter_mask, 0xff000000);
	CHECK_EQUAL(unexpected_mask,        0x00000000);

	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.file_attributes = 0;
	access_mask = 0;
	{
		int i;
		for (i=0;i<32;i++) {
			io.in.desired_access = (uint32_t)1<<i;
			status = smb2_create(tree, tctx, &io);
			if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) ||
			    NT_STATUS_EQUAL(status, NT_STATUS_PRIVILEGE_NOT_HELD)) {
				access_mask |= io.in.desired_access;
			} else {
				CHECK_STATUS(status, NT_STATUS_OK);
				status = smb2_util_close(tree, io.out.file.handle);
				CHECK_STATUS(status, NT_STATUS_OK);
			}
		}
	}

	if (TARGET_IS_WIN7(tctx)) {
		CHECK_EQUAL(access_mask, 0x0de0fe00);
	} else if (torture_setting_bool(tctx, "samba4", false)) {
		CHECK_EQUAL(access_mask, 0x0cf0fe00);
	} else {
		CHECK_EQUAL(access_mask, 0x0df0fe00);
	}

	io.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes = 0;
	ok_mask = 0;
	invalid_parameter_mask = 0;
	unexpected_mask = 0;
	file_attributes_set = 0;
	{
		int i;
		for (i=0;i<32;i++) {
			io.in.file_attributes = (uint32_t)1<<i;
			if (io.in.file_attributes & FILE_ATTRIBUTE_ENCRYPTED) {
				continue;
			}
			smb2_deltree(tree, FNAME);
			status = smb2_create(tree, tctx, &io);
			if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
				invalid_parameter_mask |= 1<<i;
			} else if (NT_STATUS_IS_OK(status)) {
				uint32_t expected;
				ok_mask |= 1<<i;

				expected = (io.in.file_attributes | FILE_ATTRIBUTE_ARCHIVE) & 0x00005127;
				io.out.file_attr &= ~FILE_ATTRIBUTE_NONINDEXED;
				CHECK_EQUAL(io.out.file_attr, expected);
				file_attributes_set |= io.out.file_attr;

				status = smb2_util_close(tree, io.out.file.handle);
				CHECK_STATUS(status, NT_STATUS_OK);
			} else {
				unexpected_mask |= 1<<i;
				torture_comment(tctx,
				    "file attribute 0x%08x returned %s\n",
				    1<<i, nt_errstr(status));
			}
		}
	}

	CHECK_EQUAL(ok_mask,                0x00003fb7);
	CHECK_EQUAL(invalid_parameter_mask, 0xffff8048);
	CHECK_EQUAL(unexpected_mask,        0x00000000);
	CHECK_EQUAL(file_attributes_set,    0x00001127);

	smb2_deltree(tree, FNAME);

	/*
	 * Standalone servers doesn't support encryption
	 */
	io.in.file_attributes = FILE_ATTRIBUTE_ENCRYPTED;
	status = smb2_create(tree, tctx, &io);
	if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		torture_comment(tctx,
		    "FILE_ATTRIBUTE_ENCRYPTED returned %s\n",
		    nt_errstr(status));
	} else {
		CHECK_STATUS(status, NT_STATUS_OK);
		CHECK_EQUAL(io.out.file_attr, (FILE_ATTRIBUTE_ENCRYPTED | FILE_ATTRIBUTE_ARCHIVE));
		status = smb2_util_close(tree, io.out.file.handle);
		CHECK_STATUS(status, NT_STATUS_OK);
	}

	smb2_deltree(tree, FNAME);

	ZERO_STRUCT(io);
	io.in.desired_access     = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes    = 0;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options = 0;
	io.in.fname = FNAME ":stream1";
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);
	CHECK_STATUS(status, NT_STATUS_OK);

	io.in.fname = FNAME;
	io.in.file_attributes = 0x8040;
	io.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	io.in.fname = FNAME;
	io.in.file_attributes = 0;
	io.in.desired_access  = SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA | SEC_FILE_APPEND_DATA;
	io.in.query_maximal_access = true;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_EQUAL(io.out.maximal_access, 0x001f01ff);

	q.access_information.level = RAW_FILEINFO_ACCESS_INFORMATION;
	q.access_information.in.file.handle = io.out.file.handle;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_EQUAL(q.access_information.out.access_flags, io.in.desired_access);

	io.in.file_attributes = 0;
	io.in.desired_access  = 0;
	io.in.query_maximal_access = false;
	io.in.share_access = 0;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);
	
	smb2_deltree(tree, FNAME);

	return true;
}


/*
  try the various request blobs
 */
static bool test_create_blob(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_create io;
	NTSTATUS status;

	smb2_deltree(tree, FNAME);

	ZERO_STRUCT(io);
	io.in.desired_access     = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes    = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io.in.share_access = 
		NTCREATEX_SHARE_ACCESS_DELETE|
		NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options		= NTCREATEX_OPTIONS_SEQUENTIAL_ONLY |
					  NTCREATEX_OPTIONS_ASYNC_ALERT	|
					  NTCREATEX_OPTIONS_NON_DIRECTORY_FILE |
					  0x00200000;
	io.in.fname = FNAME;

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "Testing alloc size\n");
	/* FIXME We use 1M cause that's the rounded size of Samba.
	 * We should ask the server for the cluser size and calulate it
	 * correctly. */
	io.in.alloc_size = 0x00100000;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_EQUAL(io.out.alloc_size, io.in.alloc_size);

	status = smb2_util_close(tree, io.out.file.handle);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "Testing durable open\n");
	io.in.durable_open = true;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "Testing query maximal access\n");
	io.in.query_maximal_access = true;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_EQUAL(io.out.maximal_access, 0x001f01ff);

	status = smb2_util_close(tree, io.out.file.handle);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "Testing timewarp\n");
	io.in.timewarp = 10000;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	io.in.timewarp = 0;

	torture_comment(tctx, "Testing query_on_disk\n");
	io.in.query_on_disk_id = true;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "Testing unknown tag\n");
	status = smb2_create_blob_add(tctx, &io.in.blobs,
				      "FooO", data_blob(NULL, 0));
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_close(tree, io.out.file.handle);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "Testing bad tag length 0\n");
	ZERO_STRUCT(io.in.blobs);
	status = smb2_create_blob_add(tctx, &io.in.blobs,
				      "x", data_blob(NULL, 0));
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	torture_comment(tctx, "Testing bad tag length 1\n");
	ZERO_STRUCT(io.in.blobs);
	status = smb2_create_blob_add(tctx, &io.in.blobs,
				      "x", data_blob(NULL, 0));
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	torture_comment(tctx, "Testing bad tag length 2\n");
	ZERO_STRUCT(io.in.blobs);
	status = smb2_create_blob_add(tctx, &io.in.blobs,
				      "xx", data_blob(NULL, 0));
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	torture_comment(tctx, "Testing bad tag length 3\n");
	ZERO_STRUCT(io.in.blobs);
	status = smb2_create_blob_add(tctx, &io.in.blobs,
				      "xxx", data_blob(NULL, 0));
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	torture_comment(tctx, "Testing tag length 4\n");
	ZERO_STRUCT(io.in.blobs);
	status = smb2_create_blob_add(tctx, &io.in.blobs,
				      "xxxx", data_blob(NULL, 0));
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "Testing tag length 5\n");
	ZERO_STRUCT(io.in.blobs);
	status = smb2_create_blob_add(tctx, &io.in.blobs,
				      "xxxxx", data_blob(NULL, 0));
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "Testing tag length 6\n");
	ZERO_STRUCT(io.in.blobs);
	status = smb2_create_blob_add(tctx, &io.in.blobs,
				      "xxxxxx", data_blob(NULL, 0));
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "Testing tag length 7\n");
	ZERO_STRUCT(io.in.blobs);
	status = smb2_create_blob_add(tctx, &io.in.blobs,
				      "xxxxxxx", data_blob(NULL, 0));
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "Testing tag length 8\n");
	ZERO_STRUCT(io.in.blobs);
	status = smb2_create_blob_add(tctx, &io.in.blobs,
				      "xxxxxxxx", data_blob(NULL, 0));
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "Testing tag length 16\n");
	ZERO_STRUCT(io.in.blobs);
	status = smb2_create_blob_add(tctx, &io.in.blobs,
				      "xxxxxxxxxxxxxxxx", data_blob(NULL, 0));
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "Testing tag length 17\n");
	ZERO_STRUCT(io.in.blobs);
	status = smb2_create_blob_add(tctx, &io.in.blobs,
				      "xxxxxxxxxxxxxxxxx", data_blob(NULL, 0));
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "Testing tag length 34\n");
	ZERO_STRUCT(io.in.blobs);
	status = smb2_create_blob_add(tctx, &io.in.blobs,
				      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
				      data_blob(NULL, 0));
	CHECK_STATUS(status, NT_STATUS_OK);
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_deltree(tree, FNAME);
	
	return true;
}

#define FAIL_UNLESS(__cond)					\
	do {							\
		if (__cond) {} else {				\
			torture_result(tctx, TORTURE_FAIL, "%s) condition violated: %s\n",	\
			       __location__, #__cond);		\
			ret = false; goto done;                 \
		}						\
	} while(0)

/*
  try creating with acls
 */
static bool test_create_acl_ext(struct torture_context *tctx, struct smb2_tree *tree, bool test_dir)
{
	bool ret = true;
	struct smb2_create io;
	NTSTATUS status;
	struct security_ace ace;
	struct security_descriptor *sd;
	struct dom_sid *test_sid;
	union smb_fileinfo q = {};
	uint32_t attrib =
	    FILE_ATTRIBUTE_HIDDEN |
	    FILE_ATTRIBUTE_SYSTEM |
	    (test_dir ? FILE_ATTRIBUTE_DIRECTORY : 0);
	NTSTATUS (*delete_func)(struct smb2_tree *, const char *) =
	    test_dir ? smb2_util_rmdir : smb2_util_unlink;

	ZERO_STRUCT(ace);

	smb2_deltree(tree, FNAME);

	ZERO_STRUCT(io);
	io.in.desired_access     = SEC_FLAG_MAXIMUM_ALLOWED;
	io.in.file_attributes    = FILE_ATTRIBUTE_NORMAL;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.share_access = 
		NTCREATEX_SHARE_ACCESS_DELETE |
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.create_options = NTCREATEX_OPTIONS_ASYNC_ALERT | 0x00200000 |
	    (test_dir ?  NTCREATEX_OPTIONS_DIRECTORY :
		(NTCREATEX_OPTIONS_NON_DIRECTORY_FILE));

	io.in.fname = FNAME;

	torture_comment(tctx, "basic create\n");

	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = io.out.file.handle;
	q.query_secdesc.in.secinfo_flags = 
		SECINFO_OWNER |
		SECINFO_GROUP |
		SECINFO_DACL;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);
	sd = q.query_secdesc.out.sd;

	status = smb2_util_close(tree, io.out.file.handle);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = delete_func(tree, FNAME);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "adding a new ACE\n");
	test_sid = dom_sid_parse_talloc(tctx, SID_NT_AUTHENTICATED_USERS);

	ace.type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	ace.flags = 0;
	ace.access_mask = SEC_STD_ALL;
	ace.trustee = *test_sid;

	status = security_descriptor_dacl_add(sd, &ace);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "creating a file with an initial ACL\n");

	io.in.sec_desc = sd;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	FAIL_UNLESS(smb2_util_verify_sd(tctx, tree, io.out.file.handle, sd));

	status = smb2_util_close(tree, io.out.file.handle);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = delete_func(tree, FNAME);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "creating with attributes\n");

	io.in.sec_desc = NULL;
	io.in.file_attributes = attrib;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	FAIL_UNLESS(smb2_util_verify_attrib(tctx, tree, io.out.file.handle, attrib));

	status = smb2_util_close(tree, io.out.file.handle);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = delete_func(tree, FNAME);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "creating with attributes and ACL\n");

	io.in.sec_desc = sd;
	io.in.file_attributes = attrib;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	FAIL_UNLESS(smb2_util_verify_sd(tctx, tree, io.out.file.handle, sd));
	FAIL_UNLESS(smb2_util_verify_attrib(tctx, tree, io.out.file.handle, attrib));
	
	status = smb2_util_close(tree, io.out.file.handle);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = delete_func(tree, FNAME);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "creating with attributes, ACL and owner\n");
	sd = security_descriptor_dacl_create(tctx,
					0, SID_WORLD, SID_BUILTIN_USERS,
					SID_WORLD,
					SEC_ACE_TYPE_ACCESS_ALLOWED,
					SEC_RIGHTS_FILE_READ | SEC_STD_ALL,
					0,
					NULL);

	io.in.sec_desc = sd;
	io.in.file_attributes = attrib;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);

	FAIL_UNLESS(smb2_util_verify_sd(tctx, tree, io.out.file.handle, sd));
	FAIL_UNLESS(smb2_util_verify_attrib(tctx, tree, io.out.file.handle, attrib));

 done:
	status = smb2_util_close(tree, io.out.file.handle);
	CHECK_STATUS(status, NT_STATUS_OK);
	status = delete_func(tree, FNAME);
	CHECK_STATUS(status, NT_STATUS_OK);

	return ret;
}

/*
  test SMB2 open
*/
static bool test_smb2_open(struct torture_context *tctx,
			   struct smb2_tree *tree)
{
	union smb_open io;
	union smb_fileinfo finfo;
	const char *fname = DNAME "\\torture_ntcreatex.txt";
	const char *dname = DNAME "\\torture_ntcreatex.dir";
	NTSTATUS status;
	struct smb2_handle h = {{0}};
	struct smb2_handle h1 = {{0}};
	bool ret = true;
	size_t i;
	struct {
		uint32_t create_disp;
		bool with_file;
		NTSTATUS correct_status;
	} open_funcs[] = {
		{ NTCREATEX_DISP_SUPERSEDE,     true,  NT_STATUS_OK },
		{ NTCREATEX_DISP_SUPERSEDE,     false, NT_STATUS_OK },
		{ NTCREATEX_DISP_OPEN,          true,  NT_STATUS_OK },
		{ NTCREATEX_DISP_OPEN,          false, NT_STATUS_OBJECT_NAME_NOT_FOUND },
		{ NTCREATEX_DISP_CREATE,        true,  NT_STATUS_OBJECT_NAME_COLLISION },
		{ NTCREATEX_DISP_CREATE,        false, NT_STATUS_OK },
		{ NTCREATEX_DISP_OPEN_IF,       true,  NT_STATUS_OK },
		{ NTCREATEX_DISP_OPEN_IF,       false, NT_STATUS_OK },
		{ NTCREATEX_DISP_OVERWRITE,     true,  NT_STATUS_OK },
		{ NTCREATEX_DISP_OVERWRITE,     false, NT_STATUS_OBJECT_NAME_NOT_FOUND },
		{ NTCREATEX_DISP_OVERWRITE_IF,  true,  NT_STATUS_OK },
		{ NTCREATEX_DISP_OVERWRITE_IF,  false, NT_STATUS_OK },
		{ 6,                            true,  NT_STATUS_INVALID_PARAMETER },
		{ 6,                            false, NT_STATUS_INVALID_PARAMETER },
	};

	torture_comment(tctx, "Checking SMB2 Open\n");

	smb2_util_unlink(tree, fname);
	smb2_util_rmdir(tree, dname);

	status = torture_smb2_testdir(tree, DNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(io.smb2);
	/* reasonable default parameters */
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 1024*1024;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	/* test the create disposition */
	for (i=0; i<ARRAY_SIZE(open_funcs); i++) {
		if (open_funcs[i].with_file) {
			io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
			status= smb2_create(tree, tctx, &(io.smb2));
			if (!NT_STATUS_IS_OK(status)) {
				torture_comment(tctx,
				    "Failed to create file %s status %s %zu\n",
				    fname, nt_errstr(status), i);

				ret = false;
				goto done;
			}
			smb2_util_close(tree, io.smb2.out.file.handle);
		}
		io.smb2.in.create_disposition = open_funcs[i].create_disp;
		status = smb2_create(tree, tctx, &(io.smb2));
		if (!NT_STATUS_EQUAL(status, open_funcs[i].correct_status)) {
			torture_comment(tctx,
			    "(%s) incorrect status %s should be %s (i=%zu "
			    "with_file=%d open_disp=%d)\n",
			 __location__, nt_errstr(status),
			nt_errstr(open_funcs[i].correct_status),
			i, (int)open_funcs[i].with_file,
			(int)open_funcs[i].create_disp);

			ret = false;
			goto done;
		}
		if (NT_STATUS_IS_OK(status) || open_funcs[i].with_file) {
			smb2_util_close(tree, io.smb2.out.file.handle);
			smb2_util_unlink(tree, fname);
		}
	}

	/* basic field testing */
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;

	status = smb2_create(tree, tctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;

	CHECK_VAL(io.smb2.out.oplock_level, 0);
	CHECK_VAL(io.smb2.out.create_action, NTCREATEX_ACTION_CREATED);
	CHECK_NTTIME(io.smb2.out.create_time, create_time);
	CHECK_NTTIME(io.smb2.out.access_time, access_time);
	CHECK_NTTIME(io.smb2.out.write_time, write_time);
	CHECK_NTTIME(io.smb2.out.change_time, change_time);
	CHECK_ALL_INFO(io.smb2.out.file_attr, attrib);
	CHECK_ALL_INFO(io.smb2.out.alloc_size, alloc_size);
	CHECK_ALL_INFO(io.smb2.out.size, size);

	/* check fields when the file already existed */
	smb2_util_close(tree, h1);
	smb2_util_unlink(tree, fname);

	status = smb2_create_complex_file(tctx, tree, fname, &h1);
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_close(tree, h1);

	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	status = smb2_create(tree, tctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;

	CHECK_VAL(io.smb2.out.oplock_level, 0);
	CHECK_VAL(io.smb2.out.create_action, NTCREATEX_ACTION_EXISTED);
	CHECK_NTTIME(io.smb2.out.create_time, create_time);
	CHECK_NTTIME(io.smb2.out.access_time, access_time);
	CHECK_NTTIME(io.smb2.out.write_time, write_time);
	CHECK_NTTIME(io.smb2.out.change_time, change_time);
	CHECK_ALL_INFO(io.smb2.out.file_attr, attrib);
	CHECK_ALL_INFO(io.smb2.out.alloc_size, alloc_size);
	CHECK_ALL_INFO(io.smb2.out.size, size);
	smb2_util_close(tree, h1);
	smb2_util_unlink(tree, fname);

	/* create a directory */
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_options = 0;
	io.smb2.in.fname = dname;
	fname = dname;

	smb2_util_rmdir(tree, fname);
	smb2_util_unlink(tree, fname);

	io.smb2.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				NTCREATEX_SHARE_ACCESS_WRITE;
	status = smb2_create(tree, tctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;

	CHECK_VAL(io.smb2.out.oplock_level, 0);
	CHECK_VAL(io.smb2.out.create_action, NTCREATEX_ACTION_CREATED);
	CHECK_NTTIME(io.smb2.out.create_time, create_time);
	CHECK_NTTIME(io.smb2.out.access_time, access_time);
	CHECK_NTTIME(io.smb2.out.write_time, write_time);
	CHECK_NTTIME(io.smb2.out.change_time, change_time);
	CHECK_ALL_INFO(io.smb2.out.file_attr, attrib);
	CHECK_VAL(io.smb2.out.file_attr & ~FILE_ATTRIBUTE_NONINDEXED,
		  FILE_ATTRIBUTE_DIRECTORY);
	CHECK_ALL_INFO(io.smb2.out.alloc_size, alloc_size);
	CHECK_ALL_INFO(io.smb2.out.size, size);
	CHECK_VAL(io.smb2.out.size, 0);
	smb2_util_unlink(tree, fname);

done:
	smb2_util_close(tree, h1);
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);
	return ret;
}

/*
  test with an already opened and byte range locked file
*/

static bool test_smb2_open_brlocked(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	union smb_open io, io1;
	union smb_lock io2;
	struct smb2_lock_element lock[1];
	const char *fname = DNAME "\\torture_ntcreatex.txt";
	NTSTATUS status;
	bool ret = true;
	struct smb2_handle h;
	char b = 42;

	torture_comment(tctx,
		"Testing SMB2 open with a byte range locked file\n");

	smb2_util_unlink(tree, fname);

	status = torture_smb2_testdir(tree, DNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.desired_access = 0x2019f;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
	io.smb2.in.security_flags = SMB2_SECURITY_DYNAMIC_TRACKING;
	io.smb2.in.fname = fname;

	status = smb2_create(tree, tctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

	status = smb2_util_write(tree, io.smb2.out.file.handle, &b, 0, 1);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(io2.smb2);
	io2.smb2.level = RAW_LOCK_SMB2;
	io2.smb2.in.file.handle = io.smb2.out.file.handle;
	io2.smb2.in.lock_count = 1;

	ZERO_STRUCT(lock);
	lock[0].offset = 0;
	lock[0].length = 1;
	lock[0].flags = SMB2_LOCK_FLAG_EXCLUSIVE |
			SMB2_LOCK_FLAG_FAIL_IMMEDIATELY;
	io2.smb2.in.locks = &lock[0];
	status = smb2_lock(tree, &(io2.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(io1.smb2);
	io1.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io1.smb2.in.desired_access = 0x20196;
	io1.smb2.in.alloc_size = 0;
	io1.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io1.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	io1.smb2.in.create_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	io1.smb2.in.create_options = 0;
	io1.smb2.in.impersonation_level = SMB2_IMPERSONATION_IMPERSONATION;
	io1.smb2.in.security_flags = SMB2_SECURITY_DYNAMIC_TRACKING;
	io1.smb2.in.fname = fname;

	status = smb2_create(tree, tctx, &(io1.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);

	smb2_util_close(tree, io.smb2.out.file.handle);
	smb2_util_close(tree, io1.smb2.out.file.handle);
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);

	return ret;
}

/* A little torture test to expose a race condition in Samba 3.0.20 ... :-) */

static bool test_smb2_open_multi(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	const char *fname = "test_oplock.dat";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_tree **trees;
	struct smb2_request **requests;
	union smb_open *ios;
	int i, num_files = 3;
	int num_ok = 0;
	int num_collision = 0;

	torture_comment(tctx,
		"Testing SMB2 Open with multiple connections\n");
	trees = talloc_array(tctx, struct smb2_tree *, num_files);
	requests = talloc_array(tctx, struct smb2_request *, num_files);
	ios = talloc_array(tctx, union smb_open, num_files);
	if ((tctx->ev == NULL) || (trees == NULL) || (requests == NULL) ||
	    (ios == NULL)) {
		torture_comment(tctx, ("talloc failed\n"));
		ret = false;
		goto done;
	}

	tree->session->transport->options.request_timeout = 60;

	for (i=0; i<num_files; i++) {
		if (!torture_smb2_connection(tctx, &(trees[i]))) {
			torture_comment(tctx,
				"Could not open %d'th connection\n", i);
			ret = false;
			goto done;
		}
		trees[i]->session->transport->options.request_timeout = 60;
	}

	/* cleanup */
	smb2_util_unlink(tree, fname);

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;
	io.smb2.in.create_flags = 0;

	for (i=0; i<num_files; i++) {
		ios[i] = io;
		requests[i] = smb2_create_send(trees[i], &(ios[i].smb2));
		if (requests[i] == NULL) {
			torture_comment(tctx,
				"could not send %d'th request\n", i);
			ret = false;
			goto done;
		}
	}

	torture_comment(tctx, "waiting for replies\n");
	while (1) {
		bool unreplied = false;
		for (i=0; i<num_files; i++) {
			if (requests[i] == NULL) {
				continue;
			}
			if (requests[i]->state < SMB2_REQUEST_DONE) {
				unreplied = true;
				break;
			}
			status = smb2_create_recv(requests[i], tctx,
						  &(ios[i].smb2));

			torture_comment(tctx,
				"File %d returned status %s\n", i,
				nt_errstr(status));

			if (NT_STATUS_IS_OK(status)) {
				num_ok += 1;
			}

			if (NT_STATUS_EQUAL(status,
					    NT_STATUS_OBJECT_NAME_COLLISION)) {
				num_collision += 1;
			}

			requests[i] = NULL;
		}
		if (!unreplied) {
			break;
		}

		if (tevent_loop_once(tctx->ev) != 0) {
			torture_comment(tctx, "tevent_loop_once failed\n");
			ret = false;
			goto done;
		}
	}

	if ((num_ok != 1) || (num_ok + num_collision != num_files)) {
		ret = false;
	}
done:
	smb2_deltree(tree, fname);

	return ret;
}

/*
  test opening for delete on a read-only attribute file.
*/

static bool test_smb2_open_for_delete(struct torture_context *tctx,
				      struct smb2_tree *tree)
{
	union smb_open io;
	union smb_fileinfo finfo;
	const char *fname = DNAME "\\torture_open_for_delete.txt";
	NTSTATUS status;
	struct smb2_handle h, h1;
	bool ret = true;

	torture_comment(tctx,
		"Checking SMB2_OPEN for delete on a readonly file.\n");
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, fname);

	status = torture_smb2_testdir(tree, DNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* reasonable default parameters */
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.create_flags = NTCREATEX_FLAGS_EXTENDED;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_READONLY;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;

	/* Create the readonly file. */

	status = smb2_create(tree, tctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;

	CHECK_VAL(io.smb2.out.oplock_level, 0);
	io.smb2.in.create_options = 0;
	CHECK_VAL(io.smb2.out.create_action, NTCREATEX_ACTION_CREATED);
	CHECK_ALL_INFO(io.smb2.out.file_attr, attrib);
	smb2_util_close(tree, h1);

	/* Now try and open for delete only - should succeed. */
	io.smb2.in.desired_access = SEC_STD_DELETE;
	io.smb2.in.file_attributes = 0;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				NTCREATEX_SHARE_ACCESS_WRITE |
				NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN;
	status = smb2_create(tree, tctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	smb2_util_close(tree, io.smb2.out.file.handle);

	/* Clear readonly flag to allow file deletion */
	io.smb2.in.desired_access = SEC_FILE_READ_ATTRIBUTE |
				SEC_FILE_WRITE_ATTRIBUTE;
	status = smb2_create(tree, tctx, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io.smb2.out.file.handle;
	SET_ATTRIB(FILE_ATTRIBUTE_ARCHIVE);
	smb2_util_close(tree, h1);

	smb2_util_close(tree, h);
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);

	return ret;
}

/*
  test SMB2 open with a leading slash on the path.
  Trying to create a directory with a leading slash
  should give NT_STATUS_INVALID_PARAMETER error
*/
static bool test_smb2_leading_slash(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	union smb_open io;
	const char *dnameslash = "\\"DNAME;
	NTSTATUS status;
	bool ret = true;

	torture_comment(tctx,
		"Trying to create a directory with leading slash on path\n");
	smb2_deltree(tree, dnameslash);

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.oplock_level = 0;
	io.smb2.in.desired_access = SEC_RIGHTS_DIR_ALL;
	io.smb2.in.file_attributes   = FILE_ATTRIBUTE_DIRECTORY;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
				NTCREATEX_SHARE_ACCESS_WRITE |
				NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.smb2.in.fname = dnameslash;

	status = smb2_create(tree, tree, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_INVALID_PARAMETER);

	smb2_deltree(tree, dnameslash);
	return ret;
}

/*
  test SMB2 open with an invalid impersonation level.
  Should give NT_STATUS_BAD_IMPERSONATION_LEVEL error
*/
static bool test_smb2_impersonation_level(struct torture_context *tctx,
				    struct smb2_tree *tree)
{
	union smb_open io;
	const char *fname = DNAME "\\torture_invalid_impersonation_level.txt";
	NTSTATUS status;
	struct smb2_handle h;
	bool ret = true;

	torture_comment(tctx,
		"Testing SMB2 open with an invalid impersonation level.\n");

	smb2_util_unlink(tree, fname);
	smb2_util_rmdir(tree, DNAME);

	status = torture_smb2_testdir(tree, DNAME, &h);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.smb2.in.create_options = 0;
	io.smb2.in.impersonation_level = 0x12345678;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;
	io.smb2.in.create_flags = 0;

	status = smb2_create(tree, tree, &(io.smb2));
	CHECK_STATUS(status, NT_STATUS_BAD_IMPERSONATION_LEVEL);

	smb2_util_close(tree, h);
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, DNAME);
	return ret;
}

static bool test_create_acl_file(struct torture_context *tctx,
    struct smb2_tree *tree)
{
	torture_comment(tctx, "Testing nttrans create with sec_desc on files\n");

	return test_create_acl_ext(tctx, tree, false);
}

static bool test_create_acl_dir(struct torture_context *tctx,
    struct smb2_tree *tree)
{
	torture_comment(tctx, "Testing nttrans create with sec_desc on directories\n");

	return test_create_acl_ext(tctx, tree, true);
}

#define CHECK_ACCESS_FLAGS(_fh, flags) do { \
	union smb_fileinfo _q; \
	_q.access_information.level = RAW_FILEINFO_ACCESS_INFORMATION; \
	_q.access_information.in.file.handle = (_fh); \
	status = smb2_getinfo_file(tree, tctx, &_q); \
	CHECK_STATUS(status, NT_STATUS_OK); \
	if (_q.access_information.out.access_flags != (flags)) { \
		torture_result(tctx, TORTURE_FAIL, "(%s) Incorrect access_flags 0x%08x - should be 0x%08x\n", \
		       __location__, _q.access_information.out.access_flags, (flags)); \
		ret = false; \
		goto done; \
	} \
} while (0)

/*
 * Test creating a file with a NULL DACL.
 */
static bool test_create_null_dacl(struct torture_context *tctx,
    struct smb2_tree *tree)
{
	NTSTATUS status;
	struct smb2_create io;
	const char *fname = "nulldacl.txt";
	bool ret = true;
	struct smb2_handle handle;
	union smb_fileinfo q;
	union smb_setfileinfo s;
	struct security_descriptor *sd = security_descriptor_initialise(tctx);
	struct security_acl dacl;

	torture_comment(tctx, "TESTING SEC_DESC WITH A NULL DACL\n");

	smb2_util_unlink(tree, fname);

	ZERO_STRUCT(io);
	io.level = RAW_OPEN_SMB2;
	io.in.create_flags = 0;
	io.in.desired_access = SEC_STD_READ_CONTROL | SEC_STD_WRITE_DAC
		| SEC_STD_WRITE_OWNER;
	io.in.create_options = 0;
	io.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.in.share_access =
		NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
	io.in.alloc_size = 0;
	io.in.create_disposition = NTCREATEX_DISP_CREATE;
	io.in.impersonation_level = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.in.security_flags = 0;
	io.in.fname = fname;
	io.in.sec_desc = sd;
	/* XXX create_options ? */
	io.in.create_options		= NTCREATEX_OPTIONS_SEQUENTIAL_ONLY |
					  NTCREATEX_OPTIONS_ASYNC_ALERT	|
					  NTCREATEX_OPTIONS_NON_DIRECTORY_FILE |
					  0x00200000;

	torture_comment(tctx, "creating a file with a empty sd\n");
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	handle = io.out.file.handle;

	torture_comment(tctx, "get the original sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags =
		SECINFO_OWNER |
		SECINFO_GROUP |
		SECINFO_DACL;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);

	/*
	 * Testing the created DACL,
	 * the server should add the inherited DACL
	 * when SEC_DESC_DACL_PRESENT isn't specified
	 */
	if (!(q.query_secdesc.out.sd->type & SEC_DESC_DACL_PRESENT)) {
		ret = false;
		torture_fail_goto(tctx, done, "DACL_PRESENT flag not set by the server!\n");
	}
	if (q.query_secdesc.out.sd->dacl == NULL) {
		ret = false;
		torture_fail_goto(tctx, done, "no DACL has been created on the server!\n");
	}

	torture_comment(tctx, "set NULL DACL\n");
	sd->type |= SEC_DESC_DACL_PRESENT;

	s.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	s.set_secdesc.in.file.handle = handle;
	s.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	s.set_secdesc.in.sd = sd;
	status = smb2_setinfo_file(tree, &s);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "get the sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags =
		SECINFO_OWNER |
		SECINFO_GROUP |
		SECINFO_DACL;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Testing the modified DACL */
	if (!(q.query_secdesc.out.sd->type & SEC_DESC_DACL_PRESENT)) {
		ret = false;
		torture_fail_goto(tctx, done, "DACL_PRESENT flag not set by the server!\n");
	}
	if (q.query_secdesc.out.sd->dacl != NULL) {
		ret = false;
		torture_fail_goto(tctx, done, "DACL has been created on the server!\n");
	}

	io.in.create_disposition = NTCREATEX_DISP_OPEN;

	torture_comment(tctx, "try open for read control\n");
	io.in.desired_access = SEC_STD_READ_CONTROL;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.out.file.handle,
		SEC_STD_READ_CONTROL);
	smb2_util_close(tree, io.out.file.handle);

	torture_comment(tctx, "try open for write\n");
	io.in.desired_access = SEC_FILE_WRITE_DATA;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.out.file.handle,
		SEC_FILE_WRITE_DATA);
	smb2_util_close(tree, io.out.file.handle);

	torture_comment(tctx, "try open for read\n");
	io.in.desired_access = SEC_FILE_READ_DATA;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.out.file.handle,
		SEC_FILE_READ_DATA);
	smb2_util_close(tree, io.out.file.handle);

	torture_comment(tctx, "try open for generic write\n");
	io.in.desired_access = SEC_GENERIC_WRITE;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.out.file.handle,
		SEC_RIGHTS_FILE_WRITE);
	smb2_util_close(tree, io.out.file.handle);

	torture_comment(tctx, "try open for generic read\n");
	io.in.desired_access = SEC_GENERIC_READ;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.out.file.handle,
		SEC_RIGHTS_FILE_READ);
	smb2_util_close(tree, io.out.file.handle);

	torture_comment(tctx, "set DACL with 0 aces\n");
	ZERO_STRUCT(dacl);
	dacl.revision = SECURITY_ACL_REVISION_NT4;
	dacl.num_aces = 0;
	sd->dacl = &dacl;

	s.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	s.set_secdesc.in.file.handle = handle;
	s.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	s.set_secdesc.in.sd = sd;
	status = smb2_setinfo_file(tree, &s);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "get the sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags =
		SECINFO_OWNER |
		SECINFO_GROUP |
		SECINFO_DACL;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Testing the modified DACL */
	if (!(q.query_secdesc.out.sd->type & SEC_DESC_DACL_PRESENT)) {
		ret = false;
		torture_fail_goto(tctx, done, "DACL_PRESENT flag not set by the server!\n");
	}
	if (q.query_secdesc.out.sd->dacl == NULL) {
		ret = false;
		torture_fail_goto(tctx, done, "no DACL has been created on the server!\n");
	}
	if (q.query_secdesc.out.sd->dacl->num_aces != 0) {
		torture_result(tctx, TORTURE_FAIL, "DACL has %u aces!\n",
		       q.query_secdesc.out.sd->dacl->num_aces);
		ret = false;
		goto done;
	}

	torture_comment(tctx, "try open for read control\n");
	io.in.desired_access = SEC_STD_READ_CONTROL;
	status = smb2_create(tree, tctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_ACCESS_FLAGS(io.out.file.handle,
		SEC_STD_READ_CONTROL);
	smb2_util_close(tree, io.out.file.handle);

	torture_comment(tctx, "try open for write => access_denied\n");
	io.in.desired_access = SEC_FILE_WRITE_DATA;
	status = smb2_create(tree, tctx, &io);
	if (torture_setting_bool(tctx, "hide_on_access_denied", false)) {
		CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	} else {
		CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);
	}

	torture_comment(tctx, "try open for read => access_denied\n");
	io.in.desired_access = SEC_FILE_READ_DATA;
	status = smb2_create(tree, tctx, &io);
	if (torture_setting_bool(tctx, "hide_on_access_denied", false)) {
		CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	} else {
		CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);
	}

	torture_comment(tctx, "try open for generic write => access_denied\n");
	io.in.desired_access = SEC_GENERIC_WRITE;
	status = smb2_create(tree, tctx, &io);
	if (torture_setting_bool(tctx, "hide_on_access_denied", false)) {
		CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	} else {
		CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);
	}

	torture_comment(tctx, "try open for generic read => access_denied\n");
	io.in.desired_access = SEC_GENERIC_READ;
	status = smb2_create(tree, tctx, &io);
	if (torture_setting_bool(tctx, "hide_on_access_denied", false)) {
		CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	} else {
		CHECK_STATUS(status, NT_STATUS_ACCESS_DENIED);
	}

	torture_comment(tctx, "set empty sd\n");
	sd->type &= ~SEC_DESC_DACL_PRESENT;
	sd->dacl = NULL;

	s.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	s.set_secdesc.in.file.handle = handle;
	s.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	s.set_secdesc.in.sd = sd;
	status = smb2_setinfo_file(tree, &s);
	CHECK_STATUS(status, NT_STATUS_OK);

	torture_comment(tctx, "get the sd\n");
	q.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	q.query_secdesc.in.file.handle = handle;
	q.query_secdesc.in.secinfo_flags =
		SECINFO_OWNER |
		SECINFO_GROUP |
		SECINFO_DACL;
	status = smb2_getinfo_file(tree, tctx, &q);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Testing the modified DACL */
	if (!(q.query_secdesc.out.sd->type & SEC_DESC_DACL_PRESENT)) {
		ret = false;
		torture_fail_goto(tctx, done, "DACL_PRESENT flag not set by the server!\n");
	}
	if (q.query_secdesc.out.sd->dacl != NULL) {
		ret = false;
		torture_fail_goto(tctx, done, "DACL has been created on the server!\n");
	}
done:
	smb2_util_close(tree, handle);
	smb2_util_unlink(tree, fname);
	smb2_tdis(tree);
	smb2_logoff(tree->session);
	return ret;
}

/*
  test SMB2 mkdir with OPEN_IF on the same name twice.
  Must use 2 connections to hit the race.
*/

static bool test_mkdir_dup(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	const char *fname = "mkdir_dup";
	NTSTATUS status;
	bool ret = true;
	union smb_open io;
	struct smb2_tree **trees;
	struct smb2_request **requests;
	union smb_open *ios;
	int i, num_files = 2;
	int num_ok = 0;
	int num_created = 0;
	int num_existed = 0;

	torture_comment(tctx,
		"Testing SMB2 Create Directory with multiple connections\n");
	trees = talloc_array(tctx, struct smb2_tree *, num_files);
	requests = talloc_array(tctx, struct smb2_request *, num_files);
	ios = talloc_array(tctx, union smb_open, num_files);
	if ((tctx->ev == NULL) || (trees == NULL) || (requests == NULL) ||
	    (ios == NULL)) {
		torture_fail(tctx, ("talloc failed\n"));
		ret = false;
		goto done;
	}

	tree->session->transport->options.request_timeout = 60;

	for (i=0; i<num_files; i++) {
		if (!torture_smb2_connection(tctx, &(trees[i]))) {
			torture_fail(tctx,
				talloc_asprintf(tctx,
					"Could not open %d'th connection\n", i));
			ret = false;
			goto done;
		}
		trees[i]->session->transport->options.request_timeout = 60;
	}

	/* cleanup */
	smb2_util_unlink(tree, fname);
	smb2_util_rmdir(tree, fname);

	/*
	  base ntcreatex parms
	*/
	ZERO_STRUCT(io.smb2);
	io.generic.level = RAW_OPEN_SMB2;
	io.smb2.in.desired_access = SEC_RIGHTS_FILE_ALL;
	io.smb2.in.alloc_size = 0;
	io.smb2.in.file_attributes = FILE_ATTRIBUTE_NORMAL;
	io.smb2.in.share_access = NTCREATEX_SHARE_ACCESS_READ|
		NTCREATEX_SHARE_ACCESS_WRITE|
		NTCREATEX_SHARE_ACCESS_DELETE;
	io.smb2.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
	io.smb2.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	io.smb2.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS;
	io.smb2.in.security_flags = 0;
	io.smb2.in.fname = fname;
	io.smb2.in.create_flags = 0;

	for (i=0; i<num_files; i++) {
		ios[i] = io;
		requests[i] = smb2_create_send(trees[i], &(ios[i].smb2));
		if (requests[i] == NULL) {
			torture_fail(tctx,
				talloc_asprintf(tctx,
				"could not send %d'th request\n", i));
			ret = false;
			goto done;
		}
	}

	torture_comment(tctx, "waiting for replies\n");
	while (1) {
		bool unreplied = false;
		for (i=0; i<num_files; i++) {
			if (requests[i] == NULL) {
				continue;
			}
			if (requests[i]->state < SMB2_REQUEST_DONE) {
				unreplied = true;
				break;
			}
			status = smb2_create_recv(requests[i], tctx,
						  &(ios[i].smb2));

			if (NT_STATUS_IS_OK(status)) {
				num_ok += 1;

				if (ios[i].smb2.out.create_action ==
						NTCREATEX_ACTION_CREATED) {
					num_created++;
				}
				if (ios[i].smb2.out.create_action ==
						NTCREATEX_ACTION_EXISTED) {
					num_existed++;
				}
			} else {
				torture_fail(tctx,
					talloc_asprintf(tctx,
					"File %d returned status %s\n", i,
					nt_errstr(status)));
			}


			requests[i] = NULL;
		}
		if (!unreplied) {
			break;
		}

		if (tevent_loop_once(tctx->ev) != 0) {
			torture_fail(tctx, "tevent_loop_once failed\n");
			ret = false;
			goto done;
		}
	}

	if (num_ok != 2) {
		torture_fail(tctx,
			talloc_asprintf(tctx,
			"num_ok == %d\n", num_ok));
		ret = false;
	}
	if (num_created != 1) {
		torture_fail(tctx,
			talloc_asprintf(tctx,
			"num_created == %d\n", num_created));
		ret = false;
	}
	if (num_existed != 1) {
		torture_fail(tctx,
			talloc_asprintf(tctx,
			"num_existed == %d\n", num_existed));
		ret = false;
	}
done:
	smb2_deltree(tree, fname);

	return ret;
}

/*
  test directory creation with an initial allocation size > 0
*/
static bool test_dir_alloc_size(struct torture_context *tctx,
				struct smb2_tree *tree)
{
	bool ret = true;
	const char *dname = DNAME "\\torture_alloc_size.dir";
	NTSTATUS status;
	struct smb2_create c;
	struct smb2_handle h1 = {{0}}, h2;

	torture_comment(tctx, "Checking initial allocation size on directories\n");

	smb2_deltree(tree, dname);

	status = torture_smb2_testdir(tree, DNAME, &h1);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done, "torture_smb2_testdir failed");

	ZERO_STRUCT(c);
	c.in.create_disposition = NTCREATEX_DISP_CREATE;
	c.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
	c.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
	c.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
	c.in.create_options = NTCREATEX_OPTIONS_DIRECTORY;
	c.in.fname = dname;
	/*
	 * An insanely large value so we can check the value is
	 * ignored: Samba either returns 0 (current behaviour), or,
	 * once vfswrap_get_alloc_size() is fixed to allow retrieving
	 * the allocated size for directories, returns
	 * smb_roundup(..., stat.st_size) which would be 1 MB by
	 * default.
	 *
	 * Windows returns 0 for empty directories, once directories
	 * have a few entries it starts replying with values > 0.
	 */
	c.in.alloc_size = 1024*1024*1024;

	status = smb2_create(tree, tctx, &c);
	h2 = c.out.file.handle;
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"dir create with initial alloc size failed");

	smb2_util_close(tree, h2);

	torture_comment(tctx, "Got directory alloc size: %ju\n", (uintmax_t)c.out.alloc_size);

	/*
	 * See above for the rational for this test
	 */
	if (c.out.alloc_size > 1024*1024) {
		torture_fail_goto(tctx, done, talloc_asprintf(tctx, "bad alloc size: %ju",
							      (uintmax_t)c.out.alloc_size));
	}

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	smb2_deltree(tree, DNAME);
	return ret;
}

static bool test_twrp_write(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_create io;
	struct smb2_handle h1 = {{0}};
	NTSTATUS status;
	bool ret = true;
	char *p = NULL;
	struct tm tm;
	time_t t;
	uint64_t nttime;
	const char *file = NULL;
	const char *snapshot = NULL;
	uint32_t expected_access;
	union smb_fileinfo getinfo;
	union smb_setfileinfo setinfo;
	struct security_descriptor *sd = NULL, *sd_orig = NULL;
	const char *owner_sid = NULL;
	struct create_disps_tests {
		const char *file;
		uint32_t create_disposition;
		uint32_t create_options;
		NTSTATUS expected_status;
	};
	struct create_disps_tests *cd_test = NULL;

	file = torture_setting_string(tctx, "twrp_file", NULL);
	if (file == NULL) {
		torture_skip(tctx, "missing 'twrp_file' option\n");
	}

	snapshot = torture_setting_string(tctx, "twrp_snapshot", NULL);
	if (snapshot == NULL) {
		torture_skip(tctx, "missing 'twrp_snapshot' option\n");
	}

	torture_comment(tctx, "Testing timewarp (%s) (%s)\n", file, snapshot);

	setenv("TZ", "GMT", 1);

	/* strptime does not set tm.tm_isdst but mktime assumes DST is in
	 * effect if it is greather than 1. */
	ZERO_STRUCT(tm);

	p = strptime(snapshot, "@GMT-%Y.%m.%d-%H.%M.%S", &tm);
	torture_assert_goto(tctx, p != NULL, ret, done, "strptime\n");
	torture_assert_goto(tctx, *p == '\0', ret, done, "strptime\n");

	t = mktime(&tm);
	unix_to_nt_time(&nttime, t);

	io = (struct smb2_create) {
		.in.desired_access = SEC_FILE_READ_DATA,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.fname = file,
		.in.query_maximal_access = true,
		.in.timewarp = nttime,
	};

	status = smb2_create(tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create\n");
	smb2_util_close(tree, io.out.file.handle);

	expected_access = SEC_RIGHTS_FILE_ALL &
				~(SEC_FILE_EXECUTE | SEC_DIR_DELETE_CHILD);

	torture_assert_int_equal_goto(tctx,
				      io.out.maximal_access & expected_access,
				      expected_access,
				      ret, done, "Bad access\n");

	{
		/*
		 * Test create dispositions
		 */
		struct create_disps_tests cd_tests[] = {
			{
				.file = file,
				.create_disposition = NTCREATEX_DISP_OPEN,
				.expected_status = NT_STATUS_OK,
			},
			{
				.file = file,
				.create_disposition = NTCREATEX_DISP_OPEN_IF,
				.expected_status = NT_STATUS_OK,
			},
			{
				.file = file,
				.create_disposition = NTCREATEX_DISP_OVERWRITE,
				.expected_status = NT_STATUS_MEDIA_WRITE_PROTECTED,
			},
			{
				.file = file,
				.create_disposition = NTCREATEX_DISP_OVERWRITE_IF,
				.expected_status = NT_STATUS_MEDIA_WRITE_PROTECTED,
			},
			{
				.file = file,
				.create_disposition = NTCREATEX_DISP_SUPERSEDE,
				.expected_status = NT_STATUS_MEDIA_WRITE_PROTECTED,
			},
			{
				.file = "newfile",
				.create_disposition = NTCREATEX_DISP_OPEN_IF,
				.expected_status = NT_STATUS_MEDIA_WRITE_PROTECTED,
			},
			{
				.file = "newfile",
				.create_disposition = NTCREATEX_DISP_OVERWRITE_IF,
				.expected_status = NT_STATUS_MEDIA_WRITE_PROTECTED,
			},
			{
				.file = "newfile",
				.create_disposition = NTCREATEX_DISP_CREATE,
				.expected_status = NT_STATUS_MEDIA_WRITE_PROTECTED,
			},
			{
				.file = "newfile",
				.create_disposition = NTCREATEX_DISP_SUPERSEDE,
				.expected_status = NT_STATUS_MEDIA_WRITE_PROTECTED,
			},
			{
				.file = "newdir",
				.create_disposition = NTCREATEX_DISP_OPEN_IF,
				.create_options = NTCREATEX_OPTIONS_DIRECTORY,
				.expected_status = NT_STATUS_MEDIA_WRITE_PROTECTED,
			},
			{
				.file = "newdir",
				.create_disposition = NTCREATEX_DISP_CREATE,
				.create_options = NTCREATEX_OPTIONS_DIRECTORY,
				.expected_status = NT_STATUS_MEDIA_WRITE_PROTECTED,
			},
			{
				.file = NULL,
			},
		};

		for (cd_test = &cd_tests[0]; cd_test->file != NULL; cd_test++) {
			io = (struct smb2_create) {
				.in.fname = cd_test->file,
				.in.create_disposition = cd_test->create_disposition,
				.in.create_options = cd_test->create_options,

				.in.desired_access = SEC_FILE_READ_DATA,
				.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
				.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
				.in.timewarp = nttime,
			};

			status = smb2_create(tree, tctx, &io);
			torture_assert_ntstatus_equal_goto(
				tctx, status, cd_test->expected_status, ret, done,
				"Bad status\n");
		}
	}

	io = (struct smb2_create) {
		.in.desired_access = expected_access,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.fname = file,
		.in.timewarp = nttime,
	};

	status = smb2_create(tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create\n");
	h1 = io.out.file.handle;

	status = smb2_util_write(tree, h1, "123", 0, 3);
	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_MEDIA_WRITE_PROTECTED,
					   ret, done, "smb2_create\n");

	/*
	 * Verify access mask
	 */

	ZERO_STRUCT(getinfo);
	getinfo.generic.level = RAW_FILEINFO_ACCESS_INFORMATION;
	getinfo.generic.in.file.handle = h1;

	status = smb2_getinfo_file(tree, tree, &getinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file\n");

	torture_assert_int_equal_goto(
		tctx,
		getinfo.access_information.out.access_flags,
		expected_access,
		ret, done,
		"Bad access mask\n");

	/*
	 * Check we can't set various things
	 */

	ZERO_STRUCT(getinfo);
	getinfo.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	getinfo.query_secdesc.in.file.handle = h1;
	getinfo.query_secdesc.in.secinfo_flags = SECINFO_DACL | SECINFO_OWNER;

	status = smb2_getinfo_file(tree, tctx, &getinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file\n");

	sd_orig = getinfo.query_secdesc.out.sd;
	owner_sid = dom_sid_string(tctx, sd_orig->owner_sid);

	sd = security_descriptor_dacl_create(tctx,
					     0, NULL, NULL,
					     owner_sid,
					     SEC_ACE_TYPE_ACCESS_ALLOWED,
					     SEC_FILE_WRITE_DATA,
					     0,
					     NULL);

	/* Try to set ACL */

	ZERO_STRUCT(setinfo);
	setinfo.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	setinfo.set_secdesc.in.file.handle = h1;
	setinfo.set_secdesc.in.secinfo_flags = SECINFO_DACL;
	setinfo.set_secdesc.in.sd = sd;

	status = smb2_setinfo_file(tree, &setinfo);
	torture_assert_ntstatus_equal_goto(
		tctx,
		status,
		NT_STATUS_MEDIA_WRITE_PROTECTED,
		ret, done,
		"smb2_setinfo_file\n");

	/* Try to delete */

	ZERO_STRUCT(setinfo);
	setinfo.generic.level = RAW_SFILEINFO_DISPOSITION_INFORMATION;
	setinfo.disposition_info.in.delete_on_close = 1;
	setinfo.generic.in.file.handle = h1;

	status = smb2_setinfo_file(tree, &setinfo);
	torture_assert_ntstatus_equal_goto(
		tctx,
		status,
		NT_STATUS_MEDIA_WRITE_PROTECTED,
		ret, done,
		"smb2_setinfo_file\n");

	ZERO_STRUCT(setinfo);
	setinfo.basic_info.in.attrib = FILE_ATTRIBUTE_HIDDEN;
	setinfo.generic.level = RAW_SFILEINFO_BASIC_INFORMATION;
	setinfo.generic.in.file.handle = h1;

	status = smb2_setinfo_file(tree, &setinfo);
	torture_assert_ntstatus_equal_goto(
		tctx,
		status,
		NT_STATUS_MEDIA_WRITE_PROTECTED,
		ret, done,
		"smb2_setinfo_file\n");

	/* Try to truncate */

	ZERO_STRUCT(setinfo);
	setinfo.generic.level = SMB_SFILEINFO_END_OF_FILE_INFORMATION;
	setinfo.generic.in.file.handle = h1;
	setinfo.end_of_file_info.in.size = 0x100000;

	status = smb2_setinfo_file(tree, &setinfo);
	torture_assert_ntstatus_equal_goto(
		tctx,
		status,
		NT_STATUS_MEDIA_WRITE_PROTECTED,
		ret, done,
		"smb2_setinfo_file\n");

	/* Try to set a hardlink */

	ZERO_STRUCT(setinfo);
	setinfo.generic.level = RAW_SFILEINFO_LINK_INFORMATION;
	setinfo.generic.in.file.handle = h1;
	setinfo.link_information.in.new_name = "hardlink";

	status = smb2_setinfo_file(tree, &setinfo);
	torture_assert_ntstatus_equal_goto(
		tctx,
		status,
		NT_STATUS_NOT_SAME_DEVICE,
		ret, done,
		"smb2_setinfo_file\n");

	/* Try to rename */

	ZERO_STRUCT(setinfo);
	setinfo.rename_information.level = RAW_SFILEINFO_RENAME_INFORMATION;
	setinfo.rename_information.in.file.handle = h1;
	setinfo.rename_information.in.new_name = "renamed";

	status = smb2_setinfo_file(tree, &setinfo);
	torture_assert_ntstatus_equal_goto(
		tctx,
		status,
		NT_STATUS_NOT_SAME_DEVICE,
		ret, done,
		"smb2_setinfo_file\n");

	smb2_util_close(tree, h1);
	ZERO_STRUCT(h1);

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	return ret;
}

static bool test_twrp_stream(struct torture_context *tctx,
			     struct smb2_tree *tree)
{
	struct smb2_create io;
	NTSTATUS status;
	bool ret = true;
	char *p = NULL;
	struct tm tm;
	time_t t;
	uint64_t nttime;
	const char *file = NULL;
	const char *stream = NULL;
	const char *snapshot = NULL;
	int stream_size;
	char *path = NULL;
	uint8_t *buf = NULL;
	struct smb2_handle h1 = {{0}};
	struct smb2_read r;

	file = torture_setting_string(tctx, "twrp_file", NULL);
	if (file == NULL) {
		torture_skip(tctx, "missing 'twrp_file' option\n");
	}

	stream = torture_setting_string(tctx, "twrp_stream", NULL);
	if (stream == NULL) {
		torture_skip(tctx, "missing 'twrp_stream' option\n");
	}

	snapshot = torture_setting_string(tctx, "twrp_snapshot", NULL);
	if (snapshot == NULL) {
		torture_skip(tctx, "missing 'twrp_snapshot' option\n");
	}

	stream_size = torture_setting_int(tctx, "twrp_stream_size", 0);
	if (stream_size == 0) {
		torture_skip(tctx, "missing 'twrp_stream_size' option\n");
	}

	torture_comment(tctx, "Testing timewarp on stream (%s) (%s)\n",
			file, snapshot);

	path = talloc_asprintf(tree, "%s:%s", file, stream);
	torture_assert_not_null_goto(tctx, path, ret, done, "path\n");

	buf = talloc_zero_array(tree, uint8_t, stream_size);
	torture_assert_not_null_goto(tctx, buf, ret, done, "buf\n");

	setenv("TZ", "GMT", 1);

	/* strptime does not set tm.tm_isdst but mktime assumes DST is in
	 * effect if it is greather than 1. */
	ZERO_STRUCT(tm);

	p = strptime(snapshot, "@GMT-%Y.%m.%d-%H.%M.%S", &tm);
	torture_assert_goto(tctx, p != NULL, ret, done, "strptime\n");
	torture_assert_goto(tctx, *p == '\0', ret, done, "strptime\n");

	t = mktime(&tm);
	unix_to_nt_time(&nttime, t);

	io = (struct smb2_create) {
		.in.desired_access = SEC_FILE_READ_DATA,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.fname = path,
		.in.timewarp = nttime,
	};

	status = smb2_create(tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create\n");
	h1 = io.out.file.handle;

	r = (struct smb2_read) {
		.in.file.handle = h1,
		.in.length = stream_size,
		.in.offset = 0,
	};

	status = smb2_read(tree, tree, &r);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create\n");

	smb2_util_close(tree, h1);

done:
	return ret;
}

static bool test_twrp_openroot(struct torture_context *tctx, struct smb2_tree *tree)
{
	struct smb2_create io;
	NTSTATUS status;
	bool ret = true;
	char *p = NULL;
	struct tm tm;
	time_t t;
	uint64_t nttime;
	const char *snapshot = NULL;

	snapshot = torture_setting_string(tctx, "twrp_snapshot", NULL);
	if (snapshot == NULL) {
		torture_skip(tctx, "missing 'twrp_snapshot' option\n");
	}

	torture_comment(tctx, "Testing open of root of "
		"share with timewarp (%s)\n",
		snapshot);

	setenv("TZ", "GMT", 1);

	/* strptime does not set tm.tm_isdst but mktime assumes DST is in
	 * effect if it is greather than 1. */
	ZERO_STRUCT(tm);

	p = strptime(snapshot, "@GMT-%Y.%m.%d-%H.%M.%S", &tm);
	torture_assert_goto(tctx, p != NULL, ret, done, "strptime\n");
	torture_assert_goto(tctx, *p == '\0', ret, done, "strptime\n");

	t = mktime(&tm);
	unix_to_nt_time(&nttime, t);

	io = (struct smb2_create) {
		.in.desired_access = SEC_FILE_READ_DATA,
		.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.fname = "",
		.in.create_options = NTCREATEX_OPTIONS_DIRECTORY,
		.in.timewarp = nttime,
	};

	status = smb2_create(tree, tctx, &io);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create\n");
	smb2_util_close(tree, io.out.file.handle);

done:
	return ret;
}

static bool test_twrp_listdir(struct torture_context *tctx,
			      struct smb2_tree *tree)
{
	struct smb2_create create;
	struct smb2_handle h = {{0}};
	struct smb2_find find;
	unsigned int count;
	union smb_search_data *d;
	char *p = NULL;
	struct tm tm;
	time_t t;
	uint64_t nttime;
	const char *snapshot = NULL;
	uint64_t normal_fileid;
	uint64_t snapshot_fileid;
	NTSTATUS status;
	bool ret = true;

	snapshot = torture_setting_string(tctx, "twrp_snapshot", NULL);
	if (snapshot == NULL) {
		torture_fail(tctx, "missing 'twrp_snapshot' option\n");
	}

	torture_comment(tctx, "Testing File-Ids of directory listing "
			"with timewarp (%s)\n",
			snapshot);

	setenv("TZ", "GMT", 1);

	/* strptime does not set tm.tm_isdst but mktime assumes DST is in
	 * effect if it is greather than 1. */
	ZERO_STRUCT(tm);

	p = strptime(snapshot, "@GMT-%Y.%m.%d-%H.%M.%S", &tm);
	torture_assert_goto(tctx, p != NULL, ret, done, "strptime\n");
	torture_assert_goto(tctx, *p == '\0', ret, done, "strptime\n");

	t = mktime(&tm);
	unix_to_nt_time(&nttime, t);

	/*
	 * 1: Query the file's File-Id
	 */
	create = (struct smb2_create) {
		.in.desired_access = SEC_FILE_READ_DATA,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.fname = "subdir/hardlink",
		.in.query_on_disk_id = true,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test file could not be created\n");
	smb2_util_close(tree, create.out.file.handle);
	normal_fileid = BVAL(&create.out.on_disk_id, 0);

	/*
	 * 2: check directory listing of the file returns same File-Id
	 */

	create = (struct smb2_create) {
		.in.desired_access = SEC_DIR_LIST,
		.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.fname = "subdir",
		.in.create_options = NTCREATEX_OPTIONS_DIRECTORY,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create\n");
	h = create.out.file.handle;

	find = (struct smb2_find) {
		.in.file.handle = h,
		.in.pattern = "*",
		.in.max_response_size = 0x1000,
		.in.level = SMB2_FIND_ID_BOTH_DIRECTORY_INFO,
	};

	status = smb2_find_level(tree, tree, &find, &count, &d);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_find_level failed\n");

	smb2_util_close(tree, h);

	torture_assert_int_equal_goto(tctx, count, 3, ret, done, "Bad count\n");
	torture_assert_str_equal_goto(tctx,
				      d[2].id_both_directory_info.name.s,
				      "hardlink",
				      ret, done, "bad name");
	torture_assert_u64_equal_goto(tctx,
				      d[2].id_both_directory_info.file_id,
				      normal_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * 3: Query File-Id of snapshot of the file and check the File-Id is
	 * different compared to the basefile
	 */

	create = (struct smb2_create) {
		.in.desired_access = SEC_FILE_READ_DATA,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.fname = "subdir/hardlink",
		.in.query_on_disk_id = true,
		.in.timewarp = nttime,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test file could not be created\n");
	smb2_util_close(tree, create.out.file.handle);

	snapshot_fileid = BVAL(&create.out.on_disk_id, 0);

	/*
	 * 4: List directory of the snapshot and check the File-Id returned here
	 * is the same as in 3.
	 */

	create = (struct smb2_create) {
		.in.desired_access = SEC_DIR_LIST,
		.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.fname = "subdir",
		.in.create_options = NTCREATEX_OPTIONS_DIRECTORY,
		.in.timewarp = nttime,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create\n");
	h = create.out.file.handle;

	find = (struct smb2_find) {
		.in.file.handle = h,
		.in.pattern = "*",
		.in.max_response_size = 0x1000,
		.in.level = SMB2_FIND_ID_BOTH_DIRECTORY_INFO,
	};

	status = smb2_find_level(tree, tree, &find, &count, &d);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_find_level failed\n");
	smb2_util_close(tree, h);

	torture_assert_int_equal_goto(tctx, count, 3, ret, done, "Bad count\n");
	torture_assert_str_equal_goto(tctx,
				      d[2].id_both_directory_info.name.s,
				      "hardlink",
				      ret, done, "bad name");
	torture_assert_u64_equal_goto(tctx,
				      snapshot_fileid,
				      d[2].id_both_directory_info.file_id,
				      ret, done, "bad fileid\n");

done:
	return ret;
}

static bool test_fileid(struct torture_context *tctx,
			struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *fname = DNAME "\\foo";
	const char *sname = DNAME "\\foo:bar";
	struct smb2_handle testdirh;
	struct smb2_handle h1;
	struct smb2_create create;
	union smb_fileinfo finfo;
	union smb_setfileinfo sinfo;
	struct smb2_find f;
	unsigned int count;
	union smb_search_data *d;
	uint64_t expected_fileid;
	uint64_t returned_fileid;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, DNAME);

	status = torture_smb2_testdir(tree, DNAME, &testdirh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");

	/*
	 * Initial create with QFID
	 */
	create = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.fname = fname,
		.in.query_on_disk_id = true,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test file could not be created\n");
	h1 = create.out.file.handle;
	expected_fileid = BVAL(&create.out.on_disk_id, 0);

	/*
	 * Getinfo the File-ID on the just opened handle
	 */
	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};

	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir\n");
	smb2_util_close(tree, h1);
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Open existing with QFID
	 */
	create = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.fname = fname,
		.in.query_on_disk_id = true,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test file could not be created\n");
	h1 = create.out.file.handle;
	returned_fileid = BVAL(&create.out.on_disk_id, 0);
	torture_assert_u64_equal_goto(tctx, returned_fileid, expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Getinfo the File-ID on the just opened handle
	 */
	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};

	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir\n");
	smb2_util_close(tree, h1);
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Overwrite with QFID
	 */
	create = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OVERWRITE,
		.in.fname = fname,
		.in.query_on_disk_id = true,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test file could not be created\n");
	h1 = create.out.file.handle;
	returned_fileid = BVAL(&create.out.on_disk_id, 0);
	torture_assert_u64_equal_goto(tctx, returned_fileid, expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Getinfo the File-ID on the open with overwrite handle
	 */
	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};

	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir\n");
	smb2_util_close(tree, h1);
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Do some modifications on the basefile (IO, setinfo), verifying
	 * File-ID after each step.
	 */
	create = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.fname = fname,
		.in.query_on_disk_id = true,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test file could not be created\n");
	h1 = create.out.file.handle;

	status = smb2_util_write(tree, h1, "foo", 0, strlen("foo"));
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_write failed\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	sinfo = (union smb_setfileinfo) {
		.basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION,
		.basic_info.in.file.handle = h1,
	};
	unix_to_nt_time(&sinfo.basic_info.in.write_time, time(NULL));

	status = smb2_setinfo_file(tree, &sinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");
	smb2_util_close(tree, h1);
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Create stream, check the stream's File-ID, should be the same as the
	 * base file (sic!, tested against Windows).
	 */
	create = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_CREATE,
		.in.fname = sname,
		.in.query_on_disk_id = true,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test file could not be created\n");
	h1 = create.out.file.handle;
	returned_fileid = BVAL(&create.out.on_disk_id, 0);
	torture_assert_u64_equal_goto(tctx, returned_fileid, expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Getinfo the File-ID on the created stream
	 */
	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};

	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");
	smb2_util_close(tree, h1);
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Open stream, check the stream's File-ID, should be the same as the
	 * base file (sic!, tested against Windows).
	 */
	create = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.fname = sname,
		.in.query_on_disk_id = true,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test file could not be created\n");
	h1 = create.out.file.handle;
	returned_fileid = BVAL(&create.out.on_disk_id, 0);
	torture_assert_u64_equal_goto(tctx, returned_fileid, expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Getinfo the File-ID on the opened stream
	 */
	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};

	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");
	smb2_util_close(tree, h1);
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Overwrite stream, check the stream's File-ID, should be the same as
	 * the base file (sic!, tested against Windows).
	 */
	create = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OVERWRITE,
		.in.fname = sname,
		.in.query_on_disk_id = true,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test file could not be created\n");
	h1 = create.out.file.handle;
	returned_fileid = BVAL(&create.out.on_disk_id, 0);
	torture_assert_u64_equal_goto(tctx, returned_fileid, expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Getinfo the File-ID on the overwritten stream
	 */
	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};

	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");
	smb2_util_close(tree, h1);
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Do some modifications on the stream (IO, setinfo), verifying File-ID
	 * after earch step.
	 */
	create = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.fname = sname,
		.in.query_on_disk_id = true,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test file could not be created\n");
	h1 = create.out.file.handle;

	status = smb2_util_write(tree, h1, "foo", 0, strlen("foo"));
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_write failed\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	sinfo = (union smb_setfileinfo) {
		.basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION,
		.basic_info.in.file.handle = h1,
	};
	unix_to_nt_time(&sinfo.basic_info.in.write_time, time(NULL));

	status = smb2_setinfo_file(tree, &sinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");
	smb2_util_close(tree, h1);
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Final open of the basefile with QFID
	 */
	create = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.fname = fname,
		.in.query_on_disk_id = true,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test file could not be created\n");
	h1 = create.out.file.handle;
	returned_fileid = BVAL(&create.out.on_disk_id, 0);
	torture_assert_u64_equal_goto(tctx, returned_fileid, expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Final Getinfo checking File-ID
	 */
	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};

	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir\n");
	smb2_util_close(tree, h1);
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Final list directory, verifying the operations on basefile and stream
	 * didn't modify the base file metadata.
	 */
	f = (struct smb2_find) {
		.in.file.handle = testdirh,
		.in.pattern = "foo",
		.in.max_response_size = 0x1000,
		.in.level = SMB2_FIND_ID_BOTH_DIRECTORY_INFO,
		.in.continue_flags = SMB2_CONTINUE_FLAG_RESTART,
	};

	status = smb2_find_level(tree, tree, &f, &count, &d);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_find_level failed\n");
	torture_assert_u64_equal_goto(tctx,
				      d->id_both_directory_info.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

done:
	smb2_util_close(tree, testdirh);
	smb2_deltree(tree, DNAME);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_fileid_dir(struct torture_context *tctx,
			    struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	const char *dname = DNAME "\\foo";
	const char *sname = DNAME "\\foo:bar";
	struct smb2_handle testdirh;
	struct smb2_handle h1;
	struct smb2_create create;
	union smb_fileinfo finfo;
	union smb_setfileinfo sinfo;
	struct smb2_find f;
	unsigned int count;
	union smb_search_data *d;
	uint64_t expected_fileid;
	uint64_t returned_fileid;
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, DNAME);

	status = torture_smb2_testdir(tree, DNAME, &testdirh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir failed\n");

	/*
	 * Initial directory create with QFID
	 */
	create = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY,
		.in.create_options = NTCREATEX_OPTIONS_DIRECTORY,
		.in.fname = dname,
		.in.query_on_disk_id = true,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test file could not be created\n");
	h1 = create.out.file.handle;
	expected_fileid = BVAL(&create.out.on_disk_id, 0);

	/*
	 * Getinfo the File-ID on the just opened handle
	 */
	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};

	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir\n");
	smb2_util_close(tree, h1);
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Open existing directory with QFID
	 */
	create = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY,
		.in.create_options = NTCREATEX_OPTIONS_DIRECTORY,
		.in.fname = dname,
		.in.query_on_disk_id = true,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test file could not be created\n");
	h1 = create.out.file.handle;
	returned_fileid = BVAL(&create.out.on_disk_id, 0);
	torture_assert_u64_equal_goto(tctx, returned_fileid, expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Getinfo the File-ID on the just opened handle
	 */
	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};

	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir\n");
	smb2_util_close(tree, h1);
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Create stream, check the stream's File-ID, should be the same as the
	 * base file (sic!, tested against Windows).
	 */
	create = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_CREATE,
		.in.fname = sname,
		.in.query_on_disk_id = true,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test file could not be created\n");
	h1 = create.out.file.handle;
	returned_fileid = BVAL(&create.out.on_disk_id, 0);
	torture_assert_u64_equal_goto(tctx, returned_fileid, expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Getinfo the File-ID on the created stream
	 */
	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};

	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");
	smb2_util_close(tree, h1);
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Open stream, check the stream's File-ID, should be the same as the
	 * base file (sic!, tested against Windows).
	 */
	create = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.fname = sname,
		.in.query_on_disk_id = true,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test file could not be created\n");
	h1 = create.out.file.handle;
	returned_fileid = BVAL(&create.out.on_disk_id, 0);
	torture_assert_u64_equal_goto(tctx, returned_fileid, expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Getinfo the File-ID on the opened stream
	 */
	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};

	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");
	smb2_util_close(tree, h1);
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Overwrite stream, check the stream's File-ID, should be the same as
	 * the base file (sic!, tested against Windows).
	 */
	create = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OVERWRITE,
		.in.fname = sname,
		.in.query_on_disk_id = true,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test file could not be created\n");
	h1 = create.out.file.handle;
	returned_fileid = BVAL(&create.out.on_disk_id, 0);
	torture_assert_u64_equal_goto(tctx, returned_fileid, expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Getinfo the File-ID on the overwritten stream
	 */
	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};

	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");
	smb2_util_close(tree, h1);
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Do some modifications on the stream (IO, setinfo), verifying File-ID
	 * after earch step.
	 */
	create = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.fname = sname,
		.in.query_on_disk_id = true,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test file could not be created\n");
	h1 = create.out.file.handle;

	status = smb2_util_write(tree, h1, "foo", 0, strlen("foo"));
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_util_write failed\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	sinfo = (union smb_setfileinfo) {
		.basic_info.level = RAW_SFILEINFO_BASIC_INFORMATION,
		.basic_info.in.file.handle = h1,
	};
	unix_to_nt_time(&sinfo.basic_info.in.write_time, time(NULL));

	status = smb2_setinfo_file(tree, &sinfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_setinfo_file failed\n");

	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};
	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_getinfo_file failed\n");
	smb2_util_close(tree, h1);
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Final open of the directory with QFID
	 */
	create = (struct smb2_create) {
		.in.desired_access = SEC_FILE_ALL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY,
		.in.create_options = NTCREATEX_OPTIONS_DIRECTORY,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.fname = dname,
		.in.query_on_disk_id = true,
	};

	status = smb2_create(tree, tctx, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test file could not be created\n");
	h1 = create.out.file.handle;
	returned_fileid = BVAL(&create.out.on_disk_id, 0);
	torture_assert_u64_equal_goto(tctx, returned_fileid, expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Final Getinfo checking File-ID
	 */
	finfo = (union smb_fileinfo) {
		.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
		.generic.in.file.handle = h1,
	};

	status = smb2_getinfo_file(tree, tctx, &finfo);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"torture_smb2_testdir\n");
	smb2_util_close(tree, h1);
	torture_assert_u64_equal_goto(tctx, finfo.all_info2.out.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

	/*
	 * Final list directory, verifying the operations on basefile and stream
	 * didn't modify the base file metadata.
	 */
	f = (struct smb2_find) {
		.in.file.handle = testdirh,
		.in.pattern = "foo",
		.in.max_response_size = 0x1000,
		.in.level = SMB2_FIND_ID_BOTH_DIRECTORY_INFO,
		.in.continue_flags = SMB2_CONTINUE_FLAG_RESTART,
	};

	status = smb2_find_level(tree, tree, &f, &count, &d);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_find_level failed\n");
	torture_assert_u64_equal_goto(tctx,
				      d->id_both_directory_info.file_id,
				      expected_fileid,
				      ret, done, "bad fileid\n");

done:
	smb2_util_close(tree, testdirh);
	smb2_deltree(tree, DNAME);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_fileid_unique_object(
			struct torture_context *tctx,
			struct smb2_tree *tree,
			unsigned int num_objs,
			bool create_dirs)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char *fname = NULL;
	struct smb2_handle testdirh;
	struct smb2_handle h1;
	struct smb2_create create;
	unsigned int i;
	uint64_t fileid_array[num_objs];
	NTSTATUS status;
	bool ret = true;

	smb2_deltree(tree, DNAME);

	status = torture_smb2_testdir(tree, DNAME, &testdirh);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"test_fileid_unique failed\n");
	smb2_util_close(tree, testdirh);

	/* Create num_obj files as rapidly as we can. */
	for (i = 0; i < num_objs; i++) {
		fname = talloc_asprintf(mem_ctx,
					"%s\\testfile.%u",
					DNAME,
					i);
		torture_assert_goto(tctx,
				fname != NULL,
				ret,
				done,
				"talloc failed\n");

		create = (struct smb2_create) {
			.in.desired_access = SEC_FILE_READ_ATTRIBUTE,
			.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
			.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
			.in.create_disposition = NTCREATEX_DISP_CREATE,
			.in.fname = fname,
		};

		if (create_dirs) {
			create.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
			create.in.create_options = FILE_DIRECTORY_FILE;
		}

		status = smb2_create(tree, tctx, &create);
		if (!NT_STATUS_IS_OK(status)) {
			torture_fail(tctx,
				talloc_asprintf(tctx,
					"test file %s could not be created\n",
					fname));
			TALLOC_FREE(fname);
			ret = false;
			goto done;
		}

		h1 = create.out.file.handle;
		smb2_util_close(tree, h1);
		TALLOC_FREE(fname);
	}

	/*
	 * Get the file ids.
	 */
	for (i = 0; i < num_objs; i++) {
		union smb_fileinfo finfo;

		fname = talloc_asprintf(mem_ctx,
					"%s\\testfile.%u",
					DNAME,
					i);
		torture_assert_goto(tctx,
				fname != NULL,
				ret,
				done,
				"talloc failed\n");

		create = (struct smb2_create) {
			.in.desired_access = SEC_FILE_READ_ATTRIBUTE,
			.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
			.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
			.in.create_disposition = NTCREATEX_DISP_OPEN,
			.in.fname = fname,
		};

		if (create_dirs) {
			create.in.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
			create.in.create_options = FILE_DIRECTORY_FILE;
		}

		status = smb2_create(tree, tctx, &create);
		if (!NT_STATUS_IS_OK(status)) {
			torture_fail(tctx,
				talloc_asprintf(tctx,
					"test file %s could not "
					"be opened: %s\n",
					fname,
					nt_errstr(status)));
			TALLOC_FREE(fname);
			ret = false;
			goto done;
		}

		h1 = create.out.file.handle;

		finfo = (union smb_fileinfo) {
			.generic.level = RAW_FILEINFO_SMB2_ALL_INFORMATION,
			.generic.in.file.handle = h1,
		};

		status = smb2_getinfo_file(tree, tctx, &finfo);
		if (!NT_STATUS_IS_OK(status)) {
			torture_fail(tctx,
				talloc_asprintf(tctx,
					"failed to get fileid for "
					"test file %s: %s\n",
					fname,
					nt_errstr(status)));
			TALLOC_FREE(fname);
			ret = false;
			goto done;
		}
		smb2_util_close(tree, h1);

		fileid_array[i] = finfo.all_info2.out.file_id;
		TALLOC_FREE(fname);
	}

	/* All returned fileids must be unique. 100 is small so brute force. */
	for (i = 0; i < num_objs - 1; i++) {
		unsigned int j;
		for (j = i + 1; j < num_objs; j++) {
			if (fileid_array[i] == fileid_array[j]) {
				torture_fail(tctx,
					talloc_asprintf(tctx,
						"fileid %u == fileid %u (0x%"PRIu64")\n",
						i,
						j,
						fileid_array[i]));
				ret = false;
				goto done;
			}
		}
	}

done:

	smb2_util_close(tree, testdirh);
	smb2_deltree(tree, DNAME);
	talloc_free(mem_ctx);
	return ret;
}

static bool test_fileid_unique(
			struct torture_context *tctx,
			struct smb2_tree *tree)
{
	return test_fileid_unique_object(tctx, tree, 100, false);
}

static bool test_fileid_unique_dir(
			struct torture_context *tctx,
			struct smb2_tree *tree)
{
	return test_fileid_unique_object(tctx, tree, 100, true);
}

static bool test_dosattr_tmp_dir(struct torture_context *tctx,
				 struct smb2_tree *tree)
{
	bool ret = true;
	NTSTATUS status;
	struct smb2_create c;
	struct smb2_handle h1 = {{0}};
	const char *fname = DNAME;

	smb2_deltree(tree, fname);
	smb2_util_rmdir(tree, fname);

	c = (struct smb2_create) {
		.in.desired_access = SEC_RIGHTS_DIR_ALL,
		.in.file_attributes  = FILE_ATTRIBUTE_DIRECTORY,
		.in.create_disposition = NTCREATEX_DISP_OPEN_IF,
		.in.share_access = NTCREATEX_SHARE_ACCESS_READ |
			NTCREATEX_SHARE_ACCESS_WRITE |
			NTCREATEX_SHARE_ACCESS_DELETE,
		.in.create_options = NTCREATEX_OPTIONS_DIRECTORY,
		.in.fname = DNAME,
	};

	status = smb2_create(tree, tctx, &c);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create\n");
	h1 = c.out.file.handle;

	/* Try to set temporary attribute on directory */
	SET_ATTRIB(FILE_ATTRIBUTE_TEMPORARY);

	torture_assert_ntstatus_equal_goto(tctx, status,
					   NT_STATUS_INVALID_PARAMETER,
					   ret, done,
					   "Unexpected setinfo result\n");

done:
	if (!smb2_util_handle_empty(h1)) {
		smb2_util_close(tree, h1);
	}
	smb2_util_unlink(tree, fname);
	smb2_deltree(tree, fname);

	return ret;
}

/*
  test opening quota fakefile handle and returned attributes
*/
static bool test_smb2_open_quota_fake_file(struct torture_context *tctx,
					   struct smb2_tree *tree)
{
	const char *fname = "$Extend\\$Quota:$Q:$INDEX_ALLOCATION";
	struct smb2_create create;
	struct smb2_handle h = {{0}};
	NTSTATUS status;
	bool ret = true;

	create = (struct smb2_create) {
		.in.desired_access = SEC_RIGHTS_FILE_READ,
		.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
		.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
		.in.create_disposition = NTCREATEX_DISP_OPEN,
		.in.impersonation_level = SMB2_IMPERSONATION_ANONYMOUS,
		.in.fname = fname,
	};

	status = smb2_create(tree, tree, &create);
	torture_assert_ntstatus_ok_goto(tctx, status, ret, done,
					"smb2_create failed\n");
	h = create.out.file.handle;

	torture_assert_u64_equal_goto(tctx,
				      create.out.file_attr,
				      FILE_ATTRIBUTE_HIDDEN
				      | FILE_ATTRIBUTE_SYSTEM
				      | FILE_ATTRIBUTE_DIRECTORY
				      | FILE_ATTRIBUTE_ARCHIVE,
				      ret,
				      done,
				      "Wrong attributes\n");

	torture_assert_u64_equal_goto(tctx,
				      create.out.create_time, 0,
				      ret,
				      done,
				      "create_time is not 0\n");
	torture_assert_u64_equal_goto(tctx,
				      create.out.access_time, 0,
				      ret,
				      done,
				      "access_time is not 0\n");
	torture_assert_u64_equal_goto(tctx,
				      create.out.write_time, 0,
				      ret,
				      done,
				      "write_time is not 0\n");
	torture_assert_u64_equal_goto(tctx,
				      create.out.change_time, 0,
				      ret,
				      done,
				      "change_time is not 0\n");

done:
	smb2_util_close(tree, h);
	return ret;
}

/**
  Find Maximum Path Length
 */
static bool generate_path(const size_t len,
			  char *buffer,
			  const size_t buf_len)
{
	size_t i;

	if (len >= buf_len) {
		return false;
	}

	for (i = 0; i < len ; i++) {
		buffer[i] = (char)(i % 10) + 48;
	}
	buffer[i] = '\0';
	return true;
}

static bool test_path_length_test(struct torture_context *tctx,
				  struct smb2_tree *tree)
{
	const size_t max_name = 2048;
	char *name = talloc_array(tctx, char, max_name);
	struct smb2_handle fh = {{0}};
	size_t length = 128;
	size_t max_file_name = 0;
	size_t max_path_length = 0;
	char *path_ok = NULL;
	char *path_next = NULL;
	char *topdir = NULL;
	bool is_interactive = torture_setting_bool(tctx, "interactive", false);
	NTSTATUS status;
	bool ret = true;

	if (!is_interactive) {
		torture_result(tctx, TORTURE_SKIP,
			       "Interactive Test: Skipping... "
			       "(enable with --interactive)\n");
		return ret;
	}

	torture_comment(tctx, "Testing filename and path lengths\n");

	/* Find Longest File Name */
	for (length = 128; length < max_name; length++) {
		if (!generate_path(length, name, max_name))  {
			torture_result(tctx, TORTURE_FAIL,
				       "Failed to generate path.");
			return false;
		}

		status = torture_smb2_testfile(tree, name, &fh);
		if (!NT_STATUS_IS_OK(status)) {
			break;
		}

		smb2_util_close(tree, fh);
		smb2_util_unlink(tree, name);

		max_file_name = length;
	}

	torture_assert_int_not_equal_goto(tctx, length, max_name, ret, done,
					  "Name too big\n");

	torture_comment(tctx, "Max file name length: %zu\n", max_file_name);

	/* Remove one char that caused the failure above */
	name[max_file_name] = '\0';

	path_ok = talloc_strdup(tree, name);
	torture_assert_not_null_goto(tctx, path_ok, ret, done,
				     "talloc_strdup failed\n");

	topdir = talloc_strdup(tree, name);
	torture_assert_not_null_goto(tctx, topdir, ret, done,
				     "talloc_strdup failed\n");

	status = smb2_util_mkdir(tree, path_ok);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "mkdir [%s] failed: %s\n",
				path_ok, nt_errstr(status));
		torture_result(tctx, TORTURE_FAIL, "Initial mkdir failed");
		return false;
	}

	while (true) {
		path_next = talloc_asprintf(tctx, "%s\\%s", path_ok, name);
		torture_assert_not_null_goto(tctx, path_next, ret, done,
					     "talloc_asprintf failed\n");

		status = smb2_util_mkdir(tree, path_next);
		if (!NT_STATUS_IS_OK(status)) {
			break;
		}

		path_ok = path_next;
	}

	for (length = 1; length < max_name; length++) {
		if (!generate_path(length, name, max_name))  {
			torture_result(tctx, TORTURE_FAIL,
				       "Failed to generate path.");
			return false;
		}

		path_next = talloc_asprintf(tctx, "%s\\%s", path_ok, name);
		torture_assert_not_null_goto(tctx, path_next, ret, done,
					     "talloc_asprintf failed\n");

		status = torture_smb2_testfile(tree, path_next, &fh);
		if (!NT_STATUS_IS_OK(status)) {
			break;
		}
		smb2_util_close(tree, fh);
		path_ok = path_next;
	}

	max_path_length = talloc_array_length(path_ok);

	torture_comment(tctx, "Max path name length: %zu\n", max_path_length);

done:
	return ret;
}

/*
   basic testing of SMB2 read
*/
struct torture_suite *torture_smb2_create_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "create");

	torture_suite_add_1smb2_test(suite, "gentest", test_create_gentest);
	torture_suite_add_1smb2_test(suite, "blob", test_create_blob);
	torture_suite_add_1smb2_test(suite, "open", test_smb2_open);
	torture_suite_add_1smb2_test(suite, "brlocked", test_smb2_open_brlocked);
	torture_suite_add_1smb2_test(suite, "multi", test_smb2_open_multi);
	torture_suite_add_1smb2_test(suite, "delete", test_smb2_open_for_delete);
	torture_suite_add_1smb2_test(suite, "leading-slash", test_smb2_leading_slash);
	torture_suite_add_1smb2_test(suite, "impersonation", test_smb2_impersonation_level);
	torture_suite_add_1smb2_test(suite, "aclfile", test_create_acl_file);
	torture_suite_add_1smb2_test(suite, "acldir", test_create_acl_dir);
	torture_suite_add_1smb2_test(suite, "nulldacl", test_create_null_dacl);
	torture_suite_add_1smb2_test(suite, "mkdir-dup", test_mkdir_dup);
	torture_suite_add_1smb2_test(suite, "dir-alloc-size", test_dir_alloc_size);
	torture_suite_add_1smb2_test(suite, "dosattr_tmp_dir", test_dosattr_tmp_dir);
	torture_suite_add_1smb2_test(suite, "quota-fake-file", test_smb2_open_quota_fake_file);
	torture_suite_add_1smb2_test(suite, "path-length", test_path_length_test);
	torture_suite_add_1smb2_test(suite, "bench-path-contention-shared", test_smb2_bench_path_contention_shared);

	suite->description = talloc_strdup(suite, "SMB2-CREATE tests");

	return suite;
}

struct torture_suite *torture_smb2_twrp_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "twrp");

	torture_suite_add_1smb2_test(suite, "write", test_twrp_write);
	torture_suite_add_1smb2_test(suite, "stream", test_twrp_stream);
	torture_suite_add_1smb2_test(suite, "openroot", test_twrp_openroot);
	torture_suite_add_1smb2_test(suite, "listdir", test_twrp_listdir);

	suite->description = talloc_strdup(suite, "SMB2-TWRP tests");

	return suite;
}

/*
   basic testing of SMB2 File-IDs
*/
struct torture_suite *torture_smb2_fileid_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "fileid");

	torture_suite_add_1smb2_test(suite, "fileid", test_fileid);
	torture_suite_add_1smb2_test(suite, "fileid-dir", test_fileid_dir);
	torture_suite_add_1smb2_test(suite, "unique", test_fileid_unique);
	torture_suite_add_1smb2_test(suite, "unique-dir", test_fileid_unique_dir);

	suite->description = talloc_strdup(suite, "SMB2-FILEID tests");

	return suite;
}

static bool test_no_stream(struct torture_context *tctx,
			   struct smb2_tree *tree)
{
	struct smb2_create c;
	NTSTATUS status;
	bool ret = true;
	const char *names[] = {
		"test_no_stream::$DATA",
		"test_no_stream::foooooooooooo",
		"test_no_stream:stream",
		"test_no_stream:stream:$DATA",
		NULL
	};
	int i;

	for (i = 0; names[i] != NULL; i++) {
		c = (struct smb2_create) {
			.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED,
			.in.file_attributes = FILE_ATTRIBUTE_NORMAL,
			.in.create_disposition = NTCREATEX_DISP_OPEN,
			.in.share_access = NTCREATEX_SHARE_ACCESS_MASK,
			.in.fname = names[i],
		};

		status = smb2_create(tree, tctx, &c);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_INVALID)) {
			torture_comment(
				tctx, "Expected NT_STATUS_OBJECT_NAME_INVALID, "
				"got %s, name: '%s'\n",
				nt_errstr(status), names[i]);
			torture_fail_goto(tctx, done, "Bad create result\n");
		}
	}
done:
	return ret;
}

struct torture_suite *torture_smb2_create_no_streams_init(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "create_no_streams");

	torture_suite_add_1smb2_test(suite, "no_stream", test_no_stream);

	suite->description = talloc_strdup(suite, "SMB2-CREATE stream test on share without streams support");

	return suite;
}

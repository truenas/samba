/*
   Unix SMB/CIFS implementation.
   file closing
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 1992-2007.
   Copyright (C) Volker Lendecke 2005

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
#include "lib/util/server_id.h"
#include "printing.h"
#include "locking/share_mode_lock.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "smbd/smbXsrv_open.h"
#include "smbd/scavenger.h"
#include "fake_file.h"
#include "transfer_file.h"
#include "auth.h"
#include "messages.h"
#include "../librpc/gen_ndr/open_files.h"
#include "lib/util/tevent_ntstatus.h"
#include "source3/smbd/dir.h"

/****************************************************************************
 Run a file if it is a magic script.
****************************************************************************/

static NTSTATUS check_magic(struct files_struct *fsp)
{
	int ret;
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	const char *magic_output = NULL;
	SMB_STRUCT_STAT st;
	int tmp_fd, outfd;
	TALLOC_CTX *ctx = NULL;
	const char *p;
	struct connection_struct *conn = fsp->conn;
	char *fname = NULL;
	NTSTATUS status;

	if (!*lp_magic_script(talloc_tos(), lp_sub, SNUM(conn))) {
		return NT_STATUS_OK;
	}

	DEBUG(5,("checking magic for %s\n", fsp_str_dbg(fsp)));

	ctx = talloc_stackframe();

	fname = fsp->fsp_name->base_name;

	if (!(p = strrchr_m(fname,'/'))) {
		p = fname;
	} else {
		p++;
	}

	if (!strequal(lp_magic_script(talloc_tos(), lp_sub, SNUM(conn)),p)) {
		status = NT_STATUS_OK;
		goto out;
	}

	if (*lp_magic_output(talloc_tos(), lp_sub, SNUM(conn))) {
		magic_output = lp_magic_output(talloc_tos(), lp_sub, SNUM(conn));
	} else {
		magic_output = talloc_asprintf(ctx,
				"%s.out",
				fname);
	}
	if (!magic_output) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	/* Ensure we don't depend on user's PATH. */
	p = talloc_asprintf(ctx, "./%s", fname);
	if (!p) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	if (chmod(fname, 0755) == -1) {
		status = map_nt_error_from_unix(errno);
		goto out;
	}
	ret = smbrun(p, &tmp_fd, NULL);
	DEBUG(3,("Invoking magic command %s gave %d\n",
		p,ret));

	unlink(fname);
	if (ret != 0 || tmp_fd == -1) {
		if (tmp_fd != -1) {
			close(tmp_fd);
		}
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}
	outfd = open(magic_output, O_CREAT|O_EXCL|O_RDWR, 0600);
	if (outfd == -1) {
		int err = errno;
		close(tmp_fd);
		status = map_nt_error_from_unix(err);
		goto out;
	}

	if (sys_fstat(tmp_fd, &st, false) == -1) {
		int err = errno;
		close(tmp_fd);
		close(outfd);
		status = map_nt_error_from_unix(err);
		goto out;
	}

	if (transfer_file(tmp_fd,outfd,(off_t)st.st_ex_size) == (off_t)-1) {
		int err = errno;
		close(tmp_fd);
		close(outfd);
		status = map_nt_error_from_unix(err);
		goto out;
	}
	close(tmp_fd);
	if (close(outfd) == -1) {
		status = map_nt_error_from_unix(errno);
		goto out;
	}

	status = NT_STATUS_OK;

 out:
	TALLOC_FREE(ctx);
	return status;
}

/****************************************************************************
 Delete all streams
****************************************************************************/

NTSTATUS delete_all_streams(connection_struct *conn,
			const struct smb_filename *smb_fname)
{
	struct stream_struct *stream_info = NULL;
	unsigned int i;
	unsigned int num_streams = 0;
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;

	status = vfs_fstreaminfo(smb_fname->fsp, talloc_tos(),
				&num_streams, &stream_info);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_IMPLEMENTED)) {
		DEBUG(10, ("no streams around\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("vfs_fstreaminfo failed: %s\n",
			   nt_errstr(status)));
		goto fail;
	}

	DEBUG(10, ("delete_all_streams found %d streams\n",
		   num_streams));

	if (num_streams == 0) {
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	for (i=0; i<num_streams; i++) {
		int res;
		struct smb_filename *smb_fname_stream;

		if (strequal(stream_info[i].name, "::$DATA")) {
			continue;
		}

		status = synthetic_pathref(talloc_tos(),
					   conn->cwd_fsp,
					   smb_fname->base_name,
					   stream_info[i].name,
					   NULL,
					   smb_fname->twrp,
					   (smb_fname->flags &
					    ~SMB_FILENAME_POSIX_PATH),
					   &smb_fname_stream);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("talloc_aprintf failed\n"));
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}

		res = SMB_VFS_UNLINKAT(conn,
				conn->cwd_fsp,
				smb_fname_stream,
				0);

		if (res == -1) {
			status = map_nt_error_from_unix(errno);
			DEBUG(10, ("Could not delete stream %s: %s\n",
				   smb_fname_str_dbg(smb_fname_stream),
				   strerror(errno)));
			TALLOC_FREE(smb_fname_stream);
			break;
		}
		TALLOC_FREE(smb_fname_stream);
	}

 fail:
	TALLOC_FREE(frame);
	return status;
}

struct has_other_nonposix_opens_state {
	files_struct *fsp;
	bool found_another;
};

static bool has_other_nonposix_opens_fn(
	struct share_mode_entry *e,
	bool *modified,
	void *private_data)
{
	struct has_other_nonposix_opens_state *state = private_data;
	struct files_struct *fsp = state->fsp;

	if (e->name_hash != fsp->name_hash) {
		return false;
	}
	if (e->flags & SHARE_MODE_FLAG_POSIX_OPEN) {
		return false;
	}
	if (e->share_file_id == fh_get_gen_id(fsp->fh)) {
		struct server_id self = messaging_server_id(
			fsp->conn->sconn->msg_ctx);
		if (server_id_equal(&self, &e->pid)) {
			return false;
		}
	}
	if (share_entry_stale_pid(e)) {
		return false;
	}

	state->found_another = true;
	return true;
}

bool has_other_nonposix_opens(struct share_mode_lock *lck,
			      struct files_struct *fsp)
{
	struct has_other_nonposix_opens_state state = { .fsp = fsp };
	bool ok;

	ok = share_mode_forall_entries(
		lck, has_other_nonposix_opens_fn, &state);
	if (!ok) {
		return false;
	}
	return state.found_another;
}

struct close_share_mode_lock_state {
	struct share_mode_entry_prepare_state prepare_state;
	const char *object_type;
	struct files_struct *fsp;
	enum file_close_type close_type;
	bool delete_object;
	bool got_tokens;
	const struct security_unix_token *del_token;
	const struct security_token *del_nt_token;
	bool reset_delete_on_close;
	share_mode_entry_prepare_unlock_fn_t cleanup_fn;
};

static void close_share_mode_lock_prepare(struct share_mode_lock *lck,
					  bool *keep_locked,
					  void *private_data)
{
	struct close_share_mode_lock_state *state =
		(struct close_share_mode_lock_state *)private_data;
	struct files_struct *fsp = state->fsp;
	bool normal_close;
	bool ok;

	/*
	 * By default drop the g_lock again if we leave the
	 * tdb chainlock.
	 */
	*keep_locked = false;

	if (fsp->oplock_type != NO_OPLOCK) {
		ok = remove_share_oplock(lck, fsp);
		if (!ok) {
			struct file_id_buf buf;

			DBG_ERR("failed to remove share oplock for "
				"%s %s, %s, %s\n",
				state->object_type,
				fsp_str_dbg(fsp), fsp_fnum_dbg(fsp),
				file_id_str_buf(fsp->file_id, &buf));
		}
	}

	if (fsp->fsp_flags.write_time_forced) {
		NTTIME mtime = share_mode_changed_write_time(lck);
		struct timespec ts = nt_time_to_full_timespec(mtime);

		DBG_DEBUG("write time forced for %s %s\n",
			  state->object_type, fsp_str_dbg(fsp));
		set_close_write_time(fsp, ts);
	} else if (fsp->fsp_flags.update_write_time_on_close) {
		/* Someone had a pending write. */
		if (is_omit_timespec(&fsp->close_write_time)) {
			DBG_DEBUG("update to current time for %s %s\n",
				  state->object_type, fsp_str_dbg(fsp));
			/* Update to current time due to "normal" write. */
			set_close_write_time(fsp, timespec_current());
		} else {
			DBG_DEBUG("write time pending for %s %s\n",
				  state->object_type, fsp_str_dbg(fsp));
			/* Update to time set on close call. */
			set_close_write_time(fsp, fsp->close_write_time);
		}
	}

	if (fsp->fsp_flags.initial_delete_on_close &&
			!is_delete_on_close_set(lck, fsp->name_hash)) {
		/* Initial delete on close was set and no one else
		 * wrote a real delete on close. */

		fsp->fsp_flags.delete_on_close = true;
		set_delete_on_close_lck(fsp, lck,
					fsp->conn->session_info->security_token,
					fsp->conn->session_info->unix_token);
	}

	state->delete_object = is_delete_on_close_set(lck, fsp->name_hash) &&
		!has_other_nonposix_opens(lck, fsp);

	/*
	 * NT can set delete_on_close of the last open
	 * reference to a file.
	 */

	normal_close = (state->close_type == NORMAL_CLOSE || state->close_type == SHUTDOWN_CLOSE);
	if (!normal_close) {
		/*
		 * Never try to delete the file/directory for ERROR_CLOSE
		 */
		state->delete_object = false;
	}

	if (!state->delete_object) {
		ok = del_share_mode(lck, fsp);
		if (!ok) {
			DBG_ERR("Could not delete share entry for %s %s\n",
				state->object_type, fsp_str_dbg(fsp));
		}
		return;
	}

	/*
	 * We're going to remove the file/directory
	 * so keep the g_lock after the tdb chainlock
	 * is left, so we hold the share_mode_lock
	 * also during the deletion
	 */
	*keep_locked = true;

	state->got_tokens = get_delete_on_close_token(lck, fsp->name_hash,
					&state->del_nt_token, &state->del_token);
	if (state->close_type != ERROR_CLOSE) {
		SMB_ASSERT(state->got_tokens);
	}
}

static void close_share_mode_lock_cleanup(struct share_mode_lock *lck,
					  void *private_data)
{
	struct close_share_mode_lock_state *state =
		(struct close_share_mode_lock_state *)private_data;
	struct files_struct *fsp = state->fsp;
	bool ok;

	if (state->reset_delete_on_close) {
		reset_delete_on_close_lck(fsp, lck);
	}

	ok = del_share_mode(lck, fsp);
	if (!ok) {
		DBG_ERR("Could not delete share entry for %s %s\n",
			state->object_type, fsp_str_dbg(fsp));
	}
}

/****************************************************************************
 Deal with removing a share mode on last close.
****************************************************************************/

static NTSTATUS close_remove_share_mode(files_struct *fsp,
					enum file_close_type close_type)
{
	connection_struct *conn = fsp->conn;
	struct close_share_mode_lock_state lck_state = {};
	bool changed_user = false;
	NTSTATUS status = NT_STATUS_OK;
	NTSTATUS tmp_status;
	NTSTATUS ulstatus;
	struct file_id id;
	struct smb_filename *parent_fname = NULL;
	struct smb_filename *base_fname = NULL;
	int ret;

	/* Ensure any pending write time updates are done. */
	if (fsp->update_write_time_event) {
		fsp_flush_write_time_update(fsp);
	}

	/*
	 * Lock the share entries, and determine if we should delete
	 * on close. If so delete whilst the lock is still in effect.
	 * This prevents race conditions with the file being created. JRA.
	 */

	lck_state = (struct close_share_mode_lock_state) {
		.fsp			= fsp,
		.object_type		= "file",
		.close_type		= close_type,
	};

	status = share_mode_entry_prepare_lock_del(&lck_state.prepare_state,
						   fsp->file_id,
						   close_share_mode_lock_prepare,
						   &lck_state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_entry_prepare_lock_del() failed for %s - %s\n",
			fsp_str_dbg(fsp), nt_errstr(status));
		return status;
	}

	/* Remove the oplock before potentially deleting the file. */
	if (fsp->oplock_type != NO_OPLOCK) {
		release_file_oplock(fsp);
	}

	/*
	 * NT can set delete_on_close of the last open
	 * reference to a file.
	 */

	if (!lck_state.delete_object) {
		status = NT_STATUS_OK;
		goto done;
	}

	/*
	 * Ok, we have to delete the file
	 */
	lck_state.cleanup_fn = close_share_mode_lock_cleanup;

	DEBUG(5,("close_remove_share_mode: file %s. Delete on close was set "
		 "- deleting file.\n", fsp_str_dbg(fsp)));

	/*
	 * Don't try to update the write time when we delete the file
	 */
	fsp->fsp_flags.update_write_time_on_close = false;

	if (lck_state.got_tokens &&
	    !unix_token_equal(lck_state.del_token, get_current_utok(conn)))
	{
		/* Become the user who requested the delete. */

		DEBUG(5,("close_remove_share_mode: file %s. "
			"Change user to uid %u\n",
			fsp_str_dbg(fsp),
			(unsigned int)lck_state.del_token->uid));

		if (!push_sec_ctx()) {
			smb_panic("close_remove_share_mode: file %s. failed to push "
				  "sec_ctx.\n");
		}

		set_sec_ctx(lck_state.del_token->uid,
			    lck_state.del_token->gid,
			    lck_state.del_token->ngroups,
			    lck_state.del_token->groups,
			    lck_state.del_nt_token);

		changed_user = true;
	}

	/* We can only delete the file if the name we have is still valid and
	   hasn't been renamed. */

	tmp_status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(tmp_status)) {
		DEBUG(5,("close_remove_share_mode: file %s. Delete on close "
			 "was set and stat failed with error %s\n",
			 fsp_str_dbg(fsp), nt_errstr(tmp_status)));
		/*
		 * Don't save the errno here, we ignore this error
		 */
		goto done;
	}

	id = vfs_file_id_from_sbuf(conn, &fsp->fsp_name->st);

	if (!file_id_equal(&fsp->file_id, &id)) {
		struct file_id_buf ftmp1, ftmp2;
		DEBUG(5,("close_remove_share_mode: file %s. Delete on close "
			 "was set and dev and/or inode does not match\n",
			 fsp_str_dbg(fsp)));
		DEBUG(5,("close_remove_share_mode: file %s. stored file_id %s, "
			 "stat file_id %s\n",
			 fsp_str_dbg(fsp),
			 file_id_str_buf(fsp->file_id, &ftmp1),
			 file_id_str_buf(id, &ftmp2)));
		/*
		 * Don't save the errno here, we ignore this error
		 */
		goto done;
	}

	if ((conn->fs_capabilities & FILE_NAMED_STREAMS)
	    && (conn->internal_tcon_flags & TCON_FLAG_STREAMS_FILE)
	    && !fsp_is_alternate_stream(fsp)) {

		status = delete_all_streams(conn, fsp->fsp_name);

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(5, ("delete_all_streams failed: %s\n",
				  nt_errstr(status)));
			goto done;
		}
	}

	if (fsp->fsp_flags.kernel_share_modes_taken) {
		/*
		 * A file system sharemode could block the unlink;
		 * remove filesystem sharemodes first.
		 */
		ret = SMB_VFS_FILESYSTEM_SHAREMODE(fsp, 0, 0);
		if (ret == -1) {
			DBG_INFO("Removing file system sharemode for %s "
				 "failed: %s\n",
				 fsp_str_dbg(fsp), strerror(errno));
		}

		fsp->fsp_flags.kernel_share_modes_taken = false;
	}

	status = parent_pathref(talloc_tos(),
				conn->cwd_fsp,
				fsp->fsp_name,
				&parent_fname,
				&base_fname);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	ret = SMB_VFS_UNLINKAT(conn,
			       parent_fname->fsp,
			       base_fname,
			       0);
	TALLOC_FREE(parent_fname);
	base_fname = NULL;
	if (ret != 0) {
		/*
		 * This call can potentially fail as another smbd may
		 * have had the file open with delete on close set and
		 * deleted it when its last reference to this file
		 * went away. Hence we log this but not at debug level
		 * zero.
		 */

		DEBUG(5,("close_remove_share_mode: file %s. Delete on close "
			 "was set and unlink failed with error %s\n",
			 fsp_str_dbg(fsp), strerror(errno)));

		status = map_nt_error_from_unix(errno);
	}

	/* As we now have POSIX opens which can unlink
 	 * with other open files we may have taken
 	 * this code path with more than one share mode
 	 * entry - ensure we only delete once by resetting
 	 * the delete on close flag. JRA.
 	 */

	fsp->fsp_flags.delete_on_close = false;
	fsp->fsp_flags.fstat_before_close = false;
	lck_state.reset_delete_on_close = true;

 done:

	if (changed_user) {
		/* unbecome user. */
		pop_sec_ctx();
	}

	if (fsp->fsp_flags.kernel_share_modes_taken) {
		/* remove filesystem sharemodes */
		ret = SMB_VFS_FILESYSTEM_SHAREMODE(fsp, 0, 0);
		if (ret == -1) {
			DBG_INFO("Removing file system sharemode for "
				 "%s failed: %s\n",
				 fsp_str_dbg(fsp), strerror(errno));
		}
	}

	ulstatus = share_mode_entry_prepare_unlock(&lck_state.prepare_state,
						   lck_state.cleanup_fn,
						   &lck_state);
	if (!NT_STATUS_IS_OK(ulstatus)) {
		DBG_ERR("share_mode_entry_prepare_unlock() failed for %s - %s\n",
			fsp_str_dbg(fsp), nt_errstr(ulstatus));
		smb_panic("share_mode_entry_prepare_unlock() failed!");
	}

	if (lck_state.delete_object) {
		/*
		 * Do the notification after we released the share
		 * mode lock. Inside notify_fname we take out another
		 * tdb lock. With ctdb also accessing our databases,
		 * this can lead to deadlocks. Putting this notify
		 * after the TALLOC_FREE(lck) above we avoid locking
		 * two records simultaneously. Notifies are async and
		 * informational only, so calling the notify_fname
		 * without holding the share mode lock should not do
		 * any harm.
		 */
		notify_fname(conn, NOTIFY_ACTION_REMOVED,
			     FILE_NOTIFY_CHANGE_FILE_NAME,
			     fsp->fsp_name->base_name);
	}

	return status;
}

void set_close_write_time(struct files_struct *fsp, struct timespec ts)
{
	DEBUG(6,("close_write_time: %s" , time_to_asc(convert_timespec_to_time_t(ts))));

	if (is_omit_timespec(&ts)) {
		return;
	}
	fsp->fsp_flags.write_time_forced = false;
	fsp->fsp_flags.update_write_time_on_close = true;
	fsp->close_write_time = ts;
}

static void update_write_time_on_close_share_mode_fn(struct share_mode_lock *lck,
						     void *private_data)
{
	struct files_struct *fsp =
		talloc_get_type_abort(private_data,
		struct files_struct);
	NTTIME share_mtime = share_mode_changed_write_time(lck);

	/*
	 * On close if we're changing the real file time we
	 * must update it in the open file db too.
	 */
	share_mode_set_old_write_time(lck, fsp->close_write_time);

	/*
	 * Close write times overwrite sticky write times
	 * so we must replace any sticky write time here.
	 */
	if (!null_nttime(share_mtime)) {
		share_mode_set_changed_write_time(lck, fsp->close_write_time);
	}
}

static NTSTATUS update_write_time_on_close(struct files_struct *fsp)
{
	struct smb_file_time ft;
	NTSTATUS status;

	init_smb_file_time(&ft);

	if (!(fsp->fsp_flags.update_write_time_on_close)) {
		return NT_STATUS_OK;
	}

	if (is_omit_timespec(&fsp->close_write_time)) {
		fsp->close_write_time = timespec_current();
	}

	/* Ensure we have a valid stat struct for the source. */
	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!VALID_STAT(fsp->fsp_name->st)) {
		/* if it doesn't seem to be a real file */
		return NT_STATUS_OK;
	}

	/*
	 * We're being called after close_remove_share_mode() inside
	 * close_normal_file() so it's quite normal to not have an
	 * existing share. So just ignore the result of
	 * share_mode_do_locked_vfs_denied()...
	 */
	share_mode_do_locked_vfs_denied(fsp->file_id,
					update_write_time_on_close_share_mode_fn,
					fsp);

	ft.mtime = fsp->close_write_time;
	/* As this is a close based update, we are not directly changing the
	   file attributes from a client call, but indirectly from a write. */
	status = smb_set_file_time(fsp->conn, fsp, fsp->fsp_name, &ft, false);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("update_write_time_on_close: smb_set_file_time "
			"on file %s returned %s\n",
			fsp_str_dbg(fsp),
			nt_errstr(status)));
		return status;
	}

	return status;
}

static NTSTATUS ntstatus_keeperror(NTSTATUS s1, NTSTATUS s2)
{
	if (!NT_STATUS_IS_OK(s1)) {
		return s1;
	}
	return s2;
}

static void assert_no_pending_aio(struct files_struct *fsp,
				  enum file_close_type close_type)
{
	struct smbXsrv_client *client = global_smbXsrv_client;
	size_t num_connections_alive;
	unsigned num_requests = fsp->num_aio_requests;

	if (num_requests == 0) {
		return;
	}

	num_connections_alive = smbXsrv_client_valid_connections(client);

	if (close_type == SHUTDOWN_CLOSE && num_connections_alive == 0) {
		/*
		 * fsp->aio_requests and the contents (fsp->aio_requests[x])
		 * are both independently owned by fsp and are not in a
		 * talloc hierarchy. This allows the fsp->aio_requests array to
		 * be reallocated independently of the array contents so it can
		 * grow on demand.
		 *
		 * This means we must ensure order of deallocation
		 * on a SHUTDOWN_CLOSE by deallocating the fsp->aio_requests[x]
		 * contents first, as their destructors access the
		 * fsp->aio_request array. If we don't deallocate them
		 * first, when fsp is deallocated fsp->aio_requests
		 * could have been deallocated *before* its contents
		 * fsp->aio_requests[x], causing a crash.
		 */
		while (fsp->num_aio_requests != 0) {
			/*
			 * NB. We *MUST* use
			 * talloc_free(fsp->aio_requests[0]),
			 * and *NOT* TALLOC_FREE() here, as
			 * TALLOC_FREE(fsp->aio_requests[0])
			 * will overwrite any new contents of
			 * fsp->aio_requests[0] that were
			 * copied into it via the destructor
			 * aio_del_req_from_fsp().
			 *
			 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=14515
			 */
			talloc_free(fsp->aio_requests[0]);
		}
		return;
	}

	DBG_ERR("fsp->num_aio_requests=%u\n", num_requests);
	smb_panic("can not close with outstanding aio requests");
	return;
}

/****************************************************************************
 Close a file.

 close_type can be NORMAL_CLOSE=0,SHUTDOWN_CLOSE,ERROR_CLOSE.
 printing and magic scripts are only run on normal close.
 delete on close is done on normal and shutdown close.
****************************************************************************/

static NTSTATUS close_normal_file(struct smb_request *req, files_struct *fsp,
				  enum file_close_type close_type)
{
	NTSTATUS status = NT_STATUS_OK;
	NTSTATUS tmp;
	connection_struct *conn = fsp->conn;
	bool is_durable = false;

	SMB_ASSERT(fsp->fsp_flags.is_fsa);

	assert_no_pending_aio(fsp, close_type);

	while (talloc_array_length(fsp->blocked_smb1_lock_reqs) != 0) {
		smbd_smb1_brl_finish_by_req(
			fsp->blocked_smb1_lock_reqs[0],
			NT_STATUS_RANGE_NOT_LOCKED);
	}

	/*
	 * If we're flushing on a close we can get a write
	 * error here, we must remember this.
	 */

	if (NT_STATUS_IS_OK(status) && fsp->op != NULL) {
		is_durable = fsp->op->global->durable;
	}

	if (close_type != SHUTDOWN_CLOSE) {
		is_durable = false;
	}

	if (is_durable) {
		DATA_BLOB new_cookie = data_blob_null;

		tmp = SMB_VFS_DURABLE_DISCONNECT(fsp,
					fsp->op->global->backend_cookie,
					fsp->op,
					&new_cookie);
		if (NT_STATUS_IS_OK(tmp)) {
			struct timeval tv;
			NTTIME now;

			if (req != NULL) {
				tv = req->request_time;
			} else {
				tv = timeval_current();
			}
			now = timeval_to_nttime(&tv);

			data_blob_free(&fsp->op->global->backend_cookie);
			fsp->op->global->backend_cookie = new_cookie;

			fsp->op->compat = NULL;
			tmp = smbXsrv_open_close(fsp->op, now);
			if (!NT_STATUS_IS_OK(tmp)) {
				DEBUG(1, ("Failed to update smbXsrv_open "
					  "record when disconnecting durable "
					  "handle for file %s: %s - "
					  "proceeding with normal close\n",
					  fsp_str_dbg(fsp), nt_errstr(tmp)));
			}
			scavenger_schedule_disconnected(fsp);
		} else {
			DEBUG(1, ("Failed to disconnect durable handle for "
				  "file %s: %s - proceeding with normal "
				  "close\n", fsp_str_dbg(fsp), nt_errstr(tmp)));
		}
		if (!NT_STATUS_IS_OK(tmp)) {
			is_durable = false;
		}
	}

	if (is_durable) {
		/*
		 * This is the case where we successfully disconnected
		 * a durable handle and closed the underlying file.
		 * In all other cases, we proceed with a genuine close.
		 */
		DEBUG(10, ("%s disconnected durable handle for file %s\n",
			   conn->session_info->unix_info->unix_name,
			   fsp_str_dbg(fsp)));
		return NT_STATUS_OK;
	}

	if (fsp->op != NULL) {
		/*
		 * Make sure the handle is not marked as durable anymore
		 */
		fsp->op->global->durable = false;
	}

	/* If this is an old DOS or FCB open and we have multiple opens on
	   the same handle we only have one share mode. Ensure we only remove
	   the share mode on the last close. */

	if (fh_get_refcount(fsp->fh) == 1) {
		/* Should we return on error here... ? */
		tmp = close_remove_share_mode(fsp, close_type);
		status = ntstatus_keeperror(status, tmp);
	}

	locking_close_file(fsp, close_type);

	/*
	 * Ensure pending modtime is set before closing underlying fd.
	 */

	tmp = update_write_time_on_close(fsp);
	if (NT_STATUS_EQUAL(tmp, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		/*
		 * Someone renamed the file or a parent directory containing
		 * this file. We can't do anything about this, eat the error.
		 */
		tmp = NT_STATUS_OK;
	}
	status = ntstatus_keeperror(status, tmp);

	tmp = fd_close(fsp);
	status = ntstatus_keeperror(status, tmp);

	/* check for magic scripts */
	if (close_type == NORMAL_CLOSE) {
		tmp = check_magic(fsp);
		status = ntstatus_keeperror(status, tmp);
	}

	DEBUG(2,("%s closed file %s (numopen=%d) %s\n",
		conn->session_info->unix_info->unix_name, fsp_str_dbg(fsp),
		conn->num_files_open - 1,
		nt_errstr(status) ));

	return status;
}
/****************************************************************************
 Function used by reply_rmdir to delete an entire directory
 tree recursively. Return True on ok, False on fail.
****************************************************************************/

NTSTATUS recursive_rmdir(TALLOC_CTX *ctx,
		     connection_struct *conn,
		     struct smb_filename *smb_dname)
{
	const char *dname = NULL;
	char *talloced = NULL;
	struct smb_Dir *dir_hnd = NULL;
	struct files_struct *dirfsp = NULL;
	int retval;
	NTSTATUS status = NT_STATUS_OK;

	SMB_ASSERT(!is_ntfs_stream_smb_fname(smb_dname));

	status = OpenDir(talloc_tos(),
			 conn,
			 smb_dname,
			 NULL,
			 0,
			 &dir_hnd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	dirfsp = dir_hnd_fetch_fsp(dir_hnd);

	while ((dname = ReadDirName(dir_hnd, &talloced))) {
		struct smb_filename *atname = NULL;
		struct smb_filename *smb_dname_full = NULL;
		char *fullname = NULL;
		bool do_break = true;
		int unlink_flags = 0;

		if (ISDOT(dname) || ISDOTDOT(dname)) {
			TALLOC_FREE(talloced);
			continue;
		}

		/* Construct the full name. */
		fullname = talloc_asprintf(ctx,
				"%s/%s",
				smb_dname->base_name,
				dname);
		if (!fullname) {
			status = NT_STATUS_NO_MEMORY;
			goto err_break;
		}

		smb_dname_full = synthetic_smb_fname(talloc_tos(),
						fullname,
						NULL,
						NULL,
						smb_dname->twrp,
						smb_dname->flags);
		if (smb_dname_full == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto err_break;
		}

		if (SMB_VFS_LSTAT(conn, smb_dname_full) != 0) {
			status = map_nt_error_from_unix(errno);
			goto err_break;
		}

		if (smb_dname_full->st.st_ex_mode & S_IFDIR) {
			status = recursive_rmdir(ctx, conn, smb_dname_full);
			if (!NT_STATUS_IS_OK(status)) {
				goto err_break;
			}
			unlink_flags = AT_REMOVEDIR;
		}

		status = synthetic_pathref(talloc_tos(),
					   dirfsp,
					   dname,
					   NULL,
					   &smb_dname_full->st,
					   smb_dname_full->twrp,
					   smb_dname_full->flags,
					   &atname);
		if (!NT_STATUS_IS_OK(status)) {
			goto err_break;
		}

		if (!is_visible_fsp(atname->fsp)) {
			TALLOC_FREE(smb_dname_full);
			TALLOC_FREE(fullname);
			TALLOC_FREE(talloced);
			TALLOC_FREE(atname);
			continue;
		}

		retval = SMB_VFS_UNLINKAT(conn,
					  dirfsp,
					  atname,
					  unlink_flags);
		if (retval != 0) {
			status = map_nt_error_from_unix(errno);
			goto err_break;
		}

		/* Successful iteration. */
		do_break = false;

	 err_break:
		TALLOC_FREE(smb_dname_full);
		TALLOC_FREE(fullname);
		TALLOC_FREE(talloced);
		TALLOC_FREE(atname);
		if (do_break) {
			break;
		}
	 }
	TALLOC_FREE(dir_hnd);
	return status;
}

/****************************************************************************
 The internals of the rmdir code - called elsewhere.
****************************************************************************/

static NTSTATUS rmdir_internals(TALLOC_CTX *ctx, struct files_struct *fsp)
{
	struct connection_struct *conn = fsp->conn;
	struct smb_filename *smb_dname = fsp->fsp_name;
	struct smb_filename *parent_fname = NULL;
	struct smb_filename *at_fname = NULL;
	const char *dname = NULL;
	char *talloced = NULL;
	struct smb_Dir *dir_hnd = NULL;
	struct files_struct *dirfsp = NULL;
	int unlink_flags = 0;
	NTSTATUS status;
	int ret;

	SMB_ASSERT(!is_ntfs_stream_smb_fname(smb_dname));

	status = parent_pathref(talloc_tos(),
				conn->cwd_fsp,
				fsp->fsp_name,
				&parent_fname,
				&at_fname);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * Todo: use SMB_VFS_STATX() once it's available.
	 */

	/* Might be a symlink. */
	ret = SMB_VFS_LSTAT(conn, smb_dname);
	if (ret != 0) {
		TALLOC_FREE(parent_fname);
		return map_nt_error_from_unix(errno);
	}

	if (S_ISLNK(smb_dname->st.st_ex_mode)) {
		/* Is what it points to a directory ? */
		ret = SMB_VFS_STAT(conn, smb_dname);
		if (ret != 0) {
			TALLOC_FREE(parent_fname);
			return map_nt_error_from_unix(errno);
		}
		if (!(S_ISDIR(smb_dname->st.st_ex_mode))) {
			TALLOC_FREE(parent_fname);
			return NT_STATUS_NOT_A_DIRECTORY;
		}
	} else {
		unlink_flags = AT_REMOVEDIR;
	}

	ret = SMB_VFS_UNLINKAT(conn,
			       parent_fname->fsp,
			       at_fname,
			       unlink_flags);
	if (ret == 0) {
		TALLOC_FREE(parent_fname);
		notify_fname(conn, NOTIFY_ACTION_REMOVED,
			     FILE_NOTIFY_CHANGE_DIR_NAME,
			     smb_dname->base_name);
		return NT_STATUS_OK;
	}

	if (!((errno == ENOTEMPTY) || (errno == EEXIST))) {
		DEBUG(3,("rmdir_internals: couldn't remove directory %s : "
			 "%s\n", smb_fname_str_dbg(smb_dname),
			 strerror(errno)));
		TALLOC_FREE(parent_fname);
		return map_nt_error_from_unix(errno);
	}

	/*
	 * Here we know the initial directory unlink failed with
	 * ENOTEMPTY or EEXIST so we know there are objects within.
	 * If we don't have permission to delete files non
	 * visible to the client just fail the directory delete.
	 */

	if (!lp_delete_veto_files(SNUM(conn))) {
		status = NT_STATUS_DIRECTORY_NOT_EMPTY;
		goto err;
	}

	/*
	 * Check to see if the only thing in this directory are
	 * files non-visible to the client. If not, fail the delete.
	 */

	status = OpenDir(talloc_tos(),
			 conn,
			 smb_dname,
			 NULL,
			 0,
			 &dir_hnd);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * Note, we deliberately squash the error here
		 * to avoid leaking information about what we
		 * can't delete.
		 */
		status = NT_STATUS_DIRECTORY_NOT_EMPTY;
		goto err;
	}

	dirfsp = dir_hnd_fetch_fsp(dir_hnd);

	while ((dname = ReadDirName(dir_hnd, &talloced)) != NULL) {
		struct smb_filename *smb_dname_full = NULL;
		struct smb_filename *direntry_fname = NULL;
		char *fullname = NULL;
		int retval;

		if (ISDOT(dname) || ISDOTDOT(dname)) {
			TALLOC_FREE(talloced);
			continue;
		}
		if (IS_VETO_PATH(conn, dname)) {
			TALLOC_FREE(talloced);
			continue;
		}

		fullname = talloc_asprintf(talloc_tos(),
					   "%s/%s",
					   smb_dname->base_name,
					   dname);

		if (fullname == NULL) {
			TALLOC_FREE(talloced);
			status = NT_STATUS_NO_MEMORY;
			goto err;
		}

		smb_dname_full = synthetic_smb_fname(talloc_tos(),
						     fullname,
						     NULL,
						     NULL,
						     smb_dname->twrp,
						     smb_dname->flags);
		if (smb_dname_full == NULL) {
			TALLOC_FREE(talloced);
			TALLOC_FREE(fullname);
			status = NT_STATUS_NO_MEMORY;
			goto err;
		}

		retval = SMB_VFS_LSTAT(conn, smb_dname_full);
		if (retval != 0) {
			status = map_nt_error_from_unix(errno);
			TALLOC_FREE(talloced);
			TALLOC_FREE(fullname);
			TALLOC_FREE(smb_dname_full);
			goto err;
		}

		if (S_ISLNK(smb_dname_full->st.st_ex_mode)) {
			/* Could it be an msdfs link ? */
			if (lp_host_msdfs() &&
			    lp_msdfs_root(SNUM(conn))) {
				struct smb_filename *smb_atname;
				smb_atname = synthetic_smb_fname(talloc_tos(),
							dname,
							NULL,
							&smb_dname_full->st,
							fsp->fsp_name->twrp,
							fsp->fsp_name->flags);
				if (smb_atname == NULL) {
					TALLOC_FREE(talloced);
					TALLOC_FREE(fullname);
					TALLOC_FREE(smb_dname_full);
					status = NT_STATUS_NO_MEMORY;
					goto err;
				}
				if (is_msdfs_link(fsp, smb_atname)) {
					TALLOC_FREE(talloced);
					TALLOC_FREE(fullname);
					TALLOC_FREE(smb_dname_full);
					TALLOC_FREE(smb_atname);
					DBG_DEBUG("got msdfs link name %s "
						"- can't delete directory %s\n",
						dname,
						fsp_str_dbg(fsp));
					status = NT_STATUS_DIRECTORY_NOT_EMPTY;
					goto err;
				}
				TALLOC_FREE(smb_atname);
			}

			/* Not a DFS link - could it be a dangling symlink ? */
			retval = SMB_VFS_STAT(conn, smb_dname_full);
			if (retval == -1 && (errno == ENOENT || errno == ELOOP)) {
				/*
				 * Dangling symlink.
				 * Allow delete as "delete veto files = yes"
				 */
				TALLOC_FREE(talloced);
				TALLOC_FREE(fullname);
				TALLOC_FREE(smb_dname_full);
				continue;
			}

			DBG_DEBUG("got symlink name %s - "
				"can't delete directory %s\n",
				dname,
				fsp_str_dbg(fsp));
			TALLOC_FREE(talloced);
			TALLOC_FREE(fullname);
			TALLOC_FREE(smb_dname_full);
			status = NT_STATUS_DIRECTORY_NOT_EMPTY;
			goto err;
		}

		/* Not a symlink, get a pathref. */
		status = synthetic_pathref(talloc_tos(),
					   dirfsp,
					   dname,
					   NULL,
					   &smb_dname_full->st,
					   smb_dname->twrp,
					   smb_dname->flags,
					   &direntry_fname);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(talloced);
			TALLOC_FREE(fullname);
			TALLOC_FREE(smb_dname_full);
			goto err;
		}

		if (!is_visible_fsp(direntry_fname->fsp)) {
			TALLOC_FREE(talloced);
			TALLOC_FREE(fullname);
			TALLOC_FREE(smb_dname_full);
			TALLOC_FREE(direntry_fname);
			continue;
		}

		/*
		 * We found a client visible name.
		 * We cannot delete this directory.
		 */
		DBG_DEBUG("got name %s - "
			"can't delete directory %s\n",
			dname,
			fsp_str_dbg(fsp));
		TALLOC_FREE(talloced);
		TALLOC_FREE(fullname);
		TALLOC_FREE(smb_dname_full);
		TALLOC_FREE(direntry_fname);
		status = NT_STATUS_DIRECTORY_NOT_EMPTY;
		goto err;
	}

	/* Do a recursive delete. */
	RewindDir(dir_hnd);

	while ((dname = ReadDirName(dir_hnd, &talloced)) != NULL) {
		struct smb_filename *direntry_fname = NULL;
		struct smb_filename *smb_dname_full = NULL;
		char *fullname = NULL;
		bool do_break = true;
		int retval;

		if (ISDOT(dname) || ISDOTDOT(dname)) {
			TALLOC_FREE(talloced);
			continue;
		}

		fullname = talloc_asprintf(ctx,
					   "%s/%s",
					   smb_dname->base_name,
					   dname);

		if (fullname == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto err_break;
		}

		smb_dname_full = synthetic_smb_fname(talloc_tos(),
						     fullname,
						     NULL,
						     NULL,
						     smb_dname->twrp,
						     smb_dname->flags);
		if (smb_dname_full == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto err_break;
		}

		/*
		 * Todo: use SMB_VFS_STATX() once that's available.
		 */

		retval = SMB_VFS_LSTAT(conn, smb_dname_full);
		if (retval != 0) {
			status = map_nt_error_from_unix(errno);
			goto err_break;
		}

		/*
		 * We are only dealing with VETO'ed objects
		 * here. If it's a symlink, just delete the
		 * link without caring what it is pointing
		 * to.
		 */
		if (S_ISLNK(smb_dname_full->st.st_ex_mode)) {
			direntry_fname = synthetic_smb_fname(talloc_tos(),
							dname,
							NULL,
							&smb_dname_full->st,
							smb_dname->twrp,
							smb_dname->flags);
			if (direntry_fname == NULL) {
				status = NT_STATUS_NO_MEMORY;
				goto err_break;
			}
		} else {
			status = synthetic_pathref(talloc_tos(),
						   dirfsp,
						   dname,
						   NULL,
						   &smb_dname_full->st,
						   smb_dname->twrp,
						   smb_dname->flags,
						   &direntry_fname);
			if (!NT_STATUS_IS_OK(status)) {
				goto err_break;
			}

			if (!is_visible_fsp(direntry_fname->fsp)) {
				TALLOC_FREE(fullname);
				TALLOC_FREE(smb_dname_full);
				TALLOC_FREE(talloced);
				TALLOC_FREE(direntry_fname);
				continue;
			}
		}

		unlink_flags = 0;

		if (smb_dname_full->st.st_ex_mode & S_IFDIR) {
			status = recursive_rmdir(ctx, conn, smb_dname_full);
			if (!NT_STATUS_IS_OK(status)) {
				goto err_break;
			}
			unlink_flags = AT_REMOVEDIR;
		}

		retval = SMB_VFS_UNLINKAT(conn,
					  dirfsp,
					  direntry_fname,
					  unlink_flags);
		if (retval != 0) {
			status = map_nt_error_from_unix(errno);
			goto err_break;
		}

		/* Successful iteration. */
		do_break = false;

	err_break:
		TALLOC_FREE(fullname);
		TALLOC_FREE(smb_dname_full);
		TALLOC_FREE(talloced);
		TALLOC_FREE(direntry_fname);
		if (do_break) {
			break;
		}
	}

	/* If we get here, we know NT_STATUS_IS_OK(status) */
	SMB_ASSERT(NT_STATUS_IS_OK(status));

	/* Retry the rmdir */
	ret = SMB_VFS_UNLINKAT(conn,
			       parent_fname->fsp,
			       at_fname,
			       AT_REMOVEDIR);
	if (ret != 0) {
		status = map_nt_error_from_unix(errno);
	}

  err:

	TALLOC_FREE(dir_hnd);
	TALLOC_FREE(parent_fname);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("couldn't remove directory %s : "
			 "%s\n", smb_fname_str_dbg(smb_dname),
			 nt_errstr(status));
		return status;
	}

	notify_fname(conn, NOTIFY_ACTION_REMOVED,
		     FILE_NOTIFY_CHANGE_DIR_NAME,
		     smb_dname->base_name);

	return status;
}

/****************************************************************************
 Close a directory opened by an NT SMB call.
****************************************************************************/

static NTSTATUS close_directory(struct smb_request *req, files_struct *fsp,
				enum file_close_type close_type)
{
	connection_struct *conn = fsp->conn;
	struct close_share_mode_lock_state lck_state = {};
	bool changed_user = false;
	NTSTATUS status = NT_STATUS_OK;
	NTSTATUS status1 = NT_STATUS_OK;
	NTSTATUS notify_status;
	NTSTATUS ulstatus;

	SMB_ASSERT(fsp->fsp_flags.is_fsa);

	if (fsp->conn->sconn->using_smb2) {
		notify_status = NT_STATUS_NOTIFY_CLEANUP;
	} else {
		notify_status = NT_STATUS_OK;
	}

	assert_no_pending_aio(fsp, close_type);

	/*
	 * NT can set delete_on_close of the last open
	 * reference to a directory also.
	 */

	lck_state = (struct close_share_mode_lock_state) {
		.fsp			= fsp,
		.object_type		= "directory",
		.close_type		= close_type,
	};

	status = share_mode_entry_prepare_lock_del(&lck_state.prepare_state,
						   fsp->file_id,
						   close_share_mode_lock_prepare,
						   &lck_state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_entry_prepare_lock_del() failed for %s - %s\n",
			fsp_str_dbg(fsp), nt_errstr(status));
		return status;
	}

	/*
	 * We don't have directory leases yet, so assert it in order
	 * to skip release_file_oplock().
	 */
	SMB_ASSERT(fsp->oplock_type == NO_OPLOCK);

	/*
	 * NT can set delete_on_close of the last open
	 * reference to a file.
	 */

	if (!lck_state.delete_object) {
		status = NT_STATUS_OK;
		goto done;
	}

	/*
	 * Ok, we have to delete the directory
	 */
	lck_state.cleanup_fn = close_share_mode_lock_cleanup;

	if (lck_state.got_tokens &&
	    !unix_token_equal(lck_state.del_token, get_current_utok(conn)))
	{
		/* Become the user who requested the delete. */

		DBG_INFO("dir %s. Change user to uid %u\n",
			 fsp_str_dbg(fsp),
			 (unsigned int)lck_state.del_token->uid);

		if (!push_sec_ctx()) {
			smb_panic("close_directory: failed to push sec_ctx.\n");
		}

		set_sec_ctx(lck_state.del_token->uid,
			    lck_state.del_token->gid,
			    lck_state.del_token->ngroups,
			    lck_state.del_token->groups,
			    lck_state.del_nt_token);

		changed_user = true;
	}

	if ((fsp->conn->fs_capabilities & FILE_NAMED_STREAMS)
	    && (conn->internal_tcon_flags & TCON_FLAG_STREAMS_FILE)
	    && !is_ntfs_stream_smb_fname(fsp->fsp_name)) {

		status = delete_all_streams(fsp->conn, fsp->fsp_name);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(5, ("delete_all_streams failed: %s\n",
				  nt_errstr(status)));
			goto done;
		}
	}

	status = rmdir_internals(talloc_tos(), fsp);

	DEBUG(5,("close_directory: %s. Delete on close was set - "
		 "deleting directory returned %s.\n",
		 fsp_str_dbg(fsp), nt_errstr(status)));

	/*
	 * Ensure we remove any change notify requests that would
	 * now fail as the directory has been deleted.
	 */

	if (NT_STATUS_IS_OK(status)) {
		notify_status = NT_STATUS_DELETE_PENDING;
	}

done:
	if (changed_user) {
		/* unbecome user. */
		pop_sec_ctx();
	}

	ulstatus = share_mode_entry_prepare_unlock(&lck_state.prepare_state,
						   lck_state.cleanup_fn,
						   &lck_state);
	if (!NT_STATUS_IS_OK(ulstatus)) {
		DBG_ERR("share_mode_entry_prepare_unlock() failed for %s - %s\n",
			fsp_str_dbg(fsp), nt_errstr(ulstatus));
		smb_panic("share_mode_entry_prepare_unlock() failed!");
	}

	remove_pending_change_notify_requests_by_fid(fsp, notify_status);

	status1 = fd_close(fsp);

	if (!NT_STATUS_IS_OK(status1)) {
		DEBUG(0, ("Could not close dir! fname=%s, fd=%d, err=%d=%s\n",
			  fsp_str_dbg(fsp), fsp_get_pathref_fd(fsp), errno,
			  strerror(errno)));
	}

	if (NT_STATUS_IS_OK(status) && !NT_STATUS_IS_OK(status1)) {
		status = status1;
	}
	return status;
}

/****************************************************************************
 Rundown all SMB-related dependencies of a files struct
****************************************************************************/

NTSTATUS close_file_smb(struct smb_request *req,
			struct files_struct *fsp,
			enum file_close_type close_type)
{
	NTSTATUS status;

	/*
	 * This fsp can never be an internal dirfsp. They must
	 * be explicitly closed by TALLOC_FREE of the dir handle.
	 */
	SMB_ASSERT(!fsp->fsp_flags.is_dirfsp);

	/*
	 * Never call directly on a base fsp
	 */
	SMB_ASSERT(fsp->stream_fsp == NULL);

	if (fsp->fake_file_handle != NULL) {
		/*
		 * Named pipes are opened as fake files and
		 * can have pending aio requests. Ensure
		 * we clear out all pending aio on force
		 * shutdown of named pipes also.
		 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=15423
		 */
		assert_no_pending_aio(fsp, close_type);
		status = close_fake_file(req, fsp);
	} else if (fsp->print_file != NULL) {
		/* FIXME: return spool errors */
		print_spool_end(fsp, close_type);
		fd_close(fsp);
		status = NT_STATUS_OK;
	} else if (!fsp->fsp_flags.is_fsa) {
		if (close_type == NORMAL_CLOSE) {
			DBG_ERR("unexpected NORMAL_CLOSE for [%s] "
				"is_fsa[%u] is_pathref[%u] is_directory[%u]\n",
				fsp_str_dbg(fsp),
				fsp->fsp_flags.is_fsa,
				fsp->fsp_flags.is_pathref,
				fsp->fsp_flags.is_directory);
		}
		SMB_ASSERT(close_type != NORMAL_CLOSE);
		fd_close(fsp);
		status = NT_STATUS_OK;
	} else if (fsp->fsp_flags.is_directory) {
		status = close_directory(req, fsp, close_type);
	} else {
		status = close_normal_file(req, fsp, close_type);
	}

	if (fsp_is_alternate_stream(fsp)) {
		/*
		 * fsp was a stream, its base_fsp can't be a stream
		 * as well
		 */
		SMB_ASSERT(!fsp_is_alternate_stream(fsp->base_fsp));

		/*
		 * There's a 1:1 relationship between fsp and a base_fsp
		 */
		SMB_ASSERT(fsp->base_fsp->stream_fsp == fsp);

		/*
		 * Make base_fsp look standalone now
		 */
		fsp->base_fsp->stream_fsp = NULL;

		close_file_free(req, &fsp->base_fsp, close_type);
	}

	fsp_unbind_smb(req, fsp);

	return status;
}

NTSTATUS close_file_free(struct smb_request *req,
			 struct files_struct **_fsp,
			 enum file_close_type close_type)
{
	struct files_struct *fsp = *_fsp;
	NTSTATUS status;

	status = close_file_smb(req, fsp, close_type);

	file_free(req, fsp);
        *_fsp = NULL;

	return status;
}

/****************************************************************************
 Deal with an (authorized) message to close a file given the share mode
 entry.
****************************************************************************/

void msg_close_file(struct messaging_context *msg_ctx,
			void *private_data,
			uint32_t msg_type,
			struct server_id server_id,
			DATA_BLOB *data)
{
	files_struct *fsp = NULL;
	struct file_id id;
	struct share_mode_entry e;
	struct smbd_server_connection *sconn =
		talloc_get_type_abort(private_data,
		struct smbd_server_connection);

	message_to_share_mode_entry(&id, &e, (char *)data->data);

	if(DEBUGLVL(10)) {
		char *sm_str = share_mode_str(NULL, 0, &id, &e);
		if (!sm_str) {
			smb_panic("talloc failed");
		}
		DEBUG(10,("msg_close_file: got request to close share mode "
			"entry %s\n", sm_str));
		TALLOC_FREE(sm_str);
	}

	fsp = file_find_dif(sconn, id, e.share_file_id);
	if (!fsp) {
		DEBUG(10,("msg_close_file: failed to find file.\n"));
		return;
	}
	close_file_free(NULL, &fsp, NORMAL_CLOSE);
}

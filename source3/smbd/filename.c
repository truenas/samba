/*
   Unix SMB/CIFS implementation.
   filename handling routines
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 1999-2007
   Copyright (C) Ying Chen 2000
   Copyright (C) Volker Lendecke 2007

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

/*
 * New hash table stat cache code added by Ying Chen.
 */

#include "includes.h"
#include "system/filesys.h"
#include "fake_file.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"

static NTSTATUS check_name(connection_struct *conn,
			   const struct smb_filename *smb_fname);

uint32_t ucf_flags_from_smb_request(struct smb_request *req)
{
	uint32_t ucf_flags = 0;

	if (req != NULL) {
		if (req->posix_pathnames) {
			ucf_flags |= UCF_POSIX_PATHNAMES;
		}
		if (req->flags2 & FLAGS2_DFS_PATHNAMES) {
			ucf_flags |= UCF_DFS_PATHNAME;
		}
		if (req->flags2 & FLAGS2_REPARSE_PATH) {
			ucf_flags |= UCF_GMT_PATHNAME;
		}
	}

	return ucf_flags;
}

uint32_t filename_create_ucf_flags(struct smb_request *req, uint32_t create_disposition)
{
	uint32_t ucf_flags = 0;

	ucf_flags |= ucf_flags_from_smb_request(req);

	switch (create_disposition) {
	case FILE_OPEN:
	case FILE_OVERWRITE:
		break;
	case FILE_SUPERSEDE:
	case FILE_CREATE:
	case FILE_OPEN_IF:
	case FILE_OVERWRITE_IF:
		ucf_flags |= UCF_PREP_CREATEFILE;
		break;
	}

	return ucf_flags;
}

static NTSTATUS build_stream_path(TALLOC_CTX *mem_ctx,
				  connection_struct *conn,
				  struct smb_filename *smb_fname);

/****************************************************************************
 Mangle the 2nd name and check if it is then equal to the first name.
****************************************************************************/

static bool mangled_equal(const char *name1,
			const char *name2,
			const struct share_params *p)
{
	char mname[13];

	if (!name_to_8_3(name2, mname, False, p)) {
		return False;
	}
	return strequal(name1, mname);
}

static NTSTATUS check_for_dot_component(const struct smb_filename *smb_fname)
{
	/* Ensure we catch all names with in "/."
	   this is disallowed under Windows and
	   in POSIX they've already been removed. */
	const char *p = strstr(smb_fname->base_name, "/."); /*mb safe*/
	if (p) {
		if (p[2] == '/') {
			/* Error code within a pathname. */
			return NT_STATUS_OBJECT_PATH_NOT_FOUND;
		} else if (p[2] == '\0') {
			/* Error code at the end of a pathname. */
			return NT_STATUS_OBJECT_NAME_INVALID;
		}
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 Optimization for common case where the missing part
 is in the last component and the client already
 sent the correct case.
 Returns NT_STATUS_OK to mean continue the tree walk
 (possibly with modified start pointer).
 Any other NT_STATUS_XXX error means terminate the path
 lookup here.
****************************************************************************/

static NTSTATUS check_parent_exists(TALLOC_CTX *ctx,
				connection_struct *conn,
				bool posix_pathnames,
				const struct smb_filename *smb_fname,
				char **pp_dirpath,
				char **pp_start,
				int *p_parent_stat_errno)
{
	char *parent_name = NULL;
	struct smb_filename *parent_fname = NULL;
	const char *last_component = NULL;
	NTSTATUS status;
	int ret;

	if (!parent_dirname(ctx, smb_fname->base_name,
				&parent_name,
				&last_component)) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!posix_pathnames) {
		if (ms_has_wild(parent_name)) {
			goto no_optimization_out;
		}
	}

	/*
	 * If there was no parent component in
	 * smb_fname->base_name then don't do this
	 * optimization.
	 */
	if (smb_fname->base_name == last_component) {
		goto no_optimization_out;
	}

	parent_fname = synthetic_smb_fname(ctx,
					   parent_name,
					   NULL,
					   NULL,
					   smb_fname->twrp,
					   smb_fname->flags);
	if (parent_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (posix_pathnames) {
		ret = SMB_VFS_LSTAT(conn, parent_fname);
	} else {
		ret = SMB_VFS_STAT(conn, parent_fname);
	}

	/* If the parent stat failed, just continue
	   with the normal tree walk. */

	if (ret == -1) {
		/*
		 * Optimization. Preserving the
		 * errno from the STAT/LSTAT here
		 * will allow us to save a duplicate
		 * STAT/LSTAT system call of the parent
		 * pathname in a hot code path in the caller.
		 */
		if (p_parent_stat_errno != NULL) {
			*p_parent_stat_errno = errno;
		}
		goto no_optimization_out;
	}

	status = check_for_dot_component(parent_fname);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Parent exists - set "start" to be the
	 * last component to shorten the tree walk. */

	/*
	 * Safe to use discard_const_p
	 * here as last_component points
	 * into our smb_fname->base_name.
	 */
	*pp_start = discard_const_p(char, last_component);

	/* Update dirpath. */
	TALLOC_FREE(*pp_dirpath);
	*pp_dirpath = talloc_strdup(ctx, parent_fname->base_name);
	if (!*pp_dirpath) {
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(5,("check_parent_exists: name "
		"= %s, dirpath = %s, "
		"start = %s\n",
		smb_fname->base_name,
		*pp_dirpath,
		*pp_start));

	return NT_STATUS_OK;

  no_optimization_out:

	/*
	 * We must still return an *pp_dirpath
	 * initialized to ".", and a *pp_start
	 * pointing at smb_fname->base_name.
	 */

	TALLOC_FREE(parent_name);
	TALLOC_FREE(parent_fname);

	*pp_dirpath = talloc_strdup(ctx, ".");
	if (*pp_dirpath == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	/*
	 * Safe to use discard_const_p
	 * here as by convention smb_fname->base_name
	 * is allocated off ctx.
	 */
	*pp_start = discard_const_p(char, smb_fname->base_name);
	return NT_STATUS_OK;
}

/*
 * Re-order a known good @GMT-token path.
 */

static NTSTATUS rearrange_snapshot_path(struct smb_filename *smb_fname,
				char *startp,
				char *endp)
{
	size_t endlen = 0;
	size_t gmt_len = endp - startp;
	char gmt_store[gmt_len + 1];
	char *parent = NULL;
	const char *last_component = NULL;
	char *newstr;
	bool ret;

	DBG_DEBUG("|%s| -> ", smb_fname->base_name);

	/* Save off the @GMT-token. */
	memcpy(gmt_store, startp, gmt_len);
	gmt_store[gmt_len] = '\0';

	if (*endp == '/') {
		/* Remove any trailing '/' */
		endp++;
	}

	if (*endp == '\0') {
		/*
		 * @GMT-token was at end of path.
		 * Remove any preceding '/'
		 */
		if (startp > smb_fname->base_name && startp[-1] == '/') {
			startp--;
		}
	}

	/* Remove @GMT-token from the path. */
	endlen = strlen(endp);
	memmove(startp, endp, endlen + 1);

	/* Split the remaining path into components. */
	ret = parent_dirname(smb_fname,
				smb_fname->base_name,
				&parent,
				&last_component);
	if (ret == false) {
		/* Must terminate debug with \n */
		DBG_DEBUG("NT_STATUS_NO_MEMORY\n");
		return NT_STATUS_NO_MEMORY;
	}

	if (ISDOT(parent)) {
		if (last_component[0] == '\0') {
			newstr = talloc_strdup(smb_fname,
					gmt_store);
		} else {
			newstr = talloc_asprintf(smb_fname,
					"%s/%s",
					gmt_store,
					last_component);
		}
	} else {
		newstr = talloc_asprintf(smb_fname,
					"%s/%s/%s",
					gmt_store,
					parent,
					last_component);
	}

	TALLOC_FREE(parent);
	TALLOC_FREE(smb_fname->base_name);
	smb_fname->base_name = newstr;

	DBG_DEBUG("|%s|\n", newstr);

	return NT_STATUS_OK;
}

/*
 * Strip a valid @GMT-token from any incoming filename path,
 * adding any NTTIME encoded in the pathname into the
 * twrp field of the passed in smb_fname.
 *
 * Valid @GMT-tokens look like @GMT-YYYY-MM-DD-HH-MM-SS
 * at the *start* of a pathname component.
 *
 * If twrp is passed in then smb_fname->twrp is set to that
 * value, and the @GMT-token part of the filename is removed
 * and does not change the stored smb_fname->twrp.
 *
 */

NTSTATUS canonicalize_snapshot_path(struct smb_filename *smb_fname,
				    uint32_t ucf_flags,
				    NTTIME twrp)
{
	char *startp = NULL;
	char *endp = NULL;
	char *tmp = NULL;
	struct tm tm;
	time_t t;
	NTTIME nt;
	NTSTATUS status;

	if (twrp != 0) {
		smb_fname->twrp = twrp;
	}

	if (!(ucf_flags & UCF_GMT_PATHNAME)) {
		return NT_STATUS_OK;
	}

	startp = strchr_m(smb_fname->base_name, '@');
	if (startp == NULL) {
		/* No @ */
		return NT_STATUS_OK;
	}

	startp = strstr_m(startp, "@GMT-");
	if (startp == NULL) {
		/* No @ */
		return NT_STATUS_OK;
	}

	if ((startp > smb_fname->base_name) && (startp[-1] != '/')) {
		/* the GMT-token does not start a path-component */
		return NT_STATUS_OK;
	}

	endp = strptime(startp, GMT_FORMAT, &tm);
	if (endp == NULL) {
		/* Not a valid timestring. */
		return NT_STATUS_OK;
	}

	if (endp[0] != '\0' && endp[0] != '/') {
		/*
		 * It is not a complete path component, i.e. the path
		 * component continues after the gmt-token.
		 */
		return NT_STATUS_OK;
	}

	status = rearrange_snapshot_path(smb_fname, startp, endp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	startp = smb_fname->base_name + GMT_NAME_LEN;
	if (startp[0] == '/') {
		startp++;
	}

	tmp = talloc_strdup(smb_fname, startp);
	if (tmp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	TALLOC_FREE(smb_fname->base_name);
	smb_fname->base_name = tmp;

	if (smb_fname->twrp == 0) {
		tm.tm_isdst = -1;
		t = timegm(&tm);
		unix_to_nt_time(&nt, t);
		smb_fname->twrp = nt;
	}

	return NT_STATUS_OK;
}

/*
 * Utility function to normalize case on an incoming client filename
 * if required on this connection struct.
 * Performs an in-place case conversion guaranteed to stay the same size.
 */

static NTSTATUS normalize_filename_case(connection_struct *conn, char *filename)
{
	bool ok;

	if (!conn->case_sensitive) {
		return NT_STATUS_OK;
	}
	if (conn->case_preserve) {
		return NT_STATUS_OK;
	}
	if (conn->short_case_preserve) {
		return NT_STATUS_OK;
	}
	ok = strnorm(filename, lp_default_case(SNUM(conn)));
	if (!ok) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	return NT_STATUS_OK;
}

/****************************************************************************
This routine is called to convert names from the dos namespace to unix
namespace. It needs to handle any case conversions, mangling, format changes,
streams etc.

We assume that we have already done a chdir() to the right "root" directory
for this service.

Conversion to basic unix format is already done in check_path_syntax().

Names must be relative to the root of the service - any leading /.  and
trailing /'s should have been trimmed by check_path_syntax().

The function will return an NTSTATUS error if some part of the name except for
the last part cannot be resolved, else NT_STATUS_OK.

Note NT_STATUS_OK doesn't mean the name exists or is valid, just that we
didn't get any fatal errors that should immediately terminate the calling SMB
processing whilst resolving.

If the orig_path was a stream, smb_filename->base_name will point to the base
filename, and smb_filename->stream_name will point to the stream name.  If
orig_path was not a stream, then smb_filename->stream_name will be NULL.

On exit from unix_convert, the smb_filename->st stat struct will be populated
if the file exists and was found, if not this stat struct will be filled with
zeros (and this can be detected by checking for nlinks = 0, which can never be
true for any file).
****************************************************************************/

struct uc_state {
	TALLOC_CTX *mem_ctx;
	struct connection_struct *conn;
	struct smb_filename *smb_fname;
	const char *orig_path;
	uint32_t ucf_flags;
	char *name;
	char *end;
	char *dirpath;
	char *stream;
	bool component_was_mangled;
	bool posix_pathnames;
	bool done;
};

static NTSTATUS unix_convert_step_search_fail(struct uc_state *state)
{
	char *unmangled;

	if (state->end) {
		/*
		 * An intermediate part of the name
		 * can't be found.
		 */
		DBG_DEBUG("Intermediate [%s] missing\n",
			  state->name);
		*state->end = '/';

		/*
		 * We need to return the fact that the
		 * intermediate name resolution failed.
		 * This is used to return an error of
		 * ERRbadpath rather than ERRbadfile.
		 * Some Windows applications depend on
		 * the difference between these two
		 * errors.
		 */

		/*
		 * ENOENT, ENOTDIR and ELOOP all map
		 * to NT_STATUS_OBJECT_PATH_NOT_FOUND
		 * in the filename walk.
		 */

		if (errno == ENOENT ||
		    errno == ENOTDIR ||
		    errno == ELOOP)
		{
			return NT_STATUS_OBJECT_PATH_NOT_FOUND;
		}
		return map_nt_error_from_unix(errno);
	}

	/*
	 * ENOENT/EACCESS are the only valid errors
	 * here.
	 */

	if (errno == EACCES) {
		if ((state->ucf_flags & UCF_PREP_CREATEFILE) == 0) {
			/*
			 * Could be a symlink pointing to
			 * a directory outside the share
			 * to which we don't have access.
			 * If so, we need to know that here
			 * so we can return the correct error code.
			 * check_name() is never called if we
			 * error out of filename_convert().
			 */
			int ret;
			NTSTATUS status;
			struct smb_filename dname = (struct smb_filename) {
					.base_name = state->dirpath,
					.twrp = state->smb_fname->twrp,
			};

			/* handle null paths */
			if ((dname.base_name == NULL) ||
					(dname.base_name[0] == '\0')) {
				return NT_STATUS_ACCESS_DENIED;
			}
			ret = SMB_VFS_LSTAT(state->conn, &dname);
			if (ret != 0) {
				return NT_STATUS_ACCESS_DENIED;
			}
			if (!S_ISLNK(dname.st.st_ex_mode)) {
				return NT_STATUS_ACCESS_DENIED;
			}
			status = check_name(state->conn, &dname);
			if (!NT_STATUS_IS_OK(status)) {
				/* We know this is an intermediate path. */
				return NT_STATUS_OBJECT_PATH_NOT_FOUND;
			}
			return NT_STATUS_ACCESS_DENIED;
		} else {
			/*
			 * This is the dropbox
			 * behaviour. A dropbox is a
			 * directory with only -wx
			 * permissions, so
			 * get_real_filename fails
			 * with EACCESS, it needs to
			 * list the directory. We
			 * nevertheless want to allow
			 * users creating a file.
			 */
			errno = 0;
		}
	}

	if ((errno != 0) && (errno != ENOENT)) {
		/*
		 * ENOTDIR and ELOOP both map to
		 * NT_STATUS_OBJECT_PATH_NOT_FOUND
		 * in the filename walk.
		 */
		if (errno == ENOTDIR || errno == ELOOP) {
			return NT_STATUS_OBJECT_PATH_NOT_FOUND;
		}
		return map_nt_error_from_unix(errno);
	}

	/*
	 * Just the last part of the name doesn't exist.
	 * We need to strupper() or strlower() it as
	 * this conversion may be used for file creation
	 * purposes. Fix inspired by
	 * Thomas Neumann <t.neumann@iku-ag.de>.
	 */
	if (!state->conn->case_preserve ||
	    (mangle_is_8_3(state->name, false,
			   state->conn->params) &&
	     !state->conn->short_case_preserve)) {
		if (!strnorm(state->name,
			     lp_default_case(SNUM(state->conn)))) {
			DBG_DEBUG("strnorm %s failed\n",
				  state->name);
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	/*
	 * check on the mangled stack to see if we can
	 * recover the base of the filename.
	 */

	if (mangle_is_mangled(state->name, state->conn->params)
	    && mangle_lookup_name_from_8_3(state->mem_ctx,
					   state->name,
					   &unmangled,
					   state->conn->params)) {
		char *tmp;
		size_t name_ofs =
			state->name - state->smb_fname->base_name;

		if (!ISDOT(state->dirpath)) {
			tmp = talloc_asprintf(
				state->smb_fname, "%s/%s",
				state->dirpath, unmangled);
			TALLOC_FREE(unmangled);
		}
		else {
			tmp = unmangled;
		}
		if (tmp == NULL) {
			DBG_ERR("talloc failed\n");
			return NT_STATUS_NO_MEMORY;
		}
		TALLOC_FREE(state->smb_fname->base_name);
		state->smb_fname->base_name = tmp;
		state->name =
			state->smb_fname->base_name + name_ofs;
		state->end = state->name + strlen(state->name);
	}

	DBG_DEBUG("New file [%s]\n", state->name);
	state->done = true;
	return NT_STATUS_OK;
}

static NTSTATUS unix_convert_step_stat(struct uc_state *state)
{
	struct smb_filename dname;
	char dot[2] = ".";
	char *found_name = NULL;
	int ret;

	/*
	 * Check if the name exists up to this point.
	 */

	DBG_DEBUG("smb_fname [%s]\n", smb_fname_str_dbg(state->smb_fname));

	ret = vfs_stat(state->conn, state->smb_fname);
	if (ret == 0) {
		/*
		 * It exists. it must either be a directory or this must
		 * be the last part of the path for it to be OK.
		 */
		if (state->end && !S_ISDIR(state->smb_fname->st.st_ex_mode)) {
			/*
			 * An intermediate part of the name isn't
			 * a directory.
			 */
			DBG_DEBUG("Not a dir [%s]\n", state->name);
			*state->end = '/';
			/*
			 * We need to return the fact that the
			 * intermediate name resolution failed. This
			 * is used to return an error of ERRbadpath
			 * rather than ERRbadfile. Some Windows
			 * applications depend on the difference between
			 * these two errors.
			 */
			return NT_STATUS_OBJECT_PATH_NOT_FOUND;
		}
		return NT_STATUS_OK;
	}

	/* Stat failed - ensure we don't use it. */
	SET_STAT_INVALID(state->smb_fname->st);

	if (state->posix_pathnames) {
		/*
		 * For posix_pathnames, we're done.
		 * Don't blunder into the
		 * get_real_filename() codepath as they may
		 * be doing case insensitive lookups. So when
		 * creating a new POSIX directory Foo they might
		 * match on name foo.
		 *
		 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=13803
		 */
		if (state->end != NULL) {
			const char *morepath = NULL;
			/*
			 * If this is intermediate we must
			 * restore the full path.
			 */
			*state->end = '/';
			/*
			 * If there are any more components
			 * after the failed LSTAT we cannot
			 * continue.
			 */
			morepath = strchr(state->end + 1, '/');
			if (morepath != NULL) {
				return NT_STATUS_OBJECT_PATH_NOT_FOUND;
			}
		}
		if (errno == ENOENT) {
			/* New file or directory. */
			state->done = true;
			return NT_STATUS_OK;
		}
		if ((errno == EACCES) &&
		    (state->ucf_flags & UCF_PREP_CREATEFILE)) {
			/* POSIX Dropbox case. */
			errno = 0;
			state->done = true;
			return NT_STATUS_OK;
		}
		return map_nt_error_from_unix(errno);
	}

	/*
	 * Reset errno so we can detect
	 * directory open errors.
	 */
	errno = 0;

	/*
	 * Try to find this part of the path in the directory.
	 */

	dname = (struct smb_filename) {
		.base_name = state->dirpath,
		.twrp = state->smb_fname->twrp,
	};

	/* handle null paths */
	if ((dname.base_name == NULL) || (dname.base_name[0] == '\0')) {
		dname.base_name = dot;
	}

	ret = get_real_filename(state->conn,
				&dname,
				state->name,
				talloc_tos(),
				&found_name);
	if (ret != 0) {
		return unix_convert_step_search_fail(state);
	}

	/*
	 * Restore the rest of the string. If the string was
	 * mangled the size may have changed.
	 */
	if (state->end) {
		char *tmp;
		size_t name_ofs =
			state->name - state->smb_fname->base_name;

		if (!ISDOT(state->dirpath)) {
			tmp = talloc_asprintf(state->smb_fname,
					      "%s/%s/%s", state->dirpath,
					      found_name, state->end+1);
		}
		else {
			tmp = talloc_asprintf(state->smb_fname,
					      "%s/%s", found_name,
					      state->end+1);
		}
		if (tmp == NULL) {
			DBG_ERR("talloc_asprintf failed\n");
			return NT_STATUS_NO_MEMORY;
		}
		TALLOC_FREE(state->smb_fname->base_name);
		state->smb_fname->base_name = tmp;
		state->name = state->smb_fname->base_name + name_ofs;
		state->end = state->name + strlen(found_name);
		*state->end = '\0';
	} else {
		char *tmp;
		size_t name_ofs =
			state->name - state->smb_fname->base_name;

		if (!ISDOT(state->dirpath)) {
			tmp = talloc_asprintf(state->smb_fname,
					      "%s/%s", state->dirpath,
					      found_name);
		} else {
			tmp = talloc_strdup(state->smb_fname,
					    found_name);
		}
		if (tmp == NULL) {
			DBG_ERR("talloc failed\n");
			return NT_STATUS_NO_MEMORY;
		}
		TALLOC_FREE(state->smb_fname->base_name);
		state->smb_fname->base_name = tmp;
		state->name = state->smb_fname->base_name + name_ofs;

		/*
		 * We just scanned for, and found the end of
		 * the path. We must return a valid stat struct
		 * if it exists. JRA.
		 */

		ret = vfs_stat(state->conn, state->smb_fname);
		if (ret != 0) {
			SET_STAT_INVALID(state->smb_fname->st);
		}
	}

	TALLOC_FREE(found_name);
	return NT_STATUS_OK;
}

static NTSTATUS unix_convert_step(struct uc_state *state)
{
	NTSTATUS status;

	/*
	 * Pinpoint the end of this section of the filename.
	 */
	/* mb safe. '/' can't be in any encoded char. */
	state->end = strchr(state->name, '/');

	/*
	 * Chop the name at this point.
	 */
	if (state->end != NULL) {
		*state->end = 0;
	}

	DBG_DEBUG("dirpath [%s] name [%s]\n", state->dirpath, state->name);

	/* The name cannot have a component of "." */

	if (ISDOT(state->name)) {
		if (state->end == NULL)  {
			/* Error code at the end of a pathname. */
			return NT_STATUS_OBJECT_NAME_INVALID;
		}
		return NT_STATUS_OBJECT_PATH_NOT_FOUND;
	}

	status = unix_convert_step_stat(state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (state->done) {
		return NT_STATUS_OK;
	}

	/*
	 * Add to the dirpath that we have resolved so far.
	 */

	if (!ISDOT(state->dirpath)) {
		char *tmp = talloc_asprintf(state->mem_ctx,
					    "%s/%s", state->dirpath, state->name);
		if (!tmp) {
			DBG_ERR("talloc_asprintf failed\n");
			return NT_STATUS_NO_MEMORY;
		}
		TALLOC_FREE(state->dirpath);
		state->dirpath = tmp;
	}
	else {
		TALLOC_FREE(state->dirpath);
		if (!(state->dirpath = talloc_strdup(state->mem_ctx,state->name))) {
			DBG_ERR("talloc_strdup failed\n");
			return NT_STATUS_NO_MEMORY;
		}
	}

	/*
	 * Cache the dirpath thus far. Don't cache a name with mangled
	 * components as this can change the size.
	 */
	if(!state->component_was_mangled) {
		stat_cache_add(state->orig_path,
			       state->dirpath,
			       state->smb_fname->twrp,
			       state->conn->case_sensitive);
	}

	/*
	 * Restore the / that we wiped out earlier.
	 */
	if (state->end != NULL) {
		*state->end = '/';
	}

	return NT_STATUS_OK;
}

NTSTATUS unix_convert(TALLOC_CTX *mem_ctx,
		      connection_struct *conn,
		      const char *orig_path,
		      NTTIME twrp,
		      struct smb_filename **smb_fname_out,
		      uint32_t ucf_flags)
{
	struct uc_state uc_state;
	struct uc_state *state = &uc_state;
	NTSTATUS status;
	int ret = -1;
	int parent_stat_errno = 0;

	*state = (struct uc_state) {
		.mem_ctx = mem_ctx,
		.conn = conn,
		.orig_path = orig_path,
		.ucf_flags = ucf_flags,
		.posix_pathnames = (ucf_flags & UCF_POSIX_PATHNAMES),
	};

	*smb_fname_out = NULL;

	state->smb_fname = talloc_zero(state->mem_ctx, struct smb_filename);
	if (state->smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (state->conn->printer) {
		/* we don't ever use the filenames on a printer share as a
			filename - so don't convert them */
		state->smb_fname->base_name = talloc_strdup(
			state->smb_fname, state->orig_path);
		if (state->smb_fname->base_name == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto err;
		}
		goto done;
	}

	state->smb_fname->flags = state->posix_pathnames ? SMB_FILENAME_POSIX_PATH : 0;

	DBG_DEBUG("Called on file [%s]\n", state->orig_path);

	if (state->orig_path[0] == '/') {
		DBG_ERR("Path [%s] starts with '/'\n", state->orig_path);
		return NT_STATUS_OBJECT_NAME_INVALID;
	}

	/* Start with the full orig_path as given by the caller. */
	state->smb_fname->base_name = talloc_strdup(
		state->smb_fname, state->orig_path);
	if (state->smb_fname->base_name == NULL) {
		DBG_ERR("talloc_strdup failed\n");
		status = NT_STATUS_NO_MEMORY;
		goto err;
	}

	/* Canonicalize any @GMT- paths. */
	status = canonicalize_snapshot_path(state->smb_fname, ucf_flags, twrp);
	if (!NT_STATUS_IS_OK(status)) {
		goto err;
	}

	/*
	 * If we trimmed down to a single '\0' character
	 * then we should use the "." directory to avoid
	 * searching the cache, but not if we are in a
	 * printing share.
	 * As we know this is valid we can return true here.
	 */

	if (state->smb_fname->base_name[0] == '\0') {
		state->smb_fname->base_name = talloc_strdup(state->smb_fname, ".");
		if (state->smb_fname->base_name == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto err;
		}
		if (SMB_VFS_STAT(state->conn, state->smb_fname) != 0) {
			status = map_nt_error_from_unix(errno);
			goto err;
		}
		DBG_DEBUG("conversion finished [] -> [%s]\n",
			  state->smb_fname->base_name);
		goto done;
	}

	if (state->orig_path[0] == '.' && (state->orig_path[1] == '/' ||
				state->orig_path[1] == '\0')) {
		/* Start of pathname can't be "." only. */
		if (state->orig_path[1] == '\0' || state->orig_path[2] == '\0') {
			status = NT_STATUS_OBJECT_NAME_INVALID;
		} else {
			status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
		}
		goto err;
	}

	/*
	 * Large directory fix normalization. If we're case sensitive, and
	 * the case preserving parameters are set to "no", normalize the case of
	 * the incoming filename from the client WHETHER IT EXISTS OR NOT !
	 * This is in conflict with the current (3.0.20) man page, but is
	 * what people expect from the "large directory howto". I'll update
	 * the man page. Thanks to jht@samba.org for finding this. JRA.
	 */

	status = normalize_filename_case(state->conn, state->smb_fname->base_name);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("normalize_filename_case %s failed\n",
				state->smb_fname->base_name);
		goto err;
	}

	/*
	 * Strip off the stream, and add it back when we're done with the
	 * base_name.
	 */
	if (!state->posix_pathnames) {
		state->stream = strchr_m(state->smb_fname->base_name, ':');

		if (state->stream != NULL) {
			char *tmp = NULL;

			if (!(conn->fs_capabilities & FILE_NAMED_STREAMS)) {
				status = NT_STATUS_OBJECT_NAME_INVALID;
				goto err;
			}

			tmp = talloc_strdup(state->smb_fname, state->stream);
			if (tmp == NULL) {
				status = NT_STATUS_NO_MEMORY;
				goto err;
			}
			/*
			 * Since this is actually pointing into
			 * smb_fname->base_name this truncates base_name.
			 */
			*state->stream = '\0';
			state->stream = tmp;

			if (state->smb_fname->base_name[0] == '\0') {
				/*
				 * orig_name was just a stream name.
				 * This is a stream on the root of
				 * the share. Replace base_name with
				 * a "."
				 */
				state->smb_fname->base_name =
					talloc_strdup(state->smb_fname, ".");
				if (state->smb_fname->base_name == NULL) {
					status = NT_STATUS_NO_MEMORY;
					goto err;
				}
				if (SMB_VFS_STAT(state->conn, state->smb_fname) != 0) {
					status = map_nt_error_from_unix(errno);
					goto err;
				}
				/* dirpath must exist. */
				state->dirpath = talloc_strdup(state->mem_ctx,".");
				if (state->dirpath == NULL) {
					status = NT_STATUS_NO_MEMORY;
					goto err;
				}
				DBG_INFO("conversion finished [%s] -> [%s]\n",
					 state->orig_path,
					 state->smb_fname->base_name);
				goto done;
			}
		}
	}

	state->name = state->smb_fname->base_name;

	/*
	 * If we're providing case insensitive semantics or
	 * the underlying filesystem is case insensitive,
	 * then a case-normalized hit in the stat-cache is
	 * authoritative. JRA.
	 *
	 * Note: We're only checking base_name.  The stream_name will be
	 * added and verified in build_stream_path().
	 */

	if (!state->conn->case_sensitive ||
	    !(state->conn->fs_capabilities & FILE_CASE_SENSITIVE_SEARCH))
	{
		bool found;

		found = stat_cache_lookup(state->conn,
					  state->posix_pathnames,
					  &state->smb_fname->base_name,
					  &state->dirpath,
					  &state->name,
					  state->smb_fname->twrp,
					  &state->smb_fname->st);
		/*
		 * stat_cache_lookup() allocates on talloc_tos() even
		 * when !found, reparent correctly
		 */
		talloc_steal(state->smb_fname, state->smb_fname->base_name);
		talloc_steal(state->mem_ctx, state->dirpath);

		if (found) {
			goto done;
		}
	}

	/*
	 * Make sure "dirpath" is an allocated string, we use this for
	 * building the directories with talloc_asprintf and free it.
	 */

	if (state->dirpath == NULL) {
		state->dirpath = talloc_strdup(state->mem_ctx,".");
		if (state->dirpath == NULL) {
			DBG_ERR("talloc_strdup failed\n");
			status = NT_STATUS_NO_MEMORY;
			goto err;
		}
	}

	/*
	 * If we have a wildcard we must walk the path to
	 * find where the error is, even if case sensitive
	 * is true.
	 */

	if (!state->posix_pathnames) {
		/* POSIX pathnames have no wildcards. */
		bool name_has_wildcard = ms_has_wild(state->smb_fname->base_name);
		if (name_has_wildcard) {
			/* Wildcard not valid anywhere. */
			status = NT_STATUS_OBJECT_NAME_INVALID;
			goto fail;
		}
	}

	DBG_DEBUG("Begin: name [%s] dirpath [%s] name [%s]\n",
		  state->smb_fname->base_name, state->dirpath, state->name);

	/*
	 * stat the name - if it exists then we can add the stream back (if
	 * there was one) and be done!
	 */

	ret = vfs_stat(state->conn, state->smb_fname);
	if (ret == 0) {
		status = check_for_dot_component(state->smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
		/* Add the path (not including the stream) to the cache. */
		stat_cache_add(state->orig_path,
			       state->smb_fname->base_name,
			       state->smb_fname->twrp,
			       state->conn->case_sensitive);
		DBG_DEBUG("Conversion of base_name finished "
			  "[%s] -> [%s]\n",
			  state->orig_path, state->smb_fname->base_name);
		goto done;
	}

	/* Stat failed - ensure we don't use it. */
	SET_STAT_INVALID(state->smb_fname->st);

	/*
	 * Note: we must continue processing a path if we get EACCES
	 * from stat. With NFS4 permissions the file might be lacking
	 * READ_ATTR, but if the parent has LIST permissions we can
	 * resolve the path in the path traversal loop down below.
	 */

	if (errno == ENOENT) {
		/* Optimization when creating a new file - only
		   the last component doesn't exist.
		   NOTE : check_parent_exists() doesn't preserve errno.
		*/
		int saved_errno = errno;
		status = check_parent_exists(state->mem_ctx,
					state->conn,
					state->posix_pathnames,
					state->smb_fname,
					&state->dirpath,
					&state->name,
					&parent_stat_errno);
		errno = saved_errno;
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}

	/*
	 * A special case - if we don't have any wildcards or mangling chars and are case
	 * sensitive or the underlying filesystem is case insensitive then searching
	 * won't help.
	 */

	if ((state->conn->case_sensitive || !(state->conn->fs_capabilities &
				FILE_CASE_SENSITIVE_SEARCH)) &&
			!mangle_is_mangled(state->smb_fname->base_name, state->conn->params)) {

		status = check_for_dot_component(state->smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}

		/*
		 * The stat failed. Could be ok as it could be
		 * a new file.
		 */

		if (errno == ENOTDIR || errno == ELOOP) {
			status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
			goto fail;
		} else if (errno == ENOENT) {
			/*
			 * Was it a missing last component ?
			 * or a missing intermediate component ?
			 *
			 * Optimization.
			 *
			 * For this code path we can guarantee that
			 * we have gone through check_parent_exists()
			 * and it returned NT_STATUS_OK.
			 *
			 * Either there was no parent component (".")
			 * parent_stat_errno == 0 and we have a missing
			 * last component here.
			 *
			 * OR check_parent_exists() called STAT/LSTAT
			 * and if it failed parent_stat_errno has been
			 * set telling us if the parent existed or not.
			 *
			 * Either way we can avoid another STAT/LSTAT
			 * system call on the parent here.
			 */
			if (parent_stat_errno == ENOTDIR ||
					parent_stat_errno == ENOENT ||
					parent_stat_errno == ELOOP) {
				status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
				goto fail;
			}

			/*
			 * Missing last component is ok - new file.
			 * Also deal with permission denied elsewhere.
			 * Just drop out to done.
			 */
			goto done;
		}
	}

	/*
	 * is_mangled() was changed to look at an entire pathname, not
	 * just a component. JRA.
	 */

	if (mangle_is_mangled(state->name, state->conn->params)) {
		state->component_was_mangled = true;
	}

	/*
	 * Now we need to recursively match the name against the real
	 * directory structure.
	 */

	/*
	 * Match each part of the path name separately, trying the names
	 * as is first, then trying to scan the directory for matching names.
	 */

	for (; state->name ; state->name = (state->end ? state->end + 1:(char *)NULL)) {
		status = unix_convert_step(state);
		if (!NT_STATUS_IS_OK(status)) {
			if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MEMORY)) {
				goto err;
			}
			goto fail;
		}
		if (state->done) {
			goto done;
		}
	}

	/*
	 * Cache the full path. Don't cache a name with mangled or wildcard
	 * components as this can change the size.
	 */

	if(!state->component_was_mangled) {
		stat_cache_add(state->orig_path,
			       state->smb_fname->base_name,
			       state->smb_fname->twrp,
			       state->conn->case_sensitive);
	}

	/*
	 * The name has been resolved.
	 */

 done:
	/* Add back the stream if one was stripped off originally. */
	if (state->stream != NULL) {
		state->smb_fname->stream_name = state->stream;

		/* Check path now that the base_name has been converted. */
		status = build_stream_path(state->mem_ctx, state->conn, state->smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
	}

	DBG_DEBUG("Conversion finished [%s] -> [%s]\n",
		   state->orig_path, smb_fname_str_dbg(state->smb_fname));

	TALLOC_FREE(state->dirpath);
	*smb_fname_out = state->smb_fname;
	return NT_STATUS_OK;
 fail:
	DBG_DEBUG("Conversion failed: dirpath [%s] name [%s]\n",
		  state->dirpath, state->name);
	if ((state->dirpath != NULL) && !ISDOT(state->dirpath)) {
		state->smb_fname->base_name = talloc_asprintf(
			state->smb_fname,
			"%s/%s",
			state->dirpath,
			state->name);
	} else {
		state->smb_fname->base_name = talloc_strdup(
			state->smb_fname, state->name);
	}
	if (state->smb_fname->base_name == NULL) {
		DBG_ERR("talloc_asprintf failed\n");
		status = NT_STATUS_NO_MEMORY;
		goto err;
	}

	*smb_fname_out = state->smb_fname;
	TALLOC_FREE(state->dirpath);
	return status;
 err:
	TALLOC_FREE(state->smb_fname);
	return status;
}

/****************************************************************************
 Ensure a path is not vetoed.
****************************************************************************/

static NTSTATUS check_veto_path(connection_struct *conn,
			const struct smb_filename *smb_fname)
{
	const char *name = smb_fname->base_name;

	if (IS_VETO_PATH(conn, name))  {
		/* Is it not dot or dot dot. */
		if (!(ISDOT(name) || ISDOTDOT(name))) {
			DEBUG(5,("check_veto_path: file path name %s vetoed\n",
						name));
			return map_nt_error_from_unix(ENOENT);
		}
	}
	return NT_STATUS_OK;
}

/****************************************************************************
 Check a filename - possibly calling check_reduced_name.
 This is called by every routine before it allows an operation on a filename.
 It does any final confirmation necessary to ensure that the filename is
 a valid one for the user to access.
****************************************************************************/

static NTSTATUS check_name(connection_struct *conn,
			const struct smb_filename *smb_fname)
{
	NTSTATUS status = check_veto_path(conn, smb_fname);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!(conn->internal_tcon_flags & TCON_FLAG_RESOLVE_BENEATH)
	    && (!lp_widelinks(SNUM(conn)) || !lp_follow_symlinks(SNUM(conn)))) {
		status = check_reduced_name(conn, NULL, smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(5,("check_name: name %s failed with %s\n",
					smb_fname->base_name,
					nt_errstr(status)));
			return status;
		}
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Check if two filenames are equal.
 This needs to be careful about whether we are case sensitive.
****************************************************************************/

static bool fname_equal(const char *name1, const char *name2,
		bool case_sensitive)
{
	/* Normal filename handling */
	if (case_sensitive) {
		return(strcmp(name1,name2) == 0);
	}

	return(strequal(name1,name2));
}

static bool sname_equal(const char *name1, const char *name2,
		bool case_sensitive)
{
	bool match;
	const char *s1 = NULL;
	const char *s2 = NULL;
	size_t n1;
	size_t n2;
	const char *e1 = NULL;
	const char *e2 = NULL;
	char *c1 = NULL;
	char *c2 = NULL;

	match = fname_equal(name1, name2, case_sensitive);
	if (match) {
		return true;
	}

	if (name1[0] != ':') {
		return false;
	}
	if (name2[0] != ':') {
		return false;
	}
	s1 = &name1[1];
	e1 = strchr(s1, ':');
	if (e1 == NULL) {
		n1 = strlen(s1);
	} else {
		n1 = PTR_DIFF(e1, s1);
	}
	s2 = &name2[1];
	e2 = strchr(s2, ':');
	if (e2 == NULL) {
		n2 = strlen(s2);
	} else {
		n2 = PTR_DIFF(e2, s2);
	}

	/* Normal filename handling */
	if (case_sensitive) {
		return (strncmp(s1, s2, n1) == 0);
	}

	/*
	 * We can't use strnequal() here
	 * as it takes the number of codepoints
	 * and not the number of bytes.
	 *
	 * So we make a copy before calling
	 * strequal().
	 *
	 * Note that we TALLOC_FREE() in reverse order
	 * in order to avoid memory fragmentation.
	 */

	c1 = talloc_strndup(talloc_tos(), s1, n1);
	c2 = talloc_strndup(talloc_tos(), s2, n2);
	if (c1 == NULL || c2 == NULL) {
		TALLOC_FREE(c2);
		TALLOC_FREE(c1);
		return (strncmp(s1, s2, n1) == 0);
	}

	match = strequal(c1, c2);
	TALLOC_FREE(c2);
	TALLOC_FREE(c1);
	return match;
}

/****************************************************************************
 Scan a directory to find a filename, matching without case sensitivity.
 If the name looks like a mangled name then try via the mangling functions
****************************************************************************/

int get_real_filename_full_scan(connection_struct *conn,
				const char *path,
				const char *name,
				bool mangled,
				TALLOC_CTX *mem_ctx,
				char **found_name)
{
	struct smb_Dir *cur_dir;
	const char *dname = NULL;
	char *talloced = NULL;
	char *unmangled_name = NULL;
	long curpos;
	struct smb_filename *smb_fname = NULL;

	/* handle null paths */
	if ((path == NULL) || (*path == 0)) {
		path = ".";
	}

	/* If we have a case-sensitive filesystem, it doesn't do us any
	 * good to search for a name. If a case variation of the name was
	 * there, then the original stat(2) would have found it.
	 */
	if (!mangled && !(conn->fs_capabilities & FILE_CASE_SENSITIVE_SEARCH)) {
		errno = ENOENT;
		return -1;
	}

	/*
	 * The incoming name can be mangled, and if we de-mangle it
	 * here it will not compare correctly against the filename (name2)
	 * read from the directory and then mangled by the name_to_8_3()
	 * call. We need to mangle both names or neither.
	 * (JRA).
	 *
	 * Fix for bug found by Dina Fine. If in case sensitive mode then
	 * the mangle cache is no good (3 letter extension could be wrong
	 * case - so don't demangle in this case - leave as mangled and
	 * allow the mangling of the directory entry read (which is done
	 * case insensitively) to match instead. This will lead to more
	 * false positive matches but we fail completely without it. JRA.
	 */

	if (mangled && !conn->case_sensitive) {
		mangled = !mangle_lookup_name_from_8_3(talloc_tos(), name,
						       &unmangled_name,
						       conn->params);
		if (!mangled) {
			/* Name is now unmangled. */
			name = unmangled_name;
		}
	}

	smb_fname = synthetic_smb_fname(talloc_tos(),
					path,
					NULL,
					NULL,
					0,
					0);
	if (smb_fname == NULL) {
		TALLOC_FREE(unmangled_name);
		return -1;
	}

	/* open the directory */
	if (!(cur_dir = OpenDir(talloc_tos(), conn, smb_fname, NULL, 0))) {
		DEBUG(3,("scan dir didn't open dir [%s]\n",path));
		TALLOC_FREE(unmangled_name);
		TALLOC_FREE(smb_fname);
		return -1;
	}

	TALLOC_FREE(smb_fname);

	/* now scan for matching names */
	curpos = 0;
	while ((dname = ReadDirName(cur_dir, &curpos, NULL, &talloced))) {

		/* Is it dot or dot dot. */
		if (ISDOT(dname) || ISDOTDOT(dname)) {
			TALLOC_FREE(talloced);
			continue;
		}

		/*
		 * At this point dname is the unmangled name.
		 * name is either mangled or not, depending on the state
		 * of the "mangled" variable. JRA.
		 */

		/*
		 * Check mangled name against mangled name, or unmangled name
		 * against unmangled name.
		 */

		if ((mangled && mangled_equal(name,dname,conn->params)) ||
			fname_equal(name, dname, conn->case_sensitive)) {
			/* we've found the file, change it's name and return */
			*found_name = talloc_strdup(mem_ctx, dname);
			TALLOC_FREE(unmangled_name);
			TALLOC_FREE(cur_dir);
			if (!*found_name) {
				errno = ENOMEM;
				TALLOC_FREE(talloced);
				return -1;
			}
			TALLOC_FREE(talloced);
			return 0;
		}
		TALLOC_FREE(talloced);
	}

	TALLOC_FREE(unmangled_name);
	TALLOC_FREE(cur_dir);
	errno = ENOENT;
	return -1;
}

/****************************************************************************
 Wrapper around the vfs get_real_filename and the full directory scan
 fallback.
****************************************************************************/

int get_real_filename(connection_struct *conn,
		      struct smb_filename *path,
		      const char *name,
		      TALLOC_CTX *mem_ctx,
		      char **found_name)
{
	int ret;
	bool mangled;

	mangled = mangle_is_mangled(name, conn->params);

	if (mangled) {
		return get_real_filename_full_scan(conn,
						   path->base_name,
						   name,
						   mangled,
						   mem_ctx,
						   found_name);
	}

	/* Try the vfs first to take advantage of case-insensitive stat. */
	ret = SMB_VFS_GET_REAL_FILENAME(conn,
					path,
					name,
					mem_ctx,
					found_name);

	/*
	 * If the case-insensitive stat was successful, or returned an error
	 * other than EOPNOTSUPP then there is no need to fall back on the
	 * full directory scan.
	 */
	if (ret == 0 || (ret == -1 && errno != EOPNOTSUPP)) {
		return ret;
	}

	return get_real_filename_full_scan(conn,
					   path->base_name,
					   name,
					   mangled,
					   mem_ctx,
					   found_name);
}

static NTSTATUS build_stream_path(TALLOC_CTX *mem_ctx,
				  connection_struct *conn,
				  struct smb_filename *smb_fname)
{
	NTSTATUS status;
	unsigned int i, num_streams = 0;
	struct stream_struct *streams = NULL;
	struct smb_filename *pathref = NULL;

	if (SMB_VFS_STAT(conn, smb_fname) == 0) {
		DEBUG(10, ("'%s' exists\n", smb_fname_str_dbg(smb_fname)));
		return NT_STATUS_OK;
	}

	if (errno != ENOENT) {
		DEBUG(10, ("vfs_stat failed: %s\n", strerror(errno)));
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	if (smb_fname->fsp == NULL) {
		status = synthetic_pathref(mem_ctx,
					conn->cwd_fsp,
					smb_fname->base_name,
					NULL,
					NULL,
					smb_fname->twrp,
					smb_fname->flags,
					&pathref);
		if (!NT_STATUS_IS_OK(status)) {
			if (NT_STATUS_EQUAL(status,
				NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
				TALLOC_FREE(pathref);
				SET_STAT_INVALID(smb_fname->st);
				return NT_STATUS_OK;
			}
			DBG_DEBUG("synthetic_pathref failed: %s\n",
				  nt_errstr(status));
			goto fail;
		}
	} else {
		pathref = smb_fname;
	}

	/* Fall back to a case-insensitive scan of all streams on the file. */
	status = vfs_fstreaminfo(pathref->fsp, mem_ctx,
				&num_streams, &streams);
	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		SET_STAT_INVALID(smb_fname->st);
		TALLOC_FREE(pathref);
		return NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("vfs_fstreaminfo failed: %s\n", nt_errstr(status)));
		goto fail;
	}

	for (i=0; i<num_streams; i++) {
		DEBUG(10, ("comparing [%s] and [%s]: ",
			   smb_fname->stream_name, streams[i].name));
		if (sname_equal(smb_fname->stream_name, streams[i].name,
				conn->case_sensitive)) {
			DEBUGADD(10, ("equal\n"));
			break;
		}
		DEBUGADD(10, ("not equal\n"));
	}

	/* Couldn't find the stream. */
	if (i == num_streams) {
		SET_STAT_INVALID(smb_fname->st);
		TALLOC_FREE(pathref);
		TALLOC_FREE(streams);
		return NT_STATUS_OK;
	}

	DEBUG(10, ("case insensitive stream. requested: %s, actual: %s\n",
		smb_fname->stream_name, streams[i].name));


	TALLOC_FREE(smb_fname->stream_name);
	smb_fname->stream_name = talloc_strdup(smb_fname, streams[i].name);
	if (smb_fname->stream_name == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	SET_STAT_INVALID(smb_fname->st);

	if (SMB_VFS_STAT(conn, smb_fname) == 0) {
		DEBUG(10, ("'%s' exists\n", smb_fname_str_dbg(smb_fname)));
	}
	status = NT_STATUS_OK;
 fail:
	TALLOC_FREE(pathref);
	TALLOC_FREE(streams);
	return status;
}

/*
 * Lightweight function to just get last component
 * for rename / enumerate directory calls.
 */

char *get_original_lcomp(TALLOC_CTX *ctx,
			connection_struct *conn,
			const char *filename_in,
			uint32_t ucf_flags)
{
	struct smb_filename *smb_fname = NULL;
	char *last_slash = NULL;
	char *orig_lcomp;
	char *fname = NULL;
	NTTIME twrp = 0;
	NTSTATUS status;

	if (ucf_flags & UCF_DFS_PATHNAME) {
		status = dfs_redirect(ctx,
				conn,
				filename_in,
				ucf_flags,
				!conn->sconn->using_smb2,
				&twrp,
				&fname);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("dfs_redirect "
				"failed for name %s with %s\n",
				filename_in,
				nt_errstr(status));
			return NULL;
		}
		filename_in = fname;
		ucf_flags &= ~UCF_DFS_PATHNAME;
	}

	/*
	 * NB. We don't need to care about
	 * is_fake_file_path(filename_in) here as these
	 * code paths don't ever return original_lcomp
	 * or use it anyway.
	 */

	if (ucf_flags & UCF_GMT_PATHNAME) {
		/*
		 * Ensure we don't return a @GMT
		 * value as the last component.
		 */
		smb_fname = synthetic_smb_fname(ctx,
					filename_in,
					NULL,
					NULL,
					twrp,
					0);
		if (smb_fname == NULL) {
			TALLOC_FREE(fname);
			return NULL;
		}
		status = canonicalize_snapshot_path(smb_fname,
						    ucf_flags,
						    twrp);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(fname);
			TALLOC_FREE(smb_fname);
			return NULL;
		}
		filename_in = smb_fname->base_name;
	}
	last_slash = strrchr(filename_in, '/');
	if (last_slash != NULL) {
		orig_lcomp = talloc_strdup(ctx, last_slash+1);
	} else {
		orig_lcomp = talloc_strdup(ctx, filename_in);
	}
	/* We're done with any temp names here. */
	TALLOC_FREE(smb_fname);
	TALLOC_FREE(fname);
	if (orig_lcomp == NULL) {
		return NULL;
	}
	status = normalize_filename_case(conn, orig_lcomp);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(orig_lcomp);
		return NULL;
	}
	return orig_lcomp;
}

/**
 * Go through all the steps to validate a filename.
 *
 * @param ctx		talloc_ctx to allocate memory with.
 * @param conn		connection struct for vfs calls.
 * @param smbreq	SMB request if we're using privileges.
 * @param name_in	The unconverted name.
 * @param ucf_flags	flags to pass through to unix_convert().
 * @param twrp		Optional VSS time
 * @param p_cont_wcard	If not NULL, will be set to true if the dfs path
 *			resolution detects a wildcard.
 * @param _smb_fname	The final converted name will be allocated if the
 *			return is NT_STATUS_OK.
 *
 * @return NT_STATUS_OK if all operations completed successfully, appropriate
 * 	   error otherwise.
 */
NTSTATUS filename_convert(TALLOC_CTX *ctx,
			  connection_struct *conn,
			  const char *name_in,
			  uint32_t ucf_flags,
			  NTTIME twrp,
			  struct smb_filename **_smb_fname)
{
	struct smb_filename *smb_fname = NULL;
	NTSTATUS status;

	*_smb_fname = NULL;

	if (ucf_flags & UCF_DFS_PATHNAME) {
		char *fname = NULL;
		NTTIME dfs_twrp = 0;
		status = dfs_redirect(ctx, conn,
				name_in,
				ucf_flags,
				!conn->sconn->using_smb2,
				&dfs_twrp,
				&fname);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("dfs_redirect "
				"failed for name %s with %s\n",
				name_in,
				nt_errstr(status));
			return status;
		}
		name_in = fname;
		ucf_flags &= ~UCF_DFS_PATHNAME;
		if (twrp == 0 && dfs_twrp != 0) {
			twrp = dfs_twrp;
		}
	}

	if (is_fake_file_path(name_in)) {
		smb_fname = synthetic_smb_fname_split(ctx,
					name_in,
					(ucf_flags & UCF_POSIX_PATHNAMES));
		if (smb_fname == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		smb_fname->st = (SMB_STRUCT_STAT) { .st_ex_nlink = 1 };
		smb_fname->st.st_ex_btime = (struct timespec){0, SAMBA_UTIME_OMIT};
		smb_fname->st.st_ex_atime = (struct timespec){0, SAMBA_UTIME_OMIT};
		smb_fname->st.st_ex_mtime = (struct timespec){0, SAMBA_UTIME_OMIT};
		smb_fname->st.st_ex_ctime = (struct timespec){0, SAMBA_UTIME_OMIT};

		*_smb_fname = smb_fname;
		return NT_STATUS_OK;
	}

	status = unix_convert(ctx, conn, name_in, twrp, &smb_fname, ucf_flags);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("unix_convert failed "
			"for name %s with %s\n",
			name_in,
			nt_errstr(status));
		return status;
	}

	if ((ucf_flags & UCF_POSIX_PATHNAMES) &&
	    VALID_STAT(smb_fname->st) &&
	    S_ISLNK(smb_fname->st.st_ex_mode))
	{
		status = check_veto_path(conn, smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(smb_fname);
			return status;
		}
	} else {
		status = check_name(conn, smb_fname);
	}
	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("check_name failed "
			"for name %s with %s\n",
			smb_fname_str_dbg(smb_fname),
			nt_errstr(status));
		TALLOC_FREE(smb_fname);
		return status;
	}

	if (!VALID_STAT(smb_fname->st)) {
		DBG_DEBUG("[%s] does not exist, skipping pathref fsp\n",
			  smb_fname_str_dbg(smb_fname));
		*_smb_fname = smb_fname;
		return NT_STATUS_OK;
	}

	status = openat_pathref_fsp(conn->cwd_fsp, smb_fname);
	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		/*
		 * We deal with symlinks here as we do in
		 * SMB_VFS_CREATE_FILE(): return success for POSIX clients with
		 * the notable difference that there will be no fsp in
		 * smb_fname->fsp.
		 *
		 * For Windows (non POSIX) clients fail with
		 * NT_STATUS_OBJECT_NAME_NOT_FOUND.
		 */
		if (smb_fname->flags & SMB_FILENAME_POSIX_PATH &&
		    S_ISLNK(smb_fname->st.st_ex_mode))
		{
			status = NT_STATUS_OK;
		}
	}
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("open_pathref_fsp [%s] failed: %s\n",
			  smb_fname_str_dbg(smb_fname),
			  nt_errstr(status));
		return status;
	}

	*_smb_fname = smb_fname;
	return status;
}

/*
 * Strip a @GMT component from an SMB1-DFS path. Could be anywhere
 * in the path.
 */

static char *strip_gmt_from_raw_dfs(TALLOC_CTX *ctx,
				    const char *name_in,
				    bool posix_pathnames,
				    NTTIME *_twrp)
{
	NTSTATUS status;
	struct smb_filename *smb_fname = NULL;
	char *name_out = NULL;

	smb_fname = synthetic_smb_fname(ctx,
					name_in,
					NULL,
					NULL,
					0,
					0);
	if (smb_fname == NULL) {
		return NULL;
	}
	if (!posix_pathnames) {
		/*
		 * Raw DFS names are still '\\' separated.
		 * canonicalize_snapshot_path() only works
		 * on '/' separated paths. Convert.
		 */
		string_replace(smb_fname->base_name, '\\', '/');
	}
	status = canonicalize_snapshot_path(smb_fname,
					    UCF_GMT_PATHNAME,
					    0);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(smb_fname);
		return NULL;
	}
	if (!posix_pathnames) {
		/* Replace as raw DFS names. */
		string_replace(smb_fname->base_name, '/', '\\');
	}
	name_out = talloc_strdup(ctx, smb_fname->base_name);
	*_twrp = smb_fname->twrp;
	TALLOC_FREE(smb_fname);
	return name_out;
}

/*
 * Deal with the SMB1 semantics of sending a pathname with a
 * wildcard as the terminal component for a SMB1search or
 * trans2 findfirst.
 */

NTSTATUS filename_convert_smb1_search_path(TALLOC_CTX *ctx,
					   connection_struct *conn,
					   const char *name_in,
					   uint32_t ucf_flags,
					   struct smb_filename **_smb_fname_out,
					   char **_mask_out)
{
	NTSTATUS status;
	char *p = NULL;
	char *mask = NULL;
	struct smb_filename *smb_fname = NULL;
	bool posix_pathnames = (ucf_flags & UCF_POSIX_PATHNAMES);
	NTTIME twrp = 0;
	TALLOC_CTX *frame = talloc_stackframe();

	*_smb_fname_out = NULL;
	*_mask_out = NULL;

	DBG_DEBUG("name_in: %s\n", name_in);

	if (ucf_flags & UCF_DFS_PATHNAME) {
		/*
		 * We've been given a raw DFS pathname.
		 * In Windows mode this is separated by '\\'
		 * characters.
		 *
		 * We need to remove the last component
		 * which must be a wildcard before passing
		 * to dfs_redirect(). But the last component
		 * may also be a @GMT- token so we have to
		 * remove that first.
		 */
		char path_sep = posix_pathnames ? '/' : '\\';
		char *fname = NULL;
		char *name_in_copy = NULL;
		char *last_component = NULL;

		/* Work on a copy of name_in. */
		if (ucf_flags & UCF_GMT_PATHNAME) {
			name_in_copy = strip_gmt_from_raw_dfs(frame,
							      name_in,
							      posix_pathnames,
							      &twrp);
			ucf_flags &= ~UCF_GMT_PATHNAME;
		} else {
			name_in_copy = talloc_strdup(frame, name_in);
		}
		if (name_in_copy == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		/*
		 * Now we know that the last component is the
		 * wildcard. Copy it and truncate to remove it.
		 */
		p = strrchr_m(name_in_copy, path_sep);
		if (p == NULL) {
			last_component = talloc_strdup(frame, name_in_copy);
			name_in_copy[0] = '\0';
		} else {
			last_component = talloc_strdup(frame, p+1);
			*p = '\0';
		}
		if (last_component == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		DBG_DEBUG("name_in_copy: %s\n", name_in);

		/*
		 * Now we can call dfs_redirect()
		 * on the name without wildcard.
		 */
		status = dfs_redirect(frame,
				      conn,
				      name_in_copy,
				      ucf_flags,
				      !conn->sconn->using_smb2,
				      NULL,
				      &fname);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("dfs_redirect "
				"failed for name %s with %s\n",
				name_in_copy,
				nt_errstr(status));
			TALLOC_FREE(frame);
			return status;
		}
		/* Add the last component back. */
		if (fname[0] == '\0') {
			name_in = talloc_strdup(frame, last_component);
		} else {
			name_in = talloc_asprintf(frame,
						  "%s%c%s",
						  fname,
						  path_sep,
						  last_component);
		}
		if (name_in == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
		ucf_flags &= ~UCF_DFS_PATHNAME;

		DBG_DEBUG("After DFS redirect name_in: %s\n", name_in);
	}

	smb_fname = synthetic_smb_fname(frame,
					name_in,
					NULL,
					NULL,
					twrp,
					posix_pathnames ?
						SMB_FILENAME_POSIX_PATH : 0);
	if (smb_fname == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	/* Canonicalize any @GMT- paths. */
	status = canonicalize_snapshot_path(smb_fname, ucf_flags, twrp);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	/* Get the original lcomp. */
	mask = get_original_lcomp(frame,
				  conn,
				  name_in,
				  ucf_flags);
	if (mask == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	if (mask[0] == '\0') {
		/* Windows and OS/2 systems treat search on the root as * */
		TALLOC_FREE(mask);
		mask = talloc_strdup(frame, "*");
		if (mask == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}

	DBG_DEBUG("mask = %s\n", mask);

	/*
	 * Remove the terminal component so
	 * filename_convert never sees the mask.
	 */
	p = strrchr_m(smb_fname->base_name,'/');
	if (p == NULL) {
		/* filename_convert handles a '\0' base_name. */
		smb_fname->base_name[0] = '\0';
	} else {
		*p = '\0';
	}

	DBG_DEBUG("For filename_convert: smb_fname = %s\n",
		smb_fname_str_dbg(smb_fname));

	/* Convert the parent directory path. */
	status = filename_convert(frame,
				  conn,
				  smb_fname->base_name,
				  ucf_flags,
				  smb_fname->twrp,
				  &smb_fname);

	if (NT_STATUS_IS_OK(status)) {
		*_smb_fname_out = talloc_move(ctx, &smb_fname);
		*_mask_out = talloc_move(ctx, &mask);
	} else {
		DBG_DEBUG("filename_convert error for %s: %s\n",
			smb_fname_str_dbg(smb_fname),
			nt_errstr(status));
	}

	TALLOC_FREE(frame);
	return status;
}

/*
 * Build the full path from a dirfsp and dirfsp relative name
 */
struct smb_filename *full_path_from_dirfsp_atname(
	TALLOC_CTX *mem_ctx,
	const struct files_struct *dirfsp,
	const struct smb_filename *atname)
{
	struct smb_filename *fname = NULL;
	char *path = NULL;

	if (dirfsp == dirfsp->conn->cwd_fsp ||
	    ISDOT(dirfsp->fsp_name->base_name) ||
	    atname->base_name[0] == '/')
	{
		path = talloc_strdup(mem_ctx, atname->base_name);
	} else {
		path = talloc_asprintf(mem_ctx, "%s/%s",
				       dirfsp->fsp_name->base_name,
				       atname->base_name);
	}
	if (path == NULL) {
		return NULL;
	}

	fname = synthetic_smb_fname(mem_ctx,
				    path,
				    atname->stream_name,
				    &atname->st,
				    atname->twrp,
				    atname->flags);
	TALLOC_FREE(path);
	if (fname == NULL) {
		return NULL;
	}

	return fname;
}

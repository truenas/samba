/*
 * Unix SMB/CIFS implementation. 
 * SMB parameters and setup
 * Copyright (C) Andrew Tridgell   1992-1998
 * Copyright (C) Simo Sorce        2000-2003
 * Copyright (C) Gerald Carter     2000-2006
 * Copyright (C) Jeremy Allison    2001-2009
 * Copyright (C) Andrew Bartlett   2002
 * Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2005
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "system/filesys.h"
#include "passdb.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "../libcli/security/security.h"
#include "util_tdb.h"
#include "passdb/pdb_tdb.h"
#include "lib/util/smb_strtox.h"
#include "lib/util/string_wrappers.h"

#if 0 /* when made a module use this */

static int tdbsam_debug_level = DBGC_ALL;
#undef DBGC_CLASS
#define DBGC_CLASS tdbsam_debug_level

#else

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_PASSDB

#endif

#define TDBSAM_VERSION	4	/* Most recent TDBSAM version */
#define TDBSAM_MINOR_VERSION	0	/* Most recent TDBSAM minor version */
#define TDBSAM_VERSION_STRING	"INFO/version"
#define TDBSAM_MINOR_VERSION_STRING	"INFO/minor_version"
#define PASSDB_FILE_NAME	"passdb.tdb"
#define USERPREFIX		"USER_"
#define USERPREFIX_LEN		5
#define RIDPREFIX		"RID_"
#define PRIVPREFIX		"PRIV_"
#define NEXT_RID_STRING		"NEXT_RID"
#define TRUENAS_PRIVATE_DIR	"/var/run/samba-cache/private/"
#define TRUENAS_PASSDB		TRUENAS_PRIVATE_DIR PASSDB_FILE_NAME

/* GLOBAL TDB SAM CONTEXT */

static struct db_context *db_sam;
static char *tdbsam_filename;
static bool map_builtin;

struct tdbsam_convert_state {
	int32_t from;
	bool success;
};

static int tdbsam_convert_one(struct db_record *rec, void *priv)
{
	struct tdbsam_convert_state *state =
		(struct tdbsam_convert_state *)priv;
	struct samu *user;
	TDB_DATA data;
	NTSTATUS status;
	bool ret;
	TDB_DATA key;
	TDB_DATA value;

	key = dbwrap_record_get_key(rec);

	if (key.dsize < USERPREFIX_LEN) {
		return 0;
	}
	if (strncmp((char *)key.dptr, USERPREFIX, USERPREFIX_LEN) != 0) {
		return 0;
	}

	user = samu_new(talloc_tos());
	if (user == NULL) {
		DEBUG(0,("tdbsam_convert: samu_new() failed!\n"));
		state->success = false;
		return -1;
	}

	DEBUG(10,("tdbsam_convert: Try unpacking a record with (key:%s) "
		  "(version:%d)\n", (char *)key.dptr, state->from));

	value = dbwrap_record_get_value(rec);

	switch (state->from) {
	case 0:
		ret = init_samu_from_buffer(user, SAMU_BUFFER_V0,
					    (uint8_t *)value.dptr,
					    value.dsize);
		break;
	case 1:
		ret = init_samu_from_buffer(user, SAMU_BUFFER_V1,
					    (uint8_t *)value.dptr,
					    value.dsize);
		break;
	case 2:
		ret = init_samu_from_buffer(user, SAMU_BUFFER_V2,
					    (uint8_t *)value.dptr,
					    value.dsize);
		break;
	case 3:
		ret = init_samu_from_buffer(user, SAMU_BUFFER_V3,
					    (uint8_t *)value.dptr,
					    value.dsize);
		break;
	case 4:
		ret = init_samu_from_buffer(user, SAMU_BUFFER_V4,
					    (uint8_t *)value.dptr,
					    value.dsize);
		break;
	default:
		/* unknown tdbsam version */
		ret = False;
	}
	if (!ret) {
		DEBUG(0,("tdbsam_convert: Bad struct samu entry returned "
			 "from TDB (key:%s) (version:%d)\n", (char *)key.dptr,
			 state->from));
		TALLOC_FREE(user);
		state->success = false;
		return -1;
	}

	data.dsize = init_buffer_from_samu(&data.dptr, user, false);
	TALLOC_FREE(user);

	if (data.dsize == -1) {
		DEBUG(0,("tdbsam_convert: cannot pack the struct samu into "
			 "the new format\n"));
		state->success = false;
		return -1;
	}

	status = dbwrap_record_store(rec, data, TDB_MODIFY);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Could not store the new record: %s\n",
			  nt_errstr(status)));
		state->success = false;
		return -1;
	}

	return 0;
}

/**********************************************************************
 Struct and function to backup an old record.
 *********************************************************************/

struct tdbsam_backup_state {
	struct db_context *new_db;
	bool success;
};

static int backup_copy_fn(struct db_record *orig_rec, void *state)
{
	struct tdbsam_backup_state *bs = (struct tdbsam_backup_state *)state;
	struct db_record *new_rec;
	NTSTATUS status;
	TDB_DATA key;
	TDB_DATA value;

	key = dbwrap_record_get_key(orig_rec);

	new_rec = dbwrap_fetch_locked(bs->new_db, talloc_tos(), key);
	if (new_rec == NULL) {
		bs->success = false;
		return 1;
	}

	value = dbwrap_record_get_value(orig_rec);

	status = dbwrap_record_store(new_rec, value, TDB_INSERT);

	TALLOC_FREE(new_rec);

	if (!NT_STATUS_IS_OK(status)) {
		bs->success = false;
                return 1;
        }
        return 0;
}

/**********************************************************************
 Make a backup of an old passdb and replace the new one with it. We
 have to do this as between 3.0.x and 3.2.x the hash function changed
 by mistake (used unsigned char * instead of char *). This means the
 previous simple update code will fail due to not being able to find
 existing records to replace in the tdbsam_convert_one() function. JRA.
 *********************************************************************/

static bool tdbsam_convert_backup(const char *dbname, struct db_context **pp_db)
{
	TALLOC_CTX *frame = talloc_stackframe();
	const char *tmp_fname = NULL;
	struct db_context *tmp_db = NULL;
	struct db_context *orig_db = *pp_db;
	struct tdbsam_backup_state bs;
	NTSTATUS status;

	tmp_fname = talloc_asprintf(frame, "%s.tmp", dbname);
	if (!tmp_fname) {
		TALLOC_FREE(frame);
		return false;
	}

	unlink(tmp_fname);

	/* Remember to open this on the NULL context. We need
	 * it to stay around after we return from here. */

	tmp_db = db_open(NULL, tmp_fname, 0,
			 TDB_DEFAULT, O_CREAT|O_RDWR, 0600,
			 DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);
	if (tmp_db == NULL) {
		DEBUG(0, ("tdbsam_convert_backup: Failed to create backup TDB passwd "
			  "[%s]\n", tmp_fname));
		TALLOC_FREE(frame);
		return false;
	}

	if (dbwrap_transaction_start(orig_db) != 0) {
		DEBUG(0, ("tdbsam_convert_backup: Could not start transaction (1)\n"));
		unlink(tmp_fname);
		TALLOC_FREE(tmp_db);
		TALLOC_FREE(frame);
		return false;
	}
	if (dbwrap_transaction_start(tmp_db) != 0) {
		DEBUG(0, ("tdbsam_convert_backup: Could not start transaction (2)\n"));
		dbwrap_transaction_cancel(orig_db);
		unlink(tmp_fname);
		TALLOC_FREE(tmp_db);
		TALLOC_FREE(frame);
		return false;
	}

	bs.new_db = tmp_db;
	bs.success = true;

        status = dbwrap_traverse(orig_db, backup_copy_fn, (void *)&bs, NULL);
        if (!NT_STATUS_IS_OK(status)) {
                DEBUG(0, ("tdbsam_convert_backup: traverse failed\n"));
                goto cancel;
        }

	if (!bs.success) {
		DEBUG(0, ("tdbsam_convert_backup: Rewriting records failed\n"));
		goto cancel;
	}

	if (dbwrap_transaction_commit(orig_db) != 0) {
		smb_panic("tdbsam_convert_backup: orig commit failed\n");
	}
	if (dbwrap_transaction_commit(tmp_db) != 0) {
		smb_panic("tdbsam_convert_backup: orig commit failed\n");
	}

	/* be sure to close the DBs _before_ renaming the file */

	TALLOC_FREE(orig_db);
	TALLOC_FREE(tmp_db);

	/* This is safe from other users as we know we're
 	 * under a mutex here. */

	if (rename(tmp_fname, dbname) == -1) {
		DEBUG(0, ("tdbsam_convert_backup: rename of %s to %s failed %s\n",
			tmp_fname,
			dbname,
			strerror(errno)));
		smb_panic("tdbsam_convert_backup: replace passdb failed\n");
	}

	TALLOC_FREE(frame);

	/* re-open the converted TDB */

	orig_db = db_open(NULL, dbname, 0,
			  TDB_DEFAULT, O_CREAT|O_RDWR, 0600,
			  DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);
	if (orig_db == NULL) {
		DEBUG(0, ("tdbsam_convert_backup: Failed to re-open "
			  "converted passdb TDB [%s]\n", dbname));
		return false;
	}

	DEBUG(1, ("tdbsam_convert_backup: updated %s file.\n",
		dbname ));

	/* Replace the global db pointer. */
	*pp_db = orig_db;
	return true;

  cancel:

	if (dbwrap_transaction_cancel(orig_db) != 0) {
		smb_panic("tdbsam_convert: transaction_cancel failed");
	}

	if (dbwrap_transaction_cancel(tmp_db) != 0) {
		smb_panic("tdbsam_convert: transaction_cancel failed");
	}

	unlink(tmp_fname);
	TALLOC_FREE(tmp_db);
	TALLOC_FREE(frame);
	return false;
}

static bool tdbsam_upgrade_next_rid(struct db_context *db)
{
	TDB_CONTEXT *tdb;
	uint32_t rid;
	bool ok = false;
	NTSTATUS status;
	char *db_path;

	status = dbwrap_fetch_uint32_bystring(db, NEXT_RID_STRING, &rid);
	if (NT_STATUS_IS_OK(status)) {
		return true;
	}

	db_path = state_path(talloc_tos(), "winbindd_idmap.tdb");
	if (db_path == NULL) {
		return false;
	}

	tdb = tdb_open_log(db_path, 0,
			   TDB_DEFAULT, O_RDONLY, 0644);
	TALLOC_FREE(db_path);
	if (tdb) {
		ok = tdb_fetch_uint32(tdb, "RID_COUNTER", &rid);
		if (!ok) {
			rid = BASE_RID;
		}
		tdb_close(tdb);
	} else {
		rid = BASE_RID;
	}

	status = dbwrap_store_uint32_bystring(db, NEXT_RID_STRING, rid);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	return true;
}

static bool tdbsam_convert(struct db_context **pp_db, const char *name, int32_t from)
{
	struct tdbsam_convert_state state;
	struct db_context *db = NULL;
	NTSTATUS status;

	/* We only need the update backup for local db's. */
	if (db_is_local(name) && !tdbsam_convert_backup(name, pp_db)) {
		DEBUG(0, ("tdbsam_convert: Could not backup %s\n", name));
		return false;
	}

	db = *pp_db;
	state.from = from;
	state.success = true;

	if (dbwrap_transaction_start(db) != 0) {
		DEBUG(0, ("tdbsam_convert: Could not start transaction\n"));
		return false;
	}

	if (!tdbsam_upgrade_next_rid(db)) {
		DEBUG(0, ("tdbsam_convert: tdbsam_upgrade_next_rid failed\n"));
		goto cancel;
	}

	status = dbwrap_traverse(db, tdbsam_convert_one, &state, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("tdbsam_convert: traverse failed\n"));
		goto cancel;
	}

	if (!state.success) {
		DEBUG(0, ("tdbsam_convert: Converting records failed\n"));
		goto cancel;
	}

	status = dbwrap_store_int32_bystring(db, TDBSAM_VERSION_STRING,
					     TDBSAM_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("tdbsam_convert: Could not store tdbsam version: "
			  "%s\n", nt_errstr(status)));
		goto cancel;
	}

	status = dbwrap_store_int32_bystring(db, TDBSAM_MINOR_VERSION_STRING,
					     TDBSAM_MINOR_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("tdbsam_convert: Could not store tdbsam minor "
			  "version: %s\n", nt_errstr(status)));
		goto cancel;
	}

	if (dbwrap_transaction_commit(db) != 0) {
		DEBUG(0, ("tdbsam_convert: Could not commit transaction\n"));
		return false;
	}

	return true;

 cancel:
	if (dbwrap_transaction_cancel(db) != 0) {
		smb_panic("tdbsam_convert: transaction_cancel failed");
	}

	return false;
}

/*********************************************************************
 Open the tdbsam file based on the absolute path specified.
 Uses a reference count to allow multiple open calls.
*********************************************************************/

static bool tdbsam_open( const char *name )
{
	int32_t version;
	int32_t minor_version;
	NTSTATUS status;

	/* check if we are already open */

	if ( db_sam ) {
		return true;
	}

	/* Try to open tdb passwd.  Create a new one if necessary */

	db_sam = db_open(NULL, name, 0, TDB_DEFAULT, O_CREAT|O_RDWR, 0600,
			 DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);
	if (db_sam == NULL) {
		DEBUG(0, ("tdbsam_open: Failed to open/create TDB passwd "
			  "[%s]\n", name));
		return false;
	}

	/* Check the version */
	status = dbwrap_fetch_int32_bystring(db_sam, TDBSAM_VERSION_STRING,
					     &version);
	if (!NT_STATUS_IS_OK(status)) {
		version = 0;	/* Version not found, assume version 0 */
	}

	/* Get the minor version */
	status = dbwrap_fetch_int32_bystring(
		db_sam, TDBSAM_MINOR_VERSION_STRING, &minor_version);
	if (!NT_STATUS_IS_OK(status)) {
		minor_version = 0; /* Minor version not found, assume 0 */
	}

	/* Compare the version */
	if (version > TDBSAM_VERSION) {
		/* Version more recent than the latest known */
		DEBUG(0, ("tdbsam_open: unknown version => %d\n", version));
		TALLOC_FREE(db_sam);
		return false;
	}

	if ( version < TDBSAM_VERSION ||
			(version == TDBSAM_VERSION &&
			 minor_version < TDBSAM_MINOR_VERSION) ) {
		/*
		 * Ok - we think we're going to have to convert.
		 * Due to the backup process we now must do to
		 * upgrade we have to get a mutex and re-check
		 * the version. Someone else may have upgraded
		 * whilst we were checking.
		 */

		struct named_mutex *mtx = grab_named_mutex(NULL,
						"tdbsam_upgrade_mutex",
						600);

		if (!mtx) {
			DEBUG(0, ("tdbsam_open: failed to grab mutex.\n"));
			TALLOC_FREE(db_sam);
			return false;
		}

		/* Re-check the version */
		status = dbwrap_fetch_int32_bystring(
			db_sam, TDBSAM_VERSION_STRING, &version);
		if (!NT_STATUS_IS_OK(status)) {
			version = 0;	/* Version not found, assume version 0 */
		}

		/* Re-check the minor version */
		status = dbwrap_fetch_int32_bystring(
			db_sam, TDBSAM_MINOR_VERSION_STRING, &minor_version);
		if (!NT_STATUS_IS_OK(status)) {
			minor_version = 0; /* Minor version not found, assume 0 */
		}

		/* Compare the version */
		if (version > TDBSAM_VERSION) {
			/* Version more recent than the latest known */
			DEBUG(0, ("tdbsam_open: unknown version => %d\n", version));
			TALLOC_FREE(db_sam);
			TALLOC_FREE(mtx);
			return false;
		}

		if ( version < TDBSAM_VERSION ||
				(version == TDBSAM_VERSION &&
				 minor_version < TDBSAM_MINOR_VERSION) ) {
			/*
			 * Note that minor versions we read that are greater
			 * than the current minor version we have hard coded
			 * are assumed to be compatible if they have the same
			 * major version. That allows previous versions of the
			 * passdb code that don't know about minor versions to
			 * still use this database. JRA.
			 */

			DEBUG(1, ("tdbsam_open: Converting version %d.%d database to "
				  "version %d.%d.\n",
					version,
					minor_version,
					TDBSAM_VERSION,
					TDBSAM_MINOR_VERSION));

			if ( !tdbsam_convert(&db_sam, name, version) ) {
				DEBUG(0, ("tdbsam_open: Error when trying to convert "
					  "tdbsam [%s]\n",name));
				TALLOC_FREE(db_sam);
				TALLOC_FREE(mtx);
				return false;
			}

			DEBUG(3, ("TDBSAM converted successfully.\n"));
		}
		TALLOC_FREE(mtx);
	}

	DEBUG(4,("tdbsam_open: successfully opened %s\n", name ));

	return true;
}

/******************************************************************
 Lookup a name in the SAM TDB
******************************************************************/

static NTSTATUS tdbsam_getsampwnam (struct pdb_methods *my_methods,
				    struct samu *user, const char *sname)
{
	TDB_DATA 	data;
	fstring 	keystr;
	fstring		name;
	NTSTATUS status;

	if ( !user ) {
		DEBUG(0,("pdb_getsampwnam: struct samu is NULL.\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* Data is stored in all lower-case */
	fstrcpy(name, sname);
	if (!strlower_m(name)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* set search key */
	fstr_sprintf(keystr, "%s%s", USERPREFIX, name);

	/* open the database */

	if ( !tdbsam_open( tdbsam_filename ) ) {
		DEBUG(0,("tdbsam_getsampwnam: failed to open %s!\n", tdbsam_filename));
		return NT_STATUS_ACCESS_DENIED;
	}

	/* get the record */

	status = dbwrap_fetch_bystring(db_sam, talloc_tos(), keystr, &data);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("pdb_getsampwnam (TDB): error fetching database.\n"));
		DEBUGADD(5, (" Key: %s\n", keystr));
		return NT_STATUS_NO_SUCH_USER;
	}

	if (data.dsize == 0) {
		DEBUG(5, ("%s: Got 0-sized record for key %s\n", __func__,
			  keystr));
		return NT_STATUS_NO_SUCH_USER;
	}

  	/* unpack the buffer */

	if (!init_samu_from_buffer(user, SAMU_BUFFER_LATEST, data.dptr, data.dsize)) {
		DEBUG(0,("pdb_getsampwent: Bad struct samu entry returned from TDB!\n"));
		TALLOC_FREE(data.dptr);
		return NT_STATUS_NO_MEMORY;
	}

	/* success */

	TALLOC_FREE(data.dptr);

	return NT_STATUS_OK;
}

/***************************************************************************
 Search by rid
 **************************************************************************/

static NTSTATUS tdbsam_getsampwrid (struct pdb_methods *my_methods,
				    struct samu *user, uint32_t rid)
{
	NTSTATUS                nt_status = NT_STATUS_UNSUCCESSFUL;
	TDB_DATA 		data;
	fstring 		keystr;
	fstring			name;

	if ( !user ) {
		DEBUG(0,("pdb_getsampwrid: struct samu is NULL.\n"));
		return nt_status;
	}

	/* set search key */

	fstr_sprintf(keystr, "%s%.8x", RIDPREFIX, rid);

	/* open the database */

	if ( !tdbsam_open( tdbsam_filename ) ) {
		DEBUG(0,("tdbsam_getsampwrid: failed to open %s!\n", tdbsam_filename));
		return NT_STATUS_ACCESS_DENIED;
	}

	/* get the record */

	nt_status = dbwrap_fetch_bystring(db_sam, talloc_tos(), keystr, &data);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(5,("pdb_getsampwrid (TDB): error looking up RID %d by key %s.\n", rid, keystr));
		return nt_status;
	}

	fstrcpy(name, (const char *)data.dptr);
	TALLOC_FREE(data.dptr);

	return tdbsam_getsampwnam (my_methods, user, name);
}

static NTSTATUS tdbsam_getsampwsid(struct pdb_methods *my_methods,
				   struct samu * user, const struct dom_sid *sid)
{
	uint32_t rid;

	if ( !sid_peek_check_rid(get_global_sam_sid(), sid, &rid) )
		return NT_STATUS_UNSUCCESSFUL;

	return tdbsam_getsampwrid(my_methods, user, rid);
}

static bool tdb_delete_samacct_only( struct samu *sam_pass )
{
	fstring 	keystr;
	fstring		name;
	NTSTATUS status;

	fstrcpy(name, pdb_get_username(sam_pass));
	if (!strlower_m(name)) {
		return false;
	}

  	/* set the search key */

	fstr_sprintf(keystr, "%s%s", USERPREFIX, name);

	/* it's outaa here!  8^) */
	if ( !tdbsam_open( tdbsam_filename ) ) {
		DEBUG(0,("tdb_delete_samacct_only: failed to open %s!\n",
			 tdbsam_filename));
		return false;
	}

	status = dbwrap_delete_bystring(db_sam, keystr);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("Error deleting entry from tdb passwd "
			  "database: %s!\n", nt_errstr(status)));
		return false;
	}

	return true;
}

/***************************************************************************
 Delete a struct samu records for the username and RID key
****************************************************************************/

static NTSTATUS tdbsam_delete_sam_account(struct pdb_methods *my_methods,
					  struct samu *sam_pass)
{
	NTSTATUS        nt_status;
	fstring 	keystr;
	uint32_t	rid;
	fstring		name;

	/* open the database */

	if ( !tdbsam_open( tdbsam_filename ) ) {
		DEBUG(0,("tdbsam_delete_sam_account: failed to open %s!\n",
			 tdbsam_filename));
		return NT_STATUS_ACCESS_DENIED;
	}

	fstrcpy(name, pdb_get_username(sam_pass));
	if (!strlower_m(name)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

  	/* set the search key */

	fstr_sprintf(keystr, "%s%s", USERPREFIX, name);

	rid = pdb_get_user_rid(sam_pass);

	/* it's outaa here!  8^) */

	if (dbwrap_transaction_start(db_sam) != 0) {
		DEBUG(0, ("Could not start transaction\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	nt_status = dbwrap_delete_bystring(db_sam, keystr);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(5, ("Error deleting entry from tdb passwd "
			  "database: %s!\n", nt_errstr(nt_status)));
		goto cancel;
	}

  	/* set the search key */

	fstr_sprintf(keystr, "%s%.8x", RIDPREFIX, rid);

	/* it's outaa here!  8^) */

	nt_status = dbwrap_delete_bystring(db_sam, keystr);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(5, ("Error deleting entry from tdb rid "
			  "database: %s!\n", nt_errstr(nt_status)));
		goto cancel;
	}

	if (dbwrap_transaction_commit(db_sam) != 0) {
		DEBUG(0, ("Could not commit transaction\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	return NT_STATUS_OK;

 cancel:
	if (dbwrap_transaction_cancel(db_sam) != 0) {
		smb_panic("transaction_cancel failed");
	}

	return nt_status;
}


/***************************************************************************
 Update the TDB SAM account record only
 Assumes that the tdbsam is already open 
****************************************************************************/
static bool tdb_update_samacct_only( struct samu* newpwd, int flag )
{
	TDB_DATA 	data;
	uint8_t		*buf = NULL;
	fstring 	keystr;
	fstring		name;
	bool		ret = false;
	NTSTATUS status;

	/* copy the struct samu struct into a BYTE buffer for storage */

	if ( (data.dsize=init_buffer_from_samu(&buf, newpwd, False)) == -1 ) {
		DEBUG(0,("tdb_update_sam: ERROR - Unable to copy struct samu info BYTE buffer!\n"));
		goto done;
	}
	data.dptr = buf;

	fstrcpy(name, pdb_get_username(newpwd));
	if (!strlower_m(name)) {
		goto done;
	}

	DEBUG(5, ("Storing %saccount %s with RID %d\n",
		  flag == TDB_INSERT ? "(new) " : "", name,
		  pdb_get_user_rid(newpwd)));

  	/* setup the USER index key */
	fstr_sprintf(keystr, "%s%s", USERPREFIX, name);

	/* add the account */

	status = dbwrap_store_bystring(db_sam, keystr, data, flag);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Unable to modify passwd TDB: %s!",
			  nt_errstr(status)));
		goto done;
	}

	ret = true;

done:
	/* cleanup */
	SAFE_FREE(buf);
	return ret;
}

/***************************************************************************
 Update the TDB SAM RID record only
 Assumes that the tdbsam is already open
****************************************************************************/
static bool tdb_update_ridrec_only( struct samu* newpwd, int flag )
{
	TDB_DATA 	data;
	fstring 	keystr;
	fstring		name;
	NTSTATUS status;

	fstrcpy(name, pdb_get_username(newpwd));
	if (!strlower_m(name)) {
		return false;
	}

	/* setup RID data */
	data = string_term_tdb_data(name);

	/* setup the RID index key */
	fstr_sprintf(keystr, "%s%.8x", RIDPREFIX, pdb_get_user_rid(newpwd));

	/* add the reference */
	status = dbwrap_store_bystring(db_sam, keystr, data, flag);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Unable to modify TDB passwd: %s!\n",
			  nt_errstr(status)));
		return false;
	}

	return true;

}

/***************************************************************************
 Update the TDB SAM
****************************************************************************/

static bool tdb_update_sam(struct pdb_methods *my_methods, struct samu* newpwd,
			   int flag)
{
	uint32_t oldrid;
	uint32_t newrid;

	if (!(newrid = pdb_get_user_rid(newpwd))) {
		DEBUG(0,("tdb_update_sam: struct samu (%s) with no RID!\n",
			 pdb_get_username(newpwd)));
		return False;
	}

	oldrid = newrid;

	/* open the database */

	if ( !tdbsam_open( tdbsam_filename ) ) {
		DEBUG(0,("tdbsam_getsampwnam: failed to open %s!\n", tdbsam_filename));
		return False;
	}

	if (dbwrap_transaction_start(db_sam) != 0) {
		DEBUG(0, ("Could not start transaction\n"));
		return false;
	}

	/* If we are updating, we may be changing this users RID. Retrieve the old RID
	   so we can check. */

	if (flag == TDB_MODIFY) {
		struct samu *account = samu_new(talloc_tos());
		if (account == NULL) {
			DEBUG(0,("tdb_update_sam: samu_new() failed\n"));
			goto cancel;
		}
		if (!NT_STATUS_IS_OK(tdbsam_getsampwnam(my_methods, account, pdb_get_username(newpwd)))) {
			DEBUG(0,("tdb_update_sam: tdbsam_getsampwnam() for %s failed\n",
				pdb_get_username(newpwd)));
			TALLOC_FREE(account);
			goto cancel;
		}
		if (!(oldrid = pdb_get_user_rid(account))) {
			DEBUG(0,("tdb_update_sam: pdb_get_user_rid() failed\n"));
			TALLOC_FREE(account);
			goto cancel;
		}
		TALLOC_FREE(account);
	}

	/* Update the new samu entry. */
	if (!tdb_update_samacct_only(newpwd, flag)) {
		goto cancel;
	}

	/* Now take care of the case where the RID changed. We need
	 * to delete the old RID key and add the new. */

	if (flag == TDB_MODIFY && newrid != oldrid) { 
		fstring keystr;

		/* Delete old RID key */
		DEBUG(10, ("tdb_update_sam: Deleting key for RID %u\n", oldrid));
		fstr_sprintf(keystr, "%s%.8x", RIDPREFIX, oldrid);
		if (!NT_STATUS_IS_OK(dbwrap_delete_bystring(db_sam, keystr))) {
			DEBUG(0, ("tdb_update_sam: Can't delete %s\n", keystr));
			goto cancel;
		}
		/* Insert new RID key */
		DEBUG(10, ("tdb_update_sam: Inserting key for RID %u\n", newrid));
		if (!tdb_update_ridrec_only(newpwd, TDB_INSERT)) {
			goto cancel;
		}
	} else {
		DEBUG(10, ("tdb_update_sam: %s key for RID %u\n",
			flag == TDB_MODIFY ? "Updating" : "Inserting", newrid));
		if (!tdb_update_ridrec_only(newpwd, flag)) {
			goto cancel;
		}
	}

	if (dbwrap_transaction_commit(db_sam) != 0) {
		DEBUG(0, ("Could not commit transaction\n"));
		return false;
	}

	return true;

 cancel:
	if (dbwrap_transaction_cancel(db_sam) != 0) {
		smb_panic("transaction_cancel failed");
	}
	return false;
}

/***************************************************************************
 Modifies an existing struct samu
****************************************************************************/

static NTSTATUS tdbsam_update_sam_account (struct pdb_methods *my_methods, struct samu *newpwd)
{
	if ( !tdb_update_sam(my_methods, newpwd, TDB_MODIFY) )
		return NT_STATUS_UNSUCCESSFUL;
	
	return NT_STATUS_OK;
}

/***************************************************************************
 Adds an existing struct samu
****************************************************************************/

static NTSTATUS tdbsam_add_sam_account (struct pdb_methods *my_methods, struct samu *newpwd)
{
	if ( !tdb_update_sam(my_methods, newpwd, TDB_INSERT) )
		return NT_STATUS_UNSUCCESSFUL;
		
	return NT_STATUS_OK;
}

/***************************************************************************
 Renames a struct samu
 - check for the posix user/rename user script
 - Add and lock the new user record
 - rename the posix user
 - rewrite the rid->username record
 - delete the old user
 - unlock the new user record
***************************************************************************/
static NTSTATUS tdbsam_rename_sam_account(struct pdb_methods *my_methods,
					  struct samu *old_acct,
					  const char *newname)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct samu      *new_acct = NULL;
	char *rename_script = NULL;
	int              rename_ret;
	fstring          oldname_lower;
	fstring          newname_lower;

	/* can't do anything without an external script */

	if ( !(new_acct = samu_new( talloc_tos() )) ) {
		return NT_STATUS_NO_MEMORY;
	}

	rename_script = lp_rename_user_script(new_acct, lp_sub);
	if (!rename_script) {
		TALLOC_FREE(new_acct);
		return NT_STATUS_NO_MEMORY;
	}
	if (!*rename_script) {
		TALLOC_FREE(new_acct);
		return NT_STATUS_ACCESS_DENIED;
	}

	if ( !pdb_copy_sam_account(new_acct, old_acct)
		|| !pdb_set_username(new_acct, newname, PDB_CHANGED))
	{
		TALLOC_FREE(new_acct);
		return NT_STATUS_NO_MEMORY;
	}

	/* open the database */
	if ( !tdbsam_open( tdbsam_filename ) ) {
		DEBUG(0, ("tdbsam_getsampwnam: failed to open %s!\n",
			  tdbsam_filename));
		TALLOC_FREE(new_acct);
		return NT_STATUS_ACCESS_DENIED;
	}

	if (dbwrap_transaction_start(db_sam) != 0) {
		DEBUG(0, ("Could not start transaction\n"));
		TALLOC_FREE(new_acct);
		return NT_STATUS_ACCESS_DENIED;

	}

	/* add the new account and lock it */
	if ( !tdb_update_samacct_only(new_acct, TDB_INSERT) ) {
		goto cancel;
	}

	/* Rename the posix user.  Follow the semantics of _samr_create_user()
	   so that we lower case the posix name but preserve the case in passdb */

	fstrcpy( oldname_lower, pdb_get_username(old_acct) );
	if (!strlower_m( oldname_lower )) {
		goto cancel;
	}

	fstrcpy( newname_lower, newname );
	if (!strlower_m( newname_lower )) {
		goto cancel;
	}

	rename_script = talloc_string_sub2(new_acct,
				rename_script,
				"%unew",
				newname_lower,
				true,
				false,
				true);
	if (!rename_script) {
		goto cancel;
	}
	rename_script = talloc_string_sub2(new_acct,
				rename_script,
				"%uold",
				oldname_lower,
				true,
				false,
				true);
	if (!rename_script) {
		goto cancel;
	}
	rename_ret = smbrun(rename_script, NULL, NULL);

	DEBUG(rename_ret ? 0 : 3,("Running the command `%s' gave %d\n",
				rename_script, rename_ret));

	if (rename_ret != 0) {
		goto cancel;
	}

	smb_nscd_flush_user_cache();

	/* rewrite the rid->username record */

	if ( !tdb_update_ridrec_only( new_acct, TDB_MODIFY) ) {
		goto cancel;
	}

	tdb_delete_samacct_only( old_acct );

	if (dbwrap_transaction_commit(db_sam) != 0) {
		/*
		 * Ok, we're screwed. We've changed the posix account, but
		 * could not adapt passdb.tdb. Shall we change the posix
		 * account back?
		 */
		DEBUG(0, ("transaction_commit failed\n"));
		TALLOC_FREE(new_acct);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;	
	}

	TALLOC_FREE(new_acct );
	return NT_STATUS_OK;

 cancel:
	if (dbwrap_transaction_cancel(db_sam) != 0) {
		smb_panic("transaction_cancel failed");
	}

	TALLOC_FREE(new_acct);

	return NT_STATUS_ACCESS_DENIED;	
}

static uint32_t tdbsam_capabilities(struct pdb_methods *methods)
{
	return PDB_CAP_STORE_RIDS;
}

static bool tdbsam_new_rid(struct pdb_methods *methods, uint32_t *prid)
{
	uint32_t rid;
	NTSTATUS status;

	rid = BASE_RID;		/* Default if not set */

	if (!tdbsam_open(tdbsam_filename)) {
		DEBUG(0,("tdbsam_new_rid: failed to open %s!\n",
			tdbsam_filename));
		return false;
	}

	status = dbwrap_trans_change_uint32_atomic_bystring(
		db_sam, NEXT_RID_STRING, &rid, 1);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("tdbsam_new_rid: Failed to increase %s: %s\n",
			NEXT_RID_STRING, nt_errstr(status)));
		return false;
	}

	*prid = rid;

	return true;
}

struct tdbsam_search_state {
	struct pdb_methods *methods;
	uint32_t acct_flags;

	uint32_t *rids;
	uint32_t num_rids;
	ssize_t array_size;
	uint32_t current;
};

static int tdbsam_collect_rids(struct db_record *rec, void *private_data)
{
	struct tdbsam_search_state *state = talloc_get_type_abort(
		private_data, struct tdbsam_search_state);
	size_t prefixlen = strlen(RIDPREFIX);
	uint32_t rid;
	int error = 0;
	TDB_DATA key;

	key = dbwrap_record_get_key(rec);

	if ((key.dsize < prefixlen)
	    || (strncmp((char *)key.dptr, RIDPREFIX, prefixlen))) {
		return 0;
	}

	rid = smb_strtoul((char *)key.dptr+prefixlen,
			  NULL,
			  16,
			  &error,
			  SMB_STR_STANDARD);
	if (error != 0) {
		return 0;
	}

	ADD_TO_LARGE_ARRAY(state, uint32_t, rid, &state->rids, &state->num_rids,
			   &state->array_size);

	return 0;
}

static void tdbsam_search_end(struct pdb_search *search)
{
	struct tdbsam_search_state *state = talloc_get_type_abort(
		search->private_data, struct tdbsam_search_state);
	TALLOC_FREE(state);
}

static bool tdbsam_search_next_entry(struct pdb_search *search,
				     struct samr_displayentry *entry)
{
	struct tdbsam_search_state *state = talloc_get_type_abort(
		search->private_data, struct tdbsam_search_state);
	struct samu *user = NULL;
	NTSTATUS status;
	uint32_t rid;

 again:
	TALLOC_FREE(user);
	user = samu_new(talloc_tos());
	if (user == NULL) {
		DEBUG(0, ("samu_new failed\n"));
		return false;
	}

	if (state->current == state->num_rids) {
		TALLOC_FREE(user);
		return false;
	}

	rid = state->rids[state->current++];

	status = tdbsam_getsampwrid(state->methods, user, rid);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_USER)) {
		/*
		 * Someone has deleted that user since we listed the RIDs
		 */
		goto again;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("tdbsam_getsampwrid failed: %s\n",
			   nt_errstr(status)));
		TALLOC_FREE(user);
		return false;
	}

	if ((state->acct_flags != 0) &&
	    ((state->acct_flags & pdb_get_acct_ctrl(user)) == 0)) {
		goto again;
	}

	entry->acct_flags = pdb_get_acct_ctrl(user);
	entry->rid = rid;
	entry->account_name = talloc_strdup(search, pdb_get_username(user));
	entry->fullname = talloc_strdup(search, pdb_get_fullname(user));
	entry->description = talloc_strdup(search, pdb_get_acct_desc(user));

	TALLOC_FREE(user);

	if ((entry->account_name == NULL) || (entry->fullname == NULL)
	    || (entry->description == NULL)) {
		DEBUG(0, ("talloc_strdup failed\n"));
		return false;
	}

	return true;
}

static bool tdbsam_search_users(struct pdb_methods *methods,
				struct pdb_search *search,
				uint32_t acct_flags)
{
	struct tdbsam_search_state *state;

	if (!tdbsam_open(tdbsam_filename)) {
		DEBUG(0,("tdbsam_getsampwnam: failed to open %s!\n",
			 tdbsam_filename));
		return false;
	}

	state = talloc_zero(search, struct tdbsam_search_state);
	if (state == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return false;
	}
	state->acct_flags = acct_flags;
	state->methods = methods;

	dbwrap_traverse_read(db_sam, tdbsam_collect_rids, state, NULL);

	search->private_data = state;
	search->next_entry = tdbsam_search_next_entry;
	search->search_end = tdbsam_search_end;

	return true;
}

static bool tdbsam_is_responsible_for_builtin(struct pdb_methods *m)
{
	return map_builtin;
}

/*********************************************************************
 Initialize the tdb sam backend.  Setup the dispatch table of methods,
 open the tdb, etc...
*********************************************************************/

static NTSTATUS pdb_init_tdbsam(struct pdb_methods **pdb_method, const char *location)
{
	NTSTATUS nt_status;
	char *tdbfile = NULL;
	const char *pfile = location;

	if (!NT_STATUS_IS_OK(nt_status = make_pdb_method( pdb_method ))) {
		return nt_status;
	}

	(*pdb_method)->name = "tdbsam";

	(*pdb_method)->getsampwnam = tdbsam_getsampwnam;
	(*pdb_method)->getsampwsid = tdbsam_getsampwsid;
	(*pdb_method)->add_sam_account = tdbsam_add_sam_account;
	(*pdb_method)->update_sam_account = tdbsam_update_sam_account;
	(*pdb_method)->delete_sam_account = tdbsam_delete_sam_account;
	(*pdb_method)->rename_sam_account = tdbsam_rename_sam_account;
	(*pdb_method)->search_users = tdbsam_search_users;

	(*pdb_method)->capabilities = tdbsam_capabilities;
	(*pdb_method)->new_rid = tdbsam_new_rid;

	(*pdb_method)->is_responsible_for_builtin =
					tdbsam_is_responsible_for_builtin;
	map_builtin = lp_parm_bool(-1, "tdbsam", "map builtin", true);

	/* save the path for later */

	if (!location) {
		tdbfile = strdup(TRUENAS_PASSDB);
		if (tdbfile == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		pfile = tdbfile;
	}
	tdbsam_filename = SMB_STRDUP(pfile);
	if (!tdbsam_filename) {
		return NT_STATUS_NO_MEMORY;
	}
	SAFE_FREE(tdbfile);

	/* no private data */

	(*pdb_method)->private_data      = NULL;
	(*pdb_method)->free_private_data = NULL;

	return NT_STATUS_OK;
}

NTSTATUS pdb_tdbsam_init(TALLOC_CTX *ctx)
{
	return smb_register_passdb(PASSDB_INTERFACE_VERSION, "tdbsam", pdb_init_tdbsam);
}

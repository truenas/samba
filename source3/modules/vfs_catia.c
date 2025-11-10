/*
 * Catia VFS module
 *
 * Implement a fixed mapping of forbidden NT characters in filenames that are
 * used a lot by the CAD package Catia.
 *
 * Catia V4 on AIX uses characters like "<*$ a *lot*, all forbidden under
 * Windows...
 *
 * Copyright (C) Volker Lendecke, 2005
 * Copyright (C) Aravind Srinivasan, 2009
 * Copyright (C) Guenter Kukkukk, 2013
 * Copyright (C) Ralph Boehme, 2017
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#include "includes.h"
#include "smbd/smbd.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/tevent_ntstatus.h"
#include "string_replace.h"

static int vfs_catia_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_catia_debug_level

struct share_mapping_entry {
	int snum;
	struct share_mapping_entry *next;
	struct char_mappings **mappings;
};

struct catia_cache {
	bool is_fsp_ext;
	const struct catia_cache * const *busy;
	char *orig_fname;
	char *fname;
	char *orig_base_fname;
	char *base_fname;
};

static struct share_mapping_entry *srt_head = NULL;

static struct share_mapping_entry *get_srt(connection_struct *conn,
					   struct share_mapping_entry **global)
{
	struct share_mapping_entry *share;

	for (share = srt_head; share != NULL; share = share->next) {
		if (share->snum == GLOBAL_SECTION_SNUM)
			(*global) = share;

		if (share->snum == SNUM(conn))
			return share;
	}

	return share;
}

static struct share_mapping_entry *add_srt(int snum, const char **mappings)
{
	struct share_mapping_entry *sme = NULL;

	sme = talloc_zero(NULL, struct share_mapping_entry);
	if (sme == NULL)
		return sme;

	sme->snum = snum;
	sme->next = srt_head;
	srt_head = sme;

	if (mappings == NULL) {
		sme->mappings = NULL;
		return sme;
	}

	sme->mappings = string_replace_init_map(sme, mappings);

	return sme;
}

static bool init_mappings(connection_struct *conn,
			  struct share_mapping_entry **selected_out)
{
	const char **mappings = NULL;
	struct share_mapping_entry *share_level = NULL;
	struct share_mapping_entry *global = NULL;

	/* check srt cache */
	share_level = get_srt(conn, &global);
	if (share_level) {
		*selected_out = share_level;
		return (share_level->mappings != NULL);
	}

	/* see if we have a global setting */
	if (!global) {
		/* global setting */
		mappings = lp_parm_string_list(-1, "catia", "mappings", NULL);
		global = add_srt(GLOBAL_SECTION_SNUM, mappings);
	}

	/* no global setting - what about share level ? */
	mappings = lp_parm_string_list(SNUM(conn), "catia", "mappings", NULL);
	share_level = add_srt(SNUM(conn), mappings);

	if (share_level->mappings) {
		(*selected_out) = share_level;
		return True;
	}
	if (global->mappings) {
		share_level->mappings = global->mappings;
		(*selected_out) = share_level;
		return True;
	}

	return False;
}

static int catia_string_replace_allocate(
	connection_struct *conn,
	const char *name_in,
	char **mapped_name,
	enum vfs_translate_direction direction)
{
	struct share_mapping_entry *selected;
	int ret;

	if (!init_mappings(conn, &selected)) {
		/* No mappings found. Just use the old name */
		*mapped_name = talloc_strdup(talloc_tos(), name_in);
		if (!*mapped_name) {
			return ENOMEM;
		}
		return 0;
	}

	ret = string_replace_allocate(conn,
				      name_in,
				      selected->mappings,
				      talloc_tos(),
				      mapped_name,
				      direction);
	return ret;
}

static int catia_connect(struct vfs_handle_struct *handle,
			 const char *service,
			 const char *user)
{
	/*
	 * Unless we have an async implementation of get_dos_attributes turn
	 * this off.
	 */
	lp_do_parameter(SNUM(handle->conn), "smbd async dosmode", "false");

	return SMB_VFS_NEXT_CONNECT(handle, service, user);
}

/*
 * TRANSLATE_NAME call which converts the given name to
 * "WINDOWS displayable" name
 */
static NTSTATUS catia_translate_name(struct vfs_handle_struct *handle,
				     const char *orig_name,
				     enum vfs_translate_direction direction,
				     TALLOC_CTX *mem_ctx,
				     char **pmapped_name)
{
	char *name = NULL;
	char *mapped_name;
	NTSTATUS ret;
	int rc;

	/*
	 * Copy the supplied name and free the memory for mapped_name,
	 * already allocated by the caller.
	 * We will be allocating new memory for mapped_name in
	 * catia_string_replace_allocate
	 */
	name = talloc_strdup(talloc_tos(), orig_name);
	if (!name) {
		errno = ENOMEM;
		return NT_STATUS_NO_MEMORY;
	}
	rc = catia_string_replace_allocate(handle->conn,
					   name,
					   &mapped_name,
					   direction);

	TALLOC_FREE(name);
	if (rc != 0) {
		return map_nt_error_from_unix(rc);
	}

	ret = SMB_VFS_NEXT_TRANSLATE_NAME(handle, mapped_name, direction,
					  mem_ctx, pmapped_name);

	if (NT_STATUS_EQUAL(ret, NT_STATUS_NONE_MAPPED)) {
		*pmapped_name = talloc_move(mem_ctx, &mapped_name);
		/* we need to return the former translation result here */
		ret = NT_STATUS_OK;
	} else {
		TALLOC_FREE(mapped_name);
	}

	return ret;
}

static struct vfs_fn_pointers vfs_catia_fns = {
	/* File operations */
	.translate_name_fn = catia_translate_name,
};

static_decl_vfs;
NTSTATUS vfs_catia_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;

        ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "catia",
				&vfs_catia_fns);
	if (!NT_STATUS_IS_OK(ret))
		return ret;

	vfs_catia_debug_level = debug_add_class("catia");
	if (vfs_catia_debug_level == -1) {
		vfs_catia_debug_level = DBGC_VFS;
		DEBUG(0, ("vfs_catia: Couldn't register custom debugging "
			  "class!\n"));
	} else {
		DEBUG(10, ("vfs_catia: Debug class number of "
			   "'catia': %d\n", vfs_catia_debug_level));
	}

	return ret;

}

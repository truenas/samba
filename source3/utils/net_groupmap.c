/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Jean François Micouleau      1998-2001.
 *  Copyright (C) Gerald Carter                2003,
 *  Copyright (C) Volker Lendecke              2004
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#include "includes.h"
#include "system/passwd.h"
#include "utils/net.h"
#include "../libcli/security/security.h"
#include "passdb.h"
#include "lib/util/string_wrappers.h"

#ifdef HAVE_JANSSON
#include <jansson.h>
#include "audit_logging.h"
#define JS_MAJ_VER	0
#define JS_MIN_VER	1
#endif /* HAVE_JANSSON */

bool is_batch_op = false;

/*********************************************************
 Figure out if the input was an NT group or a SID string.
 Return the SID.
**********************************************************/
static bool get_sid_from_input(struct dom_sid *sid, char *input)
{
	GROUP_MAP *map;

	map = talloc_zero(NULL, GROUP_MAP);
	if (!map) {
		return false;
	}

	if (strncasecmp_m( input, "S-", 2)) {
		/* Perhaps its the NT group name? */
		if (!pdb_getgrnam(map, input)) {
			printf(_("NT Group %s doesn't exist in mapping DB\n"),
			       input);
			TALLOC_FREE(map);
			return false;
		} else {
			*sid = map->sid;
		}
	} else {
		if (!string_to_sid(sid, input)) {
			printf(_("converting sid %s from a string failed!\n"),
			       input);
			TALLOC_FREE(map);
			return false;
		}
	}
	TALLOC_FREE(map);
	return true;
}

/*********************************************************
 Dump a GROUP_MAP entry to stdout (long or short listing)
**********************************************************/

static void print_map_entry (const GROUP_MAP *map, bool long_list)
{
	struct dom_sid_buf buf;

	if (!long_list)
		d_printf("%s (%s) -> %s\n", map->nt_name,
			 dom_sid_str_buf(&map->sid, &buf),
			 gidtoname(map->gid));
	else {
		d_printf("%s\n", map->nt_name);
		d_printf(_("\tSID       : %s\n"),
			 dom_sid_str_buf(&map->sid, &buf));
		d_printf(_("\tUnix gid  : %u\n"), (unsigned int)map->gid);
		d_printf(_("\tUnix group: %s\n"), gidtoname(map->gid));
		d_printf(_("\tGroup type: %s\n"),
			 sid_type_lookup(map->sid_name_use));
		d_printf(_("\tComment   : %s\n"), map->comment);
	}

}

/*********************************************************
 JSON helper functions
**********************************************************/
#ifdef HAVE_JANSSON
static bool json_to_groupmap(struct json_object *jsdata,
			     GROUP_MAP *map)
{
	const char *nt_name = NULL;
	const char *comment = NULL;
	const char *sid = NULL;
	const char *group_type = NULL;
	const char *unix_group = NULL;
	int rid = 0, error, sid_type;

	map->gid = -1;
	map->sid_name_use = SID_NAME_DOM_GRP;

	error = json_get_string_value(jsdata, "nt_name", &nt_name);
	if (error) {
		if (errno == EINVAL) {
			d_fprintf(stderr, _("\"nt_name\" must be string.\n"));
			return false;
		}
	} else {
		map->nt_name = talloc_strdup(map, nt_name);
		if (map->nt_name == NULL) {
			d_fprintf(stderr, _("memory error\n"));
			return false;
		}
	}

	error = json_get_int_value(jsdata, "rid", &rid);
	if (error) {
		if (errno == EINVAL) {
			d_fprintf(stderr, _("\"rid\" must be integer.\n"));
			return false;
		}
	}

	error = json_get_string_value(jsdata, "sid", &sid);
	if (error) {
		if (errno == EINVAL) {
			d_fprintf(stderr, _("\"sid\" must be string.\n"));
			return false;
		}
	}

	if (sid != NULL) {
		bool ok;
		const char *sid_endptr = NULL;
		ok = dom_sid_parse_endp(sid, &map->sid, &sid_endptr);
		if (!ok || (*sid_endptr != '\0')) {
			d_fprintf(stderr, _("\"sid\" is invalid.\n"));
			return false;
		}
	}
	else if (rid != 0) {
		sid_compose(&map->sid, get_global_sam_sid(), rid);
	}
	else if (nt_name != NULL) {
		bool ok;
		GROUP_MAP *tmp = NULL;
		struct dom_sid *rv = NULL;

		tmp = talloc_zero(talloc_tos(), GROUP_MAP);
		if (tmp == NULL) {
			return false;
		}
		ok = pdb_getgrnam(tmp, nt_name);
		if (ok) {
			rv = dom_sid_dup(map, &tmp->sid);
			if (rv == NULL) {
				TALLOC_FREE(tmp);
				return false;
			}
			map->sid = *rv;
		}
		TALLOC_FREE(tmp);
	}

	error = json_get_int_value(jsdata, "gid", &map->gid);
	if (error && (errno == EINVAL)) {
		d_fprintf(stderr, _("Key [gid] must be an integer.\n"));
		return false;
	}

	error = json_get_string_value(jsdata, "group_type_str", &group_type);
	if (error) {
		if (errno == EINVAL) {
			d_fprintf(stderr, _("\"group_type_str\" must be string.\n"));
			return false;
		}
	} else {
		switch (group_type[0]) {
		case 'b':
		case 'B':
			map->sid_name_use = SID_NAME_WKN_GRP;
			break;
		case 'd':
		case 'D':
			map->sid_name_use = SID_NAME_DOM_GRP;
			break;
		case 'l':
		case 'L':
			map->sid_name_use = SID_NAME_ALIAS;
			break;
		default:
			d_fprintf(stderr,
				  _("unknown group type: %s\n"),
				  group_type);
			return false;
		}
	}

	error = json_get_int_value(jsdata, "group_type", &sid_type);
	if (error) {
		if (errno == EINVAL) {
			d_fprintf(stderr, _("\"group_type\" must be integer.\n"));
			return false;
		}
	} else {
		switch(sid_type) {
		case SID_NAME_WKN_GRP:
		case SID_NAME_DOM_GRP:
		case SID_NAME_ALIAS:
			map->sid_name_use = sid_type;
			break;
		default:
			d_fprintf(stderr, _("Invalid group type: %d\n"), sid_type);
			return false;
		}
	}

	error = json_get_string_value(jsdata, "unix_group", &unix_group);
	if (error) {
		if (errno == EINVAL) {
			d_fprintf(stderr, _("\"unix_group\" must be string.\n"));
			return false;
		}
	} else {
		struct group *grp = NULL;
		grp = getgrnam(unix_group);
		if (grp == NULL) {
			d_fprintf(stderr, _("%s: getgrnam() failed: %s\n"),
					 unix_group, strerror(errno));
			return false;
		}
		map->gid = grp->gr_gid;
	}
	error = json_get_string_value(jsdata, "comment", &comment);
	if (error) {
		if (errno == EINVAL) {
			d_fprintf(stderr, _("\"comment\" must be string.\n"));
			return false;
		}
		map->comment = talloc_strdup(map, "");
		if (map->comment == NULL) {
			return false;
		}
	} else {
		map->comment = talloc_strdup(map, comment);
		if (map->comment == NULL) {
			return false;
		}
	}

	return true;
}

static bool groupmap_to_json(struct json_object *gm_array,
			     GROUP_MAP *map,
			     bool verbose)
{
	struct json_object entry;
	struct dom_sid_buf buf;
	int error;

	entry = json_new_object();
	if (json_is_invalid(&entry)) {
		return false;
	}

	error = json_add_string(&entry, "nt_name", map->nt_name);
	if (error) {
		goto fail;
	}

	error = json_add_sid(&entry, "sid", &map->sid);
	if (error) {
		goto fail;
	}

	error = json_add_int(&entry, "gid", map->gid);
	if (error) {
		goto fail;
	}

	error = json_add_int(&entry, "group_type_int", map->sid_name_use);
	if (error) {
		goto fail;
	}

	error = json_add_string(&entry, "comment", map->comment);
	if (error) {
		goto fail;
	}

	error = json_add_int(&entry, "group_type_int", map->sid_name_use);
	if (verbose) {
		char *group = NULL;
		const char *sid_type = sid_type_lookup(map->sid_name_use);

		group = gidtoname(map->gid);
		error = json_add_string(&entry, "unix_group", group);
		TALLOC_FREE(group);
		if (error) {
			goto fail;
		}

		error = json_add_string(&entry, "group_type_str", sid_type);
		if (error) {
			goto fail;
		}
	}

	error = json_add_object(gm_array, NULL, &entry);
	if (error) {
		goto fail;
	}

	return true;

fail:
	json_free(&entry);
	return false;

}
#endif

/*********************************************************
 List the groups.
**********************************************************/
#ifdef HAVE_JANSSON
static int net_groupmap_list_json(struct net_context *c, int argc, const char **argv)
{
	size_t entries;
	struct json_object jsdata, jsgroup = json_empty_object;
	struct json_object output, gm_array;
	bool verbose = false, ok;
	int error;
	char *jsout = NULL;

	if (argc == 0) {
		jsdata = json_new_object();
		if (json_is_invalid(&jsdata)) {
			return -1;
		}
	} else {
		jsdata = load_json(argv[0]);
		if (json_is_invalid(&jsdata)) {
			return -1;
		}
	}

	output = json_new_object();
	if (json_is_invalid(&output)) {
		json_free(&jsdata);
		return -1;
	}

	gm_array = json_new_array();
	if (json_is_invalid(&gm_array)) {
		goto fail;
	}

	error = json_add_version(&output, JS_MAJ_VER, JS_MIN_VER);
	if (error) {
		goto fail;
	}

	error = json_get_bool_value(&jsdata, "verbose", &verbose);
	if (error && (errno != ENOENT)) {
		goto fail;
	}

	if (json_object_get(jsdata.root, "group")) {
		fstring sid;
		GROUP_MAP *map = NULL;
		struct dom_sid *to_check = NULL;

		map = talloc_zero(to_check, GROUP_MAP);
		if (map == NULL) {
			goto fail;
		}

		jsgroup = json_get_object(&jsdata, "group");
		if (json_is_invalid(&jsgroup)) {
			goto fail;
		}

		map = talloc_zero(talloc_tos(), GROUP_MAP);
		if (map == NULL) {
			goto fail;
		}

		ok = json_to_groupmap(&jsgroup, map);
		if (!ok) {
			TALLOC_FREE(map);
			goto fail;
		}

		sid_to_fstring(sid, &map->sid);
		if (strncmp(sid, "S-0-0", 5) == 0) {
			d_fprintf(stderr, _("\rid\", \"sid\", or \"nt_p\" "
					    "is required for lookup of specific "
					    "mapping.\n"));
			TALLOC_FREE(map);
			goto fail;
		}

		to_check = dom_sid_dup(talloc_tos(), &map->sid);
		if (to_check == NULL) {
			TALLOC_FREE(map);
			goto fail;
		}

		if (!pdb_getgrsid(map, *to_check)) {
			d_fprintf(stderr, _("Failed to locate group SID [%s] "
					    "in the group database.\n"), sid);
			TALLOC_FREE(map);
			TALLOC_FREE(to_check);
			goto fail;
		}
		TALLOC_FREE(to_check);

		ok = groupmap_to_json(&gm_array, map, verbose);
		if (!ok) {
			TALLOC_FREE(map);
			goto fail;
		}

		TALLOC_FREE(map);

	} else {
		GROUP_MAP **maps = NULL;
		size_t entries;
		int i;

		ok = pdb_enum_group_mapping(NULL, SID_NAME_UNKNOWN,
					    &maps, &entries, ENUM_ALL_MAPPED);
		if (!ok) {
			TALLOC_FREE(maps);
			goto fail;
		}

		for (i = 0; i < entries; i++) {
			bool ok;

			ok = groupmap_to_json(&gm_array, maps[i], verbose);
			if (!ok) {
				TALLOC_FREE(maps);
				goto fail;
			}
		}
	}

	error = json_add_object(&output, "groupmap", &gm_array);
	if (error) {
		goto fail;
	}

	jsout = json_to_string(talloc_tos(), &output);
	if (jsout == NULL) {
		goto fail;
	}

	printf("%s\n", jsout);
	TALLOC_FREE(jsout);
	json_free(&jsdata);
	json_free(&output);
	return 0;

fail:
	json_free(&output);
	json_free(&jsdata);
	return -1;
}
#endif /* HAVE_JANSSON */

static int net_groupmap_list(struct net_context *c, int argc, const char **argv)
{
	size_t entries;
	bool long_list = false;
	size_t i;
	fstring ntgroup = "";
	fstring sid_string = "";
	const char list_usage_str[] = N_("net groupmap list [verbose] "
				         "[ntgroup=NT group] [sid=SID]\n"
				         "    verbose\tPrint verbose list\n"
				         "    ntgroup\tNT group to list\n"
				         "    sid\tSID of group to list");

	if (c->display_usage) {
		d_printf("%s\n%s\n", _("Usage: "), list_usage_str);
		return 0;
	}

#ifdef HAVE_JANSSON
	if (c->opt_json) {
		return net_groupmap_list_json(c, argc, argv);
	}
#endif /* HAVE_JANSSON */

	if (c->opt_verbose || c->opt_long_list_entries)
		long_list = true;

	/* get the options */
	for ( i=0; i<argc; i++ ) {
		if ( !strcasecmp_m(argv[i], "verbose")) {
			long_list = true;
		}
		else if ( !strncasecmp_m(argv[i], "ntgroup", strlen("ntgroup")) ) {
			fstrcpy( ntgroup, get_string_param( argv[i] ) );
			if ( !ntgroup[0] ) {
				d_fprintf(stderr, _("must supply a name\n"));
				return -1;
			}
		}
		else if ( !strncasecmp_m(argv[i], "sid", strlen("sid")) ) {
			fstrcpy( sid_string, get_string_param( argv[i] ) );
			if ( !sid_string[0] ) {
				d_fprintf(stderr, _("must supply a SID\n"));
				return -1;
			}
		}
		else {
			d_fprintf(stderr, _("Bad option: %s\n"), argv[i]);
			d_printf("%s\n%s\n", _("Usage:"), list_usage_str);
			return -1;
		}
	}

	/* list a single group is given a name */
	if ( ntgroup[0] || sid_string[0] ) {
		struct dom_sid sid;
		GROUP_MAP *map;

		if ( sid_string[0] )
			strlcpy(ntgroup, sid_string, sizeof(ntgroup));

		if (!get_sid_from_input(&sid, ntgroup)) {
			return -1;
		}

		map = talloc_zero(NULL, GROUP_MAP);
		if (!map) {
			return -1;
		}

		/* Get the current mapping from the database */
		if(!pdb_getgrsid(map, sid)) {
			d_fprintf(stderr,
				  _("Failure to local group SID in the "
				    "database\n"));
			TALLOC_FREE(map);
			return -1;
		}

		print_map_entry(map, long_list );
		TALLOC_FREE(map);
	}
	else {
		GROUP_MAP **maps = NULL;
		bool ok = false;
		/* enumerate all group mappings */
		ok = pdb_enum_group_mapping(NULL, SID_NAME_UNKNOWN,
					    &maps, &entries,
					    ENUM_ALL_MAPPED);
		if (!ok) {
			return -1;
		}

		for (i=0; i<entries; i++) {
			print_map_entry(maps[i], long_list);
		}

		TALLOC_FREE(maps);
	}

	return 0;
}

/*********************************************************
 Add a new group mapping entry
**********************************************************/
#ifdef HAVE_JANSSON
static bool add_json_mapping(int idx, struct json_object *entry, void *state)
{
	bool ok;
	GROUP_MAP *map = NULL, *tmp = NULL;
	fstring sid;
	int rid = -1;
	NTSTATUS status;

	map = talloc_zero(talloc_tos(), GROUP_MAP);
	if (map == NULL) {
		d_fprintf(stderr, _("memory error.\n"));
		return false;
	}

	ok = json_to_groupmap(entry, map);
	if (!ok) {
		d_fprintf(stderr, _("[%d]: Failed to convert entry to "
				    "GROUP_MAP.\n"), idx);
		TALLOC_FREE(map);
		return false;
	}

	if (map->gid == -1) {
		d_fprintf(stderr,
			  _("[%d]: unable to determine group id for "
			    "mapping group. Either \"gid\" or valid "
			    "\"unix_group\" is required.\n"), idx);
		TALLOC_FREE(map);
		return false;
	}
	else if (!map->nt_name[0]) {
		d_fprintf(stderr,
			  _("[%d]: \"nt_name\" is required when \"gid\" is "
			    "not specified."), idx);
		TALLOC_FREE(map);
		return false;
	}

	tmp = talloc_zero(talloc_tos(), GROUP_MAP);
	if (tmp == NULL) {
		d_fprintf(stderr, _("memory error.\n"));
		TALLOC_FREE(map);
		return false;
	}

	tmp->sid_name_use = SID_NAME_DOM_GRP;
	if (pdb_getgrgid(tmp, map->gid)) {
		sid_to_fstring(sid, &map->sid);
		d_fprintf(stderr, _("[%d] unix gid %d already mapped to SID %s\n"),
				    idx, map->gid, sid);
		TALLOC_FREE(map);
		TALLOC_FREE(tmp);
		return false;
	}
	TALLOC_FREE(tmp);

	sid_to_fstring(sid, &map->sid);
	if (strequal(sid, "S-0-0")) {
		if (pdb_capabilities() & PDB_CAP_STORE_RIDS) {
			if (!pdb_new_rid(&rid)) {
				d_fprintf(stderr,
					  _("[%d]: Failed to allocate "
					    "new RID.\n"), idx);
				return false;
			}
		} else {
			rid = algorithmic_pdb_gid_to_group_rid(map->gid);
		}
	}

	if (rid != -1) {
		struct dom_sid thesid;
		sid_compose(&thesid, get_global_sam_sid(), rid);
		sid_to_fstring(sid, &thesid);
	}


	status = add_initial_entry(map->gid,
				   sid,
				   map->sid_name_use,
				   map->nt_name,
				   map->comment);

	TALLOC_FREE(map);

	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr,
			  _("[%s] failed to add entry for gid %d\n"),
			  idx, map->gid);
		return false;
	}

	return true;
}

static int net_groupmap_add_json(struct net_context *c, int argc, const char **argv)
{
	struct json_object jsdata, jsgroupmap;
	int error;
	bool quiet = false;

	jsdata = load_json(argv[0]);
	if (json_is_invalid(&jsdata)) {
		return -1;
	}

	error = json_get_bool_value(&jsdata, "quiet", &quiet);
	if (error && (errno == EINVAL)) {
		d_fprintf(stderr, _("key \"quiet\" must be boolean.\n"));
		json_free(&jsdata);
		return -1;
	}

	jsgroupmap = json_get_array(&jsdata, "groupmap");
	if (json_is_invalid(&jsgroupmap)) {
		json_free(&jsdata);
		return -1;
	}

	error = iter_json_array(&jsgroupmap, add_json_mapping, NULL);
	if (error) {
		json_free(&jsdata);
		return -1;
	}
	json_free(&jsdata);

	if (!quiet && !is_batch_op) {
		net_groupmap_list_json(c, argc, argv);
	}

	return 0;
}
#endif /* HAVE_JANSSON */

static int net_groupmap_add(struct net_context *c, int argc, const char **argv)
{
	struct dom_sid sid;
	fstring ntgroup = "";
	fstring unixgrp = "";
	fstring string_sid = "";
	fstring type = "";
	fstring ntcomment = "";
	enum lsa_SidType sid_type = SID_NAME_DOM_GRP;
	uint32_t rid = 0;
	gid_t gid;
	int i;
	GROUP_MAP *map;
	const char *name_type;
	const char add_usage_str[] = N_("net groupmap add "
					"{rid=<int>|sid=<string>}"
					" unixgroup=<string> "
					"[type=<domain|local|builtin>] "
					"[ntgroup=<string>] "
					"[comment=<string>]");

	name_type = "domain group";

#ifdef HAVE_JANSSON
	if (c->opt_json) {
		return net_groupmap_add_json(c, argc, argv);
	}
#endif /* HAVE_JANSSON */

	if (c->display_usage) {
		d_printf("%s\n%s\n", _("Usage:\n"), add_usage_str);
		return 0;
	}

	/* get the options */
	for ( i=0; i<argc; i++ ) {
		if ( !strncasecmp_m(argv[i], "rid", strlen("rid")) ) {
			rid = get_int_param(argv[i]);
			if ( rid < DOMAIN_RID_ADMINS ) {
				d_fprintf(stderr,
					  _("RID must be greater than %d\n"),
					  (uint32_t)DOMAIN_RID_ADMINS-1);
				return -1;
			}
		}
		else if ( !strncasecmp_m(argv[i], "unixgroup", strlen("unixgroup")) ) {
			fstrcpy( unixgrp, get_string_param( argv[i] ) );
			if ( !unixgrp[0] ) {
				d_fprintf(stderr,_( "must supply a name\n"));
				return -1;
			}
		}
		else if ( !strncasecmp_m(argv[i], "ntgroup", strlen("ntgroup")) ) {
			fstrcpy( ntgroup, get_string_param( argv[i] ) );
			if ( !ntgroup[0] ) {
				d_fprintf(stderr, _("must supply a name\n"));
				return -1;
			}
		}
		else if ( !strncasecmp_m(argv[i], "sid", strlen("sid")) ) {
			fstrcpy( string_sid, get_string_param( argv[i] ) );
			if ( !string_sid[0] ) {
				d_fprintf(stderr, _("must supply a SID\n"));
				return -1;
			}
		}
		else if ( !strncasecmp_m(argv[i], "comment", strlen("comment")) ) {
			fstrcpy( ntcomment, get_string_param( argv[i] ) );
			if ( !ntcomment[0] ) {
				d_fprintf(stderr,
					  _("must supply a comment string\n"));
				return -1;
			}
		}
		else if ( !strncasecmp_m(argv[i], "type", strlen("type")) )  {
			fstrcpy( type, get_string_param( argv[i] ) );
			switch ( type[0] ) {
				case 'b':
				case 'B':
					sid_type = SID_NAME_WKN_GRP;
					name_type = "wellknown group";
					break;
				case 'd':
				case 'D':
					sid_type = SID_NAME_DOM_GRP;
					name_type = "domain group";
					break;
				case 'l':
				case 'L':
					sid_type = SID_NAME_ALIAS;
					name_type = "alias (local) group";
					break;
				default:
					d_fprintf(stderr,
						  _("unknown group type %s\n"),
						  type);
					return -1;
			}
		}
		else {
			d_fprintf(stderr, _("Bad option: %s\n"), argv[i]);
			return -1;
		}
	}

	if ( !unixgrp[0] ) {
		d_printf("%s\n%s\n", _("Usage:\n"), add_usage_str);
		return -1;
	}

	if ( (gid = nametogid(unixgrp)) == (gid_t)-1 ) {
		d_fprintf(stderr, _("Can't lookup UNIX group %s\n"), unixgrp);
		return -1;
	}

	map = talloc_zero(NULL, GROUP_MAP);
	if (!map) {
		return -1;
	}
	/* Default is domain group. */
	map->sid_name_use = SID_NAME_DOM_GRP;
	if (pdb_getgrgid(map, gid)) {
		struct dom_sid_buf buf;
		d_printf(_("Unix group %s already mapped to SID %s\n"),
			 unixgrp, dom_sid_str_buf(&map->sid, &buf));
		TALLOC_FREE(map);
		return -1;
	}
	TALLOC_FREE(map);

	if ( (rid == 0) && (string_sid[0] == '\0') ) {
		d_printf(_("No rid or sid specified, choosing a RID\n"));
		if (pdb_capabilities() & PDB_CAP_STORE_RIDS) {
			if (!pdb_new_rid(&rid)) {
				d_printf(_("Could not get new RID\n"));
			}
		} else {
			rid = algorithmic_pdb_gid_to_group_rid(gid);
		}
		d_printf(_("Got RID %d\n"), rid);
	}

	/* append the rid to our own domain/machine SID if we don't have a full SID */
	if ( !string_sid[0] ) {
		sid_compose(&sid, get_global_sam_sid(), rid);
		sid_to_fstring(string_sid, &sid);
	}

	if (!ntcomment[0]) {
		switch (sid_type) {
		case SID_NAME_WKN_GRP:
			fstrcpy(ntcomment, "Wellknown Unix group");
			break;
		case SID_NAME_DOM_GRP:
			fstrcpy(ntcomment, "Domain Unix group");
			break;
		case SID_NAME_ALIAS:
			fstrcpy(ntcomment, "Local Unix group");
			break;
		default:
			fstrcpy(ntcomment, "Unix group");
			break;
		}
	}

	if (!ntgroup[0] )
		strlcpy(ntgroup, unixgrp, sizeof(ntgroup));

	if (!NT_STATUS_IS_OK(add_initial_entry(gid, string_sid, sid_type, ntgroup, ntcomment))) {
		d_fprintf(stderr, _("adding entry for group %s failed!\n"), ntgroup);
		return -1;
	}

	d_printf(_("Successfully added group %s to the mapping db as a %s\n"),
		 ntgroup, name_type);
	return 0;
}

#ifdef HAVE_JANSSON
static bool mod_json_mapping(int idx, struct json_object *entry, void *state)
{
	bool ok;
	GROUP_MAP *map = NULL, *to_set = NULL;
	fstring sid;
	int rid = -1;
	NTSTATUS status;

	map = talloc_zero(talloc_tos(), GROUP_MAP);
	if (map == NULL) {
		d_fprintf(stderr, _("memory error.\n"));
		return false;
	}

	ok = json_to_groupmap(entry, map);
	if (!ok) {
		d_fprintf(stderr, _("[%d]: Failed to convert entry to "
				    "GROUP_MAP.\n"), idx);
		TALLOC_FREE(map);
		return false;
	}

	sid_to_fstring(sid, &map->sid);
	if (strequal(sid, "S-0-0")) {
		d_fprintf(stderr,
			  _("[%d]: either \"sid\" or \"nt_name\" "
			    "is required.\n"), idx);
		TALLOC_FREE(map);
		return false;
	}

	to_set = talloc_zero(talloc_tos(), GROUP_MAP);
	if (to_set == NULL) {
		d_fprintf(stderr, _("memory error.\n"));
		TALLOC_FREE(map);
		return false;
	}

	ok = pdb_getgrsid(to_set, map->sid);
	if (!ok) {
		d_fprintf(stderr,
			  _("[%d]: Failed to find sid %s in database\n"),
			  idx, sid);
		goto fail;
	}

	if (map->sid_name_use == SID_NAME_UNKNOWN) {
		d_fprintf(stderr,
			  _("[%d] Can't map to an unknown group type.\n"), idx);
		goto fail;
	}

	if (to_set->sid_name_use == SID_NAME_WKN_GRP) {
		d_fprintf(stderr,
			  _("[%d] Can only change between domain and local.\n"), idx);
		goto fail;
	}

	to_set->sid_name_use = map->sid_name_use;

	if (map->comment[0]) {
		to_set->comment = talloc_strdup(to_set, map->comment);
		if (to_set->comment == NULL) {
			d_fprintf(stderr, _("memory error.\n"));
			goto fail;
		}
	}

	if (map->gid != -1) {
		to_set->gid = map->gid;
	}

	if (map->nt_name[0]) {
		to_set->nt_name = talloc_strdup(to_set, map->nt_name);
		if (to_set->nt_name == NULL) {
			d_fprintf(stderr, _("memory error.\n"));
			goto fail;
		}
	}

	status = pdb_update_group_mapping_entry(map);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	TALLOC_FREE(map);
	TALLOC_FREE(to_set);
	return true;

fail:
	TALLOC_FREE(map);
	TALLOC_FREE(to_set);
	return false;
}

static int net_groupmap_modify_json(struct net_context *c, int argc, const char **argv)
{
	struct json_object jsdata, jsgroupmap;
	int error;
	bool quiet = false;

	jsdata = load_json(argv[0]);
	if (json_is_invalid(&jsdata)) {
		return -1;
	}

	error = json_get_bool_value(&jsdata, "quiet", &quiet);
	if (error && (errno == EINVAL)) {
		d_fprintf(stderr, _("key \"quiet\" must be boolean.\n"));
		json_free(&jsdata);
		return -1;
	}

	jsgroupmap = json_get_array(&jsdata, "groupmap");
	if (json_is_invalid(&jsgroupmap)) {
		json_free(&jsdata);
		return -1;
	}

	error = iter_json_array(&jsgroupmap, mod_json_mapping, NULL);
	if (error) {
		json_free(&jsdata);
		return -1;
	}
	json_free(&jsdata);

	if (!quiet && !is_batch_op) {
		net_groupmap_list_json(c, argc, argv);
	}

	return 0;
}
#endif /* HAVE_JANSSON */

static int net_groupmap_modify(struct net_context *c, int argc, const char **argv)
{
	struct dom_sid sid;
	GROUP_MAP *map = NULL;
	fstring ntcomment = "";
	fstring type = "";
	fstring ntgroup = "";
	fstring unixgrp = "";
	fstring sid_string = "";
	enum lsa_SidType sid_type = SID_NAME_UNKNOWN;
	int i;
	gid_t gid;
	const char modify_usage_str[] = N_("net groupmap modify "
					   "{ntgroup=<string>|sid=<SID>} "
					   "[comment=<string>] "
					   "[unixgroup=<string>] "
					   "[type=<domain|local>]");

#ifdef HAVE_JANSSON
	if (c->opt_json) {
		return net_groupmap_modify_json(c, argc, argv);
	}
#endif /* HAVE_JANSSON */

	if (c->display_usage) {
		d_printf("%s\n%s\n", _("Usage:\n"), modify_usage_str);
		return 0;
	}

	/* get the options */
	for ( i=0; i<argc; i++ ) {
		if ( !strncasecmp_m(argv[i], "ntgroup", strlen("ntgroup")) ) {
			fstrcpy( ntgroup, get_string_param( argv[i] ) );
			if ( !ntgroup[0] ) {
				d_fprintf(stderr, _("must supply a name\n"));
				return -1;
			}
		}
		else if ( !strncasecmp_m(argv[i], "sid", strlen("sid")) ) {
			fstrcpy( sid_string, get_string_param( argv[i] ) );
			if ( !sid_string[0] ) {
				d_fprintf(stderr, _("must supply a name\n"));
				return -1;
			}
		}
		else if ( !strncasecmp_m(argv[i], "comment", strlen("comment")) ) {
			fstrcpy( ntcomment, get_string_param( argv[i] ) );
			if ( !ntcomment[0] ) {
				d_fprintf(stderr,
					  _("must supply a comment string\n"));
				return -1;
			}
		}
		else if ( !strncasecmp_m(argv[i], "unixgroup", strlen("unixgroup")) ) {
			fstrcpy( unixgrp, get_string_param( argv[i] ) );
			if ( !unixgrp[0] ) {
				d_fprintf(stderr,
					  _("must supply a group name\n"));
				return -1;
			}
		}
		else if ( !strncasecmp_m(argv[i], "type", strlen("type")) )  {
			fstrcpy( type, get_string_param( argv[i] ) );
			switch ( type[0] ) {
				case 'd':
				case 'D':
					sid_type = SID_NAME_DOM_GRP;
					break;
				case 'l':
				case 'L':
					sid_type = SID_NAME_ALIAS;
					break;
			}
		}
		else {
			d_fprintf(stderr, _("Bad option: %s\n"), argv[i]);
			return -1;
		}
	}

	if ( !ntgroup[0] && !sid_string[0] ) {
		d_printf("%s\n%s\n", _("Usage:\n"), modify_usage_str);
		return -1;
	}

	/* give preference to the SID; if both the ntgroup name and SID
	   are defined, use the SID and assume that the group name could be a
	   new name */

	if ( sid_string[0] ) {
		if (!get_sid_from_input(&sid, sid_string)) {
			return -1;
		}
	}
	else {
		if (!get_sid_from_input(&sid, ntgroup)) {
			return -1;
		}
	}

	map = talloc_zero(NULL, GROUP_MAP);
	if (!map) {
		return -1;
	}

	/* Get the current mapping from the database */
	if(!pdb_getgrsid(map, sid)) {
		d_fprintf(stderr,
			 _("Failed to find local group SID in the database\n"));
		TALLOC_FREE(map);
		return -1;
	}

	/*
	 * Allow changing of group type only between domain and local
	 * We disallow changing Builtin groups !!! (SID problem)
	 */
	if (sid_type == SID_NAME_UNKNOWN) {
		d_fprintf(stderr, _("Can't map to an unknown group type.\n"));
		TALLOC_FREE(map);
		return -1;
        }

	if (map->sid_name_use == SID_NAME_WKN_GRP) {
		d_fprintf(stderr,
			  _("You can only change between domain and local "
			    "groups.\n"));
		TALLOC_FREE(map);
		return -1;
	}

	map->sid_name_use = sid_type;

	/* Change comment if new one */
	if (ntcomment[0]) {
		map->comment = talloc_strdup(map, ntcomment);
		if (!map->comment) {
			d_fprintf(stderr, _("Out of memory!\n"));
			return -1;
		}
	}

	if (ntgroup[0]) {
		map->nt_name = talloc_strdup(map, ntgroup);
		if (!map->nt_name) {
			d_fprintf(stderr, _("Out of memory!\n"));
			return -1;
		}
	}

	if ( unixgrp[0] ) {
		gid = nametogid( unixgrp );
		if ( gid == -1 ) {
			d_fprintf(stderr, _("Unable to lookup UNIX group %s.  "
					    "Make sure the group exists.\n"),
				unixgrp);
			TALLOC_FREE(map);
			return -1;
		}

		map->gid = gid;
	}

	if (!NT_STATUS_IS_OK(pdb_update_group_mapping_entry(map))) {
		d_fprintf(stderr, _("Could not update group database\n"));
		TALLOC_FREE(map);
		return -1;
	}

	d_printf(_("Updated mapping entry for %s\n"), map->nt_name);

	TALLOC_FREE(map);
	return 0;
}

#ifdef HAVE_JANSSON
static bool del_json_mapping(int idx, struct json_object *entry, void *state)
{
	bool ok;
	GROUP_MAP *map = NULL;
	fstring sid;
	NTSTATUS status;

	map = talloc_zero(talloc_tos(), GROUP_MAP);
	if (map == NULL) {
		d_fprintf(stderr, _("memory error.\n"));
		return false;
	}

	ok = json_to_groupmap(entry, map);
	if (!ok) {
		d_fprintf(stderr, _("[%d]: Failed to convert entry to "
				    "GROUP_MAP.\n"), idx);
		TALLOC_FREE(map);
		return false;
	}

	sid_to_fstring(sid, &map->sid);
	if (strequal(sid, "S-0-0")) {
		d_fprintf(stderr,
			  _("[%d]: either \"sid\" or \"nt_name\" "
			    "is required.\n"), idx);
		TALLOC_FREE(map);
		return false;
	}

	status = pdb_delete_group_mapping_entry(map->sid);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr,
			  _("[%d]: Failed to remove SID %s from the mapping db!\n"),
			  idx, sid);
		return false;
	}
	TALLOC_FREE(map);

	return true;
}

static int net_groupmap_delete_json(struct net_context *c, int argc, const char **argv)
{
	struct json_object jsdata, jsgroupmap;
	int error;
	bool quiet = false;

	jsdata = load_json(argv[0]);
	if (json_is_invalid(&jsdata)) {
		return -1;
	}

	error = json_get_bool_value(&jsdata, "quiet", &quiet);
	if (error && (errno == EINVAL)) {
		d_fprintf(stderr, _("key \"quiet\" must be boolean.\n"));
		json_free(&jsdata);
		return -1;
	}

	jsgroupmap = json_get_array(&jsdata, "groupmap");
	if (json_is_invalid(&jsgroupmap)) {
		json_free(&jsdata);
		return -1;
	}

	error = iter_json_array(&jsgroupmap, del_json_mapping, NULL);
	if (error) {
		json_free(&jsdata);
		return -1;
	}

	json_free(&jsdata);

	if (!quiet && !is_batch_op) {
		net_groupmap_list_json(c, 0, NULL);
	}
	return 0;
}
#endif /* HAVE_JANSSON */

static int net_groupmap_delete(struct net_context *c, int argc, const char **argv)
{
	struct dom_sid sid;
	fstring ntgroup = "";
	fstring sid_string = "";
	int i;
	const char delete_usage_str[] = N_("net groupmap delete "
					   "{ntgroup=<string>|sid=<SID>}");

#ifdef HAVE_JANSSON
	if (c->opt_json) {
		return net_groupmap_delete_json(c, argc, argv);
	}
#endif /* HAVE_JANSSON */

	if (c->display_usage) {
		d_printf("%s\n%s\n", _("Usage:\n"), delete_usage_str);
		return 0;
	}

	/* get the options */
	for ( i=0; i<argc; i++ ) {
		if ( !strncasecmp_m(argv[i], "ntgroup", strlen("ntgroup")) ) {
			fstrcpy( ntgroup, get_string_param( argv[i] ) );
			if ( !ntgroup[0] ) {
				d_fprintf(stderr, _("must supply a name\n"));
				return -1;
			}
		}
		else if ( !strncasecmp_m(argv[i], "sid", strlen("sid")) ) {
			fstrcpy( sid_string, get_string_param( argv[i] ) );
			if ( !sid_string[0] ) {
				d_fprintf(stderr, _("must supply a SID\n"));
				return -1;
			}
		}
		else {
			d_fprintf(stderr, _("Bad option: %s\n"), argv[i]);
			return -1;
		}
	}

	if ( !ntgroup[0] && !sid_string[0]) {
		d_printf("%s\n%s\n", _("Usage:\n"), delete_usage_str);
		return -1;
	}

	/* give preference to the SID if we have that */

	if ( sid_string[0] )
		strlcpy(ntgroup, sid_string, sizeof(ntgroup));

	if ( !get_sid_from_input(&sid, ntgroup) ) {
		d_fprintf(stderr, _("Unable to resolve group %s to a SID\n"),
			  ntgroup);
		return -1;
	}

	if ( !NT_STATUS_IS_OK(pdb_delete_group_mapping_entry(sid)) ) {
		d_fprintf(stderr,
			  _("Failed to remove group %s from the mapping db!\n"),
			  ntgroup);
		return -1;
	}

	d_printf(_("Successfully removed %s from the mapping db\n"), ntgroup);

	return 0;
}

static int net_groupmap_set(struct net_context *c, int argc, const char **argv)
{
	const char *ntgroup = NULL;
	struct group *grp = NULL;
	GROUP_MAP *map;
	bool have_map = false;

	if ((argc < 1) || (argc > 2) || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _(" net groupmap set \"NT Group\" "
			   "[\"unix group\"] [-C \"comment\"] [-L] [-D]\n"));
		return -1;
	}

	if ( c->opt_localgroup && c->opt_domaingroup ) {
		d_printf(_("Can only specify -L or -D, not both\n"));
		return -1;
	}

	ntgroup = argv[0];

	if (argc == 2) {
		grp = getgrnam(argv[1]);

		if (grp == NULL) {
			d_fprintf(stderr, _("Could not find unix group %s\n"),
				  argv[1]);
			return -1;
		}
	}

	map = talloc_zero(NULL, GROUP_MAP);
	if (!map) {
		d_printf(_("Out of memory!\n"));
		return -1;
	}

	have_map = pdb_getgrnam(map, ntgroup);

	if (!have_map) {
		struct dom_sid sid;
		have_map = ( (strncmp(ntgroup, "S-", 2) == 0) &&
			     string_to_sid(&sid, ntgroup) &&
			     pdb_getgrsid(map, sid) );
	}

	if (!have_map) {

		/* Ok, add it */

		if (grp == NULL) {
			d_fprintf(stderr,
				  _("Could not find group mapping for %s\n"),
				  ntgroup);
			TALLOC_FREE(map);
			return -1;
		}

		map->gid = grp->gr_gid;

		if (c->opt_rid == 0) {
			if ( pdb_capabilities() & PDB_CAP_STORE_RIDS ) {
				if ( !pdb_new_rid((uint32_t *)&c->opt_rid) ) {
					d_fprintf( stderr,
					    _("Could not allocate new RID\n"));
					TALLOC_FREE(map);
					return -1;
				}
			} else {
				c->opt_rid = algorithmic_pdb_gid_to_group_rid(map->gid);
			}
		}

		sid_compose(&map->sid, get_global_sam_sid(), c->opt_rid);

		map->sid_name_use = SID_NAME_DOM_GRP;
		map->nt_name = talloc_strdup(map, ntgroup);
		map->comment = talloc_strdup(map, "");
		if (!map->nt_name || !map->comment) {
			d_printf(_("Out of memory!\n"));
			TALLOC_FREE(map);
			return -1;
		}

		if (!NT_STATUS_IS_OK(pdb_add_group_mapping_entry(map))) {
			d_fprintf(stderr,
				  _("Could not add mapping entry for %s\n"),
				  ntgroup);
			TALLOC_FREE(map);
			return -1;
		}
	}

	/* Now we have a mapping entry, update that stuff */

	if ( c->opt_localgroup || c->opt_domaingroup ) {
		if (map->sid_name_use == SID_NAME_WKN_GRP) {
			d_fprintf(stderr,
				  _("Can't change type of the BUILTIN "
				    "group %s\n"),
				  map->nt_name);
			TALLOC_FREE(map);
			return -1;
		}
	}

	if (c->opt_localgroup)
		map->sid_name_use = SID_NAME_ALIAS;

	if (c->opt_domaingroup)
		map->sid_name_use = SID_NAME_DOM_GRP;

	/* The case (opt_domaingroup && opt_localgroup) was tested for above */

	if ((c->opt_comment != NULL) && (strlen(c->opt_comment) > 0)) {
		map->comment = talloc_strdup(map, c->opt_comment);
		if (!map->comment) {
			d_printf(_("Out of memory!\n"));
			TALLOC_FREE(map);
			return -1;
		}
	}

	if ((c->opt_newntname != NULL) && (strlen(c->opt_newntname) > 0)) {
		map->nt_name = talloc_strdup(map, c->opt_newntname);
		if (!map->nt_name) {
			d_printf(_("Out of memory!\n"));
			TALLOC_FREE(map);
			return -1;
		}
	}

	if (grp != NULL)
		map->gid = grp->gr_gid;

	if (!NT_STATUS_IS_OK(pdb_update_group_mapping_entry(map))) {
		d_fprintf(stderr, _("Could not update group mapping for %s\n"),
			  ntgroup);
		TALLOC_FREE(map);
		return -1;
	}

	TALLOC_FREE(map);
	return 0;
}

static int net_groupmap_cleanup(struct net_context *c, int argc, const char **argv)
{
	GROUP_MAP **maps = NULL;
	size_t i, entries;

	if (c->display_usage) {
		d_printf(  "%s\n"
			   "net groupmap cleanup\n"
			   "    %s\n",
			 _("Usage:"),
			 _("Delete all group mappings"));
		return 0;
	}

	if (!pdb_enum_group_mapping(NULL, SID_NAME_UNKNOWN, &maps, &entries,
				    ENUM_ALL_MAPPED)) {
		d_fprintf(stderr, _("Could not list group mappings\n"));
		return -1;
	}

	for (i=0; i<entries; i++) {

		if (maps[i]->gid == -1)
			printf(_("Group %s is not mapped\n"),
				maps[i]->nt_name);

		if (!sid_check_is_in_our_sam(&maps[i]->sid) &&
		    !sid_check_is_in_builtin(&maps[i]->sid))
		{
			struct dom_sid_buf buf;
			printf(_("Deleting mapping for NT Group %s, sid %s\n"),
				maps[i]->nt_name,
				dom_sid_str_buf(&maps[i]->sid, &buf));
			pdb_delete_group_mapping_entry(maps[i]->sid);
		}
	}

	TALLOC_FREE(maps);
	return 0;
}

#ifdef HAVE_JANSSON
struct alias_member_token {
	struct dom_sid *alias;
	struct dom_sid *members;
	uint32_t n_members;
};

static bool add_member_sid(int idx, struct json_object *member, void *private_data)
{
	struct alias_member_token *token = NULL;
	const char *sid_string = NULL;
	struct dom_sid member_sid;
	int error;
	NTSTATUS status;
	bool ok;

	token = talloc_get_type_abort(private_data, struct alias_member_token);
	error = json_get_string_value(member, "sid", &sid_string);
	if (error) {
		d_fprintf(stderr, _("[%d]: \"sid\" string is required\n"), idx);
		return false;
	}

	ok = string_to_sid(&member_sid, sid_string);
	if (!ok) {
		d_fprintf(stderr, _("[%d]: failed to convert %s to dom_sid\n"),
			  idx, sid_string);
		return false;
	}
	status = add_sid_to_array(token, &member_sid,
				  &token->members, &token->n_members);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, _("[%d]: failed to add %s to members array\n"),
			  idx, sid_string);
		return false;
	}
	return true;
}

static bool json_to_sids(struct json_object *data, struct alias_member_token *token)
{
	int error;
	const char *alias = NULL;
	struct json_object members;

	error = json_get_string_value(data, "alias", &alias);
	if (error) {
		return false;
	}

	token->alias = dom_sid_parse_talloc(token, alias);
	if (token->alias == NULL) {
		return false;
	}

	members = json_get_array(data, "members");
	if (json_is_invalid(&members)) {
		return false;
	}

	error = iter_json_array(&members, add_member_sid, token);
	if (error) {
		return false;
	}
	return true;
}


static int net_groupmap_addmem_json(struct net_context *c, int argc, const char **argv)
{
	struct json_object jsdata;
	bool ok;
	struct alias_member_token *token = NULL;
	int i;

	jsdata = load_json(argv[0]);
	if (json_is_invalid(&jsdata)) {
		return -1;
	}

	token = talloc_zero(talloc_tos(), struct alias_member_token);
	if (token == NULL) {
		json_free(&jsdata);
		return -1;
	}

	ok = json_to_sids(&jsdata, token);
	if (!ok) {
		printf("json to sids failed\n");
		json_free(&jsdata);
		return -1;
	}
	json_free(&jsdata);

	for (i = 0; i < token->n_members; i++) {
		NTSTATUS status;
		status = pdb_add_aliasmem(token->alias, &token->members[i]);
		if (!NT_STATUS_IS_OK(status)) {
			d_fprintf(stderr, _("[%d]: failed to add member: %s\n"),
				  i, nt_errstr(status));
			TALLOC_FREE(token);
			return -1;
		}
	}

	TALLOC_FREE(token);
	return 0;
}
#endif /* HAVE_JANSSON */

static int net_groupmap_addmem(struct net_context *c, int argc, const char **argv)
{
	struct dom_sid alias, member;

#ifdef HAVE_JANSSON
	if (c->opt_json) {
		return net_groupmap_addmem_json(c, argc, argv);
	}
#endif /* HAVE_JANSSON */

	if ( (argc != 2) ||
	     c->display_usage ||
	     !string_to_sid(&alias, argv[0]) ||
	     !string_to_sid(&member, argv[1]) ) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net groupmap addmem alias-sid member-sid\n"));
		return -1;
	}

	if (!NT_STATUS_IS_OK(pdb_add_aliasmem(&alias, &member))) {
		d_fprintf(stderr, _("Could not add sid %s to alias %s\n"),
			 argv[1], argv[0]);
		return -1;
	}

	return 0;
}

#ifdef HAVE_JANSSON
static int net_groupmap_delmem_json(struct net_context *c, int argc, const char **argv)
{
	struct json_object jsdata;
	bool ok;
	struct alias_member_token *token = NULL;
	int i;

	jsdata = load_json(argv[0]);
	if (json_is_invalid(&jsdata)) {
		return -1;
	}

	token = talloc_zero(talloc_tos(), struct alias_member_token);
	if (token == NULL) {
		json_free(&jsdata);
		return -1;
	}

	ok = json_to_sids(&jsdata, token);
	if (!ok) {
		printf("json to sids failed\n");
		json_free(&jsdata);
		return -1;
	}
	json_free(&jsdata);

	for (i = 0; i < token->n_members; i++) {
		NTSTATUS status;
		status = pdb_del_aliasmem(token->alias, &token->members[i]);
		if (!NT_STATUS_IS_OK(status)) {
			d_fprintf(stderr, _("[%d]: failed to add member: %s\n"),
				  i, nt_errstr(status));
			TALLOC_FREE(token);
			return -1;
		}
	}

	TALLOC_FREE(token);
	return 0;
}
#endif /* HAVE_JANSSON */

static int net_groupmap_delmem(struct net_context *c, int argc, const char **argv)
{
	struct dom_sid alias, member;

#ifdef HAVE_JANSSON
	if (c->opt_json) {
		return net_groupmap_delmem_json(c, argc, argv);
	}
#endif /* HAVE_JANSSON */

	if ( (argc != 2) ||
	     c->display_usage ||
	     !string_to_sid(&alias, argv[0]) ||
	     !string_to_sid(&member, argv[1]) ) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net groupmap delmem alias-sid member-sid\n"));
		return -1;
	}

	if (!NT_STATUS_IS_OK(pdb_del_aliasmem(&alias, &member))) {
		d_fprintf(stderr, _("Could not delete sid %s from alias %s\n"),
			 argv[1], argv[0]);
		return -1;
	}

	return 0;
}

#ifdef HAVE_JANSSON
static int net_groupmap_listmem_json(struct net_context *c, int argc, const char **argv)
{
	struct json_object jsdata, out, jsmembers;
	bool ok;
	struct alias_member_token *token = NULL;
	int i, error;
	size_t num;
	struct dom_sid *members = NULL;
	char *toprint= NULL;
	NTSTATUS status;

	jsdata = load_json(argv[0]);
	if (json_is_invalid(&jsdata)) {
		return -1;
	}

	token = talloc_zero(talloc_tos(), struct alias_member_token);
	if (token == NULL) {
		json_free(&jsdata);
		return -1;
	}

	ok = json_to_sids(&jsdata, token);
	if (!ok) {
		printf("json to sids failed\n");
		json_free(&jsdata);
		return -1;
	}
	json_free(&jsdata);

	out = json_new_object();
	if (json_is_invalid(&out)) {
		d_fprintf(stderr, _("Failed to create JSON object %s\n"));
		TALLOC_FREE(token);
		return -1;
	}

	jsmembers = json_new_array();
	if (json_is_invalid(&jsmembers)) {
		d_fprintf(stderr, _("Failed to create JSON object %s\n"));
		json_free(&out);
		TALLOC_FREE(token);
		return -1;
	}

	error = json_add_version(&out, JS_MAJ_VER, JS_MIN_VER);
	if (error) {
		goto fail;
	}

	error = json_add_sid(&out, "alias", token->alias);
	if (error) {
		goto fail;
	}

	status = pdb_enum_aliasmem(token->alias, talloc_tos(),
				   &members, &num);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, _("Failed to enumerate alias members: %s\n"),
			  nt_errstr(status));
		goto fail;
	}

	for (i = 0; i < num; i++) {
		struct json_object member;
		member = json_new_object();
		if (json_is_invalid(&member)) {
			goto fail;
		}

		error = json_add_sid(&member, "sid", &members[i]);
		if (error) {
			json_free(&member);
			goto fail;
		}

		error = json_add_object(&jsmembers, NULL, &member);
		if (error) {
			goto fail;
		}
	}

	error = json_add_object(&out, "members", &jsmembers);
	if (error) {
		json_free(&out);
		TALLOC_FREE(token);
		return -1;
	}

	toprint = json_to_string(token, &out);
	printf("%s\n", toprint);
	TALLOC_FREE(token);
	json_free(&out);
	return 0;

fail:
	json_free(&out);
	json_free(&jsmembers);
	TALLOC_FREE(token);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_SUCH_ALIAS)) {
		return ENOENT;
	}
	return -1;

}
#endif

static int net_groupmap_listmem(struct net_context *c, int argc, const char **argv)
{
	struct dom_sid alias;
	struct dom_sid *members;
	size_t i, num;

#ifdef HAVE_JANSSON
	if (c->opt_json) {
		return net_groupmap_listmem_json(c, argc, argv);
	}
#endif /* HAVE_JANSSON */

	if ( (argc != 1) ||
	     c->display_usage ||
	     !string_to_sid(&alias, argv[0]) ) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net groupmap listmem alias-sid\n"));
		return -1;
	}

	members = NULL;
	num = 0;

	if (!NT_STATUS_IS_OK(pdb_enum_aliasmem(&alias, talloc_tos(),
					       &members, &num))) {
		d_fprintf(stderr, _("Could not list members for sid %s\n"),
			  argv[0]);
		return -1;
	}

	for (i = 0; i < num; i++) {
		struct dom_sid_buf buf;
		printf("%s\n", dom_sid_str_buf(&(members[i]), &buf));
	}

	TALLOC_FREE(members);

	return 0;
}

static bool print_alias_memberships(TALLOC_CTX *mem_ctx,
				    const struct dom_sid *domain_sid,
				    const struct dom_sid *member)
{
	uint32_t *alias_rids;
	size_t i, num_alias_rids;
	struct dom_sid_buf buf;

	alias_rids = NULL;
	num_alias_rids = 0;

	if (!NT_STATUS_IS_OK(pdb_enum_alias_memberships(
				     mem_ctx, domain_sid, member, 1,
				     &alias_rids, &num_alias_rids))) {
		d_fprintf(stderr, _("Could not list memberships for sid %s\n"),
			  dom_sid_str_buf(member, &buf));
		return false;
	}

	for (i = 0; i < num_alias_rids; i++) {
		struct dom_sid alias;
		sid_compose(&alias, domain_sid, alias_rids[i]);
		printf("%s\n", dom_sid_str_buf(&alias, &buf));
	}

	return true;
}

static int net_groupmap_memberships(struct net_context *c, int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx;
	struct dom_sid *domain_sid, member;

	if ( (argc != 1) ||
	     c->display_usage ||
	     !string_to_sid(&member, argv[0]) ) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net groupmap memberships sid\n"));
		return -1;
	}

	mem_ctx = talloc_init("net_groupmap_memberships");
	if (mem_ctx == NULL) {
		d_fprintf(stderr, _("talloc_init failed\n"));
		return -1;
	}

	domain_sid = get_global_sam_sid();
	if (domain_sid == NULL) {
		d_fprintf(stderr, _("Could not get domain sid\n"));
		return -1;
	}

	if (!print_alias_memberships(mem_ctx, domain_sid, &member) ||
	    !print_alias_memberships(mem_ctx, &global_sid_Builtin, &member))
		return -1;

	talloc_destroy(mem_ctx);

	return 0;
}

#ifdef HAVE_JANSSON
const struct {
	const char *name;
	int (*fn)(struct net_context *c, int argc, const char **argv);
} optable[] = {
	{ "DEL", net_groupmap_delete },
	{ "ADD", net_groupmap_add },
	{ "MOD", net_groupmap_modify },
	{ "DELMEM", net_groupmap_delmem },
	{ "ADDMEM", net_groupmap_addmem },
};

struct batch_op_state {
	struct net_context *ctx;
	int (*fn)(struct net_context *c, int argc, const char **argv);
};

static bool dispatch_batch_op(int idx,
			      struct json_object *data,
			      void *private_data)
{
	int error;
	struct batch_op_state *state = NULL;
	char *js_data = NULL, *payload = NULL;

	state = talloc_get_type_abort(private_data, struct batch_op_state);

	payload = json_dumps(data->root, 0);
	if (payload == NULL) {
		d_fprintf(stderr, _("Failed to convert \"data\" to string.\n"));
		return false;
	}

	const char *args[] = { payload, NULL };
	error = state->fn(state->ctx, 1, args);
	if (error) {
		d_fprintf(stderr, _("operation failed on element: %d.\n"), idx);
		return false;
		free(js_data);
	}
	free(js_data);

	return true;
}

static int net_groupmap_batch_json(struct net_context *c, int argc, const char **argv)
{
	struct json_object batch_data = json_empty_object;
	size_t array_size;
	int i, error;

	is_batch_op = true;
	batch_data = load_json(argv[0]);

	if (batch_data.root == NULL) {
		d_fprintf(stderr, _("Failed to load JSON data.\n"));
		return false;
	}

	if (!json_is_object(batch_data.root)) {
		d_fprintf(stderr, _("data is not a JSON object.\n"));
		json_free(&batch_data);
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(optable); i++) {
		struct json_object op_array;
		struct batch_op_state *state = NULL;

		op_array = json_get_array(&batch_data, optable[i].name);
		if (json_is_invalid(&op_array)) {
			continue;
		}

		state = talloc_zero(talloc_tos(), struct batch_op_state);
		if (state == NULL) {
			d_fprintf(stderr, _("memory error\n"));
			json_free(&batch_data);
			return -1;
		}

		state->ctx = c;
		state->fn = optable[i].fn;

		error = iter_json_array(&op_array, dispatch_batch_op, state);
		if (error) {
			d_fprintf(stderr,
				  _("%s: operation failed\n"),
				  optable[i].name);
			json_free(&batch_data);
			return -1;
		}
		TALLOC_FREE(state);
	}

	if (error) {
		d_fprintf(stderr, _("No valid operations specified\n"));
		json_free(&batch_data);
	}

	json_free(&batch_data);

	error = net_groupmap_list(c, 0, NULL);
	if (error) {
		d_fprintf(stderr, _("failed to add updated groupmap\n"));
	}

	return 0;
}
#endif

/***********************************************************
 migrated functionality from smbgroupedit
 **********************************************************/
int net_groupmap(struct net_context *c, int argc, const char **argv)
{
	struct functable func[] = {
		{
			"add",
			net_groupmap_add,
			NET_TRANSPORT_LOCAL,
			N_("Create a new group mapping"),
			N_("net groupmap add\n"
			   "    Create a new group mapping")
		},
		{
			"modify",
			net_groupmap_modify,
			NET_TRANSPORT_LOCAL,
			N_("Update a group mapping"),
			N_("net groupmap modify\n"
			   "    Modify an existing group mapping")
		},
		{
			"delete",
			net_groupmap_delete,
			NET_TRANSPORT_LOCAL,
			N_("Remove a group mapping"),
			N_("net groupmap delete\n"
			   "    Remove a group mapping")
		},
		{
			"set",
			net_groupmap_set,
			NET_TRANSPORT_LOCAL,
			N_("Set group mapping"),
			N_("net groupmap set\n"
			   "    Set a group mapping")
		},
		{
			"cleanup",
			net_groupmap_cleanup,
			NET_TRANSPORT_LOCAL,
			N_("Remove foreign group mapping entries"),
			N_("net groupmap cleanup\n"
			   "    Remove foreign group mapping entries")
		},
		{
			"addmem",
			net_groupmap_addmem,
			NET_TRANSPORT_LOCAL,
			N_("Add a foreign alias member"),
			N_("net groupmap addmem\n"
			   "    Add a foreign alias member")
		},
		{
			"delmem",
			net_groupmap_delmem,
			NET_TRANSPORT_LOCAL,
			N_("Delete foreign alias member"),
			N_("net groupmap delmem\n"
			   "    Delete foreign alias member")
		},
		{
			"listmem",
			net_groupmap_listmem,
			NET_TRANSPORT_LOCAL,
			N_("List foreign group members"),
			N_("net groupmap listmem\n"
			   "    List foreign alias members")
		},
		{
			"memberships",
			net_groupmap_memberships,
			NET_TRANSPORT_LOCAL,
			N_("List foreign group memberships"),
			N_("net groupmap memberships\n"
			   "    List foreign group memberships")
		},
		{
			"list",
			net_groupmap_list,
			NET_TRANSPORT_LOCAL,
			N_("List current group map"),
			N_("net groupmap list\n"
			   "    List current group map")
		},
#ifdef HAVE_JANSSON
		{
			"batch",
			net_groupmap_batch_json,
			NET_TRANSPORT_LOCAL,
			N_("Perform multiple json operations"),
			N_("net groupmap batch\n"
			   "    Perform batch operation based on supplied JSON. "
			   "    Current supported operations are \"ADD\", \"MOD\", \"DEL\" \n"
			   "    '{ \"<OP>\": [ {ENTRY}, {ENTRY}, ... ]'")
		},
#endif
		{NULL, NULL, 0, NULL, NULL}
	};

	return net_run_function(c,argc, argv, "net groupmap", func);
}


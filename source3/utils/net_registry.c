/*
 * Samba Unix/Linux SMB client library
 * Distributed SMB/CIFS Server Management Utility
 * Local registry interface
 *
 * Copyright (C) Michael Adam 2008
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "registry.h"
#include "registry/reg_api.h"
#include "registry/reg_util_token.h"
#include "registry/reg_init_basic.h"
#include "utils/net.h"
#include "utils/net_registry_util.h"
#include "include/g_lock.h"
#include "registry/reg_backend_db.h"
#include "registry/reg_import.h"
#include "registry/reg_format.h"
#include "registry/reg_api_util.h"
#include <assert.h>
#include "../libcli/security/display_sec.h"
#include "../libcli/security/sddl.h"
#include "../libcli/registry/util_reg.h"
#include "passdb/machine_sid.h"
#include "net_registry_check.h"
#include "lib/util/util_tdb.h"
#include "lib/util/smb_strtox.h"

/*
 *
 * Helper functions
 *
 */

/**
 * split given path into hive and remaining path and open the hive key
 */
static WERROR open_hive(TALLOC_CTX *ctx, const char *path,
			uint32_t desired_access,
			struct registry_key **hive,
			char **subkeyname)
{
	WERROR werr;
	struct security_token *token = NULL;
	char *hivename = NULL;
	char *tmp_subkeyname = NULL;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();

	if ((hive == NULL) || (subkeyname == NULL)) {
		werr = WERR_INVALID_PARAMETER;
		goto done;
	}

	werr = split_hive_key(tmp_ctx, path, &hivename, &tmp_subkeyname);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}
	*subkeyname = talloc_strdup(ctx, tmp_subkeyname);
	if (*subkeyname == NULL) {
		werr = WERR_NOT_ENOUGH_MEMORY;
		goto done;
	}

	werr = ntstatus_to_werror(registry_create_admin_token(tmp_ctx, &token));
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = reg_openhive(ctx, hivename, desired_access, token, hive);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	werr = WERR_OK;

done:
	TALLOC_FREE(tmp_ctx);
	return werr;
}

static WERROR open_key(TALLOC_CTX *ctx, const char *path,
		       uint32_t desired_access,
		       struct registry_key **key)
{
	WERROR werr;
	char *subkey_name = NULL;
	struct registry_key *hive = NULL;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();

	if ((path == NULL) || (key == NULL)) {
		return WERR_INVALID_PARAMETER;
	}

	werr = open_hive(tmp_ctx, path, desired_access, &hive, &subkey_name);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("open_hive failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}

	werr = reg_openkey(ctx, hive, subkey_name, desired_access, key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("reg_openkey failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}

	werr = WERR_OK;

done:
	TALLOC_FREE(tmp_ctx);
	return werr;
}

static WERROR registry_enumkey(struct registry_key *parent, const char *keyname,
			       bool recursive)
{
	WERROR werr;
	TALLOC_CTX *ctx = talloc_stackframe();
	char *subkey_name;
	NTTIME modtime;
	uint32_t count;
	char *valname = NULL;
	struct registry_value *valvalue = NULL;
	struct registry_key *key = NULL;

	werr = reg_openkey(ctx, parent, keyname, REG_KEY_READ, &key);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	if (recursive) {
		printf("[%s]\n\n", key->key->name);
	} else {
		for (count = 0;
		     werr = reg_enumkey(ctx, key, count, &subkey_name, &modtime),
		     W_ERROR_IS_OK(werr);
		     count++)
		{
			print_registry_key(subkey_name, &modtime);
		}
		if (!W_ERROR_EQUAL(WERR_NO_MORE_ITEMS, werr)) {
			goto done;
		}
	}

	for (count = 0;
	     werr = reg_enumvalue(ctx, key, count, &valname, &valvalue),
	     W_ERROR_IS_OK(werr);
	     count++)
	{
		print_registry_value_with_name(valname, valvalue);
	}
	if (!W_ERROR_EQUAL(WERR_NO_MORE_ITEMS, werr)) {
		goto done;
	}

	if (!recursive) {
		werr = WERR_OK;
		goto done;
	}

	for (count = 0;
	     werr = reg_enumkey(ctx, key, count, &subkey_name, &modtime),
	     W_ERROR_IS_OK(werr);
	     count++)
	{
		werr = registry_enumkey(key, subkey_name, recursive);
		if (!W_ERROR_IS_OK(werr)) {
			goto done;
		}
	}
	if (!W_ERROR_EQUAL(WERR_NO_MORE_ITEMS, werr)) {
		goto done;
	}

	werr = WERR_OK;

done:
	TALLOC_FREE(ctx);
	return werr;
}



/*
 *
 * the main "net registry" function implementations
 *
 */
static int net_registry_enumerate(struct net_context *c, int argc,
				  const char **argv)
{
	WERROR werr;
	struct registry_key *key = NULL;
	char *name = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	int ret = -1;

	if (argc != 1 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net registry enumerate <path>\n"));
		d_printf("%s\n%s",
			 _("Example:"),
			 _("net registry enumerate 'HKLM\\Software\\Samba'\n"));
		goto done;
	}

	werr = open_hive(ctx, argv[0], REG_KEY_READ, &key, &name);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("open_key failed: %s\n"), win_errstr(werr));
		goto done;
	}

	werr = registry_enumkey(key, name, c->opt_reboot);
	if (W_ERROR_IS_OK(werr)) {
		ret = 0;
	}
done:
	TALLOC_FREE(ctx);
	return ret;
}

static int net_registry_enumerate_recursive(struct net_context *c, int argc,
					    const char **argv)
{
	WERROR werr;
	struct registry_key *key = NULL;
	char *name = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	int ret = -1;

	if (argc != 1 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net registry enumerate <path>\n"));
		d_printf("%s\n%s",
			 _("Example:"),
			 _("net registry enumerate 'HKLM\\Software\\Samba'\n"));
		goto done;
	}

	werr = open_hive(ctx, argv[0], REG_KEY_READ, &key, &name);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("open_key failed: %s\n"), win_errstr(werr));
		goto done;
	}

	werr = registry_enumkey(key, name, true);
	if (W_ERROR_IS_OK(werr)) {
		ret = 0;
	}
done:
	TALLOC_FREE(ctx);
	return ret;
}


static int net_registry_createkey(struct net_context *c, int argc,
				  const char **argv)
{
	WERROR werr;
	enum winreg_CreateAction action;
	char *subkeyname = NULL;
	struct registry_key *hivekey = NULL;
	struct registry_key *subkey = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	int ret = -1;

	if (argc != 1 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net registry createkey <path>\n"));
		d_printf("%s\n%s",
			 _("Example:"),
			 _("net registry createkey "
			   "'HKLM\\Software\\Samba\\smbconf.127.0.0.1'\n"));
		goto done;
	}
	if (strlen(argv[0]) == 0) {
		d_fprintf(stderr, _("error: zero length key name given\n"));
		goto done;
	}

	werr = open_hive(ctx, argv[0], REG_KEY_WRITE, &hivekey, &subkeyname);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("open_hive failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}

	werr = reg_createkey(ctx, hivekey, subkeyname, REG_KEY_WRITE,
			     &subkey, &action);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("reg_createkey failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}
	switch (action) {
		case REG_ACTION_NONE:
			d_printf(_("createkey did nothing -- huh?\n"));
			break;
		case REG_CREATED_NEW_KEY:
			d_printf(_("createkey created %s\n"), argv[0]);
			break;
		case REG_OPENED_EXISTING_KEY:
			d_printf(_("createkey opened existing %s\n"), argv[0]);
			break;
	}

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

static int net_registry_deletekey_internal(struct net_context *c, int argc,
					   const char **argv,
					   bool recursive)
{
	WERROR werr;
	char *subkeyname = NULL;
	struct registry_key *hivekey = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	int ret = -1;

	if (argc != 1 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net registry deletekey <path>\n"));
		d_printf("%s\n%s",
			 _("Example:"),
			 _("net registry deletekey "
			   "'HKLM\\Software\\Samba\\smbconf.127.0.0.1'\n"));
		goto done;
	}
	if (strlen(argv[0]) == 0) {
		d_fprintf(stderr, _("error: zero length key name given\n"));
		goto done;
	}

	werr = open_hive(ctx, argv[0], REG_KEY_WRITE, &hivekey, &subkeyname);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "open_hive %s: %s\n", _("failed"),
			  win_errstr(werr));
		goto done;
	}

	if (recursive) {
		werr = reg_deletekey_recursive(hivekey, subkeyname);
	} else {
		werr = reg_deletekey(hivekey, subkeyname);
	}
	if (!W_ERROR_IS_OK(werr) &&
	    !(c->opt_force && W_ERROR_EQUAL(werr, WERR_FILE_NOT_FOUND)))
	{
		d_fprintf(stderr, "reg_deletekey %s: %s\n", _("failed"),
			  win_errstr(werr));
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

static int net_registry_deletekey(struct net_context *c, int argc,
				  const char **argv)
{
	return net_registry_deletekey_internal(c, argc, argv, false);
}

static int net_registry_deletekey_recursive(struct net_context *c, int argc,
					    const char **argv)
{
	return net_registry_deletekey_internal(c, argc, argv, true);
}

static int net_registry_getvalue_internal(struct net_context *c, int argc,
					  const char **argv, bool raw)
{
	WERROR werr;
	int ret = -1;
	struct registry_key *key = NULL;
	struct registry_value *value = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();

	if (argc != 2 || c->display_usage) {
		d_fprintf(stderr, "%s\n%s",
			  _("Usage:"),
			  _("net registry getvalue <key> <valuename>\n"));
		goto done;
	}

	werr = open_key(ctx, argv[0], REG_KEY_READ, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("open_key failed: %s\n"), win_errstr(werr));
		goto done;
	}

	werr = reg_queryvalue(ctx, key, argv[1], &value);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("reg_queryvalue failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}

	print_registry_value(value, raw);

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

static int net_registry_getvalue(struct net_context *c, int argc,
				 const char **argv)
{
	return net_registry_getvalue_internal(c, argc, argv, false);
}

static int net_registry_getvalueraw(struct net_context *c, int argc,
				    const char **argv)
{
	return net_registry_getvalue_internal(c, argc, argv, true);
}

static int net_registry_getvaluesraw(struct net_context *c, int argc,
				     const char **argv)
{
	WERROR werr;
	int ret = -1;
	struct registry_key *key = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	uint32_t idx;

	if (argc != 1 || c->display_usage) {
		d_fprintf(stderr, "usage: net rpc registry getvaluesraw "
			  "<key>\n");
		goto done;
	}

	werr = open_key(ctx, argv[0], REG_KEY_READ, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "open_key failed: %s\n", win_errstr(werr));
		goto done;
	}

	idx = 0;
	while (true) {
		struct registry_value *val;

		werr = reg_enumvalue(talloc_tos(), key, idx, NULL, &val);

		if (W_ERROR_EQUAL(werr, WERR_NO_MORE_ITEMS)) {
			ret = 0;
			break;
		}
		if (!W_ERROR_IS_OK(werr)) {
			break;
		}
		print_registry_value(val, true);
		TALLOC_FREE(val);
		idx += 1;
	}
done:
	TALLOC_FREE(ctx);
	return ret;
}

static int net_registry_setvalue(struct net_context *c, int argc,
				 const char **argv)
{
	WERROR werr;
	struct registry_value value;
	struct registry_key *key = NULL;
	int ret = -1;
	TALLOC_CTX *ctx = talloc_stackframe();

	if (argc < 4 || c->display_usage) {
		d_fprintf(stderr, "%s\n%s",
			  _("Usage:"),
			  _("net registry setvalue <key> <valuename> "
			    "<type> [<val>]+\n"));
		goto done;
	}

	if (!strequal(argv[2], "multi_sz") && (argc != 4)) {
		d_fprintf(stderr, _("Too many args for type %s\n"), argv[2]);
		goto done;
	}

	if (strequal(argv[2], "dword")) {
		int error = 0;
		uint32_t v;

		v = smb_strtoul(argv[3], NULL, 10, &error, SMB_STR_STANDARD);
		if (error != 0) {
			goto done;
		}

		value.type = REG_DWORD;
		value.data = data_blob_talloc(ctx, NULL, 4);
		SIVAL(value.data.data, 0, v);
	} else if (strequal(argv[2], "sz")) {
		value.type = REG_SZ;
		if (!push_reg_sz(ctx, &value.data, argv[3])) {
			goto done;
		}
	} else if (strequal(argv[2], "multi_sz")) {
		const char **array;
		int count = argc - 3;
		int i;
		value.type = REG_MULTI_SZ;
		array = talloc_zero_array(ctx, const char *, count + 1);
		if (array == NULL) {
			goto done;
		}
		for (i=0; i < count; i++) {
			array[i] = talloc_strdup(array, argv[count+i]);
			if (array[i] == NULL) {
				goto done;
			}
		}
		if (!push_reg_multi_sz(ctx, &value.data, array)) {
			goto done;
		}
	} else {
		d_fprintf(stderr, _("type \"%s\" not implemented\n"), argv[2]);
		goto done;
	}

	werr = open_key(ctx, argv[0], REG_KEY_WRITE, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("open_key failed: %s\n"), win_errstr(werr));
		goto done;
	}

	werr = reg_setvalue(key, argv[1], &value);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("reg_setvalue failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

static int net_registry_increment(struct net_context *c, int argc,
				  const char **argv)
{
	TDB_DATA lock_key = string_term_tdb_data("registry_increment_lock");
	struct g_lock_ctx *ctx = NULL;
	const char *keyname = NULL;
	struct registry_key *key = NULL;
	const char *valuename = NULL;
	struct registry_value *value = NULL;
	uint32_t v;
	uint32_t increment;
	uint32_t newvalue;
	NTSTATUS status;
	WERROR werr;
	int ret = -1;

	if (argc < 2 || c->display_usage) {
		d_fprintf(stderr, "%s\n%s",
			  _("Usage:"),
			  _("net registry increment <key> <valuename> "
			    "[<increment>]\n"));
		goto done;
	}

	keyname = argv[0];
	valuename = argv[1];

	increment = 1;
	if (argc == 3) {
		int error = 0;

		increment = smb_strtoul(
			argv[2], NULL, 10, &error, SMB_STR_STANDARD);
		if (error != 0) {
			goto done;
		}
	}

	ctx = g_lock_ctx_init(c, c->msg_ctx);
	if (ctx == NULL) {
		d_fprintf(stderr, _("g_lock_ctx_init failed\n"));
		goto done;
	}

	status = g_lock_lock(ctx,
			     lock_key,
			     G_LOCK_WRITE,
			     timeval_set(600, 0),
			     NULL,
			     NULL);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, _("g_lock_lock failed: %s\n"),
			  nt_errstr(status));
		goto done;
	}

	werr = open_key(c, keyname, REG_KEY_READ|REG_KEY_WRITE, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("open_key failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}

	werr = reg_queryvalue(key, key, valuename, &value);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("reg_queryvalue failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}

	if (value->type != REG_DWORD) {
		d_fprintf(stderr, _("value not a DWORD: %s\n"),
			  str_regtype(value->type));
		goto done;
	}

	if (value->data.length < 4) {
		d_fprintf(stderr, _("value too short for regular DWORD\n"));
		goto done;
	}

	v = IVAL(value->data.data, 0);
	v += increment;
	newvalue = v;

	SIVAL(value->data.data, 0, v);

	werr = reg_setvalue(key, valuename, value);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("reg_setvalue failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}

	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("increment failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}

	g_lock_unlock(ctx, lock_key);

	d_printf(_("%"PRIu32"\n"), newvalue);

	ret = 0;

done:
	TALLOC_FREE(value);
	TALLOC_FREE(key);
	TALLOC_FREE(ctx);
	return ret;
}

static int net_registry_deletevalue(struct net_context *c, int argc,
				    const char **argv)
{
	WERROR werr;
	struct registry_key *key = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	int ret = -1;

	if (argc != 2 || c->display_usage) {
		d_fprintf(stderr, "%s\n%s",
			  _("Usage:"),
			  _("net registry deletevalue <key> <valuename>\n"));
		goto done;
	}

	werr = open_key(ctx, argv[0], REG_KEY_WRITE, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("open_key failed: %s\n"), win_errstr(werr));
		goto done;
	}

	werr = reg_deletevalue(key, argv[1]);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("reg_deletevalue failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

static WERROR net_registry_getsd_internal(struct net_context *c,
					  TALLOC_CTX *mem_ctx,
					  const char *keyname,
					  struct security_descriptor **sd)
{
	WERROR werr;
	struct registry_key *key = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	uint32_t access_mask = REG_KEY_READ |
			       SEC_FLAG_MAXIMUM_ALLOWED |
			       SEC_FLAG_SYSTEM_SECURITY;

	/*
	 * net_rpc_regsitry uses SEC_FLAG_SYSTEM_SECURITY, but access
	 * is denied with these perms right now...
	 */
	access_mask = REG_KEY_READ;

	if (sd == NULL) {
		d_fprintf(stderr, _("internal error: invalid argument\n"));
		werr = WERR_INVALID_PARAMETER;
		goto done;
	}

	if (strlen(keyname) == 0) {
		d_fprintf(stderr, _("error: zero length key name given\n"));
		werr = WERR_INVALID_PARAMETER;
		goto done;
	}

	werr = open_key(ctx, keyname, access_mask, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "%s%s\n", _("open_key failed: "),
			  win_errstr(werr));
		goto done;
	}

	werr = reg_getkeysecurity(mem_ctx, key, sd);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "%s%s\n", _("reg_getkeysecurity failed: "),
			  win_errstr(werr));
		goto done;
	}

	werr = WERR_OK;

done:
	TALLOC_FREE(ctx);
	return werr;
}

static int net_registry_getsd(struct net_context *c, int argc,
			      const char **argv)
{
	WERROR werr;
	int ret = -1;
	struct security_descriptor *secdesc = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();

	if (argc != 1 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net registry getsd <path>\n"));
		d_printf("%s\n%s",
			 _("Example:"),
			 _("net registry getsd 'HKLM\\Software\\Samba'\n"));
		goto done;
	}

	werr = net_registry_getsd_internal(c, ctx, argv[0], &secdesc);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	display_sec_desc(secdesc);

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

static int net_registry_getsd_sddl(struct net_context *c,
				   int argc, const char **argv)
{
	WERROR werr;
	int ret = -1;
	struct security_descriptor *secdesc = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();

	if (argc != 1 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net registry getsd_sddl <path>\n"));
		d_printf("%s\n%s",
			 _("Example:"),
			 _("net registry getsd_sddl 'HKLM\\Software\\Samba'\n"));
		goto done;
	}

	werr = net_registry_getsd_internal(c, ctx, argv[0], &secdesc);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	d_printf("%s\n", sddl_encode(ctx, secdesc, get_global_sam_sid()));

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

static WERROR net_registry_setsd_internal(struct net_context *c,
					  TALLOC_CTX *mem_ctx,
					  const char *keyname,
					  struct security_descriptor *sd)
{
	WERROR werr;
	struct registry_key *key = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	uint32_t access_mask = REG_KEY_WRITE |
			       SEC_FLAG_MAXIMUM_ALLOWED |
			       SEC_FLAG_SYSTEM_SECURITY;

	/*
	 * net_rpc_regsitry uses SEC_FLAG_SYSTEM_SECURITY, but access
	 * is denied with these perms right now...
	 */
	access_mask = REG_KEY_WRITE;

	if (strlen(keyname) == 0) {
		d_fprintf(stderr, _("error: zero length key name given\n"));
		werr = WERR_INVALID_PARAMETER;
		goto done;
	}

	werr = open_key(ctx, keyname, access_mask, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "%s%s\n", _("open_key failed: "),
			  win_errstr(werr));
		goto done;
	}

	werr = reg_setkeysecurity(key, sd);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "%s%s\n", _("reg_setkeysecurity failed: "),
			  win_errstr(werr));
		goto done;
	}

	werr = WERR_OK;

done:
	TALLOC_FREE(ctx);
	return werr;
}

static int net_registry_setsd_sddl(struct net_context *c,
				   int argc, const char **argv)
{
	WERROR werr;
	int ret = -1;
	struct security_descriptor *secdesc = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();

	if (argc != 2 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net registry setsd_sddl <path> <security_descriptor>\n"));
		d_printf("%s\n%s",
			 _("Example:"),
			 _("net registry setsd_sddl 'HKLM\\Software\\Samba'\n"));
		goto done;
	}

	secdesc = sddl_decode(ctx, argv[1], get_global_sam_sid());
	if (secdesc == NULL) {
		goto done;
	}

	werr = net_registry_setsd_internal(c, ctx, argv[0], secdesc);
	if (!W_ERROR_IS_OK(werr)) {
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(ctx);
	return ret;
}

/******************************************************************************/
/**
 * @defgroup net_registry net registry
 */

/**
 * @defgroup net_registry_import Import
 * @ingroup net_registry
 * @{
 */

struct import_ctx {
	TALLOC_CTX *mem_ctx;
};


static WERROR import_create_key(struct import_ctx *ctx,
				struct registry_key *parent,
				const char *name, void **pkey, bool *existing)
{
	WERROR werr;
	TALLOC_CTX *mem_ctx = talloc_new(ctx->mem_ctx);

	struct registry_key *key = NULL;
	enum winreg_CreateAction action;

	if (parent == NULL) {
		char *subkeyname = NULL;
		werr = open_hive(mem_ctx, name, REG_KEY_WRITE,
			 &parent, &subkeyname);
		if (!W_ERROR_IS_OK(werr)) {
			d_fprintf(stderr, _("open_hive failed: %s\n"),
				  win_errstr(werr));
			goto done;
		}
		name = subkeyname;
	}

	action = REG_ACTION_NONE;
	werr = reg_createkey(mem_ctx, parent, name, REG_KEY_WRITE,
			     &key, &action);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("reg_createkey failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}

	if (action == REG_ACTION_NONE) {
		d_fprintf(stderr, _("createkey did nothing -- huh?\n"));
		werr = WERR_CREATE_FAILED;
		goto done;
	}

	if (existing != NULL) {
		*existing = (action == REG_OPENED_EXISTING_KEY);
	}

	if (pkey!=NULL) {
		*pkey = talloc_steal(ctx->mem_ctx, key);
	}

done:
	talloc_free(mem_ctx);
	return werr;
}

static WERROR import_close_key(struct import_ctx *ctx,
			       struct registry_key *key)
{
	return WERR_OK;
}

static WERROR import_delete_key(struct import_ctx *ctx,
				struct registry_key *parent, const char *name)
{
	WERROR werr;
	TALLOC_CTX *mem_ctx = talloc_new(talloc_tos());

	if (parent == NULL) {
		char *subkeyname = NULL;
		werr = open_hive(mem_ctx, name, REG_KEY_WRITE,
			 &parent, &subkeyname);
		if (!W_ERROR_IS_OK(werr)) {
			d_fprintf(stderr, _("open_hive failed: %s\n"),
				  win_errstr(werr));
			goto done;
		}
		name = subkeyname;
	}

	werr = reg_deletekey_recursive(parent, name);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, "reg_deletekey_recursive %s: %s\n",
			  _("failed"), win_errstr(werr));
		goto done;
	}

done:
	talloc_free(mem_ctx);
	return werr;
}

static WERROR import_create_val (struct import_ctx *ctx,
				 struct registry_key *parent, const char *name,
				 const struct registry_value *value)
{
	WERROR werr;

	if (parent == NULL) {
		return WERR_INVALID_PARAMETER;
	}

	werr = reg_setvalue(parent, name, value);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("reg_setvalue failed: %s\n"),
			  win_errstr(werr));
	}
	return werr;
}

static WERROR import_delete_val (struct import_ctx *ctx,
				 struct registry_key *parent, const char *name)
{
	WERROR werr;

	if (parent == NULL) {
		return WERR_INVALID_PARAMETER;
	}

	werr = reg_deletevalue(parent, name);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("reg_deletevalue failed: %s\n"),
			  win_errstr(werr));
	}

	return werr;
}

struct precheck_ctx {
	TALLOC_CTX *mem_ctx;
	bool failed;
};

static WERROR precheck_create_key(struct precheck_ctx *ctx,
				  struct registry_key *parent,
				  const char *name, void **pkey, bool *existing)
{
	WERROR werr;
	TALLOC_CTX *frame = talloc_stackframe();
	struct registry_key *key = NULL;

	if (parent == NULL) {
		char *subkeyname = NULL;
		werr = open_hive(frame, name, REG_KEY_READ,
				 &parent, &subkeyname);
		if (!W_ERROR_IS_OK(werr)) {
			d_printf("Precheck: open_hive of [%s] failed: %s\n",
				 name, win_errstr(werr));
			goto done;
		}
		name = subkeyname;
	}

	werr = reg_openkey(frame, parent, name, 0, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_printf("Precheck: openkey [%s] failed: %s\n",
			 name, win_errstr(werr));
		goto done;
	}

	if (existing != NULL) {
		*existing = true;
	}

	if (pkey != NULL) {
		*pkey = talloc_steal(ctx->mem_ctx, key);
	}

done:
	talloc_free(frame);
	ctx->failed = !W_ERROR_IS_OK(werr);
	return werr;
}

static WERROR precheck_close_key(struct precheck_ctx *ctx,
				 struct registry_key *key)
{
	talloc_free(key);
	return WERR_OK;
}

static WERROR precheck_delete_key(struct precheck_ctx *ctx,
				  struct registry_key *parent, const char *name)
{
	WERROR werr;
	TALLOC_CTX *frame = talloc_stackframe();
	struct registry_key *key;

	if (parent == NULL) {
		char *subkeyname = NULL;
		werr = open_hive(frame, name, REG_KEY_READ,
				 &parent, &subkeyname);
		if (!W_ERROR_IS_OK(werr)) {
			d_printf("Precheck: open_hive of [%s] failed: %s\n",
				 name, win_errstr(werr));
			goto done;
		}
		name = subkeyname;
	}

	werr = reg_openkey(ctx->mem_ctx, parent, name, 0, &key);
	if (W_ERROR_IS_OK(werr)) {
		d_printf("Precheck: key [%s\\%s] should not exist\n",
			 parent->key->name, name);
		werr = WERR_FILE_EXISTS;
	} else if (W_ERROR_EQUAL(werr, WERR_FILE_NOT_FOUND)) {
		werr = WERR_OK;
	} else {
		d_printf("Precheck: openkey [%s\\%s] failed: %s\n",
			 parent->key->name, name, win_errstr(werr));
	}

done:
	talloc_free(frame);
	ctx->failed = !W_ERROR_IS_OK(werr);
	return werr;
}

static int registry_value_cmp(
	const struct registry_value* v1, const struct registry_value* v2)
{
	if (v1->type == v2->type) {
		return data_blob_cmp(&v1->data, &v2->data);
	}
	return v1->type - v2->type;
}

static WERROR precheck_create_val(struct precheck_ctx *ctx,
				  struct registry_key *parent,
				  const char *name,
				  const struct registry_value *value)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct registry_value *old;
	WERROR werr;

	SMB_ASSERT(parent);

	werr = reg_queryvalue(frame, parent, name, &old);
	if (!W_ERROR_IS_OK(werr)) {
		d_printf("Precheck: queryvalue \"%s\" of [%s] failed: %s\n",
			 name, parent->key->name, win_errstr(werr));
		goto done;
	}
	if (registry_value_cmp(value, old) != 0) {
		d_printf("Precheck: unexpected value \"%s\" of key [%s]\n",
			 name, parent->key->name);
		ctx->failed = true;
	}
done:
	talloc_free(frame);
	return werr;
}

static WERROR precheck_delete_val(struct precheck_ctx *ctx,
				  struct registry_key *parent,
				  const char *name)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct registry_value *old;
	WERROR werr;

	SMB_ASSERT(parent);

	werr = reg_queryvalue(frame, parent, name, &old);
	if (W_ERROR_IS_OK(werr)) {
		d_printf("Precheck: value \"%s\" of key [%s] should not exist\n",
			 name, parent->key->name);
		werr = WERR_FILE_EXISTS;
	} else if (W_ERROR_EQUAL(werr, WERR_FILE_NOT_FOUND)) {
		werr = WERR_OK;
	} else {
		printf("Precheck: queryvalue \"%s\" of key [%s] failed: %s\n",
		       name, parent->key->name, win_errstr(werr));
	}

	talloc_free(frame);
	ctx->failed = !W_ERROR_IS_OK(werr);
	return werr;
}

static bool import_precheck(const char *fname, const char *parse_options)
{
	TALLOC_CTX *mem_ctx = talloc_tos();
	struct precheck_ctx precheck_ctx = {
		.mem_ctx = mem_ctx,
		.failed = false,
	};
	struct reg_import_callback precheck_callback = {
		.openkey     = NULL,
		.closekey    = (reg_import_callback_closekey_t)&precheck_close_key,
		.createkey   = (reg_import_callback_createkey_t)&precheck_create_key,
		.deletekey   = (reg_import_callback_deletekey_t)&precheck_delete_key,
		.deleteval   = (reg_import_callback_deleteval_t)&precheck_delete_val,
		.setval      = {
			.registry_value = (reg_import_callback_setval_registry_value_t)
		                          &precheck_create_val,
		},
		.setval_type = REGISTRY_VALUE,
		.data        = &precheck_ctx
	};
	struct reg_parse_callback *parse_callback;
	int ret;

	if (!fname) {
		return true;
	}

	parse_callback = reg_import_adapter(mem_ctx, precheck_callback);
	if (parse_callback == NULL) {
		d_printf("talloc failed\n");
		return false;
	}

	ret = reg_parse_file(fname, parse_callback, parse_options);

	if (ret < 0 || precheck_ctx.failed) {
		d_printf("Precheck failed\n");
		return false;
	}
	return true;
}

static int import_with_precheck_action(const char *import_fname,
				       const char *precheck_fname,
				       const char *parse_options)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct import_ctx import_ctx = {
		.mem_ctx = frame,
	};
	struct reg_import_callback import_callback = {
		.openkey     = NULL,
		.closekey    = (reg_import_callback_closekey_t)&import_close_key,
		.createkey   = (reg_import_callback_createkey_t)&import_create_key,
		.deletekey   = (reg_import_callback_deletekey_t)&import_delete_key,
		.deleteval   = (reg_import_callback_deleteval_t)&import_delete_val,
		.setval      = {
			.registry_value = (reg_import_callback_setval_registry_value_t)
					  &import_create_val,
		},
		.setval_type = REGISTRY_VALUE,
		.data        = &import_ctx
	};
	struct reg_parse_callback *parse_callback;
	int ret = -1;
	bool precheck_ok;

	precheck_ok = import_precheck(precheck_fname, parse_options);
	if (!precheck_ok) {
		goto done;
	}

	parse_callback = reg_import_adapter(frame, import_callback);
	if (parse_callback == NULL) {
		d_printf("talloc failed\n");
		goto done;
	}

	ret = reg_parse_file(import_fname, parse_callback, parse_options);

done:
	talloc_free(frame);
	return ret;
}

static int net_registry_import(struct net_context *c, int argc,
			       const char **argv)
{
	const char *parse_options =  (argc > 1) ? argv[1] : NULL;
	int ret = -1;
	WERROR werr;

	if (argc < 1 || argc > 2 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net registry import <reg> [options]\n"));
		d_printf("%s\n%s",
			 _("Example:"),
			 _("net registry import file.reg enc=CP1252\n"));
		return -1;
	}

	werr = regdb_open();
	if (!W_ERROR_IS_OK(werr)) {
		d_printf("Failed to open regdb: %s\n", win_errstr(werr));
		return -1;
	}

	werr = regdb_transaction_start();
	if (!W_ERROR_IS_OK(werr)) {
		d_printf("Failed to start transaction on regdb: %s\n",
			 win_errstr(werr));
		goto done;
	}

	ret = import_with_precheck_action(argv[0], c->opt_precheck,
					  parse_options);

	if (ret < 0) {
		d_printf("Transaction canceled!\n");
		regdb_transaction_cancel();
		goto done;
	}

	SMB_ASSERT(ret == 0);

	if (c->opt_testmode) {
		d_printf("Testmode: not committing changes.\n");
		regdb_transaction_cancel();
		goto done;
	}

	werr = regdb_transaction_commit();
	if (!W_ERROR_IS_OK(werr)) {
		d_printf("Failed to commit transaction on regdb: %s\n",
			 win_errstr(werr));
		ret = -1;
	}

done:
	regdb_close();
	return ret;
}
/**@}*/

/******************************************************************************/

/**
 * @defgroup net_registry_export Export
 * @ingroup net_registry
 * @{
 */

static int registry_export(TALLOC_CTX *ctx, /*const*/ struct registry_key *key,
			   struct reg_format *f)
{
	int ret=-1;
	WERROR werr;
	uint32_t count;

	struct registry_value *valvalue = NULL;
	char *valname = NULL;

	char *subkey_name = NULL;
	NTTIME modtime = 0;

	reg_format_registry_key(f, key, false);

	/* print values */
	for (count = 0;
	     werr = reg_enumvalue(ctx, key, count, &valname, &valvalue),
		     W_ERROR_IS_OK(werr);
	     count++)
	{
		reg_format_registry_value(f, valname, valvalue);
	}
	if (!W_ERROR_EQUAL(WERR_NO_MORE_ITEMS, werr)) {
		d_fprintf(stderr, _("reg_enumvalue failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}

	/* recurse on subkeys */
	for (count = 0;
	     werr = reg_enumkey(ctx, key, count, &subkey_name, &modtime),
		     W_ERROR_IS_OK(werr);
	     count++)
	{
		struct registry_key *subkey = NULL;

		werr = reg_openkey(ctx, key, subkey_name, REG_KEY_READ,
				   &subkey);
		if (!W_ERROR_IS_OK(werr)) {
			d_fprintf(stderr, _("reg_openkey failed: %s\n"),
				  win_errstr(werr));
			goto done;
		}

		registry_export(ctx, subkey, f);
		TALLOC_FREE(subkey);
	}
	if (!W_ERROR_EQUAL(WERR_NO_MORE_ITEMS, werr)) {
		d_fprintf(stderr, _("reg_enumkey failed: %s\n"),
			  win_errstr(werr));
		goto done;
	}
	ret = 0;
done:
	return ret;
}

static int net_registry_export(struct net_context *c, int argc,
			       const char **argv)
{
	int ret=-1;
	WERROR werr;
	struct registry_key *key = NULL;
	TALLOC_CTX *ctx = talloc_stackframe();
	struct reg_format *f=NULL;

	if (argc < 2 || argc > 3 || c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net registry export <path> <file> [opt]\n"));
		d_printf("%s\n%s",
			 _("Example:"),
			 _("net registry export 'HKLM\\Software\\Samba' "
			   "samba.reg regedit5\n"));
		goto done;
	}

	werr = open_key(ctx, argv[0], REG_KEY_READ, &key);
	if (!W_ERROR_IS_OK(werr)) {
		d_fprintf(stderr, _("open_key failed: %s\n"), win_errstr(werr));
		goto done;
	}

	f = reg_format_file(ctx, argv[1], (argc > 2) ? argv[2] : NULL);
	if (f == NULL) {
		d_fprintf(stderr, _("open file failed: %s\n"), strerror(errno));
		goto done;
	}

	ret = registry_export(ctx, key, f);

done:
	TALLOC_FREE(ctx);
	return ret;
}
/**@}*/

/******************************************************************************/
/**
 * @defgroup net_registry_convert Convert
 * @ingroup net_registry
 * @{
 */

static int net_registry_convert(struct net_context *c, int argc,
			       const char **argv)
{
	int ret;
	TALLOC_CTX *mem_ctx;
	const char *in_opt  = NULL;
	const char *out_opt = NULL;

	if (argc < 2 || argc > 4|| c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net registry convert <in> <out> [in_opt] [out_opt]\n"
			   "net registry convert <in> <out> [out_opt]\n"));
		d_printf("%s\n%s",
			 _("Example:"),
			 _("net registry convert in.reg out.reg regedit4,enc=CP1252\n"));
		return -1;
	}

	mem_ctx = talloc_stackframe();

	switch (argc ) {
	case 2:
		break;
	case 3:
		out_opt = argv[2];
		break;
	case 4:
		out_opt = argv[3];
		in_opt  = argv[2];
		break;
	default:
		assert(false);
	}


	ret = reg_parse_file(argv[0], (struct reg_parse_callback*)
			     reg_format_file(mem_ctx, argv[1], out_opt),
			     in_opt);

	talloc_free(mem_ctx);

	return ret;
}
/**@}*/

static int net_registry_check(struct net_context *c, int argc,
			      const char **argv)
{
	char *dbfile;
	struct check_options opts;
	int ret;

	if (argc > 1|| c->display_usage) {
		d_printf("%s\n%s",
			 _("Usage:"),
			 _("net registry check  [-vraTfl] [-o <ODB>] [--wipe] [<TDB>]\n"
			   "  Check a registry database.\n"
			   "    -v|--verbose\t be verbose\n"
			   "    -r|--repair\t\t interactive repair mode\n"
			   "    -a|--auto\t\t noninteractive repair mode\n"
			   "    -T|--test\t\t dry run\n"
			   "    -f|--force\t\t force\n"
			   "    -l|--lock\t\t lock <TDB> while doing the check\n"
			   "    -o|--output=<ODB>\t output database\n"
			   "    --reg-version=n\t assume database format version {n|1,2,3}\n"
			   "    --wipe\t\t create a new database from scratch\n"
			   "    --db=<TDB>\t\t registry database to open\n"));
		return c->display_usage ? 0 : -1;
	}

	if (c->opt_db != NULL) {
		dbfile = talloc_strdup(talloc_tos(), c->opt_db);
	} else if (argc > 0) {
		dbfile = talloc_strdup(talloc_tos(), argv[0]);
	} else {
		dbfile = cache_path(talloc_tos(), "registry.tdb");
	}
	if (dbfile == NULL) {
		return -1;
	}

	opts = (struct check_options) {
		.lock = c->opt_lock || c->opt_long_list_entries,
		.test = c->opt_testmode,
		.automatic = c->opt_auto,
		.verbose = c->opt_verbose,
		.force = c->opt_force,
		.repair = c->opt_repair || c->opt_reboot,
		.version = c->opt_reg_version,
		.output  = c->opt_output,
		.wipe = c->opt_wipe,
		.implicit_db = (c->opt_db == NULL) && (argc == 0),
	};

	ret = net_registry_check_db(dbfile, &opts);
	talloc_free(dbfile);
	return ret;
}


/******************************************************************************/

int net_registry(struct net_context *c, int argc, const char **argv)
{
	int ret = -1;

	struct functable func[] = {
		{
			"enumerate",
			net_registry_enumerate,
			NET_TRANSPORT_LOCAL,
			N_("Enumerate registry keys and values"),
			N_("net registry enumerate\n"
			   "    Enumerate registry keys and values")
		},
		{
			"enumerate_recursive",
			net_registry_enumerate_recursive,
			NET_TRANSPORT_LOCAL,
			N_("Enumerate registry keys and values"),
			N_("net registry enumerate_recursive\n"
			   "    Enumerate registry keys and values")
		},
		{
			"createkey",
			net_registry_createkey,
			NET_TRANSPORT_LOCAL,
			N_("Create a new registry key"),
			N_("net registry createkey\n"
			   "    Create a new registry key")
		},
		{
			"deletekey",
			net_registry_deletekey,
			NET_TRANSPORT_LOCAL,
			N_("Delete a registry key"),
			N_("net registry deletekey\n"
			   "    Delete a registry key")
		},
		{
			"deletekey_recursive",
			net_registry_deletekey_recursive,
			NET_TRANSPORT_LOCAL,
			N_("Delete a registry key with subkeys"),
			N_("net registry deletekey_recursive\n"
			   "    Delete a registry key with subkeys")
		},
		{
			"getvalue",
			net_registry_getvalue,
			NET_TRANSPORT_LOCAL,
			N_("Print a registry value"),
			N_("net registry getvalue\n"
			   "    Print a registry value")
		},
		{
			"getvalueraw",
			net_registry_getvalueraw,
			NET_TRANSPORT_LOCAL,
			N_("Print a registry value (raw format)"),
			N_("net registry getvalueraw\n"
			   "    Print a registry value (raw format)")
		},
		{
			"getvaluesraw",
			net_registry_getvaluesraw,
			NET_TRANSPORT_LOCAL,
			"Print all values of a key in raw format",
			"net registry getvaluesraw <key>\n"
			"    Print a registry value (raw format)"
		},
		{
			"setvalue",
			net_registry_setvalue,
			NET_TRANSPORT_LOCAL,
			N_("Set a new registry value"),
			N_("net registry setvalue\n"
			   "    Set a new registry value")
		},
		{
			"increment",
			net_registry_increment,
			NET_TRANSPORT_LOCAL,
			N_("Increment a DWORD registry value under a lock"),
			N_("net registry increment\n"
			   "    Increment a DWORD registry value under a lock")
		},
		{
			"deletevalue",
			net_registry_deletevalue,
			NET_TRANSPORT_LOCAL,
			N_("Delete a registry value"),
			N_("net registry deletevalue\n"
			   "    Delete a registry value")
		},
		{
			"getsd",
			net_registry_getsd,
			NET_TRANSPORT_LOCAL,
			N_("Get security descriptor"),
			N_("net registry getsd\n"
			   "    Get security descriptor")
		},
		{
			"getsd_sddl",
			net_registry_getsd_sddl,
			NET_TRANSPORT_LOCAL,
			N_("Get security descriptor in sddl format"),
			N_("net registry getsd_sddl\n"
			   "    Get security descriptor in sddl format")
		},
		{
			"setsd_sddl",
			net_registry_setsd_sddl,
			NET_TRANSPORT_LOCAL,
			N_("Set security descriptor from sddl format string"),
			N_("net registry setsd_sddl\n"
			   "    Set security descriptor from sddl format string")
		},
		{
			"import",
			net_registry_import,
			NET_TRANSPORT_LOCAL,
			N_("Import .reg file"),
			N_("net registry import\n"
			   "    Import .reg file")
		},
		{
			"export",
			net_registry_export,
			NET_TRANSPORT_LOCAL,
			N_("Export .reg file"),
			N_("net registry export\n"
			   "    Export .reg file")
		},
		{
			"convert",
			net_registry_convert,
			NET_TRANSPORT_LOCAL,
			N_("Convert .reg file"),
			N_("net registry convert\n"
			   "    Convert .reg file")
		},
		{
			"check",
			net_registry_check,
			NET_TRANSPORT_LOCAL,
			N_("Check a registry database"),
			N_("net registry check\n"
			   "    Check a registry database")
		},
	{ NULL, NULL, 0, NULL, NULL }
	};

	if (!c->display_usage
	    && argc > 0
	    && (strcasecmp_m(argv[0], "convert") != 0)
	    && (strcasecmp_m(argv[0], "check") != 0))
	{
		if (!W_ERROR_IS_OK(registry_init_basic())) {
			return -1;
		}
	}

	ret = net_run_function(c, argc, argv, "net registry", func);

	return ret;
}

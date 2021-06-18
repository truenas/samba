/*
 *  Samba Unix/Linux SMB client library
 *  Distributed SMB/CIFS Server Management Utility
 *  Local configuration interface
 *  Copyright (C) Michael Adam 2007-2008
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

/*
 * This is an interface to Samba's configuration as made available
 * by the libsmbconf interface (source/lib/smbconf/smbconf.c).
 *
 * This currently supports local interaction with the configuration
 * stored in the registry. But other backends and remote access via
 * rpc might get implemented in the future.
 */

#include "includes.h"
#include "system/filesys.h"
#include "utils/net.h"
#include "utils/net_conf_util.h"
#include "lib/smbconf/smbconf.h"
#include "lib/smbconf/smbconf_init.h"
#include "lib/smbconf/smbconf_reg.h"
#include "lib/param/loadparm.h"

#ifdef HAVE_JANSSON
#include <jansson.h>
#include "audit_logging.h"
#define JS_MAJ_VER      0
#define JS_MIN_VER      1
#endif /* HAVE_JANSSON */


/**********************************************************************
 *
 * usage functions
 *
 **********************************************************************/
static const char *json_sample(void) {
	return \
	"\t{\n"
	"\t  \"service\": \"share\",\n"
	"\t  \"parameters\": {\n"
	"\t    \"vfs objects\": {\n"
	"\t      \"raw\": \"streams_xattr zfsacl\",\n"
	"\t      \"parsed\": \"streams_xattr zfsacl\"\n"
	"\t    },\n"
	"\t    \"read only\": {\n"
	"\t      \"raw\": \"true\",\n"
	"\t      \"parsed\": true\n"
	"\t    },\n"
	"\t    \"path\": {\n"
	"\t      \"raw\": \"/tank\",\n"
	"\t      \"parsed\": \"/tank\"\n"
	"\t    }\n"
	"\t  }\n"
	"\t}";
}


static int net_conf_list_usage(struct net_context *c, int argc,
			       const char **argv)
{
	d_printf("%s net conf list\n", _("Usage:"));
	return -1;
}

static int net_conf_import_usage(struct net_context *c, int argc,
				 const char**argv)
{
	d_printf("%s\n%s",
		 _("Usage:"),
		 _(" net conf import [--test|-T] <filename> "
		   "[<servicename>]\n"
		   "\t[--test|-T]    testmode - do not act, just print "
			"what would be done\n"
		   "\t<servicename>  only import service <servicename>, "
			"ignore the rest\n"));
	return -1;
}

static int net_conf_listshares_usage(struct net_context *c, int argc,
				     const char **argv)
{
	d_printf("%s\nnet conf listshares\n", _("Usage:"));
	return -1;
}

static int net_conf_drop_usage(struct net_context *c, int argc,
			       const char **argv)
{
	d_printf("%s\nnet conf drop\n", _("Usage:"));
	return -1;
}

static int net_conf_showshare_usage(struct net_context *c, int argc,
				    const char **argv)
{
	d_printf("%s\n%s",
		 _("Usage:"),
		 _("net conf showshare <sharename>\n"));
	return -1;
}

static int net_conf_addshare_json_usage(struct net_context *c, int argc,
					const char **argv)
{
	d_printf("%s\n%s\n%s\n",
		 _("Usage:"),
		 _(" net --json conf addshare  '{\"service\": \"SHARE\", "
		   "\"parameters\": {\"path\": {\"raw\": \"/tank\"}}}'\n"
		   " Multiple parameters may be set in one command. \"raw\" "
		   " values take precedence over typed \"parsed\" values. \n"
		   " \"path\" key is required. \n\n"
		   "\tsample service definition:"),
		 json_sample());
	return -1;
}

static int net_conf_addshare_usage(struct net_context *c, int argc,
				   const char **argv)
{
	d_printf("%s\n%s",
		 _("Usage:"),
		 _(" net conf addshare <sharename> <path> "
		   "[writeable={y|N} [guest_ok={y|N} [<comment>]]]\n"
		   "\t<sharename>      the new share name.\n"
		   "\t<path>           the path on the filesystem to export.\n"
		   "\twriteable={y|N}  set \"writeable to \"yes\" or "
		   "\"no\" (default) on this share.\n"
		   "\tguest_ok={y|N}   set \"guest ok\" to \"yes\" or "
		   "\"no\" (default)   on this share.\n"
		   "\t<comment>        optional comment for the new share.\n"));
	return -1;
}

static int net_conf_delshare_usage(struct net_context *c, int argc,
				   const char **argv)
{
	d_printf("%s\n%s",
		 _("Usage:"),
		 _("net conf delshare <sharename>\n"));
	return -1;
}

static int net_conf_setparm_json_usage(struct net_context *c, int argc,
				       const char **argv)
{
	d_printf("%s\n%s\n%s\n",
		 _("Usage:"),
		 _(" net --json conf setparm  '{\"service\": \"SHARE\", "
		   "\"parameters\": {\"read only\": {\"parsed\": true}}}'\n"
		   " Multiple <parameters> may be set in one command. \"raw\" "
		   " values take precedence over typed \"parsed\" values.\n\n"
		   "\tsample service definition:"),
		 json_sample());
	return -1;
}

static int net_conf_setparm_usage(struct net_context *c, int argc,
				  const char **argv)
{
	d_printf("%s\n%s",
		 _("Usage:"),
		 _(" net conf setparm <section> <param> <value>\n"));
	return -1;
}

static int net_conf_getparm_usage(struct net_context *c, int argc,
				  const char **argv)
{
	d_printf("%s\n%s",
		 _("Usage:"),
		 _(" net conf getparm <section> <param>\n"));
	return -1;
}

static int net_conf_delparm_json_usage(struct net_context *c, int argc,
				       const char **argv)
{
	d_printf("%s\n%s\n%s\n",
		 _("Usage:"),
		 _(" net --json conf delparm  '{\"service\": \"SHARE\", "
		   "\"parameters\": {\"read only\": {}}}'\n"
		   " Multiple <parameters> may be deleted in one command."
		   " Values are not required."
		   "\tsample service definition:"),
		 json_sample());
	return -1;
}

static int net_conf_delparm_usage(struct net_context *c, int argc,
				  const char **argv)
{
	d_printf("%s\n%s",
		 _("Usage:"),
		 _(" net conf delparm <section> <param>\n"));
	return -1;
}

static int net_conf_getincludes_usage(struct net_context *c, int argc,
				      const char **argv)
{
	d_printf("%s\n%s",
		 _("Usage:"),
		 _(" net conf getincludes <section>\n"));
	return -1;
}

static int net_conf_setincludes_usage(struct net_context *c, int argc,
				      const char **argv)
{
	d_printf("%s\n%s",
		 _("Usage:"),
		 _(" net conf setincludes <section> [<filename>]*\n"));
	return -1;
}

static int net_conf_delincludes_usage(struct net_context *c, int argc,
				      const char **argv)
{
	d_printf("%s\n%s",
		_("Usage:"),
		_(" net conf delincludes <section>\n"));
	return -1;
}


/**********************************************************************
 *
 * Helper functions
 *
 **********************************************************************/

/**
 * This functions process a service previously loaded with libsmbconf.
 */
static sbcErr import_process_service(struct net_context *c,
				     struct smbconf_ctx *conf_ctx,
				     struct smbconf_service *service)
{
	sbcErr err = SBC_ERR_OK;

	if (c->opt_testmode) {
		uint32_t idx;
		const char *indent = "";
		if (service->name != NULL) {
			d_printf("[%s]\n", service->name);
			indent = "\t";
		}
		for (idx = 0; idx < service->num_params; idx++) {
			d_printf("%s%s = %s\n", indent,
				 service->param_names[idx],
				 service->param_values[idx]);
		}
		d_printf("\n");
		goto done;
	}

	if (smbconf_share_exists(conf_ctx, service->name)) {
		err = smbconf_delete_share(conf_ctx, service->name);
		if (!SBC_ERROR_IS_OK(err)) {
			goto done;
		}
	}

	err = smbconf_create_set_share(conf_ctx, service);

done:
	return err;
}

#ifdef HAVE_JANSSON

/*
 * Convert JSON parameter to string. Precedence granted to raw values.
 */
static bool json_value_string(TALLOC_CTX *mem_ctx, json_t *param, char **value)
{
	json_t *parsed = NULL, *raw= NULL;
	char *out = NULL;
	double v_double;
	int v_int;
	const char *v_string = NULL;

	raw = json_object_get(param, "raw");
	if ((raw != NULL) && json_is_string(raw)) {
		v_string = json_string_value(raw);
		out = talloc_strdup(mem_ctx, v_string);
		*value = out;
		return true;
	}

	parsed = json_object_get(param, "parsed");
	if (parsed == NULL) {
		return false;
	}

	switch(json_typeof(parsed)) {
	case JSON_STRING:
		v_string = json_string_value(parsed);
		out = talloc_strdup(mem_ctx, v_string);
		break;
	case JSON_INTEGER:
		v_int = json_integer_value(parsed);
		out = talloc_asprintf(mem_ctx, "%d", v_int);
		break;
	case JSON_TRUE:
		out = talloc_strdup(mem_ctx, "true");
		break;
	case JSON_FALSE:
		out = talloc_strdup(mem_ctx, "false");
		break;
	case JSON_REAL:
		v_double = json_real_value(parsed);
		out = talloc_asprintf(mem_ctx, "%f", v_double);
		break;
	case JSON_NULL:
		out = talloc_strdup(mem_ctx, "");
		break;
	case JSON_OBJECT:
	case JSON_ARRAY:
		d_fprintf(stderr, _("Invalid JSON type: %d\n"),
			  json_typeof(parsed));
		return false;
	default:
		d_fprintf(stderr, _("Unknown JSON type: %d\n"),
			  json_typeof(parsed));
		return false;
	}

	*value = out;
	return true;
}


/*
 * Attempt to convert raw text value into JSON type.
 * Fall through to string.
 */
static bool add_parsed(struct json_object *param,
		       const char *name,
		       const char *value)
{
	int error;
	long val;
	char *endptr = NULL;
	bool ok, bool_val;

	ok = conv_str_bool(value, &bool_val);
	if (ok) {
		error = json_add_bool(param, "parsed", bool_val);
		if (error) {
			return false;
		}
		return true;
	}

	val = strtol(value, &endptr, 0);
	if ((endptr != value) && (*endptr == '\0')) {
		error = json_add_int(param, "parsed", val);
		if (error) {
			return false;
		}
		return true;
	}

	error = json_add_string(param, "parsed", value);
	if (error) {
		return false;
	}

	return true;
}

/*
 * Very basic conversion of key/value pair into JSON object.
 * JSON object structered as follows:
 * {
 *     "raw":    <parameter value as string>,
 *     "parsed": <typed parameter value>
 * }
 */
static bool param_to_json(struct json_object *param,
			  const char *name,
			  const char *value)
{
	int error;
	bool ok;

	error = json_add_string(param, "raw", value);
	if (error) {
		return false;
	}

	ok = add_parsed(param, name, value);
	if (!ok) {
		return false;
	}

	return true;
}

static bool service_to_json(struct smbconf_service *service,
			    struct json_object *share)
{
	struct json_object params;
	uint32_t param_count;
	int error;
	bool is_share = true;

	if (json_is_invalid(share)) {
		return false;
	}

	params = json_new_object();
	if (json_is_invalid(&params)) {
		return false;
	}

	error = json_add_string(share, "service", service->name);
	if (error) {
		goto fail;
	}

	if (strequal(service->name, GLOBAL_NAME)) {
		is_share = false;
	}

	error = json_add_bool(share, "is_share", is_share);
	if (error) {
		goto fail;
	}

	for (param_count = 0;
	     param_count < service->num_params;
	     param_count++) {
		struct json_object param;
		bool ok;
		const char *key = service->param_names[param_count];
		const char *val = service->param_values[param_count];

		param = json_new_object();
		if (json_is_invalid(&param)) {
			goto fail;
		}

		ok = param_to_json(&param, key, val);
		if (!ok) {
			json_free(&param);
			goto fail;
		}

		error = json_add_object(&params, key, &param);
		if (error) {
			goto fail;
		}
	}

	error = json_add_object(share, "parameters", &params);
	if (error) {
		goto fail;
	}

	return true;

fail:
	json_free(&params);
	return false;
}

struct batch_json_state {
	TALLOC_CTX *mem_ctx;
	struct smbconf_ctx *conf_ctx;
	const char *service;
	bool(*fn)(const char *key, struct json_object *parameter,
	     void *private_data);
};

static bool set_json_parameter(const char *key,
			       struct json_object *parameter,
			       void *private_data)
{
	char *value = NULL;
	bool ok;
	sbcErr err;
	struct batch_json_state *state = NULL;

	state = talloc_get_type_abort(private_data, struct batch_json_state);

	ok = json_value_string(state->mem_ctx, parameter->root, &value);
	if (!ok) {
		d_fprintf(stderr, _("malformed JSON for parameter value\n"));
		return false;
	}

	err = smbconf_set_parameter(state->conf_ctx,
				    state->service,
				    key, value);
	if (!SBC_ERROR_IS_OK(err)) {
		d_fprintf(stderr, _("Error setting parameter %s to %s: %s\n"),
			  key, value,  sbcErrorString(err));
		TALLOC_FREE(value);
		return false;
	}
	TALLOC_FREE(value);
	return true;
}

static bool del_json_parameter(const char *key,
			       struct json_object *parameter,
			       void *private_data)
{
	sbcErr err;

	struct batch_json_state *state = NULL;

	state = talloc_get_type_abort(private_data, struct batch_json_state);

	err = smbconf_delete_parameter(state->conf_ctx,
				       state->service,
				       key);
	if (!SBC_ERROR_IS_OK(err)) {
		d_fprintf(stderr, _("Error deleting parameter %s: %s\n"),
			  key,  sbcErrorString(err));
		return false;
	}

	return true;
}

/*
 * This applies a list of parameters for a service
 * by calling the json object iterator for the parameter list
 */
static bool apply_json_parameter(int idx,
				 struct json_object *service,
				 void *private_data)
{
	int error;
	const char *sharename = NULL;
	struct batch_json_state *state = NULL;
	struct json_object parameters;

	state = talloc_get_type_abort(private_data, struct batch_json_state);

	error = json_get_string_value(service, "service", &sharename);
	if (error) {
		return false;
	}

	state->service = sharename;
	parameters = json_get_object(service, "parameters");
	if (json_is_invalid(&parameters)) {
		return false;
	}

	error = iter_json_object(&parameters, state->fn, state);
	if (error) {
		return false;
	}
	return true;
}

/*
 * transaction should be started prior to calling this function.
 *
 * json data will be something like as follows:
 * { "SET": [ { <JSON Service Object> }, ... ],
 *   "DEL": [ { <JSON Service Object> }, ... ] }
 *
 * This allows batch processing of multiple share configurations to multiple
 * shares at once. It does not add or remove shares. SET is processed prior to
 *  DEL. Transaction shou.
 */
static bool batch_apply_json_parameters(TALLOC_CTX *mem_ctx,
					struct smbconf_ctx *conf_ctx,
					struct json_object *jsdata)
{
	struct json_object to_set, to_del;
	int error;
	struct batch_json_state *state = NULL;

	state = talloc_zero(mem_ctx, struct batch_json_state);
	state->mem_ctx = mem_ctx;
	state->conf_ctx = conf_ctx;

	to_set = json_get_array(jsdata, "SET");
	if (!json_is_invalid(&to_set)) {
		state->fn = set_json_parameter;
		error = iter_json_array(&to_set, apply_json_parameter, state);
		if (error) {
			return false;
		}
	}

	to_del = json_get_array(jsdata, "DEL");
	if (!json_is_invalid(&to_del)) {
		state->fn = del_json_parameter;
		error = iter_json_array(&to_del, apply_json_parameter, state);
		if (error) {
			return false;
		}
	}

	return true;
}

#endif /* HAVE_JANSSON */


/**********************************************************************
 *
 * the main conf functions
 *
 **********************************************************************/
static int net_conf_list_json(struct net_context *c, struct smbconf_ctx *conf_ctx,
			 int argc, const char **argv)
{
#ifdef HAVE_JANSSON
	sbcErr err;
	int ret = -1, error;
	TALLOC_CTX *mem_ctx;
	uint32_t num_shares;
	uint32_t share_count;
	struct smbconf_service **shares = NULL;
	struct json_object jsobj, js_shares;
	char *output = NULL;

	jsobj = json_new_object();
	if (json_is_invalid(&jsobj)) {
		goto done;
	}

	js_shares = json_new_array();
	if (json_is_invalid(&js_shares)) {
		json_free(&jsobj);
		goto done;
	}

	error = json_add_version(&jsobj, JS_MAJ_VER, JS_MIN_VER);
	if (error) {
		goto fail;
	}

	mem_ctx = talloc_stackframe();

	if (argc != 0 || c->display_usage) {
		net_conf_list_usage(c, argc, argv);
		goto done;
	}

	err = smbconf_get_config(conf_ctx, mem_ctx, &num_shares, &shares);
	if (!SBC_ERROR_IS_OK(err)) {
		d_fprintf(stderr, _("Error getting config: %s\n"),
			  sbcErrorString(err));
		goto done;
	}

	for (share_count = 0; share_count < num_shares; share_count++) {
		struct json_object share;
		bool ok;

		share = json_new_object();
		if (json_is_invalid(&share)) {
			goto fail;
		}

		ok = service_to_json(shares[share_count], &share);
		if (!ok) {
			json_free(&share);
			goto fail;
		}

		error = json_add_object(&js_shares, NULL, &share);
		if (error) {
			goto fail;
		}
	}

	error = json_add_object(&jsobj, "sections", &js_shares);
	if (error) {
		json_free(&jsobj);
		goto done;
	}

	output = json_to_string(mem_ctx, &jsobj);
	printf("%s\n", output);

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
fail:
	json_free(&jsobj);
	json_free(&js_shares);
	TALLOC_FREE(mem_ctx);
	return ret;
#else
	return -1;
#endif /* HAVE_JANSSON */
}

static int net_conf_list(struct net_context *c, struct smbconf_ctx *conf_ctx,
			 int argc, const char **argv)
{
	sbcErr err;
	int ret = -1;
	TALLOC_CTX *mem_ctx;
	uint32_t num_shares;
	uint32_t share_count, param_count;
	struct smbconf_service **shares = NULL;

	mem_ctx = talloc_stackframe();

	if (argc != 0 || c->display_usage) {
		net_conf_list_usage(c, argc, argv);
		goto done;
	}

	err = smbconf_get_config(conf_ctx, mem_ctx, &num_shares, &shares);
	if (!SBC_ERROR_IS_OK(err)) {
		d_fprintf(stderr, _("Error getting config: %s\n"),
			  sbcErrorString(err));
		goto done;
	}

	for (share_count = 0; share_count < num_shares; share_count++) {
		const char *indent = "";
		if (shares[share_count]->name != NULL) {
			d_printf("[%s]\n", shares[share_count]->name);
			indent = "\t";
		}
		for (param_count = 0;
		     param_count < shares[share_count]->num_params;
		     param_count++)
		{
			d_printf("%s%s = %s\n",
				 indent,
				 shares[share_count]->param_names[param_count],
				 shares[share_count]->param_values[param_count]);
		}
		d_printf("\n");
	}

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_conf_import(struct net_context *c, struct smbconf_ctx *conf_ctx,
			   int argc, const char **argv)
{
	int ret = -1;
	const char *filename = NULL;
	const char *servicename = NULL;
	char *conf_source = NULL;
	TALLOC_CTX *mem_ctx;
	struct smbconf_ctx *txt_ctx;
	sbcErr err;

	if (c->display_usage)
		return net_conf_import_usage(c, argc, argv);

	mem_ctx = talloc_stackframe();

	switch (argc) {
		case 0:
		default:
			net_conf_import_usage(c, argc, argv);
			goto done;
		case 2:
			servicename = talloc_strdup(mem_ctx, argv[1]);
			if (servicename == NULL) {
				d_printf(_("error: out of memory!\n"));
				goto done;
			}

			FALL_THROUGH;
		case 1:
			filename = argv[0];
			break;
	}

	DEBUG(3,("net_conf_import: reading configuration from file %s.\n",
		filename));

	conf_source = talloc_asprintf(mem_ctx, "file:%s", filename);
	if (conf_source == NULL) {
		d_printf(_("error: out of memory!\n"));
		goto done;
	}

	err = smbconf_init(mem_ctx, &txt_ctx, conf_source);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf(_("error loading file '%s': %s\n"), filename,
			 sbcErrorString(err));
		goto done;
	}

	if (c->opt_testmode) {
		d_printf(_("\nTEST MODE - "
			 "would import the following configuration:\n\n"));
	}

	if (servicename != NULL) {
		struct smbconf_service *service = NULL;

		err = smbconf_get_share(txt_ctx, mem_ctx,
					servicename,
					&service);
		if (!SBC_ERROR_IS_OK(err)) {
			goto cancel;
		}

		err = smbconf_transaction_start(conf_ctx);
		if (!SBC_ERROR_IS_OK(err)) {
			d_printf(_("error starting transaction: %s\n"),
				 sbcErrorString(err));
			goto done;
		}

		err = import_process_service(c, conf_ctx, service);
		if (!SBC_ERROR_IS_OK(err)) {
			d_printf(_("error importing service %s: %s\n"),
				 servicename, sbcErrorString(err));
			goto cancel;
		}
	} else {
		struct smbconf_service **services = NULL;
		uint32_t num_shares, sidx;

		err = smbconf_get_config(txt_ctx, mem_ctx,
					  &num_shares,
					  &services);
		if (!SBC_ERROR_IS_OK(err)) {
			goto cancel;
		}
		if (!c->opt_testmode) {
			if (!SBC_ERROR_IS_OK(smbconf_drop(conf_ctx))) {
				goto cancel;
			}
		}

		/*
		 * Wrap the importing of shares into a transaction,
		 * but only 100 at a time, in order to save memory.
		 * The allocated memory accumulates across the actions
		 * within the transaction, and for me, some 1500
		 * imported shares, the MAX_TALLOC_SIZE of 256 MB
		 * was exceeded.
		 */
		err = smbconf_transaction_start(conf_ctx);
		if (!SBC_ERROR_IS_OK(err)) {
			d_printf(_("error starting transaction: %s\n"),
				 sbcErrorString(err));
			goto done;
		}

		for (sidx = 0; sidx < num_shares; sidx++) {
			err = import_process_service(c, conf_ctx,
						     services[sidx]);
			if (!SBC_ERROR_IS_OK(err)) {
				d_printf(_("error importing service %s: %s\n"),
					 services[sidx]->name,
					 sbcErrorString(err));
				goto cancel;
			}

			if (sidx % 100) {
				continue;
			}

			err = smbconf_transaction_commit(conf_ctx);
			if (!SBC_ERROR_IS_OK(err)) {
				d_printf(_("error committing transaction: "
					   "%s\n"),
					 sbcErrorString(err));
				goto done;
			}
			err = smbconf_transaction_start(conf_ctx);
			if (!SBC_ERROR_IS_OK(err)) {
				d_printf(_("error starting transaction: %s\n"),
					 sbcErrorString(err));
				goto done;
			}
		}
	}

	err = smbconf_transaction_commit(conf_ctx);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf(_("error committing transaction: %s\n"),
			 sbcErrorString(err));
	} else {
		ret = 0;
	}

	goto done;

cancel:
	err = smbconf_transaction_cancel(conf_ctx);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf(_("error cancelling transaction: %s\n"),
			 sbcErrorString(err));
	}

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}


static int net_conf_listshares_json(struct net_context *c,
				    struct smbconf_ctx *conf_ctx, int argc,
				    const char **argv)
{
#ifdef HAVE_JANSSON
	sbcErr err;
	int ret = -1, error;
	uint32_t count, num_shares = 0;
	char **share_names = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	struct json_object jsobj, jsarray;
	char *output = NULL;

	mem_ctx = talloc_stackframe();

	if (argc != 0 || c->display_usage) {
		net_conf_listshares_usage(c, argc, argv);
		goto done;
	}

	jsobj = json_new_object();
	if (json_is_invalid(&jsobj)) {
		d_fprintf(stderr, _("Failed to create JSON object.\n"));
		return -1;
	}

	jsarray = json_new_array();
	if (json_is_invalid(&jsarray)) {
		json_free(&jsobj);
		d_fprintf(stderr, _("Failed to create JSON object.\n"));
		return -1;
	}

	error = json_add_version(&jsobj, JS_MAJ_VER, JS_MIN_VER);
	if (error) {
		d_fprintf(stderr, _("Failed to add JSON version.\n"));
		goto fail;
	}

	err = smbconf_get_share_names(conf_ctx, mem_ctx, &num_shares,
				      &share_names);
	if (!SBC_ERROR_IS_OK(err)) {
		goto done;
	}

	for (count = 0; count < num_shares; count++)
	{
		struct json_object share;

		share = json_new_object();
		if (json_is_invalid(&share)) {
			d_fprintf(stderr, _("Failed to create JSON object.\n"));
			goto fail;
		}

		error = json_add_string(&share, "name",
					share_names[count]);
		if (error) {
			d_fprintf(stderr, _("Failed to add JSON string.\n"));
			json_free(&share);
			goto fail;
		}

		error = json_add_object(&jsarray, NULL, &share);
		if (error) {
			d_fprintf(stderr, _("Failed to add share to array.\n"));
			goto fail;
		}
	}

	error = json_add_object(&jsobj, "shares", &jsarray);
	if (error) {
		d_fprintf(stderr, _("Failed to add array to JSON object.\n"));
		json_free(&jsobj);
		return -1;
	}

	output = json_to_string(mem_ctx, &jsobj);
	if (output == NULL) {
		d_fprintf(stderr, _("Failed to generate JSON output.\n"));
		json_free(&jsobj);
		return -1;
	}

	printf("%s\n", output);
	json_free(&jsobj);

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
fail:
	json_free(&jsobj);
	json_free(&jsarray);
	TALLOC_FREE(mem_ctx);
#endif
	return -1;
}

static int net_conf_listshares(struct net_context *c,
			       struct smbconf_ctx *conf_ctx, int argc,
			       const char **argv)
{
	sbcErr err;
	int ret = -1;
	uint32_t count, num_shares = 0;
	char **share_names = NULL;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_stackframe();

	if (argc != 0 || c->display_usage) {
		net_conf_listshares_usage(c, argc, argv);
		goto done;
	}

	err = smbconf_get_share_names(conf_ctx, mem_ctx, &num_shares,
				      &share_names);
	if (!SBC_ERROR_IS_OK(err)) {
		goto done;
	}

	for (count = 0; count < num_shares; count++)
	{
		d_printf("%s\n", share_names[count]);
	}

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_conf_drop(struct net_context *c, struct smbconf_ctx *conf_ctx,
			 int argc, const char **argv)
{
	int ret = -1;
	sbcErr err;

	if (argc != 0 || c->display_usage) {
		net_conf_drop_usage(c, argc, argv);
		goto done;
	}

	err = smbconf_drop(conf_ctx);
	if (!SBC_ERROR_IS_OK(err)) {
		d_fprintf(stderr, _("Error deleting configuration: %s\n"),
			  sbcErrorString(err));
		goto done;
	}

	ret = 0;

done:
	return ret;
}

static int net_conf_showshare_json(struct net_context *c,
				   struct smbconf_ctx *conf_ctx, int argc,
				   const char **argv)
{
	int ret = -1, error;
#ifdef HAVE_JANSSON
	sbcErr err;
	const char *sharename = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	struct smbconf_service *service = NULL;
	struct json_object share;
	char *output = NULL;
	bool ok;

	mem_ctx = talloc_stackframe();

	if (argc != 1 || c->display_usage) {
		net_conf_showshare_usage(c, argc, argv);
		goto done;
	}

	share = json_new_object();
	if (json_is_invalid(&share)) {
		d_fprintf(stderr, _("Failed to create JSON object.\n"));
		goto done;
	}

	error = json_add_version(&share, JS_MAJ_VER, JS_MIN_VER);
	if (error) {
		d_fprintf(stderr, _("Failed to add version string.\n"));
		json_free(&share);
		goto done;
	}

	sharename = talloc_strdup(mem_ctx, argv[0]);
	if (sharename == NULL) {
		d_fprintf(stderr, "error: out of memory!\n");
		json_free(&share);
		goto done;
	}

	err = smbconf_get_share(conf_ctx, mem_ctx, sharename, &service);
	if (!SBC_ERROR_IS_OK(err)) {
		d_fprintf(stderr, _("error getting share parameters: %s\n"),
			  sbcErrorString(err));
		json_free(&share);
		goto done;
	}

	ok = service_to_json(service, &share);
	if (!ok) {
		d_fprintf(stderr, _("Failed to convert share to JSON.\n"));
		json_free(&share);
		goto done;
	}

	output = json_to_string(mem_ctx, &share);
	if (output == NULL) {
		json_free(&share);
		d_fprintf(stderr, "Memory error\n");
		goto done;
	}

	printf("%s\n", output);
	json_free(&share);
	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
#endif
	return ret;
}

static int net_conf_showshare(struct net_context *c,
			      struct smbconf_ctx *conf_ctx, int argc,
			      const char **argv)
{
	int ret = -1;
	sbcErr err;
	const char *sharename = NULL;
	TALLOC_CTX *mem_ctx;
	uint32_t count;
	struct smbconf_service *service = NULL;

	mem_ctx = talloc_stackframe();

	if (argc != 1 || c->display_usage) {
		net_conf_showshare_usage(c, argc, argv);
		goto done;
	}

	sharename = talloc_strdup(mem_ctx, argv[0]);
	if (sharename == NULL) {
		d_printf("error: out of memory!\n");
		goto done;
	}

	err = smbconf_get_share(conf_ctx, mem_ctx, sharename, &service);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf(_("error getting share parameters: %s\n"),
			 sbcErrorString(err));
		goto done;
	}

	d_printf("[%s]\n", service->name);

	for (count = 0; count < service->num_params; count++) {
		d_printf("\t%s = %s\n", service->param_names[count],
			 service->param_values[count]);
	}

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

/**
 * Add a share, with a couple of standard parameters, partly optional.
 *
 * This is a high level utility function of the net conf utility,
 * not a direct frontend to the smbconf API.
 */
#ifdef HAVE_JANSSON
struct validate_parms_state {
	TALLOC_CTX *mem_ctx;
	const char *path;
};

static bool validate_param(const char *key, struct json_object *parm, void *private_data)
{
	struct validate_parms_state *state = NULL;
	json_t *value = NULL;

	state = talloc_get_type_abort(private_data, struct validate_parms_state);

	value = json_object_get(parm->root, "raw");
	if (value == NULL) {
		value = json_object_get(parm->root, "parsed");
		if (value == NULL) {
			d_fprintf(stderr,
				  _("\"parameters\" object %s is invalid. "
				    "\"raw\" or \"parsed\" keys must be "
				    "present in object.\n"), key);
			return false;
		}
	}

	if (strequal(key, "path")) {
		if (state->path != NULL) {
			d_fprintf(stderr,
				  _("\"params\" object \"path\" is invalid. "
				    "more than one path specified.\n"));
			return false;
		}
		if (!json_is_string(value)) {
			d_fprintf(stderr,
				  _("\"params\" object \"path\" is invalid. "
				    "path must be a string.\n"));
			return false;
		}
		state->path = json_string_value(value);
	}

	return true;
}

static bool validate_share_path(const char *sname, const char *path)
{
	if (path == NULL) {
		return false;
	}
	else if (path[0] == '/') {
		return true;
	}

	if (strequal(sname, HOMES_NAME) && path[0] == '\0') {
		/* The homes share can be an empty path. */
		return true;
	}

	return false;
}

static int validate_share_json(TALLOC_CTX *mem_ctx,
			       struct smbconf_ctx *conf_ctx,
			       struct json_object *data)
{
	int error;
	bool ok;
	struct json_object params;
	json_t *service = NULL;
	const char *sname = NULL;
	struct validate_parms_state *state = NULL;

	/* validate share name */
	service = json_object_get(data->root, "service");
	if ((service == NULL) || !json_is_string(service)) {
		d_fprintf(stderr,
			  _("\"service\" string is required in JSON data.\n"));
		return EINVAL;
	}

	sname = json_string_value(service);
	if (!validate_net_name(sname, INVALID_SHARENAME_CHARS, strlen(sname))) {
		d_fprintf(stderr, _("ERROR: share name %s contains "
			  "invalid characters (any of %s)\n"),
			  sname, INVALID_SHARENAME_CHARS);
		return EINVAL;
	}

	if (strequal(sname, GLOBAL_NAME)) {
		d_fprintf(stderr,
			  _("ERROR: 'global' is not a valid share name.\n"));
		return EINVAL;
	}

	if (smbconf_share_exists(conf_ctx, sname)) {
		d_fprintf(stderr, _("ERROR: share %s already exists.\n"),
			  sname);
		return EEXIST;
	}

	params = json_get_object(data, "parameters");
	if (json_is_invalid(&params)) {
		return EINVAL;
	}

	state = talloc_zero(mem_ctx, struct validate_parms_state);
	if (state == NULL) {
		d_fprintf(stderr, _("Memory failure.\n"));
		return EINVAL;
	}
	error = iter_json_object(&params, validate_param, state);
	if (error) {
		return EINVAL;
	}

	ok = validate_share_path(sname, state->path);
	if (!ok) {
		return EINVAL;
	}

	return 0;
}
#endif /* HAVE_JANSSON */

static int net_conf_addshare_json(struct net_context *c,
			          struct smbconf_ctx *conf_ctx, int argc,
				  const char **argv)
{
	int ret = -1, error;
#ifdef HAVE_JANSSON
	sbcErr err;
	struct json_object data, payload, to_set;
	json_t *jsservice = NULL;
	const char *sharename = NULL;
	bool ok;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (argc != 1 || c->display_usage) {
		net_conf_addshare_json_usage(c, argc, argv);
		TALLOC_FREE(mem_ctx);
		return 0;
	}

	data = load_json(argv[0]);
	if (json_is_invalid(&data)) {
		TALLOC_FREE(mem_ctx);
		return ret;
	}

	error = validate_share_json(mem_ctx, conf_ctx, &data);
	if (error) {
		json_free(&data);
		TALLOC_FREE(mem_ctx);
		return error;
	}

	payload = json_new_object();
	if (json_is_invalid(&payload)) {
		json_free(&data);
		goto done;
	}

	to_set = json_new_array();
	if (json_is_invalid(&to_set)) {
		json_free(&data);
		goto done;
	}

	error = json_array_append_new(to_set.root, data.root);
	if (error) {
		json_free(&to_set);
		json_free(&data);
		goto done;
	}

	error = json_add_object(&payload, "SET", &to_set);
	if (error) {
		json_free(&to_set);
		goto done;
	}

	jsservice = json_object_get(data.root, "service");
	if (jsservice == NULL) {
		goto done;
	}

	sharename = json_string_value(jsservice);

	err = smbconf_transaction_start(conf_ctx);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf("error starting transaction: %s\n",
			 sbcErrorString(err));
		goto done;
	}

	err = smbconf_create_share(conf_ctx, sharename);
	if (!SBC_ERROR_IS_OK(err)) {
		d_fprintf(stderr, _("Error creating share %s: %s\n"),
			  sharename, sbcErrorString(err));
		goto cancel;
	}

	ok = batch_apply_json_parameters(mem_ctx, conf_ctx, &payload);
	if (!ok) {
		goto cancel;
	}

	err = smbconf_transaction_commit(conf_ctx);
	if (!SBC_ERROR_IS_OK(err)) {
		d_fprintf(stderr, "error committing transaction: %s\n",
			 sbcErrorString(err));
	} else {
		ret = 0;
	}

	goto done;

cancel:
	err = smbconf_transaction_cancel(conf_ctx);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf("error cancelling transaction: %s\n",
			 sbcErrorString(err));
	}

done:
	json_free(&payload);
	TALLOC_FREE(mem_ctx);
#endif /* HAVE_JANSSON */
	return ret;
}

static int net_conf_addshare(struct net_context *c,
			     struct smbconf_ctx *conf_ctx, int argc,
			     const char **argv)
{
	int ret = -1;
	sbcErr err;
	char *sharename = NULL;
	const char *path = NULL;
	const char *comment = NULL;
	const char *guest_ok = "no";
	const char *writeable = "no";
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (c->display_usage) {
		net_conf_addshare_usage(c, argc, argv);
		ret = 0;
		goto done;
	}

	switch (argc) {
		case 0:
		case 1:
		default:
			net_conf_addshare_usage(c, argc, argv);
			goto done;
		case 5:
			comment = argv[4];

			FALL_THROUGH;
		case 4:
			if (!strnequal(argv[3], "guest_ok=", 9)) {
				net_conf_addshare_usage(c, argc, argv);
				goto done;
			}
			switch (argv[3][9]) {
				case 'y':
				case 'Y':
					guest_ok = "yes";
					break;
				case 'n':
				case 'N':
					guest_ok = "no";
					break;
				default:
					net_conf_addshare_usage(c, argc, argv);
					goto done;
			}

			FALL_THROUGH;
		case 3:
			if (!strnequal(argv[2], "writeable=", 10)) {
				net_conf_addshare_usage(c, argc, argv);
				goto done;
			}
			switch (argv[2][10]) {
				case 'y':
				case 'Y':
					writeable = "yes";
					break;
				case 'n':
				case 'N':
					writeable = "no";
					break;
				default:
					net_conf_addshare_usage(c, argc, argv);
					goto done;
			}

			FALL_THROUGH;
		case 2:
			path = argv[1];
			sharename = talloc_strdup(mem_ctx, argv[0]);
			if (sharename == NULL) {
				d_printf(_("error: out of memory!\n"));
				goto done;
			}

			break;
	}

	/*
	 * validate arguments
	 */

	/* validate share name */

	if (!validate_net_name(sharename, INVALID_SHARENAME_CHARS,
			       strlen(sharename)))
	{
		d_fprintf(stderr, _("ERROR: share name %s contains "
			  "invalid characters (any of %s)\n"),
			  sharename, INVALID_SHARENAME_CHARS);
		goto done;
	}

	if (strequal(sharename, GLOBAL_NAME)) {
		d_fprintf(stderr,
			  _("ERROR: 'global' is not a valid share name.\n"));
		goto done;
	}

	if (smbconf_share_exists(conf_ctx, sharename)) {
		d_fprintf(stderr, _("ERROR: share %s already exists.\n"),
			  sharename);
		goto done;
	}

	/* validate path */

	if (path[0] != '/') {
		bool ok = false;

		if (strequal(sharename, HOMES_NAME) && path[0] == '\0') {
			/* The homes share can be an empty path. */
			ok = true;
		}
		if (!ok) {
			d_fprintf(stderr,
				  _("Error: path '%s' is not an absolute path.\n"),
				 path);
			goto done;
		}
	}

	/*
	 * start a transaction
	 */

	err = smbconf_transaction_start(conf_ctx);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf("error starting transaction: %s\n",
			 sbcErrorString(err));
		goto done;
	}

	/*
	 * create the share
	 */

	err = smbconf_create_share(conf_ctx, sharename);
	if (!SBC_ERROR_IS_OK(err)) {
		d_fprintf(stderr, _("Error creating share %s: %s\n"),
			  sharename, sbcErrorString(err));
		goto cancel;
	}

	/*
	 * fill the share with parameters
	 */

	err = smbconf_set_parameter(conf_ctx, sharename, "path", path);
	if (!SBC_ERROR_IS_OK(err)) {
		d_fprintf(stderr, _("Error setting parameter %s: %s\n"),
			  "path", sbcErrorString(err));
		goto cancel;
	}

	if (comment != NULL) {
		err = smbconf_set_parameter(conf_ctx, sharename, "comment",
					    comment);
		if (!SBC_ERROR_IS_OK(err)) {
			d_fprintf(stderr, _("Error setting parameter %s: %s\n"),
				  "comment", sbcErrorString(err));
			goto cancel;
		}
	}

	err = smbconf_set_parameter(conf_ctx, sharename, "guest ok", guest_ok);
	if (!SBC_ERROR_IS_OK(err)) {
		d_fprintf(stderr, _("Error setting parameter %s: %s\n"),
			  "'guest ok'", sbcErrorString(err));
		goto cancel;
	}

	err = smbconf_set_parameter(conf_ctx, sharename, "writeable",
				    writeable);
	if (!SBC_ERROR_IS_OK(err)) {
		d_fprintf(stderr, _("Error setting parameter %s: %s\n"),
			  "writeable", sbcErrorString(err));
		goto cancel;
	}

	/*
	 * commit the whole thing
	 */

	err = smbconf_transaction_commit(conf_ctx);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf("error committing transaction: %s\n",
			 sbcErrorString(err));
	} else {
		ret = 0;
	}

	goto done;

cancel:
	err = smbconf_transaction_cancel(conf_ctx);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf("error cancelling transaction: %s\n",
			 sbcErrorString(err));
	}

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_conf_delshare(struct net_context *c,
			     struct smbconf_ctx *conf_ctx, int argc,
			     const char **argv)
{
	int ret = -1;
	const char *sharename = NULL;
	sbcErr err;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (argc != 1 || c->display_usage) {
		net_conf_delshare_usage(c, argc, argv);
		goto done;
	}
	sharename = talloc_strdup(mem_ctx, argv[0]);
	if (sharename == NULL) {
		d_printf(_("error: out of memory!\n"));
		goto done;
	}

	err = smbconf_delete_share(conf_ctx, sharename);
	if (!SBC_ERROR_IS_OK(err)) {
		d_fprintf(stderr, _("Error deleting share %s: %s\n"),
			  sharename, sbcErrorString(err));
		goto done;
	}

	status = delete_share_security(sharename);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		d_fprintf(stderr, _("deleting share acl failed for %s: %s\n"),
			  sharename, nt_errstr(status));
		goto done;
	}

	ret = 0;
done:
	TALLOC_FREE(mem_ctx);
	return ret;
}


static int net_conf_setparm_json(struct net_context *c, struct smbconf_ctx *conf_ctx,
				 int argc, const char **argv)
{
	int ret = -1, error;
#ifdef HAVE_JANSSON
	sbcErr err;
	bool ok;
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	struct json_object data, payload, to_set;
	json_t *jsservice = NULL;

	if (argc != 1 || c->display_usage) {
		net_conf_setparm_json_usage(c, argc, argv);
		TALLOC_FREE(mem_ctx);
		return ret;
	}

	data = load_json(argv[0]);
	if (json_is_invalid(&data)) {
		TALLOC_FREE(mem_ctx);
		return ret;
	}

	payload = json_new_object();
	if (json_is_invalid(&payload)) {
		json_free(&data);
		goto done;
	}

	to_set = json_new_array();
	if (json_is_invalid(&to_set)) {
		json_free(&data);
		goto done;
	}

	error = json_array_append_new(to_set.root, data.root);
	if (error) {
		json_free(&to_set);
		json_free(&data);
		goto done;
	}

	error = json_add_object(&payload, "SET", &to_set);
	if (error) {
		json_free(&to_set);
		goto done;
	}

	jsservice = json_object_get(data.root, "service");
	if (jsservice == NULL) {
		goto done;
	}

	err = smbconf_transaction_start(conf_ctx);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf("error starting transaction: %s\n",
			 sbcErrorString(err));
		goto done;
	}

	ok = batch_apply_json_parameters(mem_ctx, conf_ctx, &payload);
	if (!ok) {
		goto cancel;
	}

	err = smbconf_transaction_commit(conf_ctx);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf(_("error committing transaction: %s\n"),
			 sbcErrorString(err));
	} else {
		ret = 0;
	}

	goto done;

cancel:
	err = smbconf_transaction_cancel(conf_ctx);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf(_("error cancelling transaction: %s\n"),
			 sbcErrorString(err));
	}

done:
	json_free(&payload);
	TALLOC_FREE(mem_ctx);
#endif /* HAVE_JANSSON */
	return ret;
}

static int net_conf_setparm(struct net_context *c, struct smbconf_ctx *conf_ctx,
			    int argc, const char **argv)
{
	int ret = -1;
	sbcErr err;
	char *service = NULL;
	char *param = NULL;
	const char *value_str = NULL;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (argc != 3 || c->display_usage) {
		net_conf_setparm_usage(c, argc, argv);
		goto done;
	}
	/*
	 * NULL service name means "dangling parameters" to libsmbconf.
	 * We use the empty string from the command line for this purpose.
	 */
	if (strlen(argv[0]) != 0) {
		service = talloc_strdup(mem_ctx, argv[0]);
		if (service == NULL) {
			d_printf(_("error: out of memory!\n"));
			goto done;
		}
	}
	param = strlower_talloc(mem_ctx, argv[1]);
	if (param == NULL) {
		d_printf(_("error: out of memory!\n"));
		goto done;
	}
	value_str = argv[2];

	if (!net_conf_param_valid(service,param, value_str)) {
		goto done;
	}

	err = smbconf_transaction_start(conf_ctx);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf(_("error starting transaction: %s\n"),
			 sbcErrorString(err));
		goto done;
	}

	if (!smbconf_share_exists(conf_ctx, service)) {
		err = smbconf_create_share(conf_ctx, service);
		if (!SBC_ERROR_IS_OK(err)) {
			d_fprintf(stderr, _("Error creating share '%s': %s\n"),
				  service, sbcErrorString(err));
			goto cancel;
		}
	}

	err = smbconf_set_parameter(conf_ctx, service, param, value_str);
	if (!SBC_ERROR_IS_OK(err)) {
		d_fprintf(stderr, _("Error setting value '%s': %s\n"),
			  param, sbcErrorString(err));
		goto cancel;
	}

	err = smbconf_transaction_commit(conf_ctx);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf(_("error committing transaction: %s\n"),
			 sbcErrorString(err));
	} else {
		ret = 0;
	}

	goto done;

cancel:
	err = smbconf_transaction_cancel(conf_ctx);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf(_("error cancelling transaction: %s\n"),
			 sbcErrorString(err));
	}

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_conf_getparm(struct net_context *c, struct smbconf_ctx *conf_ctx,
			    int argc, const char **argv)
{
	int ret = -1;
	sbcErr err;
	char *service = NULL;
	char *param = NULL;
	char *valstr = NULL;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_stackframe();

	if (argc != 2 || c->display_usage) {
		net_conf_getparm_usage(c, argc, argv);
		goto done;
	}
	/*
	 * NULL service name means "dangling parameters" to libsmbconf.
	 * We use the empty string from the command line for this purpose.
	 */
	if (strlen(argv[0]) != 0) {
		service = talloc_strdup(mem_ctx, argv[0]);
		if (service == NULL) {
			d_printf(_("error: out of memory!\n"));
			goto done;
		}
	}
	param = strlower_talloc(mem_ctx, argv[1]);
	if (param == NULL) {
		d_printf(_("error: out of memory!\n"));
		goto done;
	}

	err = smbconf_get_parameter(conf_ctx, mem_ctx, service, param, &valstr);
	if (SBC_ERROR_EQUAL(err, SBC_ERR_NO_SUCH_SERVICE)) {
		d_fprintf(stderr,
			  _("Error: given service '%s' does not exist.\n"),
			  service);
		goto done;
	} else if (SBC_ERROR_EQUAL(err, SBC_ERR_INVALID_PARAM)) {
		d_fprintf(stderr,
			  _("Error: given parameter '%s' is not set.\n"),
			  param);
		goto done;
	} else if (!SBC_ERROR_IS_OK(err)) {
		d_fprintf(stderr, _("Error getting value '%s': %s.\n"),
			  param, sbcErrorString(err));
		goto done;
	}

	d_printf("%s\n", valstr);

	ret = 0;
done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_conf_delparm_json(struct net_context *c, struct smbconf_ctx *conf_ctx,
				 int argc, const char **argv)
{
	int ret = -1, error;
#ifdef HAVE_JANSSON
	sbcErr err;
	bool ok;
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	struct json_object data, payload, to_del;
	json_t *jsservice = NULL;

	if (argc != 1 || c->display_usage) {
		net_conf_delparm_json_usage(c, argc, argv);
		TALLOC_FREE(mem_ctx);
		return ret;
	}

	data = load_json(argv[0]);
	if (json_is_invalid(&data)) {
		TALLOC_FREE(mem_ctx);
		return ret;
	}

	payload = json_new_object();
	if (json_is_invalid(&payload)) {
		json_free(&data);
		goto done;
	}

	to_del = json_new_array();
	if (json_is_invalid(&payload)) {
		json_free(&data);
		goto done;
	}

	error = json_array_append_new(to_del.root, data.root);
	if (error) {
		json_free(&to_del);
		json_free(&data);
		goto done;
	}

	error = json_add_object(&payload, "DEL", &to_del);
	if (error) {
		json_free(&to_del);
		goto done;
	}

	jsservice = json_object_get(data.root, "service");
	if (jsservice == NULL) {
		goto done;
	}

	err = smbconf_transaction_start(conf_ctx);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf("error starting transaction: %s\n",
			 sbcErrorString(err));
		goto done;
	}

	ok = batch_apply_json_parameters(mem_ctx, conf_ctx, &payload);
	if (!ok) {
		goto cancel;
	}

	err = smbconf_transaction_commit(conf_ctx);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf(_("error committing transaction: %s\n"),
			 sbcErrorString(err));
	} else {
		ret = 0;
	}

	goto done;

cancel:
	err = smbconf_transaction_cancel(conf_ctx);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf(_("error cancelling transaction: %s\n"),
			 sbcErrorString(err));
	}

done:
	json_free(&payload);
	TALLOC_FREE(mem_ctx);
#endif /* HAVE_JANSSON */
	return ret;
}

static int net_conf_delparm(struct net_context *c, struct smbconf_ctx *conf_ctx,
			    int argc, const char **argv)
{
	int ret = -1;
	sbcErr err;
	char *service = NULL;
	char *param = NULL;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (argc != 2 || c->display_usage) {
		net_conf_delparm_usage(c, argc, argv);
		goto done;
	}
	/*
	 * NULL service name means "dangling parameters" to libsmbconf.
	 * We use the empty string from the command line for this purpose.
	 */
	if (strlen(argv[0]) != 0) {
		service = talloc_strdup(mem_ctx, argv[0]);
		if (service == NULL) {
			d_printf(_("error: out of memory!\n"));
			goto done;
		}
	}
	param = strlower_talloc(mem_ctx, argv[1]);
	if (param == NULL) {
		d_printf("error: out of memory!\n");
		goto done;
	}

	err = smbconf_delete_parameter(conf_ctx, service, param);
	if (SBC_ERROR_EQUAL(err, SBC_ERR_NO_SUCH_SERVICE)) {
		d_fprintf(stderr,
			  _("Error: given service '%s' does not exist.\n"),
			  service);
		goto done;
	} else if (SBC_ERROR_EQUAL(err, SBC_ERR_INVALID_PARAM)) {
		d_fprintf(stderr,
			  _("Error: given parameter '%s' is not set.\n"),
			  param);
		goto done;
	} else if (!SBC_ERROR_IS_OK(err)) {
		d_fprintf(stderr, _("Error deleting value '%s': %s.\n"),
			  param, sbcErrorString(err));
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_conf_getincludes(struct net_context *c,
				struct smbconf_ctx *conf_ctx,
				int argc, const char **argv)
{
	sbcErr err;
	uint32_t num_includes;
	uint32_t count;
	char *service;
	char **includes = NULL;
	int ret = -1;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (argc != 1 || c->display_usage) {
		net_conf_getincludes_usage(c, argc, argv);
		goto done;
	}

	service = talloc_strdup(mem_ctx, argv[0]);
	if (service == NULL) {
		d_printf(_("error: out of memory!\n"));
		goto done;
	}

	err = smbconf_get_includes(conf_ctx, mem_ctx, service,
				    &num_includes, &includes);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf(_("error getting includes: %s\n"), sbcErrorString(err));
		goto done;
	}

	for (count = 0; count < num_includes; count++) {
		d_printf("include = %s\n", includes[count]);
	}

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_conf_setincludes(struct net_context *c,
				struct smbconf_ctx *conf_ctx,
				int argc, const char **argv)
{
	sbcErr err;
	char *service;
	uint32_t num_includes;
	const char **includes;
	int ret = -1;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (argc < 1 || c->display_usage) {
		net_conf_setincludes_usage(c, argc, argv);
		goto done;
	}

	service = talloc_strdup(mem_ctx, argv[0]);
	if (service == NULL) {
		d_printf(_("error: out of memory!\n"));
		goto done;
	}

	num_includes = argc - 1;
	if (num_includes == 0) {
		includes = NULL;
	} else {
		includes = argv + 1;
	}

	err = smbconf_set_includes(conf_ctx, service, num_includes, includes);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf(_("error setting includes: %s\n"), sbcErrorString(err));
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}

static int net_conf_delincludes(struct net_context *c,
				struct smbconf_ctx *conf_ctx,
				int argc, const char **argv)
{
	sbcErr err;
	char *service;
	int ret = -1;
	TALLOC_CTX *mem_ctx = talloc_stackframe();

	if (argc != 1 || c->display_usage) {
		net_conf_delincludes_usage(c, argc, argv);
		goto done;
	}

	service = talloc_strdup(mem_ctx, argv[0]);
	if (service == NULL) {
		d_printf(_("error: out of memory!\n"));
		goto done;
	}

	err = smbconf_delete_includes(conf_ctx, service);
	if (!SBC_ERROR_IS_OK(err)) {
		d_printf(_("error deleting includes: %s\n"), sbcErrorString(err));
		goto done;
	}

	ret = 0;

done:
	TALLOC_FREE(mem_ctx);
	return ret;
}


/**********************************************************************
 *
 * Wrapper and net_conf_run_function mechanism.
 *
 **********************************************************************/

/**
 * Wrapper function to call the main conf functions.
 * The wrapper calls handles opening and closing of the
 * configuration.
 */
static int net_conf_wrap_function(struct net_context *c,
				  int (*fn)(struct net_context *,
					    struct smbconf_ctx *,
					    int, const char **),
				  int argc, const char **argv)
{
	sbcErr err;
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	struct smbconf_ctx *conf_ctx;
	int ret = -1;

	err = smbconf_init(mem_ctx, &conf_ctx, "registry:");
	if (!SBC_ERROR_IS_OK(err)) {
		talloc_free(mem_ctx);
		return -1;
	}

	ret = fn(c, conf_ctx, argc, argv);

	smbconf_shutdown(conf_ctx);

	talloc_free(mem_ctx);
	return ret;
}

/*
 * We need a functable struct of our own, because the
 * functions are called through a wrapper that handles
 * the opening and closing of the configuration, and so on.
 */
struct conf_functable {
	const char *funcname;
	int (*fn)(struct net_context *c, struct smbconf_ctx *ctx, int argc,
		  const char **argv);
	int (*json_fn)(struct net_context *c, struct smbconf_ctx *ctx, int argc,
		  const char **argv);
	int valid_transports;
	const char *description;
	const char *usage;
};

/**
 * This imitates net_run_function but calls the main functions
 * through the wrapper net_conf_wrap_function().
 */
static int net_conf_run_function(struct net_context *c, int argc,
				 const char **argv, const char *whoami,
				 struct conf_functable *table)
{
	int i;

	if (argc != 0) {
		for (i=0; table[i].funcname; i++) {
			if (strcasecmp_m(argv[0], table[i].funcname) == 0) {
				if (c->opt_json && table[i].json_fn == NULL) {
					d_fprintf(stderr,
						  _("JSON variant for [%s] is "
						    "not available.\n"),
						  table[i].funcname);
					break;
				}
				else if (c->opt_json) {
					return net_conf_wrap_function(
					    c, table[i].json_fn,
					    argc-1, argv+1);
				}
				return net_conf_wrap_function(c, table[i].fn,
							      argc-1,
							      argv+1);
			}
		}
	}

	d_printf(_("Usage:\n"));
	for (i=0; table[i].funcname; i++) {
		if (c->display_usage == false)
			d_printf("%s %-15s %s\n", whoami, table[i].funcname,
				 table[i].description);
		else
			d_printf("%s\n", table[i].usage);
	}

	return c->display_usage?0:-1;
}

/*
 * Entry-point for all the CONF functions.
 */

int net_conf(struct net_context *c, int argc, const char **argv)
{
	int ret = -1;
	struct conf_functable func_table[] = {
		{
			"list",
			net_conf_list,
			net_conf_list_json,
			NET_TRANSPORT_LOCAL,
			N_("Dump the complete configuration in smb.conf like "
			   "format."),
			N_("net conf list\n"
			   "    Dump the complete configuration in smb.conf "
			   "like format.")

		},
		{
			"import",
			net_conf_import,
			NULL,
			NET_TRANSPORT_LOCAL,
			N_("Import configuration from file in smb.conf "
			   "format."),
			N_("net conf import\n"
			   "    Import configuration from file in smb.conf "
			   "format.")
		},
		{
			"listshares",
			net_conf_listshares,
			net_conf_listshares_json,
			NET_TRANSPORT_LOCAL,
			N_("List the share names."),
			N_("net conf listshares\n"
			   "    List the share names.")
		},
		{
			"drop",
			net_conf_drop,
			NULL,
			NET_TRANSPORT_LOCAL,
			N_("Delete the complete configuration."),
			N_("net conf drop\n"
			   "    Delete the complete configuration.")
		},
		{
			"showshare",
			net_conf_showshare,
			net_conf_showshare_json,
			NET_TRANSPORT_LOCAL,
			N_("Show the definition of a share."),
			N_("net conf showshare\n"
			   "    Show the definition of a share.")
		},
		{
			"addshare",
			net_conf_addshare,
			net_conf_addshare_json,
			NET_TRANSPORT_LOCAL,
			N_("Create a new share."),
			N_("net conf addshare\n"
			   "    Create a new share.")
		},
		{
			"delshare",
			net_conf_delshare,
			NULL,
			NET_TRANSPORT_LOCAL,
			N_("Delete a share."),
			N_("net conf delshare\n"
			   "    Delete a share.")
		},
		{
			"setparm",
			net_conf_setparm,
			net_conf_setparm_json,
			NET_TRANSPORT_LOCAL,
			N_("Store a parameter."),
			N_("net conf setparm\n"
			   "    Store a parameter.")
		},
		{
			"getparm",
			net_conf_getparm,
			NULL,
			NET_TRANSPORT_LOCAL,
			N_("Retrieve the value of a parameter."),
			N_("net conf getparm\n"
			   "    Retrieve the value of a parameter.")
		},
		{
			"delparm",
			net_conf_delparm,
			net_conf_delparm_json,
			NET_TRANSPORT_LOCAL,
			N_("Delete a parameter."),
			N_("net conf delparm\n"
			   "    Delete a parameter.")
		},
		{
			"getincludes",
			net_conf_getincludes,
			NULL,
			NET_TRANSPORT_LOCAL,
			N_("Show the includes of a share definition."),
			N_("net conf getincludes\n"
			   "    Show the includes of a share definition.")
		},
		{
			"setincludes",
			net_conf_setincludes,
			NULL,
			NET_TRANSPORT_LOCAL,
			N_("Set includes for a share."),
			N_("net conf setincludes\n"
			   "    Set includes for a share.")
		},
		{
			"delincludes",
			net_conf_delincludes,
			NULL,
			NET_TRANSPORT_LOCAL,
			N_("Delete includes from a share definition."),
			N_("net conf delincludes\n"
			   "    Delete includes from a share definition.")
		},
		{NULL, NULL, NULL, 0, NULL, NULL}
	};

	ret = net_conf_run_function(c, argc, argv, "net conf", func_table);

	return ret;
}


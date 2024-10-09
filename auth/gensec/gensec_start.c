/*
   Unix SMB/CIFS implementation.

   Generic Authentication Interface

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2006

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
#include "system/network.h"
#include "tevent.h"
#include "../lib/util/tevent_ntstatus.h"
#include "librpc/gen_ndr/dcerpc.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_internal.h"
#include "lib/param/param.h"
#include "lib/param/loadparm.h"
#include "lib/util/tsort.h"
#include "lib/util/samba_modules.h"
#include "lib/util/base64.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

#undef strcasecmp

/* the list of currently registered GENSEC backends */
static const struct gensec_security_ops **generic_security_ops;
static int gensec_num_backends;

bool gensec_security_ops_enabled(const struct gensec_security_ops *ops, struct gensec_security *security)
{
	bool ok = lpcfg_parm_bool(security->settings->lp_ctx,
				  NULL,
				  "gensec",
				  ops->name,
				  ops->enabled);

	if (ops->weak_crypto &&
	    lpcfg_weak_crypto(security->settings->lp_ctx) != SAMBA_WEAK_CRYPTO_ALLOWED) {
		ok = false;
	}

	return ok;
}

/* Sometimes we want to force only kerberos, sometimes we want to
 * force it's avoidance.  The old list could be either
 * gensec_security_all(), or from cli_credentials_gensec_list() (ie,
 * an existing list we have trimmed down)
 *
 * The intended logic is:
 *
 * if we are in the default AUTO have kerberos:
 * - take a reference to the master list
 * otherwise
 * - always add spnego then:
 * - if we 'MUST' have kerberos:
 *   only add kerberos mechs
 * - if we 'DONT' want kerberos':
 *   only add non-kerberos mechs
 *
 * Once we get things like NegoEx or moonshot, this will of course get
 * more complex.
 */

static const struct gensec_security_ops **gensec_use_kerberos_mechs(
		TALLOC_CTX *mem_ctx,
		const struct gensec_security_ops * const *old_gensec_list,
		enum credentials_use_kerberos use_kerberos,
		bool keep_schannel)
{
	const struct gensec_security_ops **new_gensec_list;
	int i, j, num_mechs_in;

	for (num_mechs_in=0; old_gensec_list && old_gensec_list[num_mechs_in]; num_mechs_in++) {
		/* noop */
	}

	new_gensec_list = talloc_array(mem_ctx,
				       const struct gensec_security_ops *,
				       num_mechs_in + 1);
	if (!new_gensec_list) {
		return NULL;
	}

	j = 0;
	for (i=0; old_gensec_list && old_gensec_list[i]; i++) {
		bool keep = false;

		/*
		 * We want to keep SPNEGO and other backends
		 */
		keep = old_gensec_list[i]->glue;

		if (old_gensec_list[i]->auth_type == DCERPC_AUTH_TYPE_SCHANNEL) {
			keep = keep_schannel;
		}

		switch (use_kerberos) {
		case CRED_USE_KERBEROS_DESIRED:
			keep = true;
			break;

		case CRED_USE_KERBEROS_DISABLED:
			if (old_gensec_list[i]->kerberos == false) {
				keep = true;
			}

			break;

		case CRED_USE_KERBEROS_REQUIRED:
			if (old_gensec_list[i]->kerberos == true) {
				keep = true;
			}

			break;
		default:
			/* Can't happen or invalid parameter */
			return NULL;
		}

		if (!keep) {
			continue;
		}

		new_gensec_list[j] = old_gensec_list[i];
		j++;
	}
	new_gensec_list[j] = NULL;

	return new_gensec_list;
}

_PUBLIC_ const struct gensec_security_ops **gensec_security_mechs(
				struct gensec_security *gensec_security,
				TALLOC_CTX *mem_ctx)
{
	const struct gensec_security_ops * const *backends =
		generic_security_ops;
	enum credentials_use_kerberos use_kerberos = CRED_USE_KERBEROS_DESIRED;
	bool keep_schannel = false;

	if (gensec_security != NULL) {
		struct cli_credentials *creds = NULL;

		creds = gensec_get_credentials(gensec_security);
		if (creds != NULL) {
			use_kerberos = cli_credentials_get_kerberos_state(creds);
			if (cli_credentials_get_netlogon_creds(creds) != NULL) {
				keep_schannel = true;
			}

			/*
			 * Even if Kerberos is set to REQUIRED, keep the
			 * schannel auth mechanism so that machine accounts are
			 * able to authenticate via netlogon.
			 */
			if (gensec_security->gensec_role == GENSEC_SERVER) {
				keep_schannel = true;
			}
		}

		if (gensec_security->settings->backends) {
			backends = gensec_security->settings->backends;
		}
	}

	return gensec_use_kerberos_mechs(mem_ctx, backends,
					 use_kerberos, keep_schannel);

}

_PUBLIC_ const struct gensec_security_ops *gensec_security_by_oid(
				struct gensec_security *gensec_security,
				const char *oid_string)
{
	int i, j;
	const struct gensec_security_ops **backends;
	const struct gensec_security_ops *backend;
	TALLOC_CTX *mem_ctx = talloc_new(gensec_security);
	if (!mem_ctx) {
		return NULL;
	}
	backends = gensec_security_mechs(gensec_security, mem_ctx);
	for (i=0; backends && backends[i]; i++) {
		if (gensec_security != NULL &&
				!gensec_security_ops_enabled(backends[i],
											 gensec_security))
		    continue;
		if (backends[i]->oid) {
			for (j=0; backends[i]->oid[j]; j++) {
				if (backends[i]->oid[j] &&
				    (strcmp(backends[i]->oid[j], oid_string) == 0)) {
					backend = backends[i];
					talloc_free(mem_ctx);
					return backend;
				}
			}
		}
	}
	talloc_free(mem_ctx);

	return NULL;
}

_PUBLIC_ const struct gensec_security_ops *gensec_security_by_sasl_name(
				struct gensec_security *gensec_security,
				const char *sasl_name)
{
	int i;
	const struct gensec_security_ops **backends;
	const struct gensec_security_ops *backend;
	TALLOC_CTX *mem_ctx = talloc_new(gensec_security);
	if (!mem_ctx) {
		return NULL;
	}
	backends = gensec_security_mechs(gensec_security, mem_ctx);
	for (i=0; backends && backends[i]; i++) {
		if (gensec_security != NULL &&
		    !gensec_security_ops_enabled(backends[i], gensec_security)) {
			continue;
		}
		if (backends[i]->sasl_name
		    && (strcmp(backends[i]->sasl_name, sasl_name) == 0)) {
			backend = backends[i];
			talloc_free(mem_ctx);
			return backend;
		}
	}
	talloc_free(mem_ctx);

	return NULL;
}

_PUBLIC_ const struct gensec_security_ops *gensec_security_by_auth_type(
				struct gensec_security *gensec_security,
				uint32_t auth_type)
{
	int i;
	const struct gensec_security_ops **backends;
	const struct gensec_security_ops *backend;
	TALLOC_CTX *mem_ctx;

	if (auth_type == DCERPC_AUTH_TYPE_NONE) {
		return NULL;
	}

	mem_ctx = talloc_new(gensec_security);
	if (!mem_ctx) {
		return NULL;
	}
	backends = gensec_security_mechs(gensec_security, mem_ctx);
	for (i=0; backends && backends[i]; i++) {
		if (gensec_security != NULL &&
		    !gensec_security_ops_enabled(backends[i], gensec_security)) {
			continue;
		}
		if (backends[i]->auth_type == auth_type) {
			backend = backends[i];
			talloc_free(mem_ctx);
			return backend;
		}
	}
	talloc_free(mem_ctx);

	return NULL;
}

const struct gensec_security_ops *gensec_security_by_name(struct gensec_security *gensec_security,
							  const char *name)
{
	int i;
	const struct gensec_security_ops **backends;
	const struct gensec_security_ops *backend;
	TALLOC_CTX *mem_ctx = talloc_new(gensec_security);
	if (!mem_ctx) {
		return NULL;
	}
	backends = gensec_security_mechs(gensec_security, mem_ctx);
	for (i=0; backends && backends[i]; i++) {
		if (gensec_security != NULL &&
				!gensec_security_ops_enabled(backends[i], gensec_security))
		    continue;
		if (backends[i]->name
		    && (strcmp(backends[i]->name, name) == 0)) {
			backend = backends[i];
			talloc_free(mem_ctx);
			return backend;
		}
	}
	talloc_free(mem_ctx);
	return NULL;
}

static const char **gensec_security_sasl_names_from_ops(
	struct gensec_security *gensec_security,
	TALLOC_CTX *mem_ctx,
	const struct gensec_security_ops * const *ops)
{
	const char **sasl_names = NULL;
	size_t i, sasl_names_count = 0;

	if (ops == NULL) {
		return NULL;
	}

	sasl_names = talloc_array(mem_ctx, const char *, 1);
	if (sasl_names == NULL) {
		return NULL;
	}

	for (i = 0; ops[i] != NULL; i++) {
		enum gensec_role role = GENSEC_SERVER;
		const char **tmp = NULL;

		if (ops[i]->sasl_name == NULL) {
			continue;
		}

		if (gensec_security != NULL) {
			if (!gensec_security_ops_enabled(ops[i],
							 gensec_security)) {
				continue;
			}

			role = gensec_security->gensec_role;
		}

		switch (role) {
		case GENSEC_CLIENT:
			if (ops[i]->client_start == NULL) {
				continue;
			}
			break;
		case GENSEC_SERVER:
			if (ops[i]->server_start == NULL) {
				continue;
			}
			break;
		}

		tmp = talloc_realloc(mem_ctx,
				     sasl_names,
				     const char *,
				     sasl_names_count + 2);
		if (tmp == NULL) {
			TALLOC_FREE(sasl_names);
			return NULL;
		}
		sasl_names = tmp;

		sasl_names[sasl_names_count] = ops[i]->sasl_name;
		sasl_names_count++;
	}
	sasl_names[sasl_names_count] = NULL;

	return sasl_names;
}

/**
 * @brief Get the sasl names from the gensec security context.
 *
 * @param[in]  gensec_security The gensec security context.
 *
 * @param[in]  mem_ctx The memory context to allocate memory on.
 *
 * @return An allocated array with sasl names, NULL on error.
 */
_PUBLIC_
const char **gensec_security_sasl_names(struct gensec_security *gensec_security,
					TALLOC_CTX *mem_ctx)
{
	const struct gensec_security_ops **ops = NULL;

	ops = gensec_security_mechs(gensec_security, mem_ctx);

	return gensec_security_sasl_names_from_ops(gensec_security,
						   mem_ctx,
						   ops);
}

/**
 * Return a unique list of security subsystems from those specified in
 * the list of SASL names.
 *
 * Use the list of enabled GENSEC mechanisms from the credentials
 * attached to the gensec_security, and return in our preferred order.
 */

static const struct gensec_security_ops **gensec_security_by_sasl_list(
	struct gensec_security *gensec_security,
	TALLOC_CTX *mem_ctx,
	const char **sasl_names)
{
	const struct gensec_security_ops **backends_out;
	const struct gensec_security_ops **backends;
	int i, k, sasl_idx;
	int num_backends_out = 0;

	if (!sasl_names) {
		return NULL;
	}

	backends = gensec_security_mechs(gensec_security, mem_ctx);

	backends_out = talloc_array(mem_ctx, const struct gensec_security_ops *, 1);
	if (!backends_out) {
		return NULL;
	}
	backends_out[0] = NULL;

	/* Find backends in our preferred order, by walking our list,
	 * then looking in the supplied list */
	for (i=0; backends && backends[i]; i++) {
		if (gensec_security != NULL &&
				!gensec_security_ops_enabled(backends[i], gensec_security))
		    continue;
		for (sasl_idx = 0; sasl_names[sasl_idx]; sasl_idx++) {
			if (!backends[i]->sasl_name ||
			    !(strcmp(backends[i]->sasl_name,
				     sasl_names[sasl_idx]) == 0)) {
				continue;
			}

			for (k=0; backends_out[k]; k++) {
				if (backends_out[k] == backends[i]) {
					break;
				}
			}

			if (k < num_backends_out) {
				/* already in there */
				continue;
			}

			backends_out = talloc_realloc(mem_ctx, backends_out,
						      const struct gensec_security_ops *,
						      num_backends_out + 2);
			if (!backends_out) {
				return NULL;
			}

			backends_out[num_backends_out] = backends[i];
			num_backends_out++;
			backends_out[num_backends_out] = NULL;
		}
	}
	return backends_out;
}

/**
 * Return a unique list of security subsystems from those specified in
 * the OID list.  That is, where two OIDs refer to the same module,
 * return that module only once.
 *
 * Use the list of enabled GENSEC mechanisms from the credentials
 * attached to the gensec_security, and return in our preferred order.
 */

_PUBLIC_ const struct gensec_security_ops_wrapper *gensec_security_by_oid_list(
					struct gensec_security *gensec_security,
					TALLOC_CTX *mem_ctx,
					const char * const *oid_strings,
					const char *skip)
{
	struct gensec_security_ops_wrapper *backends_out;
	const struct gensec_security_ops **backends;
	int i, j, k, oid_idx;
	int num_backends_out = 0;

	if (!oid_strings) {
		return NULL;
	}

	backends = gensec_security_mechs(gensec_security, gensec_security);

	backends_out = talloc_array(mem_ctx, struct gensec_security_ops_wrapper, 1);
	if (!backends_out) {
		return NULL;
	}
	backends_out[0].op = NULL;
	backends_out[0].oid = NULL;

	/* Find backends in our preferred order, by walking our list,
	 * then looking in the supplied list */
	for (i=0; backends && backends[i]; i++) {
		if (gensec_security != NULL &&
				!gensec_security_ops_enabled(backends[i], gensec_security))
		    continue;
		if (!backends[i]->oid) {
			continue;
		}
		for (oid_idx = 0; oid_strings[oid_idx]; oid_idx++) {
			if (strcmp(oid_strings[oid_idx], skip) == 0) {
				continue;
			}

			for (j=0; backends[i]->oid[j]; j++) {
				if (!backends[i]->oid[j] ||
				    !(strcmp(backends[i]->oid[j],
					    oid_strings[oid_idx]) == 0)) {
					continue;
				}

				for (k=0; backends_out[k].op; k++) {
					if (backends_out[k].op == backends[i]) {
						break;
					}
				}

				if (k < num_backends_out) {
					/* already in there */
					continue;
				}

				backends_out = talloc_realloc(mem_ctx, backends_out,
							      struct gensec_security_ops_wrapper,
							      num_backends_out + 2);
				if (!backends_out) {
					return NULL;
				}

				backends_out[num_backends_out].op = backends[i];
				backends_out[num_backends_out].oid = backends[i]->oid[j];
				num_backends_out++;
				backends_out[num_backends_out].op = NULL;
				backends_out[num_backends_out].oid = NULL;
			}
		}
	}
	return backends_out;
}

/**
 * Return OIDS from the security subsystems listed
 */

static const char **gensec_security_oids_from_ops(
	struct gensec_security *gensec_security,
	TALLOC_CTX *mem_ctx,
	const struct gensec_security_ops * const *ops,
	const char *skip)
{
	int i;
	int j = 0;
	int k;
	const char **oid_list;
	if (!ops) {
		return NULL;
	}
	oid_list = talloc_array(mem_ctx, const char *, 1);
	if (!oid_list) {
		return NULL;
	}

	for (i=0; ops && ops[i]; i++) {
		if (gensec_security != NULL &&
			!gensec_security_ops_enabled(ops[i], gensec_security)) {
			continue;
		}
		if (!ops[i]->oid) {
			continue;
		}

		for (k = 0; ops[i]->oid[k]; k++) {
			if (skip && strcmp(skip, ops[i]->oid[k])==0) {
			} else {
				oid_list = talloc_realloc(mem_ctx, oid_list, const char *, j + 2);
				if (!oid_list) {
					return NULL;
				}
				oid_list[j] = ops[i]->oid[k];
				j++;
			}
		}
	}
	oid_list[j] = NULL;
	return oid_list;
}


/**
 * Return OIDS from the security subsystems listed
 */

_PUBLIC_ const char **gensec_security_oids_from_ops_wrapped(TALLOC_CTX *mem_ctx,
				const struct gensec_security_ops_wrapper *wops)
{
	int i;
	int j = 0;
	int k;
	const char **oid_list;
	if (!wops) {
		return NULL;
	}
	oid_list = talloc_array(mem_ctx, const char *, 1);
	if (!oid_list) {
		return NULL;
	}

	for (i=0; wops[i].op; i++) {
		if (!wops[i].op->oid) {
			continue;
		}

		for (k = 0; wops[i].op->oid[k]; k++) {
			oid_list = talloc_realloc(mem_ctx, oid_list, const char *, j + 2);
			if (!oid_list) {
				return NULL;
			}
			oid_list[j] = wops[i].op->oid[k];
			j++;
		}
	}
	oid_list[j] = NULL;
	return oid_list;
}


/**
 * Return all the security subsystems currently enabled on a GENSEC context.
 *
 * This is taken from a list attached to the cli_credentials, and
 * skips the OID in 'skip'.  (Typically the SPNEGO OID)
 *
 */

_PUBLIC_ const char **gensec_security_oids(struct gensec_security *gensec_security,
					   TALLOC_CTX *mem_ctx,
					   const char *skip)
{
	const struct gensec_security_ops **ops;

	ops = gensec_security_mechs(gensec_security, mem_ctx);

	return gensec_security_oids_from_ops(gensec_security, mem_ctx, ops, skip);
}

static int gensec_security_destructor(struct gensec_security *gctx)
{
	if (gctx->parent_security != NULL) {
		if (gctx->parent_security->child_security == gctx) {
			gctx->parent_security->child_security = NULL;
		}
		gctx->parent_security = NULL;
	}

	if (gctx->child_security != NULL) {
		if (gctx->child_security->parent_security == gctx) {
			gctx->child_security->parent_security = NULL;
		}
		gctx->child_security = NULL;
	}

	return 0;
}

/**
  Start the GENSEC system, returning a context pointer.
  @param mem_ctx The parent TALLOC memory context.
  @param gensec_security Returned GENSEC context pointer.
  @note  The mem_ctx is only a parent and may be NULL.
  @note, the auth context is moved to be a referenced pointer of the
  @ gensec_security return
*/
static NTSTATUS gensec_start(TALLOC_CTX *mem_ctx,
			     struct gensec_settings *settings,
			     struct auth4_context *auth_context,
			     struct gensec_security **gensec_security)
{
	(*gensec_security) = talloc_zero(mem_ctx, struct gensec_security);
	NT_STATUS_HAVE_NO_MEMORY(*gensec_security);

	(*gensec_security)->max_update_size = 0;

	SMB_ASSERT(settings->lp_ctx != NULL);
	(*gensec_security)->settings = talloc_reference(*gensec_security, settings);

	/* We need to reference this, not steal, as the caller may be
	 * python, which won't like it if we steal it's object away
	 * from it */
	(*gensec_security)->auth_context = talloc_reference(*gensec_security, auth_context);

	talloc_set_destructor((*gensec_security), gensec_security_destructor);
	return NT_STATUS_OK;
}

/**
 * Start a GENSEC subcontext, with a copy of the properties of the parent
 * @param mem_ctx The parent TALLOC memory context.
 * @param parent The parent GENSEC context
 * @param gensec_security Returned GENSEC context pointer.
 * @note Used by SPNEGO in particular, for the actual implementation mechanism
 */

_PUBLIC_ NTSTATUS gensec_subcontext_start(TALLOC_CTX *mem_ctx,
				 struct gensec_security *parent,
				 struct gensec_security **gensec_security)
{
	if (parent->child_security != NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	(*gensec_security) = talloc_zero(mem_ctx, struct gensec_security);
	NT_STATUS_HAVE_NO_MEMORY(*gensec_security);

	(**gensec_security) = *parent;
	(*gensec_security)->ops = NULL;
	(*gensec_security)->private_data = NULL;
	(*gensec_security)->update_busy_ptr = NULL;

	(*gensec_security)->subcontext = true;
	(*gensec_security)->want_features = parent->want_features;
	(*gensec_security)->max_update_size = parent->max_update_size;
	(*gensec_security)->dcerpc_auth_level = parent->dcerpc_auth_level;
	(*gensec_security)->auth_context = talloc_reference(*gensec_security, parent->auth_context);
	(*gensec_security)->settings = talloc_reference(*gensec_security, parent->settings);
	(*gensec_security)->auth_context = talloc_reference(*gensec_security, parent->auth_context);
	(*gensec_security)->channel_bindings = talloc_reference(*gensec_security, parent->channel_bindings);

	talloc_set_destructor((*gensec_security), gensec_security_destructor);
	return NT_STATUS_OK;
}

_PUBLIC_ NTSTATUS gensec_child_ready(struct gensec_security *parent,
				     struct gensec_security *child)
{
	if (parent->child_security != NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (child->parent_security != NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	parent->child_security = child;
	child->parent_security = parent;
	return NT_STATUS_OK;
}

/**
  Start the GENSEC system, in client mode, returning a context pointer.
  @param mem_ctx The parent TALLOC memory context.
  @param gensec_security Returned GENSEC context pointer.
  @note  The mem_ctx is only a parent and may be NULL.
*/
_PUBLIC_ NTSTATUS gensec_client_start(TALLOC_CTX *mem_ctx,
			     struct gensec_security **gensec_security,
			     struct gensec_settings *settings)
{
	NTSTATUS status;

	if (settings == NULL) {
		DEBUG(0,("gensec_client_start: no settings given!\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	status = gensec_start(mem_ctx, settings, NULL, gensec_security);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	(*gensec_security)->gensec_role = GENSEC_CLIENT;

	return status;
}



/**
  Start the GENSEC system, in server mode, returning a context pointer.
  @param mem_ctx The parent TALLOC memory context.
  @param gensec_security Returned GENSEC context pointer.
  @note  The mem_ctx is only a parent and may be NULL.
*/
_PUBLIC_ NTSTATUS gensec_server_start(TALLOC_CTX *mem_ctx,
				      struct gensec_settings *settings,
				      struct auth4_context *auth_context,
				      struct gensec_security **gensec_security)
{
	NTSTATUS status;

	if (!settings) {
		DEBUG(0,("gensec_server_start: no settings given!\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	status = gensec_start(mem_ctx, settings, auth_context, gensec_security);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	(*gensec_security)->gensec_role = GENSEC_SERVER;

	return status;
}

static NTSTATUS gensec_start_mech(struct gensec_security *gensec_security)
{
	NTSTATUS status;

	/*
	 * Callers sometimes just reuse a context, we should
	 * clear the internal state before starting it again.
	 */
	talloc_unlink(gensec_security, gensec_security->private_data);
	gensec_security->private_data = NULL;

	if (gensec_security->child_security != NULL) {
		/*
		 * The talloc_unlink(.., gensec_security->private_data)
		 * should have cleared this via
		 * gensec_security_destructor().
		 */
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (gensec_security->credentials) {
		const char *forced_mech = cli_credentials_get_forced_sasl_mech(gensec_security->credentials);
		if (forced_mech &&
		    (gensec_security->ops->sasl_name == NULL ||
		     strcasecmp(forced_mech, gensec_security->ops->sasl_name) != 0)) {
			DEBUG(5, ("GENSEC mechanism %s (%s) skipped, as it "
				  "did not match forced mechanism %s\n",
				  gensec_security->ops->name,
				  gensec_security->ops->sasl_name,
				  forced_mech));
			return NT_STATUS_INVALID_PARAMETER;
		}
	}
	DEBUG(5, ("Starting GENSEC %smechanism %s\n",
		  gensec_security->subcontext ? "sub" : "",
		  gensec_security->ops->name));
	switch (gensec_security->gensec_role) {
	case GENSEC_CLIENT:
		if (gensec_security->ops->client_start) {
			status = gensec_security->ops->client_start(gensec_security);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(gensec_security->subcontext?4:2, ("Failed to start GENSEC client mech %s: %s\n",
					  gensec_security->ops->name, nt_errstr(status)));
			}
			return status;
		}
		break;
	case GENSEC_SERVER:
		if (gensec_security->ops->server_start) {
			status = gensec_security->ops->server_start(gensec_security);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(1, ("Failed to start GENSEC server mech %s: %s\n",
					  gensec_security->ops->name, nt_errstr(status)));
			}
			return status;
		}
		break;
	}
	return NT_STATUS_INVALID_PARAMETER;
}

/**
 * Start a GENSEC sub-mechanism with a specified mechanism structure, used in SPNEGO
 *
 */

NTSTATUS gensec_start_mech_by_ops(struct gensec_security *gensec_security,
				  const struct gensec_security_ops *ops)
{
	gensec_security->ops = ops;
	return gensec_start_mech(gensec_security);
}


/**
 * Start a GENSEC sub-mechanism by DCERPC allocated 'auth type' number
 * @param gensec_security GENSEC context pointer.
 * @param auth_type DCERPC auth type
 * @param auth_level DCERPC auth level
 */

_PUBLIC_ NTSTATUS gensec_start_mech_by_authtype(struct gensec_security *gensec_security,
				       uint8_t auth_type, uint8_t auth_level)
{
	gensec_security->ops = gensec_security_by_auth_type(gensec_security, auth_type);
	if (!gensec_security->ops) {
		DEBUG(3, ("Could not find GENSEC backend for auth_type=%d\n", (int)auth_type));
		return NT_STATUS_INVALID_PARAMETER;
	}
	gensec_security->dcerpc_auth_level = auth_level;
	/*
	 * We need to reset sign/seal in order to reset it.
	 * We may got some default features inherited by the credentials
	 */
	gensec_security->want_features &= ~GENSEC_FEATURE_SIGN;
	gensec_security->want_features &= ~GENSEC_FEATURE_SEAL;
	gensec_want_feature(gensec_security, GENSEC_FEATURE_DCE_STYLE);
	gensec_want_feature(gensec_security, GENSEC_FEATURE_ASYNC_REPLIES);
	if (auth_level == DCERPC_AUTH_LEVEL_INTEGRITY) {
		if (gensec_security->gensec_role == GENSEC_CLIENT) {
			gensec_want_feature(gensec_security, GENSEC_FEATURE_SIGN);
		}
	} else if (auth_level == DCERPC_AUTH_LEVEL_PACKET) {
		/*
		 * For connection oriented DCERPC DCERPC_AUTH_LEVEL_PACKET (4)
		 * has the same behavior as DCERPC_AUTH_LEVEL_INTEGRITY (5).
		 */
		if (gensec_security->gensec_role == GENSEC_CLIENT) {
			gensec_want_feature(gensec_security, GENSEC_FEATURE_SIGN);
		}
	} else if (auth_level == DCERPC_AUTH_LEVEL_PRIVACY) {
		gensec_want_feature(gensec_security, GENSEC_FEATURE_SIGN);
		gensec_want_feature(gensec_security, GENSEC_FEATURE_SEAL);
	} else if (auth_level == DCERPC_AUTH_LEVEL_CONNECT) {
		/* Default features */
	} else {
		DEBUG(2,("auth_level %d not supported in DCE/RPC authentication\n",
			 auth_level));
		return NT_STATUS_INVALID_PARAMETER;
	}

	return gensec_start_mech(gensec_security);
}

_PUBLIC_ const char *gensec_get_name_by_authtype(struct gensec_security *gensec_security, uint8_t authtype)
{
	const struct gensec_security_ops *ops;
	ops = gensec_security_by_auth_type(gensec_security, authtype);
	if (ops) {
		return ops->name;
	}
	return NULL;
}


_PUBLIC_ const char *gensec_get_name_by_oid(struct gensec_security *gensec_security,
											const char *oid_string)
{
	const struct gensec_security_ops *ops;
	ops = gensec_security_by_oid(gensec_security, oid_string);
	if (ops) {
		return ops->name;
	}
	return oid_string;
}

/**
 * Start a GENSEC sub-mechanism by OID, used in SPNEGO
 *
 * @note This should also be used when you wish to just start NLTMSSP (for example), as it uses a
 *       well-known #define to hook it in.
 */

_PUBLIC_ NTSTATUS gensec_start_mech_by_oid(struct gensec_security *gensec_security,
				  const char *mech_oid)
{
	SMB_ASSERT(gensec_security != NULL);

	gensec_security->ops = gensec_security_by_oid(gensec_security, mech_oid);
	if (!gensec_security->ops) {
		DEBUG(3, ("Could not find GENSEC backend for oid=%s\n", mech_oid));
		return NT_STATUS_INVALID_PARAMETER;
	}
	return gensec_start_mech(gensec_security);
}

/**
 * Start a GENSEC sub-mechanism by a well known SASL name
 *
 */

_PUBLIC_ NTSTATUS gensec_start_mech_by_sasl_name(struct gensec_security *gensec_security,
					const char *sasl_name)
{
	gensec_security->ops = gensec_security_by_sasl_name(gensec_security, sasl_name);
	if (!gensec_security->ops) {
		DEBUG(3, ("Could not find GENSEC backend for sasl_name=%s\n", sasl_name));
		return NT_STATUS_INVALID_PARAMETER;
	}
	return gensec_start_mech(gensec_security);
}

/**
 * Start a GENSEC sub-mechanism with the preferred option from a SASL name list
 *
 */

_PUBLIC_ NTSTATUS gensec_start_mech_by_sasl_list(struct gensec_security *gensec_security,
						 const char **sasl_names)
{
	NTSTATUS nt_status = NT_STATUS_INVALID_PARAMETER;
	TALLOC_CTX *mem_ctx = talloc_new(gensec_security);
	const struct gensec_security_ops **ops;
	int i;
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}
	ops = gensec_security_by_sasl_list(gensec_security, mem_ctx, sasl_names);
	if (!ops || !*ops) {
		DEBUG(3, ("Could not find GENSEC backend for any of sasl_name = %s\n",
			  str_list_join(mem_ctx,
					sasl_names, ' ')));
		talloc_free(mem_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}
	for (i=0; ops[i]; i++) {
		nt_status = gensec_start_mech_by_ops(gensec_security, ops[i]);
		if (!NT_STATUS_EQUAL(nt_status, NT_STATUS_INVALID_PARAMETER)) {
			break;
		}
	}
	talloc_free(mem_ctx);
	return nt_status;
}

/**
 * Start a GENSEC sub-mechanism by an internal name
 *
 */

_PUBLIC_ NTSTATUS gensec_start_mech_by_name(struct gensec_security *gensec_security,
					const char *name)
{
	gensec_security->ops = gensec_security_by_name(gensec_security, name);
	if (!gensec_security->ops) {
		DEBUG(3, ("Could not find GENSEC backend for name=%s\n", name));
		return NT_STATUS_INVALID_PARAMETER;
	}
	return gensec_start_mech(gensec_security);
}

/**
 * Associate a credentials structure with a GENSEC context - talloc_reference()s it to the context
 *
 */

_PUBLIC_ NTSTATUS gensec_set_credentials(struct gensec_security *gensec_security, struct cli_credentials *credentials)
{
	gensec_security->credentials = talloc_reference(gensec_security, credentials);
	NT_STATUS_HAVE_NO_MEMORY(gensec_security->credentials);
	gensec_want_feature(gensec_security, cli_credentials_get_gensec_features(gensec_security->credentials));
	return NT_STATUS_OK;
}

/*
  register a GENSEC backend.

  The 'name' can be later used by other backends to find the operations
  structure for this backend.
*/
_PUBLIC_ NTSTATUS gensec_register(TALLOC_CTX *ctx,
			const struct gensec_security_ops *ops)
{
	if (gensec_security_by_name(NULL, ops->name) != NULL) {
		/* its already registered! */
		DEBUG(0,("GENSEC backend '%s' already registered\n",
			 ops->name));
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	generic_security_ops = talloc_realloc(ctx,
					      generic_security_ops,
					      const struct gensec_security_ops *,
					      gensec_num_backends+2);
	if (!generic_security_ops) {
		return NT_STATUS_NO_MEMORY;
	}

	generic_security_ops[gensec_num_backends] = ops;
	gensec_num_backends++;
	generic_security_ops[gensec_num_backends] = NULL;

	DEBUG(3,("GENSEC backend '%s' registered\n",
		 ops->name));

	return NT_STATUS_OK;
}

/*
  return the GENSEC interface version, and the size of some critical types
  This can be used by backends to either detect compilation errors, or provide
  multiple implementations for different smbd compilation options in one module
*/
_PUBLIC_ const struct gensec_critical_sizes *gensec_interface_version(void)
{
	static const struct gensec_critical_sizes critical_sizes = {
		GENSEC_INTERFACE_VERSION,
		sizeof(struct gensec_security_ops),
		sizeof(struct gensec_security),
	};

	return &critical_sizes;
}

static int sort_gensec(const struct gensec_security_ops **gs1, const struct gensec_security_ops **gs2) {
	return NUMERIC_CMP((*gs2)->priority, (*gs1)->priority);
}

int gensec_setting_int(struct gensec_settings *settings, const char *mechanism, const char *name, int default_value)
{
	return lpcfg_parm_int(settings->lp_ctx, NULL, mechanism, name, default_value);
}

bool gensec_setting_bool(struct gensec_settings *settings, const char *mechanism, const char *name, bool default_value)
{
	return lpcfg_parm_bool(settings->lp_ctx, NULL, mechanism, name, default_value);
}

/*
  initialise the GENSEC subsystem
*/
_PUBLIC_ NTSTATUS gensec_init(void)
{
	static bool initialized = false;
#define _MODULE_PROTO(init) extern NTSTATUS init(TALLOC_CTX *);
#ifdef STATIC_gensec_MODULES
	STATIC_gensec_MODULES_PROTO;
	init_module_fn static_init[] = { STATIC_gensec_MODULES };
#else
	init_module_fn *static_init = NULL;
#endif
	init_module_fn *shared_init;

	if (initialized) return NT_STATUS_OK;
	initialized = true;

	shared_init = load_samba_modules(NULL, "gensec");

	run_init_functions(NULL, static_init);
	run_init_functions(NULL, shared_init);

	talloc_free(shared_init);

	TYPESAFE_QSORT(generic_security_ops, gensec_num_backends, sort_gensec);

	return NT_STATUS_OK;
}

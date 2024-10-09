/*
   Unix SMB/CIFS implementation.
   Parameter loading functions
   Copyright (C) Karl Auer 1993-1998

   Largely re-written by Andrew Tridgell, September 1994

   Copyright (C) Simo Sorce 2001
   Copyright (C) Alexander Bokovoy 2002
   Copyright (C) Stefan (metze) Metzmacher 2002
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   Copyright (C) James Myers 2003 <myersjj@samba.org>
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
   Copyright (C) Andrew Bartlett 2011-2012

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
 *  Load parameters.
 *
 *  This module provides suitable callback functions for the params
 *  module. It builds the internal table of service details which is
 *  then used by the rest of the server.
 *
 * To add a parameter:
 *
 * 1) add it to the global or service structure definition
 * 2) add it to the parm_table
 * 3) add it to the list of available functions (eg: using FN_GLOBAL_STRING())
 * 4) If it's a global then initialise it in init_globals. If a local
 *    (ie. service) parameter then initialise it in the sDefault structure
 *
 *
 * Notes:
 *   The configuration file is processed sequentially for speed. It is NOT
 *   accessed randomly as happens in 'real' Windows. For this reason, there
 *   is a fair bit of sequence-dependent code here - ie., code which assumes
 *   that certain things happen before others. In particular, the code which
 *   happens at the boundary between sections is delicately poised, so be
 *   careful!
 *
 */

#include "includes.h"
#include "version.h"
#include "dynconfig/dynconfig.h"
#include "system/time.h"
#include "system/locale.h"
#include "system/network.h" /* needed for TCP_NODELAY */
#include "../lib/util/dlinklist.h"
#include "lib/param/param.h"
#define LOADPARM_SUBSTITUTION_INTERNALS 1
#include "lib/param/loadparm.h"
#include "auth/gensec/gensec.h"
#include "lib/param/s3_param.h"
#include "lib/util/bitmap.h"
#include "libcli/smb/smb_constants.h"
#include "tdb.h"
#include "librpc/gen_ndr/nbt.h"
#include "librpc/gen_ndr/dns.h"
#include "librpc/gen_ndr/security.h"
#include "libds/common/roles.h"
#include "lib/util/samba_util.h"
#include "libcli/auth/ntlm_check.h"
#include "lib/crypto/gnutls_helpers.h"
#include "lib/util/smb_strtox.h"
#include "auth/credentials/credentials.h"

#ifdef HAVE_HTTPCONNECTENCRYPT
#include <cups/http.h>
#endif

#define standard_sub_basic talloc_strdup

#include "lib/param/param_global.h"

struct loadparm_service *lpcfg_default_service(struct loadparm_context *lp_ctx)
{
	return lp_ctx->sDefault;
}

int lpcfg_rpc_low_port(struct loadparm_context *lp_ctx)
{
	return lp_ctx->globals->rpc_low_port;
}

int lpcfg_rpc_high_port(struct loadparm_context *lp_ctx)
{
	return lp_ctx->globals->rpc_high_port;
}

enum samba_weak_crypto lpcfg_weak_crypto(struct loadparm_context *lp_ctx)
{
	if (lp_ctx->globals->weak_crypto == SAMBA_WEAK_CRYPTO_UNKNOWN) {
		lp_ctx->globals->weak_crypto = SAMBA_WEAK_CRYPTO_DISALLOWED;

		if (samba_gnutls_weak_crypto_allowed()) {
			lp_ctx->globals->weak_crypto = SAMBA_WEAK_CRYPTO_ALLOWED;
		}
	}

	return lp_ctx->globals->weak_crypto;
}

/**
 * Convenience routine to grab string parameters into temporary memory
 * and run standard_sub_basic on them.
 *
 * The buffers can be written to by
 * callers without affecting the source string.
 */

static const char *lpcfg_string(const char *s)
{
#if 0  /* until REWRITE done to make thread-safe */
	size_t len = s ? strlen(s) : 0;
	char *ret;
#endif

	/* The follow debug is useful for tracking down memory problems
	   especially if you have an inner loop that is calling a lp_*()
	   function that returns a string.  Perhaps this debug should be
	   present all the time? */

#if 0
	DEBUG(10, ("lpcfg_string(%s)\n", s));
#endif

#if 0  /* until REWRITE done to make thread-safe */
	if (!lp_talloc)
		lp_talloc = talloc_init("lp_talloc");

	ret = talloc_array(lp_talloc, char, len + 100);	/* leave room for substitution */

	if (!ret)
		return NULL;

	if (!s)
		*ret = 0;
	else
		strlcpy(ret, s, len);

	if (trim_string(ret, "\"", "\"")) {
		if (strchr(ret,'"') != NULL)
			strlcpy(ret, s, len);
	}

	standard_sub_basic(ret,len+100);
	return (ret);
#endif
	return s;
}

/*
   In this section all the functions that are used to access the
   parameters from the rest of the program are defined
*/

/*
 * the creation of separate lpcfg_*() and lp_*() functions is to allow
 * for code compatibility between existing Samba4 and Samba3 code.
 */

/* this global context supports the lp_*() function variants */
static struct loadparm_context *global_loadparm_context;

#define FN_GLOBAL_SUBSTITUTED_STRING(fn_name,var_name) \
 _PUBLIC_ char *lpcfg_ ## fn_name(struct loadparm_context *lp_ctx, \
		 const struct loadparm_substitution *lp_sub, TALLOC_CTX *mem_ctx) \
{ \
	 if (lp_ctx == NULL) return NULL;				\
	 return lpcfg_substituted_string(mem_ctx, lp_sub, \
			 lp_ctx->globals->var_name ? lp_ctx->globals->var_name : ""); \
}

#define FN_GLOBAL_CONST_STRING(fn_name,var_name)				\
 _PUBLIC_ const char *lpcfg_ ## fn_name(struct loadparm_context *lp_ctx) { \
	if (lp_ctx == NULL) return NULL;				\
	return lp_ctx->globals->var_name ? lpcfg_string(lp_ctx->globals->var_name) : ""; \
}

#define FN_GLOBAL_LIST(fn_name,var_name)				\
 _PUBLIC_ const char **lpcfg_ ## fn_name(struct loadparm_context *lp_ctx) { \
	 if (lp_ctx == NULL) return NULL;				\
	 return lp_ctx->globals->var_name;				\
 }

#define FN_GLOBAL_BOOL(fn_name,var_name) \
 _PUBLIC_ bool lpcfg_ ## fn_name(struct loadparm_context *lp_ctx) {\
	 if (lp_ctx == NULL) return false;				\
	 return lp_ctx->globals->var_name;				\
}

#define FN_GLOBAL_INTEGER(fn_name,var_name) \
 _PUBLIC_ int lpcfg_ ## fn_name(struct loadparm_context *lp_ctx) { \
	 return lp_ctx->globals->var_name;				\
 }

/* Local parameters don't need the ->s3_fns because the struct
 * loadparm_service is shared and lpcfg_service() checks the ->s3_fns
 * hook */
#define FN_LOCAL_SUBSTITUTED_STRING(fn_name,val) \
 _PUBLIC_ char *lpcfg_ ## fn_name(struct loadparm_service *service, \
					struct loadparm_service *sDefault, TALLOC_CTX *ctx) { \
	 return(talloc_strdup(ctx, lpcfg_string((const char *)((service != NULL && service->val != NULL) ? service->val : sDefault->val)))); \
 }

#define FN_LOCAL_CONST_STRING(fn_name,val) \
 _PUBLIC_ const char *lpcfg_ ## fn_name(struct loadparm_service *service, \
					struct loadparm_service *sDefault) { \
	 return((const char *)((service != NULL && service->val != NULL) ? service->val : sDefault->val)); \
 }

#define FN_LOCAL_LIST(fn_name,val) \
 _PUBLIC_ const char **lpcfg_ ## fn_name(struct loadparm_service *service, \
					 struct loadparm_service *sDefault) {\
	 return(const char **)(service != NULL && service->val != NULL? service->val : sDefault->val); \
 }

#define FN_LOCAL_PARM_BOOL(fn_name, val) FN_LOCAL_BOOL(fn_name, val)

#define FN_LOCAL_BOOL(fn_name,val) \
 _PUBLIC_ bool lpcfg_ ## fn_name(struct loadparm_service *service, \
				 struct loadparm_service *sDefault) {	\
	 return((service != NULL)? service->val : sDefault->val); \
 }

#define FN_LOCAL_INTEGER(fn_name,val) \
 _PUBLIC_ int lpcfg_ ## fn_name(struct loadparm_service *service, \
				struct loadparm_service *sDefault) {	\
	 return((service != NULL)? service->val : sDefault->val); \
 }

#define FN_LOCAL_PARM_INTEGER(fn_name, val) FN_LOCAL_INTEGER(fn_name, val)

#define FN_LOCAL_CHAR(fn_name,val) \
 _PUBLIC_ char lpcfg_ ## fn_name(struct loadparm_service *service, \
				struct loadparm_service *sDefault) {	\
	 return((service != NULL)? service->val : sDefault->val); \
 }

#define FN_LOCAL_PARM_CHAR(fn_name,val) FN_LOCAL_CHAR(fn_name, val)

#include "lib/param/param_functions.c"

/* These functions cannot be auto-generated */
FN_LOCAL_BOOL(autoloaded, autoloaded)
FN_GLOBAL_CONST_STRING(dnsdomain, dnsdomain)

/* local prototypes */
static struct loadparm_service *lpcfg_getservicebyname(struct loadparm_context *lp_ctx,
					const char *pszServiceName);
static bool do_section(const char *pszSectionName, void *);
static bool set_variable_helper(TALLOC_CTX *mem_ctx, int parmnum, void *parm_ptr,
				const char *pszParmName, const char *pszParmValue);
static bool lp_do_parameter_parametric(struct loadparm_context *lp_ctx,
				       struct loadparm_service *service,
				       const char *pszParmName,
				       const char *pszParmValue, int flags);

/* The following are helper functions for parametrical options support. */
/* It returns a pointer to parametrical option value if it exists or NULL otherwise */
/* Actual parametrical functions are quite simple */
struct parmlist_entry *get_parametric_helper(struct loadparm_service *service,
					     const char *type, const char *option,
					     struct parmlist_entry *global_opts)
{
	size_t type_len = strlen(type);
	size_t option_len = strlen(option);
	char param_key[type_len + option_len + 2];
	struct parmlist_entry *data = NULL;

	snprintf(param_key, sizeof(param_key), "%s:%s", type, option);

	/*
	 * Try to fetch the option from the data.
	 */
	if (service != NULL) {
		data = service->param_opt;
		while (data != NULL) {
			if (strwicmp(data->key, param_key) == 0) {
				return data;
			}
			data = data->next;
		}
	}

	/*
	 * Fall back to fetching from the globals.
	 */
	data = global_opts;
	while (data != NULL) {
		if (strwicmp(data->key, param_key) == 0) {
			return data;
		}
		data = data->next;
	}

	return NULL;
}

const char *lpcfg_get_parametric(struct loadparm_context *lp_ctx,
			      struct loadparm_service *service,
			      const char *type, const char *option)
{
	struct parmlist_entry *data;

	if (lp_ctx == NULL)
		return NULL;

	data = get_parametric_helper(service,
				     type, option, lp_ctx->globals->param_opt);

	if (data == NULL) {
		return NULL;
	} else {
		return data->value;
	}
}


/**
 * convenience routine to return int parameters.
 */
int lp_int(const char *s)
{

	if (!s || !*s) {
		DEBUG(0,("lp_int(%s): is called with NULL!\n",s));
		return -1;
	}

	return strtol(s, NULL, 0);
}

/**
 * convenience routine to return unsigned long parameters.
 */
unsigned long lp_ulong(const char *s)
{
	int error = 0;
	unsigned long int ret;

	if (!s || !*s) {
		DBG_DEBUG("lp_ulong(%s): is called with NULL!\n",s);
		return -1;
	}

	ret = smb_strtoul(s, NULL, 0, &error, SMB_STR_STANDARD);
	if (error != 0) {
		DBG_DEBUG("lp_ulong(%s): conversion failed\n",s);
		return -1;
	}

	return ret;
}

/**
 * convenience routine to return unsigned long long parameters.
 */
unsigned long long lp_ulonglong(const char *s)
{
	int error = 0;
	unsigned long long int ret;

	if (!s || !*s) {
		DBG_DEBUG("lp_ulonglong(%s): is called with NULL!\n", s);
		return -1;
	}

	ret = smb_strtoull(s, NULL, 0, &error, SMB_STR_STANDARD);
	if (error != 0) {
		DBG_DEBUG("lp_ulonglong(%s): conversion failed\n",s);
		return -1;
	}

	return ret;
}

/**
 * convenience routine to return unsigned long parameters.
 */
static long lp_long(const char *s)
{

	if (!s) {
		DEBUG(0,("lp_long(%s): is called with NULL!\n",s));
		return -1;
	}

	return strtol(s, NULL, 0);
}

/**
 * convenience routine to return unsigned long parameters.
 */
static double lp_double(const char *s)
{

	if (!s) {
		DEBUG(0,("lp_double(%s): is called with NULL!\n",s));
		return -1;
	}

	return strtod(s, NULL);
}

/**
 * convenience routine to return boolean parameters.
 */
bool lp_bool(const char *s)
{
	bool ret = false;

	if (!s || !*s) {
		DEBUG(0,("lp_bool(%s): is called with NULL!\n",s));
		return false;
	}

	if (!set_boolean(s, &ret)) {
		DEBUG(0,("lp_bool(%s): value is not boolean!\n",s));
		return false;
	}

	return ret;
}

/**
 * Return parametric option from a given service. Type is a part of option before ':'
 * Parametric option has following syntax: 'Type: option = value'
 * Returned value is allocated in 'lp_talloc' context
 */

const char *lpcfg_parm_string(struct loadparm_context *lp_ctx,
			      struct loadparm_service *service, const char *type,
			      const char *option)
{
	const char *value = lpcfg_get_parametric(lp_ctx, service, type, option);

	if (value)
		return lpcfg_string(value);

	return NULL;
}

/**
 * Return parametric option from a given service. Type is a part of option before ':'
 * Parametric option has following syntax: 'Type: option = value'
 * Returned value is allocated in 'lp_talloc' context
 */

const char **lpcfg_parm_string_list(TALLOC_CTX *mem_ctx,
				    struct loadparm_context *lp_ctx,
				    struct loadparm_service *service,
				    const char *type,
				    const char *option, const char *separator)
{
	const char *value = lpcfg_get_parametric(lp_ctx, service, type, option);

	if (value != NULL) {
		char **l = str_list_make(mem_ctx, value, separator);
		return discard_const_p(const char *, l);
	}

	return NULL;
}

/**
 * Return parametric option from a given service. Type is a part of option before ':'
 * Parametric option has following syntax: 'Type: option = value'
 */

int lpcfg_parm_int(struct loadparm_context *lp_ctx,
		   struct loadparm_service *service, const char *type,
		   const char *option, int default_v)
{
	const char *value = lpcfg_get_parametric(lp_ctx, service, type, option);

	if (value)
		return lp_int(value);

	return default_v;
}

/**
 * Return parametric option from a given service. Type is a part of
 * option before ':'.
 * Parametric option has following syntax: 'Type: option = value'.
 */

int lpcfg_parm_bytes(struct loadparm_context *lp_ctx,
		  struct loadparm_service *service, const char *type,
		  const char *option, int default_v)
{
	uint64_t bval;

	const char *value = lpcfg_get_parametric(lp_ctx, service, type, option);

	if (value && conv_str_size_error(value, &bval)) {
		if (bval <= INT_MAX) {
			return (int)bval;
		}
	}

	return default_v;
}

/**
 * Return parametric option from a given service.
 * Type is a part of option before ':'
 * Parametric option has following syntax: 'Type: option = value'
 */
unsigned long lpcfg_parm_ulong(struct loadparm_context *lp_ctx,
			    struct loadparm_service *service, const char *type,
			    const char *option, unsigned long default_v)
{
	const char *value = lpcfg_get_parametric(lp_ctx, service, type, option);

	if (value)
		return lp_ulong(value);

	return default_v;
}

/**
 * Return parametric option from a given service.
 * Type is a part of option before ':'
 * Parametric option has following syntax: 'Type: option = value'
 */
unsigned long long lpcfg_parm_ulonglong(struct loadparm_context *lp_ctx,
					struct loadparm_service *service,
					const char *type, const char *option,
					unsigned long long default_v)
{
	const char *value = lpcfg_get_parametric(lp_ctx, service, type, option);

	if (value) {
		return lp_ulonglong(value);
	}

	return default_v;
}

long lpcfg_parm_long(struct loadparm_context *lp_ctx,
		     struct loadparm_service *service, const char *type,
		     const char *option, long default_v)
{
	const char *value = lpcfg_get_parametric(lp_ctx, service, type, option);

	if (value)
		return lp_long(value);

	return default_v;
}

double lpcfg_parm_double(struct loadparm_context *lp_ctx,
		      struct loadparm_service *service, const char *type,
		      const char *option, double default_v)
{
	const char *value = lpcfg_get_parametric(lp_ctx, service, type, option);

	if (value != NULL)
		return lp_double(value);

	return default_v;
}

/**
 * Return parametric option from a given service. Type is a part of option before ':'
 * Parametric option has following syntax: 'Type: option = value'
 */

bool lpcfg_parm_bool(struct loadparm_context *lp_ctx,
		     struct loadparm_service *service, const char *type,
		     const char *option, bool default_v)
{
	const char *value = lpcfg_get_parametric(lp_ctx, service, type, option);

	if (value != NULL)
		return lp_bool(value);

	return default_v;
}


/* this is used to prevent lots of mallocs of size 1 */
static const char lpcfg_string_empty[] = "";

/**
 Free a string value.
**/
void lpcfg_string_free(char **s)
{
	if (s == NULL) {
		return;
	}
	if (*s == lpcfg_string_empty) {
		*s = NULL;
		return;
	}
	TALLOC_FREE(*s);
}

/**
 * Set a string value, deallocating any existing space, and allocing the space
 * for the string
 */
bool lpcfg_string_set(TALLOC_CTX *mem_ctx, char **dest, const char *src)
{
	lpcfg_string_free(dest);

	if ((src == NULL) || (*src == '\0')) {
		*dest = discard_const_p(char, lpcfg_string_empty);
		return true;
	}

	*dest = talloc_strdup(mem_ctx, src);
	if ((*dest) == NULL) {
		DEBUG(0,("Out of memory in string_set\n"));
		return false;
	}

	return true;
}

/**
 * Set a string value, deallocating any existing space, and allocing the space
 * for the string
 */
bool lpcfg_string_set_upper(TALLOC_CTX *mem_ctx, char **dest, const char *src)
{
	lpcfg_string_free(dest);

	if ((src == NULL) || (*src == '\0')) {
		*dest = discard_const_p(char, lpcfg_string_empty);
		return true;
	}

	*dest = strupper_talloc(mem_ctx, src);
	if ((*dest) == NULL) {
		DEBUG(0,("Out of memory in string_set_upper\n"));
		return false;
	}

	return true;
}



/**
 * Add a new service to the services array initialising it with the given
 * service.
 */

struct loadparm_service *lpcfg_add_service(struct loadparm_context *lp_ctx,
					   const struct loadparm_service *pservice,
					   const char *name)
{
	int i;
	int num_to_alloc = lp_ctx->iNumServices + 1;
	struct parmlist_entry *data, *pdata;

	if (lp_ctx->s3_fns != NULL) {
		smb_panic("Add a service should not be called on an s3 loadparm ctx");
	}

	if (pservice == NULL) {
		pservice = lp_ctx->sDefault;
	}

	/* it might already exist */
	if (name) {
		struct loadparm_service *service = lpcfg_getservicebyname(lp_ctx,
								    name);
		if (service != NULL) {
			/* Clean all parametric options for service */
			/* They will be added during parsing again */
			data = service->param_opt;
			while (data) {
				pdata = data->next;
				talloc_free(data);
				data = pdata;
			}
			service->param_opt = NULL;
			return service;
		}
	}

	/* find an invalid one */
	for (i = 0; i < lp_ctx->iNumServices; i++)
		if (lp_ctx->services[i] == NULL)
			break;

	/* if not, then create one */
	if (i == lp_ctx->iNumServices) {
		struct loadparm_service **tsp;

		tsp = talloc_realloc(lp_ctx, lp_ctx->services, struct loadparm_service *, num_to_alloc);

		if (!tsp) {
			DEBUG(0,("lpcfg_add_service: failed to enlarge services!\n"));
			return NULL;
		} else {
			lp_ctx->services = tsp;
			lp_ctx->services[lp_ctx->iNumServices] = NULL;
		}

		lp_ctx->iNumServices++;
	}

	lp_ctx->services[i] = talloc_zero(lp_ctx->services, struct loadparm_service);
	if (lp_ctx->services[i] == NULL) {
		DEBUG(0,("lpcfg_add_service: out of memory!\n"));
		return NULL;
	}
	copy_service(lp_ctx->services[i], pservice, NULL);
	if (name != NULL)
		lpcfg_string_set(lp_ctx->services[i], &lp_ctx->services[i]->szService, name);
	return lp_ctx->services[i];
}

/**
 * Map a parameter's string representation to something we can use.
 * Returns False if the parameter string is not recognised, else TRUE.
 */

int lpcfg_map_parameter(const char *pszParmName)
{
	int iIndex;

	for (iIndex = 0; parm_table[iIndex].label; iIndex++)
		if (strwicmp(parm_table[iIndex].label, pszParmName) == 0)
			return iIndex;

	/* Warn only if it isn't parametric option */
	if (strchr(pszParmName, ':') == NULL)
		DEBUG(0, ("Unknown parameter encountered: \"%s\"\n", pszParmName));
	/* We do return 'fail' for parametric options as well because they are
	   stored in different storage
	 */
	return -1;
}


/**
  return the parameter structure for a parameter
*/
struct parm_struct *lpcfg_parm_struct(struct loadparm_context *lp_ctx, const char *name)
{
	int num = lpcfg_map_parameter(name);

	if (num < 0) {
		return NULL;
	}

	return &parm_table[num];
}

/**
  return the parameter pointer for a parameter
*/
void *lpcfg_parm_ptr(struct loadparm_context *lp_ctx,
		  struct loadparm_service *service, struct parm_struct *parm)
{
	if (lp_ctx->s3_fns) {
		return lp_ctx->s3_fns->get_parm_ptr(service, parm);
	}

	if (service == NULL) {
		if (parm->p_class == P_LOCAL)
			return ((char *)lp_ctx->sDefault)+parm->offset;
		else if (parm->p_class == P_GLOBAL)
			return ((char *)lp_ctx->globals)+parm->offset;
		else return NULL;
	} else {
		return ((char *)service) + parm->offset;
	}
}

/**
  return the parameter pointer for a parameter
*/
bool lpcfg_parm_is_cmdline(struct loadparm_context *lp_ctx, const char *name)
{
	int parmnum;

	parmnum = lpcfg_map_parameter(name);
	if (parmnum == -1) return false;

	return lp_ctx->flags[parmnum] & FLAG_CMDLINE;
}

bool lpcfg_parm_is_unspecified(struct loadparm_context *lp_ctx, const char *name)
{
	int parmnum;

	parmnum = lpcfg_map_parameter(name);
	if (parmnum == -1) return false;

	return lp_ctx->flags[parmnum] & FLAG_DEFAULT;
}

/**
 * Find a service by name. Otherwise works like get_service.
 */

static struct loadparm_service *lpcfg_getservicebyname(struct loadparm_context *lp_ctx,
					const char *pszServiceName)
{
	int iService;

	if (lp_ctx->s3_fns) {
		return lp_ctx->s3_fns->get_service(pszServiceName);
	}

	for (iService = lp_ctx->iNumServices - 1; iService >= 0; iService--)
		if (lp_ctx->services[iService] != NULL &&
		    strwicmp(lp_ctx->services[iService]->szService, pszServiceName) == 0) {
			return lp_ctx->services[iService];
		}

	return NULL;
}

/**
 * Add a parametric option to a parmlist_entry,
 * replacing old value, if already present.
 */
void set_param_opt(TALLOC_CTX *mem_ctx,
		   struct parmlist_entry **opt_list,
		   const char *opt_name,
		   const char *opt_value,
		   unsigned priority)
{
	struct parmlist_entry *new_opt, *opt;

	opt = *opt_list;

	/* Traverse destination */
	while (opt) {
		/* If we already have same option, override it */
		if (strwicmp(opt->key, opt_name) == 0) {
			if ((opt->priority & FLAG_CMDLINE) &&
			    !(priority & FLAG_CMDLINE)) {
				/* it's been marked as not to be
				   overridden */
				return;
			}
			TALLOC_FREE(opt->list);
			lpcfg_string_set(opt, &opt->value, opt_value);
			opt->priority = priority;
			return;
		}
		opt = opt->next;
	}

	new_opt = talloc_pooled_object(
		mem_ctx, struct parmlist_entry,
		2, strlen(opt_name) + 1 + strlen(opt_value) + 1);
	if (new_opt == NULL) {
		smb_panic("OOM");
	}
	new_opt->key = NULL;
	lpcfg_string_set(new_opt, &new_opt->key, opt_name);
	new_opt->value = NULL;
	lpcfg_string_set(new_opt, &new_opt->value, opt_value);

	new_opt->list = NULL;
	new_opt->priority = priority;
	DLIST_ADD(*opt_list, new_opt);
}

/**
 * Copy a service structure to another.
 * If pcopymapDest is NULL then copy all fields
 */

void copy_service(struct loadparm_service *pserviceDest,
		  const struct loadparm_service *pserviceSource,
		  struct bitmap *pcopymapDest)
{
	int i;
	bool bcopyall = (pcopymapDest == NULL);
	struct parmlist_entry *data;

	for (i = 0; parm_table[i].label; i++)
		if (parm_table[i].p_class == P_LOCAL &&
		    (bcopyall || bitmap_query(pcopymapDest, i))) {
			const void *src_ptr =
				((const char *)pserviceSource) + parm_table[i].offset;
			void *dest_ptr =
				((char *)pserviceDest) + parm_table[i].offset;

			switch (parm_table[i].type) {
				case P_BOOL:
				case P_BOOLREV:
					*(bool *)dest_ptr = *(const bool *)src_ptr;
					break;

				case P_INTEGER:
				case P_BYTES:
				case P_OCTAL:
				case P_ENUM:
					*(int *)dest_ptr = *(const int *)src_ptr;
					break;

				case P_CHAR:
					*(char *)dest_ptr = *(const char *)src_ptr;
					break;

				case P_STRING:
					lpcfg_string_set(pserviceDest,
						   (char **)dest_ptr,
						   *(const char * const *)src_ptr);
					break;

				case P_USTRING:
					lpcfg_string_set_upper(pserviceDest,
							 (char **)dest_ptr,
							 *(const char * const *)src_ptr);
					break;
				case P_CMDLIST:
				case P_LIST:
					TALLOC_FREE(*((char ***)dest_ptr));
					*(char ***)dest_ptr = str_list_copy(pserviceDest,
									    *discard_const_p(const char **, src_ptr));
					break;
				default:
					break;
			}
		}

	if (bcopyall) {
		init_copymap(pserviceDest);
		if (pserviceSource->copymap)
			bitmap_copy(pserviceDest->copymap,
				    pserviceSource->copymap);
	}

	for (data = pserviceSource->param_opt; data != NULL; data = data->next) {
		set_param_opt(pserviceDest, &pserviceDest->param_opt,
			      data->key, data->value, data->priority);
	}
}

/**
 * Check a service for consistency. Return False if the service is in any way
 * incomplete or faulty, else True.
 */
bool lpcfg_service_ok(struct loadparm_service *service)
{
	bool bRetval;

	bRetval = true;
	if (service->szService[0] == '\0') {
		DEBUG(0, ("The following message indicates an internal error:\n"));
		DEBUG(0, ("No service name in service entry.\n"));
		bRetval = false;
	}

	/* The [printers] entry MUST be printable. I'm all for flexibility, but */
	/* I can't see why you'd want a non-printable printer service...        */
	if (strwicmp(service->szService, PRINTERS_NAME) == 0) {
		if (!service->printable) {
			DEBUG(0, ("WARNING: [%s] service MUST be printable!\n",
			       service->szService));
			service->printable = true;
		}
		/* [printers] service must also be non-browsable. */
		if (service->browseable)
			service->browseable = false;
	}

	if (service->path[0] == '\0' &&
	    strwicmp(service->szService, HOMES_NAME) != 0 &&
	    service->msdfs_proxy[0] == '\0')
	{
		DEBUG(0, ("WARNING: No path in service %s - making it unavailable!\n",
			service->szService));
		service->available = false;
	}

	if (!service->available)
		DEBUG(1, ("NOTE: Service %s is flagged unavailable.\n",
			  service->szService));

	return bRetval;
}


/*******************************************************************
 Keep a linked list of all config files so we know when one has changed
 it's date and needs to be reloaded.
********************************************************************/

void add_to_file_list(TALLOC_CTX *mem_ctx, struct file_lists **list,
			     const char *fname, const char *subfname)
{
	struct file_lists *f = *list;

	while (f) {
		if (f->name && !strcmp(f->name, fname))
			break;
		f = f->next;
	}

	if (!f) {
		f = talloc_zero(mem_ctx, struct file_lists);
		if (!f)
			goto fail;
		f->next = *list;
		f->name = talloc_strdup(f, fname);
		if (!f->name) {
			TALLOC_FREE(f);
			goto fail;
		}
		f->subfname = talloc_strdup(f, subfname);
		if (!f->subfname) {
			TALLOC_FREE(f);
			goto fail;
		}
		*list = f;
	}

	/* If file_modtime() fails it leaves f->modtime as zero. */
	(void)file_modtime(subfname, &f->modtime);
	return;

fail:
	DEBUG(0, ("Unable to add file to file list: %s\n", fname));

}

/*
 * set the value for a P_ENUM
 */
bool lp_set_enum_parm( struct parm_struct *parm, const char *pszParmValue,
                              int *ptr )
{
	int i;

	for (i = 0; parm->enum_list[i].name; i++) {
		if (strwicmp(pszParmValue, parm->enum_list[i].name) == 0) {
			*ptr = parm->enum_list[i].value;
			return true;
		}
	}
	DEBUG(0, ("WARNING: Ignoring invalid value '%s' for parameter '%s'\n",
		  pszParmValue, parm->label));
	return false;
}


/***************************************************************************
 Handle the "realm" parameter
***************************************************************************/

bool handle_realm(struct loadparm_context *lp_ctx, struct loadparm_service *service,
		  const char *pszParmValue, char **ptr)
{
	char *upper;
	char *lower;

	upper = strupper_talloc(lp_ctx, pszParmValue);
	if (upper == NULL) {
		return false;
	}

	lower = strlower_talloc(lp_ctx, pszParmValue);
	if (lower == NULL) {
		TALLOC_FREE(upper);
		return false;
	}

	lpcfg_string_set(lp_ctx->globals->ctx, &lp_ctx->globals->realm, upper);
	lpcfg_string_set(lp_ctx->globals->ctx, &lp_ctx->globals->dnsdomain, lower);

	return true;
}

/***************************************************************************
 Handle the include operation.
***************************************************************************/

bool handle_include(struct loadparm_context *lp_ctx, struct loadparm_service *service,
			   const char *pszParmValue, char **ptr)
{
	char *fname;
	const char *substitution_variable_substring;
	char next_char;

	if (lp_ctx->s3_fns) {
		return lp_ctx->s3_fns->lp_include(lp_ctx, service, pszParmValue, ptr);
	}

	fname = standard_sub_basic(lp_ctx, pszParmValue);

	add_to_file_list(lp_ctx, &lp_ctx->file_lists, pszParmValue, fname);

	lpcfg_string_set(lp_ctx, ptr, fname);

	if (file_exist(fname))
		return pm_process(fname, do_section, lpcfg_do_parameter, lp_ctx);

       /*
        * If the file doesn't exist, we check that it isn't due to variable
        * substitution
        */
	substitution_variable_substring = strchr(fname, '%');

	if (substitution_variable_substring != NULL) {
		next_char = substitution_variable_substring[1];
		if ((next_char >= 'a' && next_char <= 'z')
		    || (next_char >= 'A' && next_char <= 'Z')) {
			DEBUG(2, ("Tried to load %s but variable substitution in "
				 "filename, ignoring file.\n", fname));
			return true;
		}
	}

	DEBUG(2, ("Can't find include file %s\n", fname));

	return true;
}

/***************************************************************************
 Handle the interpretation of the copy parameter.
***************************************************************************/

bool handle_copy(struct loadparm_context *lp_ctx, struct loadparm_service *service,
			const char *pszParmValue, char **ptr)
{
	bool bRetval;
	struct loadparm_service *serviceTemp = NULL;

	bRetval = false;

	DEBUG(3, ("Copying service from service %s\n", pszParmValue));

	serviceTemp = lpcfg_getservicebyname(lp_ctx, pszParmValue);

	if (service == NULL) {
		DEBUG(0, ("Unable to copy service - invalid service destination.\n"));
		return false;
	}

	if (serviceTemp != NULL) {
		if (serviceTemp == service) {
			DEBUG(0, ("Can't copy service %s - unable to copy self!\n", pszParmValue));
		} else {
			copy_service(service,
				     serviceTemp,
				     service->copymap);
			lpcfg_string_set(service, ptr, pszParmValue);

			bRetval = true;
		}
	} else {
		DEBUG(0, ("Unable to copy service - source not found: %s\n",
			  pszParmValue));
		bRetval = false;
	}

	return bRetval;
}

bool handle_debug_list(struct loadparm_context *lp_ctx, struct loadparm_service *service,
			const char *pszParmValue, char **ptr)
{
	lpcfg_string_set(lp_ctx->globals->ctx, ptr, pszParmValue);

	return debug_parse_levels(pszParmValue);
}

bool handle_logfile(struct loadparm_context *lp_ctx, struct loadparm_service *service,
		    const char *pszParmValue, char **ptr)
{
	if (lp_ctx->s3_fns == NULL) {
		debug_set_logfile(pszParmValue);
	}

	lpcfg_string_set(lp_ctx->globals->ctx, ptr, pszParmValue);

	return true;
}

/*
 * These special charset handling methods only run in the source3 code.
 */

bool handle_charset(struct loadparm_context *lp_ctx, struct loadparm_service *service,
			const char *pszParmValue, char **ptr)
{
	if (lp_ctx->s3_fns) {
		if (*ptr == NULL || strcmp(*ptr, pszParmValue) != 0) {
			struct smb_iconv_handle *ret = NULL;

			ret = reinit_iconv_handle(NULL,
						  lpcfg_dos_charset(lp_ctx),
						  lpcfg_unix_charset(lp_ctx));
			if (ret == NULL) {
				smb_panic("reinit_iconv_handle failed");
			}
		}

	}
	return lpcfg_string_set(lp_ctx->globals->ctx, ptr, pszParmValue);

}

bool handle_dos_charset(struct loadparm_context *lp_ctx, struct loadparm_service *service,
			const char *pszParmValue, char **ptr)
{
	bool is_utf8 = false;
	size_t len = strlen(pszParmValue);

	if (lp_ctx->s3_fns) {
		if (len == 4 || len == 5) {
			/* Don't use StrCaseCmp here as we don't want to
			   initialize iconv. */
			if ((toupper_m(pszParmValue[0]) == 'U') &&
			    (toupper_m(pszParmValue[1]) == 'T') &&
			    (toupper_m(pszParmValue[2]) == 'F')) {
				if (len == 4) {
					if (pszParmValue[3] == '8') {
						is_utf8 = true;
					}
				} else {
					if (pszParmValue[3] == '-' &&
					    pszParmValue[4] == '8') {
						is_utf8 = true;
					}
				}
			}
		}

		if (*ptr == NULL || strcmp(*ptr, pszParmValue) != 0) {
			struct smb_iconv_handle *ret = NULL;
			if (is_utf8) {
				DEBUG(0,("ERROR: invalid DOS charset: 'dos charset' must not "
					"be UTF8, using (default value) %s instead.\n",
					DEFAULT_DOS_CHARSET));
				pszParmValue = DEFAULT_DOS_CHARSET;
			}
			ret = reinit_iconv_handle(NULL,
						lpcfg_dos_charset(lp_ctx),
						lpcfg_unix_charset(lp_ctx));
			if (ret == NULL) {
				smb_panic("reinit_iconv_handle failed");
			}
		}
	}

	return lpcfg_string_set(lp_ctx->globals->ctx, ptr, pszParmValue);
}

bool handle_printing(struct loadparm_context *lp_ctx, struct loadparm_service *service,
			    const char *pszParmValue, char **ptr)
{
	static int parm_num = -1;

	if (parm_num == -1) {
		parm_num = lpcfg_map_parameter("printing");
	}

	if (!lp_set_enum_parm(&parm_table[parm_num], pszParmValue, (int*)ptr)) {
		return false;
	}

	if (lp_ctx->s3_fns) {
		if (service == NULL) {
			init_printer_values(lp_ctx, lp_ctx->globals->ctx, lp_ctx->sDefault);
		} else {
			init_printer_values(lp_ctx, service, service);
		}
	}

	return true;
}

bool handle_ldap_debug_level(struct loadparm_context *lp_ctx, struct loadparm_service *service,
			     const char *pszParmValue, char **ptr)
{
	lp_ctx->globals->ldap_debug_level = lp_int(pszParmValue);

	if (lp_ctx->s3_fns) {
		lp_ctx->s3_fns->init_ldap_debugging();
	}
	return true;
}

/*
 * idmap related parameters
 */

bool handle_idmap_backend(struct loadparm_context *lp_ctx, struct loadparm_service *service,
			  const char *pszParmValue, char **ptr)
{
	if (lp_ctx->s3_fns) {
		lp_do_parameter_parametric(lp_ctx, service, "idmap config * : backend",
					   pszParmValue, 0);
	}

	return lpcfg_string_set(lp_ctx->globals->ctx, ptr, pszParmValue);
}

bool handle_idmap_uid(struct loadparm_context *lp_ctx, struct loadparm_service *service,
		      const char *pszParmValue, char **ptr)
{
	if (lp_ctx->s3_fns) {
		lp_do_parameter_parametric(lp_ctx, service, "idmap config * : range",
					   pszParmValue, 0);
	}

	return lpcfg_string_set(lp_ctx->globals->ctx, ptr, pszParmValue);
}

bool handle_idmap_gid(struct loadparm_context *lp_ctx, struct loadparm_service *service,
		      const char *pszParmValue, char **ptr)
{
	if (lp_ctx->s3_fns) {
		lp_do_parameter_parametric(lp_ctx, service, "idmap config * : range",
					   pszParmValue, 0);
	}

	return lpcfg_string_set(lp_ctx->globals->ctx, ptr, pszParmValue);
}

bool handle_smb_ports(struct loadparm_context *lp_ctx, struct loadparm_service *service,
		      const char *pszParmValue, char **ptr)
{
	static int parm_num = -1;
	int i;
	const char **list;

	if (!pszParmValue || !*pszParmValue) {
		return false;
	}

	if (parm_num == -1) {
		parm_num = lpcfg_map_parameter("smb ports");
		if (parm_num == -1) {
			return false;
		}
	}

	if (!set_variable_helper(lp_ctx->globals->ctx, parm_num, ptr, "smb ports",
			       	pszParmValue)) {
		return false;
	}

	list = lp_ctx->globals->smb_ports;
	if (list == NULL) {
		return false;
	}

	/* Check that each port is a valid integer and within range */
	for (i = 0; list[i] != NULL; i++) {
		char *end = NULL;
		int port = 0;
		port = strtol(list[i], &end, 10);
		if (*end != '\0' || port <= 0 || port > 65535) {
			TALLOC_FREE(list);
			return false;
		}
	}

	return true;
}

bool handle_rpc_server_dynamic_port_range(struct loadparm_context *lp_ctx,
					  struct loadparm_service *service,
					  const char *pszParmValue,
					  char **ptr)
{
	static int parm_num = -1;
	int low_port = -1, high_port = -1;
	int rc;

	if (parm_num == -1) {
		parm_num = lpcfg_map_parameter("rpc server dynamic port range");
		if (parm_num == -1) {
			return false;
		}
	}

	if (pszParmValue == NULL || pszParmValue[0] == '\0') {
		return false;
	}

	rc = sscanf(pszParmValue, "%d - %d", &low_port, &high_port);
	if (rc != 2) {
		return false;
	}

	if (low_port > high_port) {
		return false;
	}

	if (low_port < SERVER_TCP_PORT_MIN|| high_port > SERVER_TCP_PORT_MAX) {
		return false;
	}

	if (!set_variable_helper(lp_ctx->globals->ctx, parm_num, ptr,
				 "rpc server dynamic port range",
				 pszParmValue)) {
		return false;
	}

	lp_ctx->globals->rpc_low_port = low_port;
	lp_ctx->globals->rpc_high_port = high_port;

	return true;
}

bool handle_smb2_max_credits(struct loadparm_context *lp_ctx,
			     struct loadparm_service *service,
			     const char *pszParmValue, char **ptr)
{
	int value = lp_int(pszParmValue);

	if (value <= 0) {
		value = DEFAULT_SMB2_MAX_CREDITS;
	}

	*(int *)ptr = value;

	return true;
}

bool handle_cups_encrypt(struct loadparm_context *lp_ctx,
			 struct loadparm_service *service,
			 const char *pszParmValue, char **ptr)
{
	int result = 0;
#ifdef HAVE_HTTPCONNECTENCRYPT
	int value = lp_int(pszParmValue);

	switch (value) {
		case Auto:
			result = HTTP_ENCRYPT_REQUIRED;
			break;
		case true:
			result = HTTP_ENCRYPT_ALWAYS;
			break;
		case false:
			result = HTTP_ENCRYPT_NEVER;
			break;
		default:
			result = 0;
			break;
	}
#endif
	*(int *)ptr = result;

	return true;
}

/***************************************************************************
 Initialise a copymap.
***************************************************************************/

/**
 * Initializes service copymap
 * Note: pservice *must* be valid TALLOC_CTX
 */
void init_copymap(struct loadparm_service *pservice)
{
	int i;

	TALLOC_FREE(pservice->copymap);

	pservice->copymap = bitmap_talloc(pservice, num_parameters());
	if (!pservice->copymap) {
		DEBUG(0,
		      ("Couldn't allocate copymap!! (size %d)\n",
		       (int)num_parameters()));
	} else {
		for (i = 0; i < num_parameters(); i++) {
			bitmap_set(pservice->copymap, i);
		}
	}
}

/**
 * Process a parametric option
 */
static bool lp_do_parameter_parametric(struct loadparm_context *lp_ctx,
				       struct loadparm_service *service,
				       const char *pszParmName,
				       const char *pszParmValue, int flags)
{
	struct parmlist_entry **data;
	char *name;
	TALLOC_CTX *mem_ctx;

	while (isspace((unsigned char)*pszParmName)) {
		pszParmName++;
	}

	name = strlower_talloc(lp_ctx, pszParmName);
	if (!name) return false;

	if (service == NULL) {
		data = &lp_ctx->globals->param_opt;
		/**
		 * s3 code cannot deal with parametric options stored on the globals ctx.
		 */
		if (lp_ctx->s3_fns != NULL) {
			mem_ctx = NULL;
		} else {
			mem_ctx = lp_ctx->globals->ctx;
		}
	} else {
		data = &service->param_opt;
		mem_ctx = service;
	}

	set_param_opt(mem_ctx, data, name, pszParmValue, flags);

	talloc_free(name);

	return true;
}

static bool set_variable_helper(TALLOC_CTX *mem_ctx, int parmnum, void *parm_ptr,
			 const char *pszParmName, const char *pszParmValue)
{
	size_t i;

	/* switch on the type of variable it is */
	switch (parm_table[parmnum].type)
	{
		case P_BOOL: {
			bool b;
			if (!set_boolean(pszParmValue, &b)) {
				DEBUG(0, ("set_variable_helper(%s): value is not "
					  "boolean!\n", pszParmValue));
				return false;
			}
			*(bool *)parm_ptr = b;
			}
			break;

		case P_BOOLREV: {
			bool b;
			if (!set_boolean(pszParmValue, &b)) {
				DEBUG(0, ("set_variable_helper(%s): value is not "
					  "boolean!\n", pszParmValue));
				return false;
			}
			*(bool *)parm_ptr = !b;
			}
			break;

		case P_INTEGER:
			*(int *)parm_ptr = lp_int(pszParmValue);
			break;

		case P_CHAR:
			*(char *)parm_ptr = *pszParmValue;
			break;

		case P_OCTAL:
			i = sscanf(pszParmValue, "%o", (int *)parm_ptr);
			if ( i != 1 ) {
				DEBUG ( 0, ("Invalid octal number %s\n", pszParmName ));
				return false;
			}
			break;

		case P_BYTES:
		{
			uint64_t val;
			if (conv_str_size_error(pszParmValue, &val)) {
				if (val <= INT_MAX) {
					*(int *)parm_ptr = (int)val;
					break;
				}
			}

			DEBUG(0, ("set_variable_helper(%s): value is not "
			          "a valid size specifier!\n", pszParmValue));
			return false;
		}

		case P_CMDLIST:
			TALLOC_FREE(*(char ***)parm_ptr);
			*(char ***)parm_ptr = str_list_make_v3(mem_ctx,
							pszParmValue, NULL);
			break;

		case P_LIST:
		{
			char **new_list = str_list_make_v3(mem_ctx,
							pszParmValue, NULL);
			if (new_list == NULL) {
				break;
			}

			for (i=0; new_list[i]; i++) {
				if (*(const char ***)parm_ptr != NULL &&
				    new_list[i][0] == '+' &&
				    new_list[i][1])
				{
					if (!str_list_check(*(const char ***)parm_ptr,
							    &new_list[i][1])) {
						*(const char ***)parm_ptr = str_list_add(*(const char ***)parm_ptr,
											 &new_list[i][1]);
					}
				} else if (*(const char ***)parm_ptr != NULL &&
					   new_list[i][0] == '-' &&
					   new_list[i][1])
				{
					str_list_remove(*(const char ***)parm_ptr,
							&new_list[i][1]);
				} else {
					if (i != 0) {
						DEBUG(0, ("Unsupported list syntax for: %s = %s\n",
							  pszParmName, pszParmValue));
						return false;
					}
					*(char ***)parm_ptr = new_list;
					break;
				}
			}
			break;
		}

		case P_STRING:
			lpcfg_string_set(mem_ctx, (char **)parm_ptr, pszParmValue);
			break;

		case P_USTRING:
			lpcfg_string_set_upper(mem_ctx, (char **)parm_ptr, pszParmValue);
			break;

		case P_ENUM:
			if (!lp_set_enum_parm(&parm_table[parmnum], pszParmValue, (int*)parm_ptr)) {
				return false;
			}
			break;

	}

	return true;

}

bool handle_name_resolve_order(struct loadparm_context *lp_ctx,
			       struct loadparm_service *service,
			       const char *pszParmValue, char **ptr)
{
	const char **valid_values = NULL;
	const char **values_to_set = NULL;
	int i;
	bool value_is_valid = false;
	valid_values = str_list_make_v3_const(NULL,
					      DEFAULT_NAME_RESOLVE_ORDER,
					      NULL);
	if (valid_values == NULL) {
		DBG_ERR("OOM: failed to make string list from %s\n",
			DEFAULT_NAME_RESOLVE_ORDER);
		goto out;
	}
	values_to_set = str_list_make_v3_const(lp_ctx->globals->ctx,
					       pszParmValue,
					       NULL);
	if (values_to_set == NULL) {
		DBG_ERR("OOM: failed to make string list from %s\n",
			pszParmValue);
		goto out;
	}
	TALLOC_FREE(lp_ctx->globals->name_resolve_order);
	for (i = 0; values_to_set[i] != NULL; i++) {
		value_is_valid = str_list_check(valid_values, values_to_set[i]);
		if (!value_is_valid) {
			DBG_ERR("WARNING: Ignoring invalid list value '%s' "
				"for parameter 'name resolve order'\n",
				values_to_set[i]);
			break;
		}
	}
out:
	if (value_is_valid) {
		lp_ctx->globals->name_resolve_order = values_to_set;
	} else {
		TALLOC_FREE(values_to_set);
	}
	TALLOC_FREE(valid_values);
	return value_is_valid;
}

bool handle_kdc_default_domain_supported_enctypes(struct loadparm_context *lp_ctx,
						  struct loadparm_service *service,
						  const char *pszParmValue, char **ptr)
{
	char **enctype_list = NULL;
	char **enctype = NULL;
	uint32_t result = 0;
	bool ok = true;

	enctype_list = str_list_make(NULL, pszParmValue, NULL);
	if (enctype_list == NULL) {
		DBG_ERR("OOM: failed to make string list from %s\n",
			pszParmValue);
		ok = false;
		goto out;
	}

	for (enctype = enctype_list; *enctype != NULL; ++enctype) {
		if (strwicmp(*enctype, "arcfour-hmac-md5") == 0 ||
		    strwicmp(*enctype, "rc4-hmac") == 0)
		{
			result |= KERB_ENCTYPE_RC4_HMAC_MD5;
		}
		else if (strwicmp(*enctype, "aes128-cts-hmac-sha1-96") == 0 ||
			 strwicmp(*enctype, "aes128-cts") == 0)
		{
			result |= KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96;
		}
		else if (strwicmp(*enctype, "aes256-cts-hmac-sha1-96") == 0 ||
			 strwicmp(*enctype, "aes256-cts") == 0)
		{
			result |= KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96;
		}
		else if (strwicmp(*enctype, "aes256-cts-hmac-sha1-96-sk") == 0 ||
			 strwicmp(*enctype, "aes256-cts-sk") == 0)
		{
			result |= KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96_SK;
		}
		else {
			const char *bitstr = *enctype;
			int base;
			int error;
			unsigned long bit;

			/* See if the bit's specified in hexadecimal. */
			if (bitstr[0] == '0' &&
			    (bitstr[1] == 'x' || bitstr[2] == 'X'))
			{
				base = 16;
				bitstr += 2;
			}
			else {
				base = 10;
			}

			bit = smb_strtoul(bitstr, NULL, base, &error, SMB_STR_FULL_STR_CONV);
			if (error) {
				DBG_ERR("WARNING: Ignoring invalid value '%s' "
					"for parameter 'kdc default domain supported enctypes'\n",
					*enctype);
				ok = false;
			} else {
				result |= bit;
			}
		}
	}

	*(int *)ptr = result;
out:
	TALLOC_FREE(enctype_list);

	return ok;
}

bool handle_kdc_supported_enctypes(struct loadparm_context *lp_ctx,
				   struct loadparm_service *service,
				   const char *pszParmValue, char **ptr)
{
	char **enctype_list = NULL;
	char **enctype = NULL;
	uint32_t result = 0;
	bool ok = true;

	enctype_list = str_list_make(NULL, pszParmValue, NULL);
	if (enctype_list == NULL) {
		DBG_ERR("OOM: failed to make string list from %s\n",
			pszParmValue);
		ok = false;
		goto out;
	}

	for (enctype = enctype_list; *enctype != NULL; ++enctype) {
		if (strwicmp(*enctype, "arcfour-hmac-md5") == 0 ||
		    strwicmp(*enctype, "rc4-hmac") == 0)
		{
			result |= KERB_ENCTYPE_RC4_HMAC_MD5;
		}
		else if (strwicmp(*enctype, "aes128-cts-hmac-sha1-96") == 0 ||
			 strwicmp(*enctype, "aes128-cts") == 0)
		{
			result |= KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96;
		}
		else if (strwicmp(*enctype, "aes256-cts-hmac-sha1-96") == 0 ||
			 strwicmp(*enctype, "aes256-cts") == 0)
		{
			result |= KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96;
		}
		else {
			const char *bitstr = *enctype;
			int base;
			int error;
			unsigned long bit;

			/* See if the bit's specified in hexadecimal. */
			if (bitstr[0] == '0' &&
			    (bitstr[1] == 'x' || bitstr[2] == 'X'))
			{
				base = 16;
				bitstr += 2;
			}
			else {
				base = 10;
			}

			bit = smb_strtoul(bitstr, NULL, base, &error, SMB_STR_FULL_STR_CONV);
			if (error) {
				DBG_ERR("WARNING: Ignoring invalid value '%s' "
					"for parameter 'kdc default domain supported enctypes'\n",
					*enctype);
				ok = false;
			} else {
				result |= bit;
			}
		}
	}

	*(int *)ptr = result;
out:
	TALLOC_FREE(enctype_list);

	return ok;
}

static bool set_variable(TALLOC_CTX *mem_ctx, struct loadparm_service *service,
			 int parmnum, void *parm_ptr,
			 const char *pszParmName, const char *pszParmValue,
			 struct loadparm_context *lp_ctx, bool on_globals)
{
	int i;
	bool ok;

	/* if it is a special case then go ahead */
	if (parm_table[parmnum].special) {
		ok = parm_table[parmnum].special(lp_ctx, service, pszParmValue,
						  (char **)parm_ptr);
	} else {
		ok = set_variable_helper(mem_ctx, parmnum, parm_ptr,
					 pszParmName, pszParmValue);
	}

	if (!ok) {
		return false;
	}

	if (on_globals && (lp_ctx->flags[parmnum] & FLAG_DEFAULT)) {
		lp_ctx->flags[parmnum] &= ~FLAG_DEFAULT;
		/* we have to also unset FLAG_DEFAULT on aliases */
		for (i=parmnum-1;i>=0 && parm_table[i].offset == parm_table[parmnum].offset;i--) {
			lp_ctx->flags[i] &= ~FLAG_DEFAULT;
		}
		for (i=parmnum+1;i<num_parameters() && parm_table[i].offset == parm_table[parmnum].offset;i++) {
			lp_ctx->flags[i] &= ~FLAG_DEFAULT;
		}
	}
	return true;
}


bool lpcfg_do_global_parameter(struct loadparm_context *lp_ctx,
			       const char *pszParmName, const char *pszParmValue)
{
	int parmnum = lpcfg_map_parameter(pszParmName);
	void *parm_ptr;

	if (parmnum < 0) {
		if (strchr(pszParmName, ':')) {
			return lp_do_parameter_parametric(lp_ctx, NULL, pszParmName, pszParmValue, 0);
		}
		DEBUG(0, ("Ignoring unknown parameter \"%s\"\n", pszParmName));
		return true;
	}

	/* if the flag has been set on the command line, then don't allow override,
	   but don't report an error */
	if (lp_ctx->flags[parmnum] & FLAG_CMDLINE) {
		return true;
	}

	if (parm_table[parmnum].flags & FLAG_DEPRECATED) {
		char *suppress_env = getenv("SAMBA_DEPRECATED_SUPPRESS");
		bool print_warning = (suppress_env == NULL
				      || suppress_env[0] == '\0');
		if (print_warning) {
			DBG_WARNING("WARNING: The \"%s\" option "
				    "is deprecated\n",
				    pszParmName);

		}
	}

	parm_ptr = lpcfg_parm_ptr(lp_ctx, NULL, &parm_table[parmnum]);

	return set_variable(lp_ctx->globals->ctx, NULL, parmnum, parm_ptr,
			    pszParmName, pszParmValue, lp_ctx, true);
}

bool lpcfg_do_service_parameter(struct loadparm_context *lp_ctx,
				struct loadparm_service *service,
				const char *pszParmName, const char *pszParmValue)
{
	void *parm_ptr;
	int i;
	int parmnum = lpcfg_map_parameter(pszParmName);

	if (parmnum < 0) {
		if (strchr(pszParmName, ':')) {
			return lp_do_parameter_parametric(lp_ctx, service, pszParmName, pszParmValue, 0);
		}
		DEBUG(0, ("Ignoring unknown parameter \"%s\"\n", pszParmName));
		return true;
	}

	/* if the flag has been set on the command line, then don't allow override,
	   but don't report an error */
	if (lp_ctx->flags[parmnum] & FLAG_CMDLINE) {
		return true;
	}

	if (parm_table[parmnum].flags & FLAG_DEPRECATED) {
		char *suppress_env = getenv("SAMBA_DEPRECATED_SUPPRESS");
		bool print_warning = (suppress_env == NULL
				      || suppress_env[0] == '\0');
		if (print_warning) {
			DBG_WARNING("WARNING: The \"%s\" option "
				    "is deprecated\n",
				    pszParmName);

		}
	}

	if (parm_table[parmnum].p_class == P_GLOBAL) {
		DEBUG(0,
		      ("Global parameter %s found in service section!\n",
		       pszParmName));
		return true;
	}
	parm_ptr = ((char *)service) + parm_table[parmnum].offset;

	if (!service->copymap)
		init_copymap(service);

	/* this handles the aliases - set the copymap for other
	 * entries with the same data pointer */
	for (i = 0; parm_table[i].label; i++)
		if (parm_table[i].offset == parm_table[parmnum].offset &&
		    parm_table[i].p_class == parm_table[parmnum].p_class)
			bitmap_clear(service->copymap, i);

	return set_variable(service, service, parmnum, parm_ptr, pszParmName,
			    pszParmValue, lp_ctx, false);
}

/**
 * Process a parameter.
 */

bool lpcfg_do_parameter(const char *pszParmName, const char *pszParmValue,
			 void *userdata)
{
	struct loadparm_context *lp_ctx = (struct loadparm_context *)userdata;

	if (lp_ctx->bInGlobalSection)
		return lpcfg_do_global_parameter(lp_ctx, pszParmName,
					      pszParmValue);
	else
		return lpcfg_do_service_parameter(lp_ctx, lp_ctx->currentService,
						  pszParmName, pszParmValue);
}

/*
  variable argument do parameter
*/
bool lpcfg_do_global_parameter_var(struct loadparm_context *lp_ctx, const char *pszParmName, const char *fmt, ...) PRINTF_ATTRIBUTE(3, 4);
bool lpcfg_do_global_parameter_var(struct loadparm_context *lp_ctx,
				const char *pszParmName, const char *fmt, ...)
{
	char *s;
	bool ret;
	va_list ap;

	va_start(ap, fmt);
	s = talloc_vasprintf(NULL, fmt, ap);
	va_end(ap);
	ret = lpcfg_do_global_parameter(lp_ctx, pszParmName, s);
	talloc_free(s);
	return ret;
}


/*
  set a parameter from the commandline - this is called from command line parameter
  parsing code. It sets the parameter then marks the parameter as unable to be modified
  by smb.conf processing
*/
bool lpcfg_set_cmdline(struct loadparm_context *lp_ctx, const char *pszParmName,
		       const char *pszParmValue)
{
	int parmnum;
	int i;

	while (isspace((unsigned char)*pszParmValue)) pszParmValue++;

	parmnum = lpcfg_map_parameter(pszParmName);

	if (parmnum < 0 && strchr(pszParmName, ':')) {
		/* set a parametric option */
		bool ok;
		ok = lp_do_parameter_parametric(lp_ctx, NULL, pszParmName,
						pszParmValue, FLAG_CMDLINE);
		if (lp_ctx->s3_fns != NULL) {
			if (ok) {
				lp_ctx->s3_fns->store_cmdline(pszParmName, pszParmValue);
			}
		}
		return ok;
	}

	if (parmnum < 0) {
		DEBUG(0,("Unknown option '%s'\n", pszParmName));
		return false;
	}

	/* reset the CMDLINE flag in case this has been called before */
	lp_ctx->flags[parmnum] &= ~FLAG_CMDLINE;

	if (!lpcfg_do_global_parameter(lp_ctx, pszParmName, pszParmValue)) {
		return false;
	}

	lp_ctx->flags[parmnum] |= FLAG_CMDLINE;

	/* we have to also set FLAG_CMDLINE on aliases */
	for (i=parmnum-1;
	     i>=0 && parm_table[i].p_class == parm_table[parmnum].p_class &&
	     parm_table[i].offset == parm_table[parmnum].offset;
	     i--) {
		lp_ctx->flags[i] |= FLAG_CMDLINE;
	}
	for (i=parmnum+1;
	     i<num_parameters() &&
	     parm_table[i].p_class == parm_table[parmnum].p_class &&
	     parm_table[i].offset == parm_table[parmnum].offset;
	     i++) {
		lp_ctx->flags[i] |= FLAG_CMDLINE;
	}

	if (lp_ctx->s3_fns != NULL) {
		lp_ctx->s3_fns->store_cmdline(pszParmName, pszParmValue);
	}

	return true;
}

/*
  set a option from the commandline in 'a=b' format. Use to support --option
*/
bool lpcfg_set_option(struct loadparm_context *lp_ctx, const char *option)
{
	char *p, *s;
	bool ret;

	s = talloc_strdup(NULL, option);
	if (!s) {
		return false;
	}

	p = strchr(s, '=');
	if (!p) {
		talloc_free(s);
		return false;
	}

	*p = 0;

	ret = lpcfg_set_cmdline(lp_ctx, s, p+1);
	talloc_free(s);
	return ret;
}


#define BOOLSTR(b) ((b) ? "Yes" : "No")

/**
 * Print a parameter of the specified type.
 */

void lpcfg_print_parameter(struct parm_struct *p, void *ptr, FILE * f)
{
	/* For the separation of lists values that we print below */
	const char *list_sep = ", ";
	int i;
	switch (p->type)
	{
		case P_ENUM:
			for (i = 0; p->enum_list[i].name; i++) {
				if (*(int *)ptr == p->enum_list[i].value) {
					fprintf(f, "%s",
						p->enum_list[i].name);
					break;
				}
			}
			break;

		case P_BOOL:
			fprintf(f, "%s", BOOLSTR(*(bool *)ptr));
			break;

		case P_BOOLREV:
			fprintf(f, "%s", BOOLSTR(!*(bool *)ptr));
			break;

		case P_INTEGER:
		case P_BYTES:
			fprintf(f, "%d", *(int *)ptr);
			break;

		case P_CHAR:
			fprintf(f, "%c", *(char *)ptr);
			break;

		case P_OCTAL: {
			int val = *(int *)ptr;
			if (val == -1) {
				fprintf(f, "-1");
			} else {
				fprintf(f, "0%03o", val);
			}
			break;
		}

		case P_CMDLIST:
			list_sep = " ";

			FALL_THROUGH;
		case P_LIST:
			if ((char ***)ptr && *(char ***)ptr) {
				char **list = *(char ***)ptr;
				for (; *list; list++) {
					/* surround strings with whitespace in double quotes */
					if (*(list+1) == NULL) {
						/* last item, no extra separator */
						list_sep = "";
					}
					if ( strchr_m( *list, ' ' ) ) {
						fprintf(f, "\"%s\"%s", *list, list_sep);
					} else {
						fprintf(f, "%s%s", *list, list_sep);
					}
				}
			}
			break;

		case P_STRING:
		case P_USTRING:
			if (*(char **)ptr) {
				fprintf(f, "%s", *(char **)ptr);
			}
			break;
	}
}

/**
 * Check if two parameters are equal.
 */

static bool lpcfg_equal_parameter(parm_type type, void *ptr1, void *ptr2)
{
	switch (type) {
		case P_BOOL:
		case P_BOOLREV:
			return (*((bool *)ptr1) == *((bool *)ptr2));

		case P_INTEGER:
		case P_ENUM:
		case P_OCTAL:
		case P_BYTES:
			return (*((int *)ptr1) == *((int *)ptr2));

		case P_CHAR:
			return (*((char *)ptr1) == *((char *)ptr2));

		case P_LIST:
		case P_CMDLIST:
			return str_list_equal(*(const char ***)ptr1, *(const char ***)ptr2);

		case P_STRING:
		case P_USTRING:
		{
			char *p1 = *(char **)ptr1, *p2 = *(char **)ptr2;
			if (p1 && !*p1)
				p1 = NULL;
			if (p2 && !*p2)
				p2 = NULL;
			return (p1 == p2 || strequal(p1, p2));
		}
	}
	return false;
}

/**
 * Process a new section (service).
 *
 * At this stage all sections are services.
 * Later we'll have special sections that permit server parameters to be set.
 * Returns True on success, False on failure.
 */

static bool do_section(const char *pszSectionName, void *userdata)
{
	struct loadparm_context *lp_ctx = (struct loadparm_context *)userdata;
	bool bRetval;
	bool isglobal;

	if (lp_ctx->s3_fns != NULL) {
		return lp_ctx->s3_fns->do_section(pszSectionName, lp_ctx);
	}

	isglobal = ((strwicmp(pszSectionName, GLOBAL_NAME) == 0) ||
			 (strwicmp(pszSectionName, GLOBAL_NAME2) == 0));

	/* if we've just struck a global section, note the fact. */
	lp_ctx->bInGlobalSection = isglobal;

	/* check for multiple global sections */
	if (lp_ctx->bInGlobalSection) {
		DEBUG(4, ("Processing section \"[%s]\"\n", pszSectionName));
		bRetval = true;
		goto out;
	}

	/* if we have a current service, tidy it up before moving on */
	bRetval = true;

	if (lp_ctx->currentService != NULL)
		bRetval = lpcfg_service_ok(lp_ctx->currentService);

	/* if all is still well, move to the next record in the services array */
	if (bRetval) {
		/* We put this here to avoid an odd message order if messages are */
		/* issued by the post-processing of a previous section. */
		DEBUG(4, ("Processing section \"[%s]\"\n", pszSectionName));

		if ((lp_ctx->currentService = lpcfg_add_service(lp_ctx, lp_ctx->sDefault,
								   pszSectionName))
		    == NULL) {
			DEBUG(0, ("Failed to add a new service\n"));
			bRetval = false;
			goto out;
		}
	}
out:
	return bRetval;
}


/**
 * Determine if a particular base parameter is currently set to the default value.
 */

static bool is_default(void *base_structure, int i)
{
	void *def_ptr = ((char *)base_structure) + parm_table[i].offset;
	switch (parm_table[i].type) {
		case P_CMDLIST:
		case P_LIST:
			return str_list_equal((const char * const *)parm_table[i].def.lvalue,
					      *(const char * const **)def_ptr);
		case P_STRING:
		case P_USTRING:
			return strequal(parm_table[i].def.svalue,
					*(char **)def_ptr);
		case P_BOOL:
		case P_BOOLREV:
			return parm_table[i].def.bvalue ==
				*(bool *)def_ptr;
		case P_INTEGER:
		case P_CHAR:
		case P_OCTAL:
		case P_BYTES:
		case P_ENUM:
			return parm_table[i].def.ivalue ==
				*(int *)def_ptr;
	}
	return false;
}

/**
 *Display the contents of the global structure.
 */

void lpcfg_dump_globals(struct loadparm_context *lp_ctx, FILE *f,
			 bool show_defaults)
{
	int i;
	struct parmlist_entry *data;

	fprintf(f, "# Global parameters\n[global]\n");

	for (i = 0; parm_table[i].label; i++) {
		if (parm_table[i].p_class != P_GLOBAL) {
			continue;
		}

		if (parm_table[i].flags & FLAG_SYNONYM) {
			continue;
		}

		if (!show_defaults) {
			if (lp_ctx->flags && (lp_ctx->flags[i] & FLAG_DEFAULT)) {
				continue;
			}

			if (is_default(lp_ctx->globals, i)) {
				continue;
			}
		}

		fprintf(f, "\t%s = ", parm_table[i].label);
		lpcfg_print_parameter(&parm_table[i], lpcfg_parm_ptr(lp_ctx, NULL, &parm_table[i]), f);
		fprintf(f, "\n");
	}
	if (lp_ctx->globals->param_opt != NULL) {
		for (data = lp_ctx->globals->param_opt; data;
		     data = data->next) {
			if (!show_defaults && (data->priority & FLAG_DEFAULT)) {
				continue;
			}
			fprintf(f, "\t%s = %s\n", data->key, data->value);
		}
        }

}

/**
 * Display the contents of a single services record.
 */

void lpcfg_dump_a_service(struct loadparm_service * pService, struct loadparm_service *sDefault, FILE * f,
			  unsigned int *flags, bool show_defaults)
{
	int i;
	struct parmlist_entry *data;

	if (pService != sDefault)
		fprintf(f, "\n[%s]\n", pService->szService);

	for (i = 0; parm_table[i].label; i++) {
		if (parm_table[i].p_class != P_LOCAL) {
			continue;
		}

		if (parm_table[i].flags & FLAG_SYNONYM) {
			continue;
		}

		if (*parm_table[i].label == '-') {
			continue;
		}

		if (pService == sDefault) {
			if (!show_defaults) {
				if (flags && (flags[i] & FLAG_DEFAULT)) {
					continue;
				}

				if (is_default(sDefault, i)) {
					continue;
				}
			}
		} else {
			bool equal;

			equal = lpcfg_equal_parameter(parm_table[i].type,
						      ((char *)pService) +
						      parm_table[i].offset,
						      ((char *)sDefault) +
						      parm_table[i].offset);
			if (equal) {
				continue;
			}
		}

		fprintf(f, "\t%s = ", parm_table[i].label);
		lpcfg_print_parameter(&parm_table[i],
				((char *)pService) + parm_table[i].offset, f);
		fprintf(f, "\n");
	}
	if (pService->param_opt != NULL) {
		for (data = pService->param_opt; data; data = data->next) {
			if (!show_defaults && (data->priority & FLAG_DEFAULT)) {
				continue;
			}
			fprintf(f, "\t%s = %s\n", data->key, data->value);
		}
        }
}

bool lpcfg_dump_a_parameter(struct loadparm_context *lp_ctx,
			    struct loadparm_service *service,
			    const char *parm_name, FILE * f)
{
	struct parm_struct *parm;
	void *ptr;
	char *local_parm_name;
	char *parm_opt;
	const char *parm_opt_value;

	/* check for parametrical option */
	local_parm_name = talloc_strdup(lp_ctx, parm_name);
	if (local_parm_name == NULL) {
		return false;
	}

	parm_opt = strchr( local_parm_name, ':');

	if (parm_opt) {
		*parm_opt = '\0';
		parm_opt++;
		if (strlen(parm_opt)) {
			parm_opt_value = lpcfg_parm_string(lp_ctx, service,
				local_parm_name, parm_opt);
			if (parm_opt_value) {
				fprintf(f, "%s\n", parm_opt_value);
				TALLOC_FREE(local_parm_name);
				return true;
			}
		}
		TALLOC_FREE(local_parm_name);
		return false;
	}
	TALLOC_FREE(local_parm_name);

	/* parameter is not parametric, search the table */
	parm = lpcfg_parm_struct(lp_ctx, parm_name);
	if (!parm) {
		return false;
	}

	if (service != NULL && parm->p_class == P_GLOBAL) {
		return false;
	}

	ptr = lpcfg_parm_ptr(lp_ctx, service,parm);

	lpcfg_print_parameter(parm, ptr, f);
	fprintf(f, "\n");
	return true;
}

/**
 * Auto-load some home services.
 */
static void lpcfg_add_auto_services(struct loadparm_context *lp_ctx,
				    const char *str)
{
	return;
}

/***************************************************************************
 Initialise the sDefault parameter structure for the printer values.
***************************************************************************/

void init_printer_values(struct loadparm_context *lp_ctx, TALLOC_CTX *ctx,
			 struct loadparm_service *pService)
{
	/* choose defaults depending on the type of printing */
	switch (pService->printing) {
		case PRINT_BSD:
		case PRINT_AIX:
		case PRINT_LPRNT:
		case PRINT_LPROS2:
			lpcfg_string_set(ctx, &pService->lpq_command, "lpq -P'%p'");
			lpcfg_string_set(ctx, &pService->lprm_command, "lprm -P'%p' %j");
			lpcfg_string_set(ctx, &pService->print_command, "lpr -r -P'%p' %s");
			break;

		case PRINT_LPRNG:
		case PRINT_PLP:
			lpcfg_string_set(ctx, &pService->lpq_command, "lpq -P'%p'");
			lpcfg_string_set(ctx, &pService->lprm_command, "lprm -P'%p' %j");
			lpcfg_string_set(ctx, &pService->print_command, "lpr -r -P'%p' %s");
			lpcfg_string_set(ctx, &pService->queuepause_command, "lpc stop '%p'");
			lpcfg_string_set(ctx, &pService->queueresume_command, "lpc start '%p'");
			lpcfg_string_set(ctx, &pService->lppause_command, "lpc hold '%p' %j");
			lpcfg_string_set(ctx, &pService->lpresume_command, "lpc release '%p' %j");
			break;

		case PRINT_CUPS:
		case PRINT_IPRINT:
			/* set the lpq command to contain the destination printer
			   name only.  This is used by cups_queue_get() */
			lpcfg_string_set(ctx, &pService->lpq_command, "%p");
			lpcfg_string_set(ctx, &pService->lprm_command, "");
			lpcfg_string_set(ctx, &pService->print_command, "");
			lpcfg_string_set(ctx, &pService->lppause_command, "");
			lpcfg_string_set(ctx, &pService->lpresume_command, "");
			lpcfg_string_set(ctx, &pService->queuepause_command, "");
			lpcfg_string_set(ctx, &pService->queueresume_command, "");
			break;

		case PRINT_SYSV:
		case PRINT_HPUX:
			lpcfg_string_set(ctx, &pService->lpq_command, "lpstat -o%p");
			lpcfg_string_set(ctx, &pService->lprm_command, "cancel %p-%j");
			lpcfg_string_set(ctx, &pService->print_command, "lp -c -d%p %s; rm %s");
			lpcfg_string_set(ctx, &pService->queuepause_command, "disable %p");
			lpcfg_string_set(ctx, &pService->queueresume_command, "enable %p");
#ifndef HPUX
			lpcfg_string_set(ctx, &pService->lppause_command, "lp -i %p-%j -H hold");
			lpcfg_string_set(ctx, &pService->lpresume_command, "lp -i %p-%j -H resume");
#endif /* HPUX */
			break;

		case PRINT_QNX:
			lpcfg_string_set(ctx, &pService->lpq_command, "lpq -P%p");
			lpcfg_string_set(ctx, &pService->lprm_command, "lprm -P%p %j");
			lpcfg_string_set(ctx, &pService->print_command, "lp -r -P%p %s");
			break;

#if defined(DEVELOPER) || defined(ENABLE_SELFTEST)

	case PRINT_TEST:
	case PRINT_VLP: {
		const char *tdbfile;
		TALLOC_CTX *tmp_ctx = talloc_new(ctx);
		const char *tmp;

		tmp = lpcfg_parm_string(lp_ctx, NULL, "vlp", "tdbfile");
		if (tmp == NULL) {
			tmp = "/tmp/vlp.tdb";
		}

		tdbfile = talloc_asprintf(tmp_ctx, "tdbfile=%s", tmp);
		if (tdbfile == NULL) {
			tdbfile="tdbfile=/tmp/vlp.tdb";
		}

		tmp = talloc_asprintf(tmp_ctx, "vlp %s print %%p %%s",
				      tdbfile);
		lpcfg_string_set(ctx, &pService->print_command,
			   tmp ? tmp : "vlp print %p %s");

		tmp = talloc_asprintf(tmp_ctx, "vlp %s lpq %%p",
				      tdbfile);
		lpcfg_string_set(ctx, &pService->lpq_command,
			   tmp ? tmp : "vlp lpq %p");

		tmp = talloc_asprintf(tmp_ctx, "vlp %s lprm %%p %%j",
				      tdbfile);
		lpcfg_string_set(ctx, &pService->lprm_command,
			   tmp ? tmp : "vlp lprm %p %j");

		tmp = talloc_asprintf(tmp_ctx, "vlp %s lppause %%p %%j",
				      tdbfile);
		lpcfg_string_set(ctx, &pService->lppause_command,
			   tmp ? tmp : "vlp lppause %p %j");

		tmp = talloc_asprintf(tmp_ctx, "vlp %s lpresume %%p %%j",
				      tdbfile);
		lpcfg_string_set(ctx, &pService->lpresume_command,
			   tmp ? tmp : "vlp lpresume %p %j");

		tmp = talloc_asprintf(tmp_ctx, "vlp %s queuepause %%p",
				      tdbfile);
		lpcfg_string_set(ctx, &pService->queuepause_command,
			   tmp ? tmp : "vlp queuepause %p");

		tmp = talloc_asprintf(tmp_ctx, "vlp %s queueresume %%p",
				      tdbfile);
		lpcfg_string_set(ctx, &pService->queueresume_command,
			   tmp ? tmp : "vlp queueresume %p");
		TALLOC_FREE(tmp_ctx);

		break;
	}
#endif /* DEVELOPER */

	}
}


static int lpcfg_destructor(struct loadparm_context *lp_ctx)
{
	struct parmlist_entry *data;

	if (lp_ctx->refuse_free) {
		/* someone is trying to free the
		   global_loadparm_context.
		   We can't allow that. */
		return -1;
	}

	if (lp_ctx->globals->param_opt != NULL) {
		struct parmlist_entry *next;
		for (data = lp_ctx->globals->param_opt; data; data=next) {
			next = data->next;
			if (data->priority & FLAG_CMDLINE) continue;
			DLIST_REMOVE(lp_ctx->globals->param_opt, data);
			talloc_free(data);
		}
	}

	return 0;
}

/**
 * Initialise the global parameter structure.
 *
 * Note that most callers should use loadparm_init_global() instead
 */
struct loadparm_context *loadparm_init(TALLOC_CTX *mem_ctx)
{
	int i;
	char *myname;
	struct loadparm_context *lp_ctx;
	struct parmlist_entry *parm;
	char *logfile;

	lp_ctx = talloc_zero(mem_ctx, struct loadparm_context);
	if (lp_ctx == NULL)
		return NULL;

	talloc_set_destructor(lp_ctx, lpcfg_destructor);
	lp_ctx->bInGlobalSection = true;
	lp_ctx->globals = talloc_zero(lp_ctx, struct loadparm_global);
	/* This appears odd, but globals in s3 isn't a pointer */
	lp_ctx->globals->ctx = lp_ctx->globals;
	lp_ctx->globals->rpc_low_port = SERVER_TCP_LOW_PORT;
	lp_ctx->globals->rpc_high_port = SERVER_TCP_HIGH_PORT;
	lp_ctx->globals->weak_crypto = SAMBA_WEAK_CRYPTO_UNKNOWN;
	lp_ctx->sDefault = talloc_zero(lp_ctx, struct loadparm_service);
	lp_ctx->flags = talloc_zero_array(lp_ctx, unsigned int, num_parameters());

	lp_ctx->sDefault->max_print_jobs = 1000;
	lp_ctx->sDefault->available = true;
	lp_ctx->sDefault->browseable = true;
	lp_ctx->sDefault->read_only = true;
	lp_ctx->sDefault->map_archive = true;
	lp_ctx->sDefault->strict_locking = true;
	lp_ctx->sDefault->oplocks = true;
	lp_ctx->sDefault->create_mask = 0744;
	lp_ctx->sDefault->force_create_mode = 0000;
	lp_ctx->sDefault->directory_mask = 0755;
	lp_ctx->sDefault->force_directory_mode = 0000;
	lp_ctx->sDefault->aio_read_size = 1;
	lp_ctx->sDefault->aio_write_size = 1;
	lp_ctx->sDefault->smbd_search_ask_sharemode = true;
	lp_ctx->sDefault->smbd_getinfo_ask_sharemode = true;
	lp_ctx->sDefault->volume_serial_number = -1;

	DEBUG(3, ("Initialising global parameters\n"));

	for (i = 0; parm_table[i].label; i++) {
		if ((parm_table[i].type == P_STRING ||
		     parm_table[i].type == P_USTRING) &&
		    !(lp_ctx->flags[i] & FLAG_CMDLINE)) {
			TALLOC_CTX *parent_mem;
			char **r;
			if (parm_table[i].p_class == P_LOCAL) {
				parent_mem = lp_ctx->sDefault;
				r = (char **)(((char *)lp_ctx->sDefault) + parm_table[i].offset);
			} else {
				parent_mem = lp_ctx->globals;
				r = (char **)(((char *)lp_ctx->globals) + parm_table[i].offset);
			}
			lpcfg_string_set(parent_mem, r, "");
		}
	}

	logfile = talloc_asprintf(lp_ctx, "%s/log.samba", dyn_LOGFILEBASE);
	lpcfg_do_global_parameter(lp_ctx, "log file", logfile);
	talloc_free(logfile);

	lpcfg_do_global_parameter(lp_ctx, "log level", "0");

	lpcfg_do_global_parameter(lp_ctx, "syslog", "1");
	lpcfg_do_global_parameter(lp_ctx, "syslog only", "No");
	lpcfg_do_global_parameter(lp_ctx, "debug timestamp", "Yes");
	lpcfg_do_global_parameter(lp_ctx, "debug prefix timestamp", "No");
	lpcfg_do_global_parameter(lp_ctx, "debug hires timestamp", "Yes");
	lpcfg_do_global_parameter(lp_ctx, "debug syslog format", "No");
	lpcfg_do_global_parameter(lp_ctx, "debug pid", "No");
	lpcfg_do_global_parameter(lp_ctx, "debug uid", "No");
	lpcfg_do_global_parameter(lp_ctx, "debug class", "No");

	lpcfg_do_global_parameter(lp_ctx, "server role", "auto");
	lpcfg_do_global_parameter(lp_ctx, "domain logons", "No");
	lpcfg_do_global_parameter(lp_ctx, "domain master", "Auto");

	/* options that can be set on the command line must be initialised via
	   the slower lpcfg_do_global_parameter() to ensure that FLAG_CMDLINE is obeyed */
#ifdef TCP_NODELAY
	lpcfg_do_global_parameter(lp_ctx, "socket options", "TCP_NODELAY");
#endif
	lpcfg_do_global_parameter(lp_ctx, "workgroup", DEFAULT_WORKGROUP);
	myname = get_myname(lp_ctx);
	lpcfg_do_global_parameter(lp_ctx, "netbios name", myname);
	talloc_free(myname);
	lpcfg_do_global_parameter(lp_ctx,
				  "name resolve order",
				  DEFAULT_NAME_RESOLVE_ORDER);

	lpcfg_do_global_parameter(lp_ctx, "fstype", "NTFS");

	lpcfg_do_global_parameter(lp_ctx, "ntvfs handler", "unixuid default");
	lpcfg_do_global_parameter(lp_ctx, "max connections", "0");

	lpcfg_do_global_parameter(lp_ctx, "dcerpc endpoint servers", "epmapper wkssvc samr netlogon lsarpc drsuapi dssetup unixinfo browser eventlog6 backupkey dnsserver");
	lpcfg_do_global_parameter(lp_ctx, "server services", "s3fs rpc nbt wrepl ldap cldap kdc drepl winbindd ntp_signd kcc dnsupdate dns");
	lpcfg_do_global_parameter(lp_ctx, "kccsrv:samba_kcc", "true");
	/* the winbind method for domain controllers is for both RODC
	   auth forwarding and for trusted domains */
	lpcfg_do_global_parameter(lp_ctx, "private dir", dyn_PRIVATE_DIR);
	lpcfg_do_global_parameter(lp_ctx, "binddns dir", dyn_BINDDNS_DIR);
	lpcfg_do_global_parameter(lp_ctx, "registry:HKEY_LOCAL_MACHINE", "hklm.ldb");

	/* This hive should be dynamically generated by Samba using
	   data from the sam, but for the moment leave it in a tdb to
	   keep regedt32 from popping up an annoying dialog. */
	lpcfg_do_global_parameter(lp_ctx, "registry:HKEY_USERS", "hku.ldb");

	/* using UTF8 by default allows us to support all chars */
	lpcfg_do_global_parameter(lp_ctx, "unix charset", "UTF-8");

	/* Use codepage 850 as a default for the dos character set */
	lpcfg_do_global_parameter(lp_ctx, "dos charset", "CP850");

	/*
	 * Allow the default PASSWD_CHAT to be overridden in local.h.
	 */
	lpcfg_do_global_parameter(lp_ctx, "passwd chat", DEFAULT_PASSWD_CHAT);

	lpcfg_do_global_parameter(lp_ctx, "pid directory", dyn_PIDDIR);
	lpcfg_do_global_parameter(lp_ctx, "lock dir", dyn_LOCKDIR);
	lpcfg_do_global_parameter(lp_ctx, "state directory", dyn_STATEDIR);
	lpcfg_do_global_parameter(lp_ctx, "cache directory", dyn_CACHEDIR);
	lpcfg_do_global_parameter(lp_ctx, "ncalrpc dir", dyn_NCALRPCDIR);

	lpcfg_do_global_parameter(lp_ctx, "nbt client socket address", "0.0.0.0");
	lpcfg_do_global_parameter_var(lp_ctx, "server string",
				   "Samba %s", SAMBA_VERSION_STRING);

	lpcfg_do_global_parameter(lp_ctx, "password server", "*");

	lpcfg_do_global_parameter(lp_ctx, "max mux", "50");
	lpcfg_do_global_parameter(lp_ctx, "max xmit", "16644");
	lpcfg_do_global_parameter(lp_ctx, "host msdfs", "true");

	lpcfg_do_global_parameter(lp_ctx, "LargeReadwrite", "True");
	lpcfg_do_global_parameter(lp_ctx, "server min protocol", "SMB2_02");
	lpcfg_do_global_parameter(lp_ctx, "server max protocol", "SMB3");
	lpcfg_do_global_parameter(lp_ctx, "client min protocol", "SMB2_02");
	lpcfg_do_global_parameter(lp_ctx, "client max protocol", "default");
	lpcfg_do_global_parameter(lp_ctx, "client ipc min protocol", "default");
	lpcfg_do_global_parameter(lp_ctx, "client ipc max protocol", "default");
	lpcfg_do_global_parameter(lp_ctx, "security", "AUTO");
	lpcfg_do_global_parameter(lp_ctx, "EncryptPasswords", "True");
	lpcfg_do_global_parameter(lp_ctx, "ReadRaw", "True");
	lpcfg_do_global_parameter(lp_ctx, "WriteRaw", "True");
	lpcfg_do_global_parameter(lp_ctx, "NullPasswords", "False");
	lpcfg_do_global_parameter(lp_ctx, "old password allowed period", "60");
	lpcfg_do_global_parameter(lp_ctx, "ObeyPamRestrictions", "False");

	lpcfg_do_global_parameter(lp_ctx, "TimeServer", "False");
	lpcfg_do_global_parameter(lp_ctx, "BindInterfacesOnly", "False");
	lpcfg_do_global_parameter(lp_ctx, "Unicode", "True");
	lpcfg_do_global_parameter(lp_ctx, "ClientLanManAuth", "False");
	lpcfg_do_global_parameter(lp_ctx, "ClientNTLMv2Auth", "True");
	lpcfg_do_global_parameter(lp_ctx, "LanmanAuth", "False");
	lpcfg_do_global_parameter(lp_ctx, "NTLMAuth", "ntlmv2-only");
	lpcfg_do_global_parameter(lp_ctx, "NT hash store", "always");
	lpcfg_do_global_parameter(lp_ctx, "RawNTLMv2Auth", "False");
	lpcfg_do_global_parameter(lp_ctx, "client use spnego principal", "False");

	lpcfg_do_global_parameter(lp_ctx, "allow dcerpc auth level connect", "False");

	lpcfg_do_global_parameter(lp_ctx, "UnixExtensions", "True");

	lpcfg_do_global_parameter(lp_ctx, "PreferredMaster", "Auto");
	lpcfg_do_global_parameter(lp_ctx, "LocalMaster", "True");

	lpcfg_do_global_parameter(lp_ctx, "wins support", "False");
	lpcfg_do_global_parameter(lp_ctx, "dns proxy", "True");

	lpcfg_do_global_parameter(lp_ctx, "winbind separator", "\\");
	lpcfg_do_global_parameter(lp_ctx, "winbind sealed pipes", "True");
	lpcfg_do_global_parameter(lp_ctx, "winbind scan trusted domains", "False");
	lpcfg_do_global_parameter(lp_ctx, "require strong key", "True");
	lpcfg_do_global_parameter(lp_ctx, "reject md5 servers", "True");
	lpcfg_do_global_parameter(lp_ctx, "winbindd socket directory", dyn_WINBINDD_SOCKET_DIR);
	lpcfg_do_global_parameter(lp_ctx, "ntp signd socket directory", dyn_NTP_SIGND_SOCKET_DIR);
	lpcfg_do_global_parameter_var(lp_ctx, "gpo update command", "%s/samba-gpupdate", dyn_SCRIPTSBINDIR);
	lpcfg_do_global_parameter_var(lp_ctx, "apply group policies", "False");
	lpcfg_do_global_parameter_var(lp_ctx, "dns update command", "%s/samba_dnsupdate", dyn_SCRIPTSBINDIR);
	lpcfg_do_global_parameter_var(lp_ctx, "spn update command", "%s/samba_spnupdate", dyn_SCRIPTSBINDIR);
	lpcfg_do_global_parameter_var(lp_ctx, "samba kcc command",
					"%s/samba_kcc", dyn_SCRIPTSBINDIR);
#ifdef MIT_KDC_PATH
	lpcfg_do_global_parameter_var(lp_ctx,
				      "mit kdc command",
				      MIT_KDC_PATH);
#endif
	lpcfg_do_global_parameter(lp_ctx, "template shell", "/bin/false");
	lpcfg_do_global_parameter(lp_ctx, "template homedir", "/home/%D/%U");

	lpcfg_do_global_parameter(lp_ctx, "client signing", "default");
	lpcfg_do_global_parameter(lp_ctx, "client ipc signing", "default");
	lpcfg_do_global_parameter(lp_ctx, "server signing", "default");

	lpcfg_do_global_parameter(lp_ctx, "use mmap", "True");

	lpcfg_do_global_parameter(lp_ctx, "smb ports", "445 139");
	lpcfg_do_global_parameter_var(lp_ctx, "nbt port", "%d", NBT_NAME_SERVICE_PORT);
	lpcfg_do_global_parameter_var(lp_ctx, "dgram port", "%d", NBT_DGRAM_SERVICE_PORT);
	lpcfg_do_global_parameter(lp_ctx, "cldap port", "389");
	lpcfg_do_global_parameter(lp_ctx, "krb5 port", "88");
	lpcfg_do_global_parameter(lp_ctx, "kpasswd port", "464");
	lpcfg_do_global_parameter_var(lp_ctx, "dns port", "%d", DNS_SERVICE_PORT);

	lpcfg_do_global_parameter(lp_ctx, "kdc enable fast", "True");

	lpcfg_do_global_parameter(lp_ctx, "nt status support", "True");

	lpcfg_do_global_parameter(lp_ctx, "max wins ttl", "518400"); /* 6 days */
	lpcfg_do_global_parameter(lp_ctx, "min wins ttl", "21600");

	lpcfg_do_global_parameter(lp_ctx, "tls enabled", "True");
	lpcfg_do_global_parameter(lp_ctx, "tls verify peer", "as_strict_as_possible");
	lpcfg_do_global_parameter(lp_ctx, "tls keyfile", "tls/key.pem");
	lpcfg_do_global_parameter(lp_ctx, "tls certfile", "tls/cert.pem");
	lpcfg_do_global_parameter(lp_ctx, "tls cafile", "tls/ca.pem");
	lpcfg_do_global_parameter(lp_ctx,
				  "tls priority",
				  "NORMAL:-VERS-SSL3.0");

	lpcfg_do_global_parameter(lp_ctx, "nsupdate command", "/usr/bin/nsupdate -g");

        lpcfg_do_global_parameter(lp_ctx, "allow dns updates", "secure only");
	lpcfg_do_global_parameter(lp_ctx, "dns zone scavenging", "False");
        lpcfg_do_global_parameter(lp_ctx, "dns forwarder", "");

	lpcfg_do_global_parameter(lp_ctx, "algorithmic rid base", "1000");

	lpcfg_do_global_parameter(lp_ctx, "enhanced browsing", "True");

	lpcfg_do_global_parameter(lp_ctx, "winbind nss info", "template");

	lpcfg_do_global_parameter(lp_ctx, "server schannel", "True");
	lpcfg_do_global_parameter(lp_ctx, "server schannel require seal", "True");
	lpcfg_do_global_parameter(lp_ctx, "reject md5 clients", "True");

	lpcfg_do_global_parameter(lp_ctx, "short preserve case", "True");

	lpcfg_do_global_parameter(lp_ctx, "max open files", "16384");

	lpcfg_do_global_parameter(lp_ctx, "cups connection timeout", "30");

	lpcfg_do_global_parameter(lp_ctx, "locking", "True");

	lpcfg_do_global_parameter(lp_ctx, "block size", "1024");

	lpcfg_do_global_parameter(lp_ctx, "client use spnego", "True");

	lpcfg_do_global_parameter(lp_ctx, "change notify", "True");

	lpcfg_do_global_parameter(lp_ctx, "name cache timeout", "660");

	lpcfg_do_global_parameter(lp_ctx, "defer sharing violations", "True");

	lpcfg_do_global_parameter(lp_ctx, "ldap replication sleep", "1000");

	lpcfg_do_global_parameter(lp_ctx, "idmap backend", "tdb");

	lpcfg_do_global_parameter(lp_ctx, "enable privileges", "True");

	lpcfg_do_global_parameter_var(lp_ctx, "smb2 max write", "%u", DEFAULT_SMB2_MAX_WRITE);

	lpcfg_do_global_parameter(lp_ctx, "passdb backend", "tdbsam");

	lpcfg_do_global_parameter(lp_ctx, "deadtime", "10080");

	lpcfg_do_global_parameter(lp_ctx, "getwd cache", "True");

	lpcfg_do_global_parameter(lp_ctx, "winbind nested groups", "True");

	lpcfg_do_global_parameter(lp_ctx, "mangled names", "illegal");

	lpcfg_do_global_parameter_var(lp_ctx, "smb2 max credits", "%u", DEFAULT_SMB2_MAX_CREDITS);

	lpcfg_do_global_parameter(lp_ctx, "ldap ssl", "start tls");

	lpcfg_do_global_parameter(lp_ctx, "ldap deref", "auto");

	lpcfg_do_global_parameter(lp_ctx, "lm interval", "60");

	lpcfg_do_global_parameter(lp_ctx, "mangling method", "hash2");

	lpcfg_do_global_parameter(lp_ctx, "hide dot files", "True");

	lpcfg_do_global_parameter(lp_ctx, "browse list", "True");

	lpcfg_do_global_parameter(lp_ctx, "passwd chat timeout", "2");

	lpcfg_do_global_parameter(lp_ctx, "guest account", GUEST_ACCOUNT);

	lpcfg_do_global_parameter(lp_ctx, "client schannel", "True");

	lpcfg_do_global_parameter(lp_ctx, "smb encrypt", "default");

	lpcfg_do_global_parameter(lp_ctx, "max log size", "5000");

	lpcfg_do_global_parameter(lp_ctx, "idmap negative cache time", "120");

	lpcfg_do_global_parameter(lp_ctx, "ldap follow referral", "auto");

	lpcfg_do_global_parameter(lp_ctx, "multicast dns register", "yes");

	lpcfg_do_global_parameter(lp_ctx, "winbind reconnect delay", "30");

	lpcfg_do_global_parameter(lp_ctx, "winbind request timeout", "60");

	lpcfg_do_global_parameter(lp_ctx, "nt acl support", "yes");

	lpcfg_do_global_parameter(lp_ctx, "acl check permissions", "yes");

	lpcfg_do_global_parameter(lp_ctx, "keepalive", "300");

	lpcfg_do_global_parameter(lp_ctx, "smbd profiling level", "off");

	lpcfg_do_global_parameter(lp_ctx, "winbind cache time", "300");

	lpcfg_do_global_parameter(lp_ctx, "level2 oplocks", "yes");

	lpcfg_do_global_parameter(lp_ctx, "show add printer wizard", "yes");

	lpcfg_do_global_parameter(lp_ctx, "ldap page size", "1000");

	lpcfg_do_global_parameter(lp_ctx, "kernel share modes", "no");

	lpcfg_do_global_parameter(lp_ctx, "strict locking", "Auto");

	lpcfg_do_global_parameter(lp_ctx, "strict sync", "yes");

	lpcfg_do_global_parameter(lp_ctx, "map readonly", "no");

	lpcfg_do_global_parameter(lp_ctx, "allow trusted domains", "yes");

	lpcfg_do_global_parameter(lp_ctx, "default devmode", "yes");

	lpcfg_do_global_parameter(lp_ctx, "os level", "20");

	lpcfg_do_global_parameter(lp_ctx, "dos filetimes", "yes");

	lpcfg_do_global_parameter(lp_ctx, "mangling char", "~");

	lpcfg_do_global_parameter(lp_ctx, "printcap cache time", "750");

	lpcfg_do_global_parameter(lp_ctx, "create krb5 conf", "yes");

	lpcfg_do_global_parameter(lp_ctx, "winbind max clients", "200");

	lpcfg_do_global_parameter(lp_ctx, "acl map full control", "yes");

	lpcfg_do_global_parameter(lp_ctx, "nt pipe support", "yes");

	lpcfg_do_global_parameter(lp_ctx, "ldap debug threshold", "10");

	lpcfg_do_global_parameter(lp_ctx, "client ldap sasl wrapping", "seal");

	lpcfg_do_global_parameter(lp_ctx, "mdns name", "netbios");

	lpcfg_do_global_parameter(lp_ctx, "ldap server require strong auth", "yes");

	lpcfg_do_global_parameter(lp_ctx, "follow symlinks", "yes");

	lpcfg_do_global_parameter(lp_ctx, "machine password timeout", "604800");

	lpcfg_do_global_parameter(lp_ctx, "ldap connection timeout", "2");

	lpcfg_do_global_parameter(lp_ctx, "winbind expand groups", "0");

	lpcfg_do_global_parameter(lp_ctx, "stat cache", "yes");

	lpcfg_do_global_parameter(lp_ctx, "lpq cache time", "30");

	lpcfg_do_global_parameter_var(lp_ctx, "smb2 max trans", "%u", DEFAULT_SMB2_MAX_TRANSACT);

	lpcfg_do_global_parameter_var(lp_ctx, "smb2 max read", "%u", DEFAULT_SMB2_MAX_READ);

	lpcfg_do_global_parameter(lp_ctx, "durable handles", "yes");

	lpcfg_do_global_parameter(lp_ctx, "max stat cache size", "512");

	lpcfg_do_global_parameter(lp_ctx, "ldap passwd sync", "no");

	lpcfg_do_global_parameter(lp_ctx, "kernel change notify", "yes");

	lpcfg_do_global_parameter(lp_ctx, "max ttl", "259200");

	lpcfg_do_global_parameter(lp_ctx, "blocking locks", "yes");

	lpcfg_do_global_parameter(lp_ctx, "load printers", "yes");

	lpcfg_do_global_parameter(lp_ctx, "idmap cache time", "604800");

	lpcfg_do_global_parameter(lp_ctx, "preserve case", "yes");

	lpcfg_do_global_parameter(lp_ctx, "lm announce", "auto");

	lpcfg_do_global_parameter(lp_ctx, "afs token lifetime", "604800");

	lpcfg_do_global_parameter(lp_ctx, "enable core files", "yes");

	lpcfg_do_global_parameter(lp_ctx, "winbind max domain connections", "1");

	lpcfg_do_global_parameter(lp_ctx, "case sensitive", "auto");

	lpcfg_do_global_parameter(lp_ctx, "ldap timeout", "15");

	lpcfg_do_global_parameter(lp_ctx, "mangle prefix", "1");

	lpcfg_do_global_parameter(lp_ctx, "posix locking", "yes");

	lpcfg_do_global_parameter(lp_ctx, "lock spin time", "200");

	lpcfg_do_global_parameter(lp_ctx, "nmbd bind explicit broadcast", "yes");

	lpcfg_do_global_parameter(lp_ctx, "init logon delay", "100");

	lpcfg_do_global_parameter(lp_ctx, "usershare owner only", "yes");

	lpcfg_do_global_parameter(lp_ctx, "-valid", "yes");

	lpcfg_do_global_parameter_var(lp_ctx, "usershare path", "%s/usershares", get_dyn_STATEDIR());

#ifdef DEVELOPER
	lpcfg_do_global_parameter_var(lp_ctx, "panic action", "/bin/sleep 999999999");
#endif

	lpcfg_do_global_parameter(lp_ctx, "smb passwd file", get_dyn_SMB_PASSWD_FILE());

	lpcfg_do_global_parameter(lp_ctx, "logon home", "\\\\%N\\%U");

	lpcfg_do_global_parameter(lp_ctx, "logon path", "\\\\%N\\%U\\profile");

	lpcfg_do_global_parameter(lp_ctx, "printjob username", "%U");

	lpcfg_do_global_parameter(lp_ctx, "aio max threads", "100");

	lpcfg_do_global_parameter(lp_ctx, "smb2 leases", "yes");

	lpcfg_do_global_parameter(lp_ctx, "server multi channel support", "yes");

	lpcfg_do_global_parameter(lp_ctx, "kerberos encryption types", "all");

	lpcfg_do_global_parameter(lp_ctx,
				  "rpc server dynamic port range",
				  "49152-65535");

	lpcfg_do_global_parameter(lp_ctx, "prefork children", "4");
	lpcfg_do_global_parameter(lp_ctx, "prefork backoff increment", "10");
	lpcfg_do_global_parameter(lp_ctx, "prefork maximum backoff", "120");

	lpcfg_do_global_parameter(lp_ctx, "check parent directory delete on close", "no");

	lpcfg_do_global_parameter(lp_ctx, "ea support", "yes");

	lpcfg_do_global_parameter(lp_ctx, "store dos attributes", "yes");

	lpcfg_do_global_parameter(lp_ctx, "debug encryption", "no");

	lpcfg_do_global_parameter(lp_ctx, "spotlight backend", "noindex");

	lpcfg_do_global_parameter(
		lp_ctx, "ldap max anonymous request size", "256000");
	lpcfg_do_global_parameter(
		lp_ctx, "ldap max authenticated request size", "16777216");
	lpcfg_do_global_parameter(
		lp_ctx, "ldap max search request size", "256000");

	/* Async DNS query timeout in seconds. */
	lpcfg_do_global_parameter(lp_ctx, "async dns timeout", "10");

	lpcfg_do_global_parameter(lp_ctx,
				  "client smb encrypt",
				  "default");

	lpcfg_do_global_parameter(lp_ctx,
				  "client use kerberos",
				  "desired");

	lpcfg_do_global_parameter(lp_ctx,
				  "client protection",
				  "default");

	lpcfg_do_global_parameter(lp_ctx,
				  "smbd max xattr size",
				  "65536");

	lpcfg_do_global_parameter(lp_ctx,
				  "kernel dosmodes",
				  "False");

	lpcfg_do_global_parameter(lp_ctx,
				  "acl flag inherited canonicalization",
				  "yes");

	lpcfg_do_global_parameter(lp_ctx,
				  "winbind use krb5 enterprise principals",
				  "yes");

	lpcfg_do_global_parameter(lp_ctx,
				  "client smb3 signing algorithms",
				  DEFAULT_SMB3_SIGNING_ALGORITHMS);
	lpcfg_do_global_parameter(lp_ctx,
				  "server smb3 signing algorithms",
				  DEFAULT_SMB3_SIGNING_ALGORITHMS);

	lpcfg_do_global_parameter(lp_ctx,
				  "client smb3 encryption algorithms",
				  DEFAULT_SMB3_ENCRYPTION_ALGORITHMS);
	lpcfg_do_global_parameter(lp_ctx,
				  "server smb3 encryption algorithms",
				  DEFAULT_SMB3_ENCRYPTION_ALGORITHMS);

	lpcfg_do_global_parameter(lp_ctx,
				  "min domain uid",
				  "1000");

	lpcfg_do_global_parameter(lp_ctx,
				  "rpc start on demand helpers",
				  "yes");

	lpcfg_do_global_parameter(lp_ctx,
				  "ad dc functional level",
				  "2008_R2");

	lpcfg_do_global_parameter(lp_ctx,
				  "acl claims evaluation",
				  "AD DC only");

	for (i = 0; parm_table[i].label; i++) {
		if (!(lp_ctx->flags[i] & FLAG_CMDLINE)) {
			lp_ctx->flags[i] |= FLAG_DEFAULT;
		}
	}

	for (parm=lp_ctx->globals->param_opt; parm; parm=parm->next) {
		if (!(parm->priority & FLAG_CMDLINE)) {
			parm->priority |= FLAG_DEFAULT;
		}
	}

	for (parm=lp_ctx->sDefault->param_opt; parm; parm=parm->next) {
		if (!(parm->priority & FLAG_CMDLINE)) {
			parm->priority |= FLAG_DEFAULT;
		}
	}

	return lp_ctx;
}

/**
 * Initialise the global parameter structure.
 */
struct loadparm_context *loadparm_init_global(bool load_default)
{
	if (global_loadparm_context == NULL) {
		global_loadparm_context = loadparm_init(NULL);
	}
	if (global_loadparm_context == NULL) {
		return NULL;
	}
	global_loadparm_context->global = true;
	if (load_default && !global_loadparm_context->loaded) {
		lpcfg_load_default(global_loadparm_context);
	}
	global_loadparm_context->refuse_free = true;
	return global_loadparm_context;
}

/**
 * @brief Initialise the global parameter structure.
 *
 * This function initialized the globals if needed. Make sure that
 * gfree_loadparm() is called before the application exits.
 *
 * @param mem_ctx   The talloc memory context to allocate lp_ctx on.
 *
 * @param s3_fns    The loadparm helper functions to use
 *
 * @return An initialized lp_ctx pointer or NULL on error.
 */
struct loadparm_context *loadparm_init_s3(TALLOC_CTX *mem_ctx,
					  const struct loadparm_s3_helpers *s3_fns)
{
	struct loadparm_context *loadparm_context = talloc_zero(mem_ctx, struct loadparm_context);
	if (!loadparm_context) {
		return NULL;
	}
	loadparm_context->s3_fns = s3_fns;
	loadparm_context->globals = s3_fns->globals;
	loadparm_context->flags = s3_fns->flags;

	/* Make sure globals are correctly initialized */
	loadparm_context->s3_fns->init_globals(loadparm_context, false);

	return loadparm_context;
}

const char *lpcfg_configfile(struct loadparm_context *lp_ctx)
{
	return lp_ctx->szConfigFile;
}

const char *lp_default_path(void)
{
    if (getenv("SMB_CONF_PATH"))
        return getenv("SMB_CONF_PATH");
    else
        return dyn_CONFIGFILE;
}

/**
 * Update the internal state of a loadparm context after settings
 * have changed.
 */
static bool lpcfg_update(struct loadparm_context *lp_ctx)
{
	struct debug_settings settings;
	int max_protocol, min_protocol;
	TALLOC_CTX *tmp_ctx;
	const struct loadparm_substitution *lp_sub =
		lpcfg_noop_substitution();

	tmp_ctx = talloc_new(lp_ctx);
	if (tmp_ctx == NULL) {
		return false;
	}

	lpcfg_add_auto_services(lp_ctx, lpcfg_auto_services(lp_ctx, lp_sub, tmp_ctx));

	if (!lp_ctx->globals->wins_server_list && lp_ctx->globals->we_are_a_wins_server) {
		lpcfg_do_global_parameter(lp_ctx, "wins server", "127.0.0.1");
	}

	if (!lp_ctx->global) {
		TALLOC_FREE(tmp_ctx);
		return true;
	}

	panic_action = lp_ctx->globals->panic_action;

	reload_charcnv(lp_ctx);

	ZERO_STRUCT(settings);
	/* Add any more debug-related smb.conf parameters created in
	 * future here */
	settings.timestamp_logs = lp_ctx->globals->timestamp_logs;
	settings.debug_prefix_timestamp = lp_ctx->globals->debug_prefix_timestamp;
	settings.debug_hires_timestamp = lp_ctx->globals->debug_hires_timestamp;
	settings.debug_syslog_format = lp_ctx->globals->debug_syslog_format;
	settings.debug_pid = lp_ctx->globals->debug_pid;
	settings.debug_uid = lp_ctx->globals->debug_uid;
	settings.debug_class = lp_ctx->globals->debug_class;
	settings.max_log_size = lp_ctx->globals->max_log_size;
	debug_set_settings(&settings, lp_ctx->globals->logging,
			   lp_ctx->globals->syslog,
			   lp_ctx->globals->syslog_only);

	/* FIXME: This is a bit of a hack, but we can't use a global, since
	 * not everything that uses lp also uses the socket library */
	if (lpcfg_parm_bool(lp_ctx, NULL, "socket", "testnonblock", false)) {
		setenv("SOCKET_TESTNONBLOCK", "1", 1);
	} else {
		unsetenv("SOCKET_TESTNONBLOCK");
	}

	/* Check if command line max protocol < min protocol, if so
	 * report a warning to the user.
	 */
	max_protocol = lpcfg_client_max_protocol(lp_ctx);
	min_protocol = lpcfg_client_min_protocol(lp_ctx);
	if (lpcfg_client_max_protocol(lp_ctx) < lpcfg_client_min_protocol(lp_ctx)) {
		const char *max_protocolp, *min_protocolp;
		max_protocolp = lpcfg_get_smb_protocol(max_protocol);
		min_protocolp = lpcfg_get_smb_protocol(min_protocol);
		DBG_ERR("Max protocol %s is less than min protocol %s.\n",
			max_protocolp, min_protocolp);
	}

	TALLOC_FREE(tmp_ctx);
	return true;
}

bool lpcfg_load_default(struct loadparm_context *lp_ctx)
{
    const char *path;

    path = lp_default_path();

    if (!file_exist(path)) {
	    /* We allow the default smb.conf file to not exist,
	     * basically the equivalent of an empty file. */
	    return lpcfg_update(lp_ctx);
    }

    return lpcfg_load(lp_ctx, path);
}

/**
 * Load the services array from the services file.
 *
 * Return True on success, False on failure.
 */
static bool lpcfg_load_internal(struct loadparm_context *lp_ctx,
				const char *filename, bool set_global)
{
	char *n2;
	bool bRetval;

	if (lp_ctx->szConfigFile != NULL) {
		talloc_free(discard_const_p(char, lp_ctx->szConfigFile));
		lp_ctx->szConfigFile = NULL;
	}

	lp_ctx->szConfigFile = talloc_strdup(lp_ctx, filename);

	if (lp_ctx->s3_fns) {
		return lp_ctx->s3_fns->load(filename);
	}

	lp_ctx->bInGlobalSection = true;
	n2 = standard_sub_basic(lp_ctx, lp_ctx->szConfigFile);
	DEBUG(2, ("lpcfg_load: refreshing parameters from %s\n", n2));

	add_to_file_list(lp_ctx, &lp_ctx->file_lists, lp_ctx->szConfigFile, n2);

	/* We get sections first, so have to start 'behind' to make up */
	lp_ctx->currentService = NULL;
	bRetval = pm_process(n2, do_section, lpcfg_do_parameter, lp_ctx);

	/* finish up the last section */
	DEBUG(4, ("pm_process() returned %s\n", BOOLSTR(bRetval)));
	if (bRetval)
		if (lp_ctx->currentService != NULL)
			bRetval = lpcfg_service_ok(lp_ctx->currentService);

	bRetval = bRetval && lpcfg_update(lp_ctx);

	/* we do this unconditionally, so that it happens even
	   for a missing smb.conf */
	reload_charcnv(lp_ctx);

	if (bRetval == true && set_global) {
		/* set this up so that any child python tasks will
		   find the right smb.conf */
		setenv("SMB_CONF_PATH", filename, 1);

		/* set the context used by the lp_*() function
		   variants */
		global_loadparm_context = lp_ctx;
		lp_ctx->loaded = true;
	}

	return bRetval;
}

bool lpcfg_load_no_global(struct loadparm_context *lp_ctx, const char *filename)
{
    return lpcfg_load_internal(lp_ctx, filename, false);
}

bool lpcfg_load(struct loadparm_context *lp_ctx, const char *filename)
{
    return lpcfg_load_internal(lp_ctx, filename, true);
}

/**
 * Return the max number of services.
 */

int lpcfg_numservices(struct loadparm_context *lp_ctx)
{
	if (lp_ctx->s3_fns) {
		return lp_ctx->s3_fns->get_numservices();
	}

	return lp_ctx->iNumServices;
}

/**
 * Display the contents of the services array in human-readable form.
 */

void lpcfg_dump(struct loadparm_context *lp_ctx, FILE *f, bool show_defaults,
	     int maxtoprint)
{
	int iService;

	if (lp_ctx->s3_fns) {
		lp_ctx->s3_fns->dump(f, show_defaults, maxtoprint);
		return;
	}

	lpcfg_dump_globals(lp_ctx, f, show_defaults);

	lpcfg_dump_a_service(lp_ctx->sDefault, lp_ctx->sDefault, f, lp_ctx->flags, show_defaults);

	for (iService = 0; iService < maxtoprint; iService++)
		lpcfg_dump_one(f, show_defaults, lp_ctx->services[iService], lp_ctx->sDefault);
}

/**
 * Display the contents of one service in human-readable form.
 */
void lpcfg_dump_one(FILE *f, bool show_defaults, struct loadparm_service *service, struct loadparm_service *sDefault)
{
	if (service != NULL) {
		if (service->szService[0] == '\0')
			return;
		lpcfg_dump_a_service(service, sDefault, f, NULL, show_defaults);
	}
}

struct loadparm_service *lpcfg_servicebynum(struct loadparm_context *lp_ctx,
					    int snum)
{
	if (lp_ctx->s3_fns) {
		return lp_ctx->s3_fns->get_servicebynum(snum);
	}

	return lp_ctx->services[snum];
}

struct loadparm_service *lpcfg_service(struct loadparm_context *lp_ctx,
				    const char *service_name)
{
	int iService;
        char *serviceName;

	if (lp_ctx->s3_fns) {
		return lp_ctx->s3_fns->get_service(service_name);
	}

	for (iService = lp_ctx->iNumServices - 1; iService >= 0; iService--) {
		if (lp_ctx->services[iService] &&
		    lp_ctx->services[iService]->szService) {
			/*
			 * The substitution here is used to support %U is
			 * service names
			 */
			serviceName = standard_sub_basic(
					lp_ctx->services[iService],
					lp_ctx->services[iService]->szService);
			if (strequal(serviceName, service_name)) {
				talloc_free(serviceName);
				return lp_ctx->services[iService];
			}
			talloc_free(serviceName);
		}
	}

	DEBUG(7,("lpcfg_servicenumber: couldn't find %s\n", service_name));
	return NULL;
}

const char *lpcfg_servicename(const struct loadparm_service *service)
{
	return service ? lpcfg_string((const char *)service->szService) : NULL;
}

struct smb_iconv_handle *lpcfg_iconv_handle(struct loadparm_context *lp_ctx)
{
	if (lp_ctx == NULL) {
		return get_iconv_handle();
	}
	return lp_ctx->iconv_handle;
}

_PUBLIC_ void reload_charcnv(struct loadparm_context *lp_ctx)
{
	if (!lp_ctx->global) {
		return;
	}

	lp_ctx->iconv_handle =
		reinit_iconv_handle(lp_ctx,
				    lpcfg_dos_charset(lp_ctx),
				    lpcfg_unix_charset(lp_ctx));
	if (lp_ctx->iconv_handle == NULL) {
		smb_panic("reinit_iconv_handle failed");
	}
}

_PUBLIC_ char *lpcfg_tls_keyfile(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx)
{
	return lpcfg_private_path(mem_ctx, lp_ctx, lpcfg__tls_keyfile(lp_ctx));
}

_PUBLIC_ char *lpcfg_tls_certfile(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx)
{
	return lpcfg_private_path(mem_ctx, lp_ctx, lpcfg__tls_certfile(lp_ctx));
}

_PUBLIC_ char *lpcfg_tls_cafile(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx)
{
	return lpcfg_private_path(mem_ctx, lp_ctx, lpcfg__tls_cafile(lp_ctx));
}

_PUBLIC_ char *lpcfg_tls_crlfile(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx)
{
	return lpcfg_private_path(mem_ctx, lp_ctx, lpcfg__tls_crlfile(lp_ctx));
}

_PUBLIC_ char *lpcfg_tls_dhpfile(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx)
{
	return lpcfg_private_path(mem_ctx, lp_ctx, lpcfg__tls_dhpfile(lp_ctx));
}

struct gensec_settings *lpcfg_gensec_settings(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx)
{
	struct gensec_settings *settings = talloc_zero(mem_ctx, struct gensec_settings);
	if (settings == NULL)
		return NULL;
	SMB_ASSERT(lp_ctx != NULL);
	settings->lp_ctx = talloc_reference(settings, lp_ctx);
	settings->target_hostname = lpcfg_parm_string(lp_ctx, NULL, "gensec", "target_hostname");
	return settings;
}

int lpcfg_server_role(struct loadparm_context *lp_ctx)
{
	int domain_master = lpcfg__domain_master(lp_ctx);

	return lp_find_server_role(lpcfg__server_role(lp_ctx),
				   lpcfg__security(lp_ctx),
				   lpcfg__domain_logons(lp_ctx),
				   (domain_master == true) ||
				   (domain_master == Auto));
}

int lpcfg_security(struct loadparm_context *lp_ctx)
{
	return lp_find_security(lpcfg__server_role(lp_ctx),
				lpcfg__security(lp_ctx));
}

int lpcfg_client_max_protocol(struct loadparm_context *lp_ctx)
{
	int client_max_protocol = lpcfg__client_max_protocol(lp_ctx);
	if (client_max_protocol == PROTOCOL_DEFAULT) {
		return PROTOCOL_LATEST;
	}
	return client_max_protocol;
}

int lpcfg_client_ipc_min_protocol(struct loadparm_context *lp_ctx)
{
	int client_ipc_min_protocol = lpcfg__client_ipc_min_protocol(lp_ctx);
	if (client_ipc_min_protocol == PROTOCOL_DEFAULT) {
		client_ipc_min_protocol = lpcfg_client_min_protocol(lp_ctx);
	}
	if (client_ipc_min_protocol < PROTOCOL_NT1) {
		return PROTOCOL_NT1;
	}
	return client_ipc_min_protocol;
}

int lpcfg_client_ipc_max_protocol(struct loadparm_context *lp_ctx)
{
	int client_ipc_max_protocol = lpcfg__client_ipc_max_protocol(lp_ctx);
	if (client_ipc_max_protocol == PROTOCOL_DEFAULT) {
		return PROTOCOL_LATEST;
	}
	if (client_ipc_max_protocol < PROTOCOL_NT1) {
		return PROTOCOL_NT1;
	}
	return client_ipc_max_protocol;
}

int lpcfg_client_ipc_signing(struct loadparm_context *lp_ctx)
{
	int client_ipc_signing = lpcfg__client_ipc_signing(lp_ctx);
	if (client_ipc_signing == SMB_SIGNING_DEFAULT) {
		return SMB_SIGNING_REQUIRED;
	}
	return client_ipc_signing;
}

enum credentials_use_kerberos lpcfg_client_use_kerberos(struct loadparm_context *lp_ctx)
{
	if (lpcfg_weak_crypto(lp_ctx) == SAMBA_WEAK_CRYPTO_DISALLOWED) {
		return CRED_USE_KERBEROS_REQUIRED;
	}

	return lpcfg__client_use_kerberos(lp_ctx);
}

bool lpcfg_server_signing_allowed(struct loadparm_context *lp_ctx, bool *mandatory)
{
	bool allowed = true;
	enum smb_signing_setting signing_setting = lpcfg_server_signing(lp_ctx);

	*mandatory = false;

	if (signing_setting == SMB_SIGNING_DEFAULT) {
		/*
		 * If we are a domain controller, SMB signing is
		 * really important, as it can prevent a number of
		 * attacks on communications between us and the
		 * clients
		 *
		 * However, it really sucks (no sendfile, CPU
		 * overhead) performance-wise when used on a
		 * file server, so disable it by default
		 * on non-DCs
		 */

		if (lpcfg_server_role(lp_ctx) >= ROLE_ACTIVE_DIRECTORY_DC) {
			signing_setting = SMB_SIGNING_REQUIRED;
		} else {
			signing_setting = SMB_SIGNING_OFF;
		}
	}

	switch (signing_setting) {
	case SMB_SIGNING_REQUIRED:
		*mandatory = true;
		break;
	case SMB_SIGNING_DESIRED:
	case SMB_SIGNING_IF_REQUIRED:
		break;
	case SMB_SIGNING_OFF:
		allowed = false;
		break;
	case SMB_SIGNING_DEFAULT:
	case SMB_SIGNING_IPC_DEFAULT:
		smb_panic(__location__);
		break;
	}

	return allowed;
}

int lpcfg_tdb_hash_size(struct loadparm_context *lp_ctx, const char *name)
{
	const char *base;

	if (name == NULL) {
		return 0;
	}

	base = strrchr_m(name, '/');
	if (base != NULL) {
		base += 1;
	} else {
		base = name;
	}
	return lpcfg_parm_int(lp_ctx, NULL, "tdb_hashsize", base, 0);

}

int lpcfg_tdb_flags(struct loadparm_context *lp_ctx, int tdb_flags)
{
	if (!lpcfg_use_mmap(lp_ctx)) {
		tdb_flags |= TDB_NOMMAP;
	}
	return tdb_flags;
}

/*
 * Do not allow LanMan auth if unless NTLMv1 is also allowed
 *
 * This also ensures it is disabled if NTLM is totally disabled
 */
bool lpcfg_lanman_auth(struct loadparm_context *lp_ctx)
{
	enum ntlm_auth_level ntlm_auth_level = lpcfg_ntlm_auth(lp_ctx);

	if (ntlm_auth_level == NTLM_AUTH_ON) {
		return lpcfg__lanman_auth(lp_ctx);
	} else {
		return false;
	}
}

static char *lpcfg_noop_substitution_fn(
			TALLOC_CTX *mem_ctx,
			const struct loadparm_substitution *lp_sub,
			const char *raw_value,
			void *private_data)
{
	return talloc_strdup(mem_ctx, raw_value);
}

static const struct loadparm_substitution global_noop_substitution = {
	.substituted_string_fn = lpcfg_noop_substitution_fn,
};

const struct loadparm_substitution *lpcfg_noop_substitution(void)
{
	return &global_noop_substitution;
}

char *lpcfg_substituted_string(TALLOC_CTX *mem_ctx,
			       const struct loadparm_substitution *lp_sub,
			       const char *raw_value)
{
	return lp_sub->substituted_string_fn(mem_ctx,
					     lp_sub,
					     raw_value,
					     lp_sub->private_data);
}

/**
 * @brief Parse a string value of a given parameter to its integer enum value.
 *
 * @param[in]  param_name    The parameter name (e.g. 'client smb encrypt')
 *
 * @param[in]  param_value   The parameter value (e.g. 'required').
 *
 * @return The integer value of the enum the param_value matches or INT32_MIN
 * on error.
 */
int32_t lpcfg_parse_enum_vals(const char *param_name,
			      const char *param_value)
{
	struct parm_struct *parm = NULL;
	int32_t ret = INT32_MIN;
	bool ok;

	parm = lpcfg_parm_struct(NULL, param_name);
	if (parm == NULL) {
		return INT32_MIN;
	}

	ok = lp_set_enum_parm(parm, param_value, &ret);
	if (!ok) {
		return INT32_MIN;
	}

	return ret;
}

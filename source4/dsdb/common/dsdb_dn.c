/* 
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) Andrew Tridgell 2009
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2009

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
#include "dsdb/samdb/samdb.h"
#include <ldb_module.h>
#include "librpc/ndr/libndr.h"
#include "libcli/security/dom_sid.h"
#include "lib/util/smb_strtox.h"

enum dsdb_dn_format dsdb_dn_oid_to_format(const char *oid) 
{
	if (strcmp(oid, LDB_SYNTAX_DN) == 0) {
		return DSDB_NORMAL_DN;
	} else if (strcmp(oid, DSDB_SYNTAX_BINARY_DN) == 0) {
		return DSDB_BINARY_DN;
	} else if (strcmp(oid, DSDB_SYNTAX_STRING_DN) == 0) {
		return DSDB_STRING_DN;
	} else if (strcmp(oid, DSDB_SYNTAX_OR_NAME) == 0) {
		return DSDB_NORMAL_DN;
	} else {
		return DSDB_INVALID_DN;
	}
}

static struct dsdb_dn *dsdb_dn_construct_internal(TALLOC_CTX *mem_ctx, 
						  struct ldb_dn *dn, 
						  DATA_BLOB extra_part, 
						  enum dsdb_dn_format dn_format, 
						  const char *oid) 
{
	struct dsdb_dn *dsdb_dn = NULL;

	switch (dn_format) {
	case DSDB_BINARY_DN:
	case DSDB_STRING_DN:
		break;
	case DSDB_NORMAL_DN:
		if (extra_part.length != 0) {
			errno = EINVAL;
			return NULL;
		}
		break;
	case DSDB_INVALID_DN:
	default:
		errno = EINVAL;
		return NULL;
	}

	dsdb_dn = talloc(mem_ctx, struct dsdb_dn);
	if (!dsdb_dn) {
		errno = ENOMEM;
		return NULL;
	}
	dsdb_dn->dn = talloc_steal(dsdb_dn, dn);
	dsdb_dn->extra_part = extra_part;
	dsdb_dn->dn_format = dn_format;

	dsdb_dn->oid = oid;
	talloc_steal(dsdb_dn, extra_part.data);
	return dsdb_dn;
}

struct dsdb_dn *dsdb_dn_construct(TALLOC_CTX *mem_ctx, struct ldb_dn *dn, DATA_BLOB extra_part, 
				  const char *oid) 
{
	enum dsdb_dn_format dn_format = dsdb_dn_oid_to_format(oid);
	return dsdb_dn_construct_internal(mem_ctx, dn, extra_part, dn_format, oid);
}

struct dsdb_dn *dsdb_dn_parse_trusted(TALLOC_CTX *mem_ctx, struct ldb_context *ldb, 
				      const struct ldb_val *dn_blob, const char *dn_oid)
{
	struct dsdb_dn *dsdb_dn;
	struct ldb_dn *dn;
	size_t len;
	TALLOC_CTX *tmp_ctx;
	char *p1;
	char *p2;
	uint32_t blen;
	struct ldb_val bval;
	struct ldb_val dval;
	char *dn_str;
	int error = 0;

	enum dsdb_dn_format dn_format = dsdb_dn_oid_to_format(dn_oid);

	if (dn_blob == NULL || dn_blob->data == NULL || dn_blob->length == 0) {
		return NULL;
	}

	switch (dn_format) {
	case DSDB_INVALID_DN:
		return NULL;
	case DSDB_NORMAL_DN:
	{
		dn = ldb_dn_from_ldb_val(mem_ctx, ldb, dn_blob);
		if (!dn) {
			talloc_free(dn);
			return NULL;
		}
		return dsdb_dn_construct_internal(mem_ctx, dn, data_blob_null, dn_format, dn_oid);
	}
	case DSDB_BINARY_DN:
		if (dn_blob->length < 2 || dn_blob->data[0] != 'B' || dn_blob->data[1] != ':') {
			return NULL;
		}
		break;
	case DSDB_STRING_DN:
		if (dn_blob->length < 2 || dn_blob->data[0] != 'S' || dn_blob->data[1] != ':') {
			return NULL;
		}
		break;
	default:
		return NULL;
	}

	if (strlen((const char*)dn_blob->data) != dn_blob->length) {
		/* The RDN must not contain a character with value 0x0 */
		return NULL;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NULL;
	}

	len = dn_blob->length - 2;
	p1 = talloc_strndup(tmp_ctx, (const char *)dn_blob->data + 2, len);
	if (!p1) {
		goto failed;
	}

	errno = 0;
	blen = smb_strtoul(p1, &p2, 10, &error, SMB_STR_STANDARD);
	if (error != 0) {
		DEBUG(10, (__location__ ": failed\n"));
		goto failed;
	}
	if (p2 == NULL) {
		DEBUG(10, (__location__ ": failed\n"));
		goto failed;
	}
	if (p2[0] != ':') {
		DEBUG(10, (__location__ ": failed\n"));
		goto failed;
	}
	len -= PTR_DIFF(p2,p1);//???
	p1 = p2+1;
	len--;
		
	if (blen >= len) {
		DEBUG(10, (__location__ ": blen=%u len=%u\n", (unsigned)blen, (unsigned)len));
		goto failed;
	}
		
	p2 = p1 + blen;
	if (p2[0] != ':') {
		DEBUG(10, (__location__ ": %s", p2));
		goto failed;
	}
	dn_str = p2+1;
		
		
	switch (dn_format) {
	case DSDB_BINARY_DN:
		if ((blen % 2 != 0)) {
			DEBUG(10, (__location__ ": blen=%u - not an even number\n", (unsigned)blen));
			goto failed;
		}
		
		if (blen >= 2) {
			bval.length = (blen/2)+1;
			bval.data = talloc_size(tmp_ctx, bval.length);
			if (bval.data == NULL) {
				DEBUG(10, (__location__ ": err\n"));
				goto failed;
			}
			bval.data[bval.length-1] = 0;
		
			bval.length = strhex_to_str((char *)bval.data, bval.length,
						    p1, blen);
			if (bval.length != (blen / 2)) {
				DEBUG(10, (__location__ ": non hexadecimal characters found in binary prefix\n"));
				goto failed;
			}
		} else {
			bval = data_blob_null;
		}

		break;
	case DSDB_STRING_DN:
		bval = data_blob(p1, blen);
		break;
	default:
		/* never reached */
		return NULL;
	}
	

	dval.data = (uint8_t *)dn_str;
	dval.length = strlen(dn_str);
		
	dn = ldb_dn_from_ldb_val(tmp_ctx, ldb, &dval);
	if (!dn) {
		DEBUG(10, (__location__ ": err\n"));
		goto failed;
	}
		
	dsdb_dn = dsdb_dn_construct(mem_ctx, dn, bval, dn_oid);
		
	talloc_free(tmp_ctx);
	return dsdb_dn;

failed:
	talloc_free(tmp_ctx);
	return NULL;
}

struct dsdb_dn *dsdb_dn_parse(TALLOC_CTX *mem_ctx, struct ldb_context *ldb, 
			      const struct ldb_val *dn_blob, const char *dn_oid)
{
	struct dsdb_dn *dsdb_dn = dsdb_dn_parse_trusted(mem_ctx, ldb,
							dn_blob, dn_oid);
	if (dsdb_dn == NULL) {
		return NULL;
	}
	if (ldb_dn_validate(dsdb_dn->dn) == false) {
		DEBUG(10, ("could not parse %.*s as a %s DN",
			   (int)dn_blob->length, dn_blob->data,
			   dn_oid));
		return NULL;
	}
	return dsdb_dn;
}

static char *dsdb_dn_get_with_postfix(TALLOC_CTX *mem_ctx, 
				     struct dsdb_dn *dsdb_dn,
				     const char *postfix)
{
	if (!postfix) {
		return NULL;
	}

	switch (dsdb_dn->dn_format) {
	case DSDB_NORMAL_DN:
	{
		return talloc_strdup(mem_ctx, postfix);
	}
	case DSDB_BINARY_DN:
	{
		char *hexstr = data_blob_hex_string_upper(mem_ctx, &dsdb_dn->extra_part);
	
		char *p = talloc_asprintf(mem_ctx, "B:%u:%s:%s", (unsigned)(dsdb_dn->extra_part.length*2), hexstr, 
					  postfix);
		talloc_free(hexstr);
		return p;
	}
	case DSDB_STRING_DN:
	{
		return talloc_asprintf(mem_ctx, "S:%u:%*.*s:%s", 
				    (unsigned)(dsdb_dn->extra_part.length), 
				    (int)(dsdb_dn->extra_part.length), 
				    (int)(dsdb_dn->extra_part.length), 
				    (const char *)dsdb_dn->extra_part.data, 
				    postfix);
	}
	default:
		return NULL;
	}
}

char *dsdb_dn_get_linearized(TALLOC_CTX *mem_ctx, 
			      struct dsdb_dn *dsdb_dn)
{
	const char *postfix = ldb_dn_get_linearized(dsdb_dn->dn);
	return dsdb_dn_get_with_postfix(mem_ctx, dsdb_dn, postfix);
}

char *dsdb_dn_get_casefold(TALLOC_CTX *mem_ctx, 
			   struct dsdb_dn *dsdb_dn) 
{
	const char *postfix = ldb_dn_get_casefold(dsdb_dn->dn);
	return dsdb_dn_get_with_postfix(mem_ctx, dsdb_dn, postfix);
}

char *dsdb_dn_get_extended_linearized(TALLOC_CTX *mem_ctx, 
				      struct dsdb_dn *dsdb_dn,
				      int mode)
{
	char *postfix = ldb_dn_get_extended_linearized(mem_ctx, dsdb_dn->dn, mode);
	char *ret = dsdb_dn_get_with_postfix(mem_ctx, dsdb_dn, postfix);
	talloc_free(postfix);
	return ret;
}

int dsdb_dn_binary_canonicalise(struct ldb_context *ldb, void *mem_ctx,
				const struct ldb_val *in, struct ldb_val *out)
{
	struct dsdb_dn *dsdb_dn = dsdb_dn_parse(mem_ctx, ldb, in, DSDB_SYNTAX_BINARY_DN);
	
	if (!dsdb_dn) {
		return -1;
	}
	*out = data_blob_string_const(dsdb_dn_get_casefold(mem_ctx, dsdb_dn));
	talloc_free(dsdb_dn);
	if (!out->data) {
		return -1;
	}
	return 0;
}

int dsdb_dn_binary_comparison(struct ldb_context *ldb, void *mem_ctx,
				     const struct ldb_val *v1,
				     const struct ldb_val *v2)
{
	return ldb_any_comparison(ldb, mem_ctx, dsdb_dn_binary_canonicalise, v1, v2);
}

int dsdb_dn_string_canonicalise(struct ldb_context *ldb, void *mem_ctx,
				const struct ldb_val *in, struct ldb_val *out)
{
	struct dsdb_dn *dsdb_dn = dsdb_dn_parse(mem_ctx, ldb, in, DSDB_SYNTAX_STRING_DN);
	
	if (!dsdb_dn) {
		return -1;
	}
	*out = data_blob_string_const(dsdb_dn_get_casefold(mem_ctx, dsdb_dn));
	talloc_free(dsdb_dn);
	if (!out->data) {
		return -1;
	}
	return 0;
}

int dsdb_dn_string_comparison(struct ldb_context *ldb, void *mem_ctx,
				     const struct ldb_val *v1,
				     const struct ldb_val *v2)
{
	return ldb_any_comparison(ldb, mem_ctx, dsdb_dn_string_canonicalise, v1, v2);
}

/*
 * format a drsuapi_DsReplicaObjectIdentifier naming context as a string for debugging
 *
 * When forming a DN for DB access you must use drs_ObjectIdentifier_to_dn()
 */
char *drs_ObjectIdentifier_to_debug_string(TALLOC_CTX *mem_ctx,
					   struct drsuapi_DsReplicaObjectIdentifier *nc)
{
	char *ret = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (!GUID_all_zero(&nc->guid)) {
		char *guid = GUID_string(tmp_ctx, &nc->guid);
		if (guid) {
			ret = talloc_asprintf_append(ret, "<GUID=%s>;", guid);
		}
	}
	if (nc->__ndr_size_sid != 0 && nc->sid.sid_rev_num != 0) {
		const char *sid = dom_sid_string(tmp_ctx, &nc->sid);
		if (sid) {
			ret = talloc_asprintf_append(ret, "<SID=%s>;", sid);
		}
	}
	if (nc->__ndr_size_dn != 0 && nc->dn) {
		ret = talloc_asprintf_append(ret, "%s", nc->dn);
	}
	talloc_free(tmp_ctx);
	talloc_steal(mem_ctx, ret);
	return ret;
}

/*
 * Safely convert a drsuapi_DsReplicaObjectIdentifier into an LDB DN
 *
 * We need to have GUID and SID prority and not allow extended
 * components in the DN.
 *
 * We must also totally honour the prority even if the string DN is not valid or able to parse as a DN.
 */
static struct ldb_dn *drs_ObjectIdentifier_to_dn(TALLOC_CTX *mem_ctx,
						 struct ldb_context *ldb,
						 struct drsuapi_DsReplicaObjectIdentifier *nc)
{
	struct ldb_dn *new_dn = NULL;

	if (!GUID_all_zero(&nc->guid)) {
		struct GUID_txt_buf buf;
		char *guid = GUID_buf_string(&nc->guid, &buf);

		new_dn = ldb_dn_new_fmt(mem_ctx,
					ldb,
					"<GUID=%s>",
					guid);
		if (new_dn == NULL) {
			DBG_ERR("Failed to prepare drs_ObjectIdentifier "
				"GUID %s into a DN\n",
				guid);
			return NULL;
		}

		return new_dn;
	}

	if (nc->__ndr_size_sid != 0 && nc->sid.sid_rev_num != 0) {
		struct dom_sid_buf buf;
		char *sid = dom_sid_str_buf(&nc->sid, &buf);

		new_dn = ldb_dn_new_fmt(mem_ctx,
					ldb,
					"<SID=%s>",
					sid);
		if (new_dn == NULL) {
			DBG_ERR("Failed to prepare drs_ObjectIdentifier "
				"SID %s into a DN\n",
				sid);
			return NULL;
		}
		return new_dn;
	}

	if (nc->__ndr_size_dn != 0 && nc->dn) {
		int dn_comp_num = 0;
		bool new_dn_valid = false;

		new_dn = ldb_dn_new(mem_ctx, ldb, nc->dn);
		if (new_dn == NULL) {
			/* Set to WARNING as this is user-controlled, don't print the value into the logs */
			DBG_WARNING("Failed to parse string DN in "
				    "drs_ObjectIdentifier into an LDB DN\n");
			return NULL;
		}

		new_dn_valid = ldb_dn_validate(new_dn);
		if (!new_dn_valid) {
			/*
			 * Set to WARNING as this is user-controlled,
			 * but can print the value into the logs as it
			 * parsed a bit
			 */
			DBG_WARNING("Failed to validate string DN [%s] in "
				    "drs_ObjectIdentifier as an LDB DN\n",
				    ldb_dn_get_linearized(new_dn));
			return NULL;
		}

		dn_comp_num = ldb_dn_get_comp_num(new_dn);
		if (dn_comp_num <= 0) {
			/*
			 * Set to WARNING as this is user-controlled,
			 * but can print the value into the logs as it
			 * parsed a bit
			 */
			DBG_WARNING("DN [%s] in drs_ObjectIdentifier "
				    "must have 1 or more components\n",
				    ldb_dn_get_linearized(new_dn));
			return NULL;
		}

		if (ldb_dn_is_special(new_dn)) {
			/*
			 * Set to WARNING as this is user-controlled,
			 * but can print the value into the logs as it
			 * parsed a bit
			 */
			DBG_WARNING("New string DN [%s] in "
				    "drs_ObjectIdentifier is a "
				    "special LDB DN\n",
				    ldb_dn_get_linearized(new_dn));
			return NULL;
		}

		/*
		 * We want this just to be a string DN, extended
		 * components are manually handled above
		 */
		if (ldb_dn_has_extended(new_dn)) {
			/*
			 * Set to WARNING as this is user-controlled,
			 * but can print the value into the logs as it
			 * parsed a bit
			 */
			DBG_WARNING("Refusing to parse New string DN [%s] in "
				    "drs_ObjectIdentifier as an "
				    "extended LDB DN "
				    "(GUIDs and SIDs should be in the "
				    ".guid and .sid IDL elelements, "
				    "not in the string\n",
				    ldb_dn_get_extended_linearized(mem_ctx,
								   new_dn,
								   1));
			return NULL;
		}
		return new_dn;
	}

	DBG_WARNING("Refusing to parse empty string DN "
		    "(and no GUID or SID) "
		    "drs_ObjectIdentifier into a empty "
		    "(eg RootDSE) LDB DN\n");
	return NULL;
}

/*
 * Safely convert a drsuapi_DsReplicaObjectIdentifier into a validated
 * LDB DN of an existing DB entry, and/or find the NC root
 *
 * We need to have GUID and SID prority and not allow extended
 * components in the DN.
 *
 * We must also totally honour the prority even if the string DN is
 * not valid or able to parse as a DN.
 *
 * Finally, we must return the DN as found in the DB, as otherwise a
 * subsequence ldb_dn_compare(dn, nc_root) will fail (as this is based
 * on the string components).
 */
int drs_ObjectIdentifier_to_dn_and_nc_root(TALLOC_CTX *mem_ctx,
					   struct ldb_context *ldb,
					   struct drsuapi_DsReplicaObjectIdentifier *nc,
					   struct ldb_dn **normalised_dn,
					   struct ldb_dn **nc_root)
{
	int ret;
	struct ldb_dn *new_dn = NULL;

	new_dn = drs_ObjectIdentifier_to_dn(mem_ctx,
					    ldb,
					    nc);
	if (new_dn == NULL) {
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	ret = dsdb_normalise_dn_and_find_nc_root(ldb,
						 mem_ctx,
						 new_dn,
						 normalised_dn,
						 nc_root);
	if (ret != LDB_SUCCESS) {
		/*
		 * dsdb_normalise_dn_and_find_nc_root() sets LDB error
		 * strings, and the functions it calls do also
		 */
		DBG_NOTICE("Failed to find DN \"%s\" -> \"%s\" for normalisation: %s (%s)\n",
			   drs_ObjectIdentifier_to_debug_string(mem_ctx, nc),
			   ldb_dn_get_extended_linearized(mem_ctx, new_dn, 1),
			   ldb_errstring(ldb),
			   ldb_strerror(ret));
	}

	TALLOC_FREE(new_dn);
	return ret;
}

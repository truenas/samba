/*
   Unix SMB/CIFS implementation.
   DSDB schema header

   Copyright (C) Stefan Metzmacher <metze@samba.org> 2006-2007
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2006-2008
   Copyright (C) Matthieu Patou <mat@matws.net> 2011

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
#include "lib/util/dlinklist.h"
#include "dsdb/samdb/samdb.h"
#include <ldb_module.h>
#include "param/param.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "lib/util/tsort.h"

#undef strcasecmp

/* change this when we change something in our schema code that
 * requires a re-index of the database
 */
#define SAMDB_INDEXING_VERSION "3"

/*
  override the name to attribute handler function
 */
const struct ldb_schema_attribute *dsdb_attribute_handler_override(struct ldb_context *ldb,
								   void *private_data,
								   const char *name)
{
	struct dsdb_schema *schema = talloc_get_type_abort(private_data, struct dsdb_schema);
	const struct dsdb_attribute *a = dsdb_attribute_by_lDAPDisplayName(schema, name);
	if (a == NULL) {
		/* this will fall back to ldb internal handling */
		return NULL;
	}
	return a->ldb_schema_attribute;
}

/*
 * Set the attribute handlers onto the LDB, and potentially write the
 * @INDEXLIST, @IDXONE and @ATTRIBUTES records.  The @ATTRIBUTES records
 * are required so we can operate on a schema-less database (say the
 * backend during emergency fixes) and during the schema load.
 */
int dsdb_schema_set_indices_and_attributes(struct ldb_context *ldb,
					   struct dsdb_schema *schema,
					   enum schema_set_enum mode)
{
	int ret = LDB_SUCCESS;
	struct ldb_result *res;
	struct ldb_result *res_idx;
	struct dsdb_attribute *attr;
	struct ldb_message *mod_msg;
	TALLOC_CTX *mem_ctx;
	struct ldb_message *msg;
	struct ldb_message *msg_idx;

	struct loadparm_context *lp_ctx =
		talloc_get_type(ldb_get_opaque(ldb, "loadparm"),
				struct loadparm_context);
	bool guid_indexing = true;
	bool declare_ordered_integer_in_attributes = true;
	uint32_t pack_format_override;
	if (lp_ctx != NULL) {
		/*
		 * GUID indexing is wanted by Samba by default.  This allows
		 * an override in a specific case for downgrades.
		 */
		guid_indexing = lpcfg_parm_bool(lp_ctx,
						NULL,
						"dsdb",
						"guid index",
						true);
		/*
		 * If the pack format has been overridden to a previous
		 * version, then act like ORDERED_INTEGER doesn't exist,
		 * because it's a new type and we don't want to deal with
		 * possible issues with databases containing version 1 pack
		 * format and ordered types.
		 *
		 * This approach means that the @ATTRIBUTES will be
		 * incorrect for integers.  Many other @ATTRIBUTES
		 * values are gross simplifications, but the presence
		 * of the ORDERED_INTEGER keyword prevents the old
		 * Samba from starting and then forcing a reindex.
		 *
		 * It is too difficult to override the actual index
		 * formatter, but this doesn't matter in practice.
		 */
		pack_format_override =
			(intptr_t)ldb_get_opaque(ldb, "pack_format_override");
		if (pack_format_override == LDB_PACKING_FORMAT ||
		    pack_format_override == LDB_PACKING_FORMAT_NODN) {
			declare_ordered_integer_in_attributes = false;
		}
	}
	/* setup our own attribute name to schema handler */
	ldb_schema_attribute_set_override_handler(ldb, dsdb_attribute_handler_override, schema);
	ldb_schema_set_override_indexlist(ldb, true);
	if (guid_indexing) {
		ldb_schema_set_override_GUID_index(ldb, "objectGUID", "GUID");
	}

	if (mode == SCHEMA_MEMORY_ONLY) {
		return ret;
	}

	mem_ctx = talloc_new(ldb);
	if (!mem_ctx) {
		return ldb_oom(ldb);
	}

	msg = ldb_msg_new(mem_ctx);
	if (!msg) {
		ldb_oom(ldb);
		goto op_error;
	}
	msg_idx = ldb_msg_new(mem_ctx);
	if (!msg_idx) {
		ldb_oom(ldb);
		goto op_error;
	}
	msg->dn = ldb_dn_new(msg, ldb, "@ATTRIBUTES");
	if (!msg->dn) {
		ldb_oom(ldb);
		goto op_error;
	}
	msg_idx->dn = ldb_dn_new(msg_idx, ldb, "@INDEXLIST");
	if (!msg_idx->dn) {
		ldb_oom(ldb);
		goto op_error;
	}

	ret = ldb_msg_add_string(msg_idx, "@IDXONE", "1");
	if (ret != LDB_SUCCESS) {
		goto op_error;
	}

	if (guid_indexing) {
		ret = ldb_msg_add_string(msg_idx, "@IDXGUID", "objectGUID");
		if (ret != LDB_SUCCESS) {
			goto op_error;
		}

		ret = ldb_msg_add_string(msg_idx, "@IDX_DN_GUID", "GUID");
		if (ret != LDB_SUCCESS) {
			goto op_error;
		}
	}

	ret = ldb_msg_add_string(msg_idx, "@SAMDB_INDEXING_VERSION", SAMDB_INDEXING_VERSION);
	if (ret != LDB_SUCCESS) {
		goto op_error;
	}

	ret = ldb_msg_add_string(msg_idx, SAMBA_FEATURES_SUPPORTED_FLAG, "1");
	if (ret != LDB_SUCCESS) {
		goto op_error;
	}

	for (attr = schema->attributes; attr; attr = attr->next) {
		const char *syntax = attr->syntax->ldb_syntax;

		if (!syntax) {
			syntax = attr->syntax->ldap_oid;
		}

		/*
		 * Write out a rough approximation of the schema
		 * as an @ATTRIBUTES value, for bootstrapping.
		 * Only write ORDERED_INTEGER if we're using GUID indexes,
		 */
		if (strcmp(syntax, LDB_SYNTAX_INTEGER) == 0) {
			ret = ldb_msg_add_string(msg, attr->lDAPDisplayName, "INTEGER");
		} else if (strcmp(syntax, LDB_SYNTAX_ORDERED_INTEGER) == 0) {
			if (declare_ordered_integer_in_attributes &&
			    guid_indexing) {
				/*
				 * The normal production case
				 */
				ret = ldb_msg_add_string(msg,
							 attr->lDAPDisplayName,
							 "ORDERED_INTEGER");
			} else {
				/*
				 * For this mode, we are going back to
				 * before GUID indexing so we write it out
				 * as INTEGER
				 *
				 * Down in LDB, the special handler
				 * (index_format_fn) that made
				 * ORDERED_INTEGER and INTEGER
				 * different has been disabled.
				 */
				ret = ldb_msg_add_string(msg,
							 attr->lDAPDisplayName,
							 "INTEGER");
			}
		} else if (strcmp(syntax, LDB_SYNTAX_DIRECTORY_STRING) == 0) {
			ret = ldb_msg_add_string(msg, attr->lDAPDisplayName,
						 "CASE_INSENSITIVE");
		}
		if (ret != LDB_SUCCESS) {
			break;
		}

		/*
		 * Is the attribute indexed? By treating confidential attributes
		 * as unindexed, we force searches to go through the unindexed
		 * search path, avoiding observable timing differences.
		 */
		if (attr->searchFlags & SEARCH_FLAG_ATTINDEX &&
		    !(attr->searchFlags & SEARCH_FLAG_CONFIDENTIAL))
		{
			/*
			 * When preparing to downgrade Samba, we need to write
			 * out an LDB without the new key word ORDERED_INTEGER.
			 */
			if (strcmp(syntax, LDB_SYNTAX_ORDERED_INTEGER) == 0
			    && !declare_ordered_integer_in_attributes) {
				/*
				 * Ugly, but do nothing, the best
				 * thing is to omit the reference
				 * entirely, the next transaction will
				 * spot this and rewrite everything.
				 *
				 * This way nothing will look at the
				 * index for this attribute until
				 * Samba starts and this is all
				 * rewritten.
				 */
			} else {
				ret = ldb_msg_add_string(msg_idx, "@IDXATTR", attr->lDAPDisplayName);
				if (ret != LDB_SUCCESS) {
					break;
				}
			}
		}
	}

	if (ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		return ret;
	}

	/*
	 * Try to avoid churning the attributes too much,
	 * we only want to do this if they have changed
	 */
	ret = ldb_search(ldb, mem_ctx, &res, msg->dn, LDB_SCOPE_BASE, NULL,
			 NULL);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		if (mode == SCHEMA_COMPARE) {
			/* We are probably not in a transaction */
			goto wrong_mode;
		}
		ret = ldb_add(ldb, msg);
	} else if (ret != LDB_SUCCESS) {
	} else if (res->count != 1) {
		if (mode == SCHEMA_COMPARE) {
			/* We are probably not in a transaction */
			goto wrong_mode;
		}
		ret = ldb_add(ldb, msg);
	} else {
		/* Annoyingly added to our search results */
		ldb_msg_remove_attr(res->msgs[0], "distinguishedName");

		ret = ldb_msg_difference(ldb, mem_ctx,
		                         res->msgs[0], msg, &mod_msg);
		if (ret != LDB_SUCCESS) {
			goto op_error;
		}
		if (mod_msg->num_elements > 0) {
			/*
			 * Do the replace with the difference, as we
			 * are under the read lock and we wish to do a
			 * delete of any removed/renamed attributes
			 */
			if (mode == SCHEMA_COMPARE) {
				/* We are probably not in a transaction */
				goto wrong_mode;
			}
			ret = dsdb_modify(ldb, mod_msg, 0);
		}
		talloc_free(mod_msg);
	}

	if (ret == LDB_ERR_OPERATIONS_ERROR || ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS || ret == LDB_ERR_INVALID_DN_SYNTAX) {
		/* We might be on a read-only DB or LDAP */
		ret = LDB_SUCCESS;
	}
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to set schema into @ATTRIBUTES: %s\n",
			ldb_errstring(ldb));
		talloc_free(mem_ctx);
		return ret;
	}

	/* Now write out the indexes, as found in the schema (if they have changed) */

	ret = ldb_search(ldb, mem_ctx, &res_idx, msg_idx->dn, LDB_SCOPE_BASE,
			 NULL, NULL);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		if (mode == SCHEMA_COMPARE) {
			/* We are probably not in a transaction */
			goto wrong_mode;
		}
		ret = ldb_add(ldb, msg_idx);
	} else if (ret != LDB_SUCCESS) {
	} else if (res_idx->count != 1) {
		if (mode == SCHEMA_COMPARE) {
			/* We are probably not in a transaction */
			goto wrong_mode;
		}
		ret = ldb_add(ldb, msg_idx);
	} else {
		/* Annoyingly added to our search results */
		ldb_msg_remove_attr(res_idx->msgs[0], "distinguishedName");

		ret = ldb_msg_difference(ldb, mem_ctx,
		                         res_idx->msgs[0], msg_idx, &mod_msg);
		if (ret != LDB_SUCCESS) {
			goto op_error;
		}

		/*
		 * We don't want to re-index just because we didn't
		 * see this flag
		 *
		 * DO NOT backport this logic earlier than 4.7, it
		 * isn't needed and would be dangerous before 4.6,
		 * where we add logic to samba_dsdb to manage
		 * @SAMBA_FEATURES_SUPPORTED and need to know if the
		 * DB has been re-opened by an earlier version.
		 *
		 */

		if (mod_msg->num_elements == 1
		    && ldb_attr_cmp(mod_msg->elements[0].name,
				    SAMBA_FEATURES_SUPPORTED_FLAG) == 0) {
			/*
			 * Ignore only adding
			 * @SAMBA_FEATURES_SUPPORTED
			 */
		} else if (mod_msg->num_elements > 0) {

			/*
			 * Do the replace with the difference, as we
			 * are under the read lock and we wish to do a
			 * delete of any removed/renamed attributes
			 */
			if (mode == SCHEMA_COMPARE) {
				/* We are probably not in a transaction */
				goto wrong_mode;
			}
			ret = dsdb_modify(ldb, mod_msg, 0);
		}
		talloc_free(mod_msg);
	}
	if (ret == LDB_ERR_OPERATIONS_ERROR || ret == LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS || ret == LDB_ERR_INVALID_DN_SYNTAX) {
		/* We might be on a read-only DB */
		ret = LDB_SUCCESS;
	}

	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to set schema into @INDEXLIST: %s\n",
			ldb_errstring(ldb));
	}

	talloc_free(mem_ctx);
	return ret;

op_error:
	talloc_free(mem_ctx);
	return ldb_operr(ldb);

wrong_mode:
	talloc_free(mem_ctx);
	return LDB_ERR_BUSY;
}


/*
  create extra attribute shortcuts
 */
static void dsdb_setup_attribute_shortcuts(struct ldb_context *ldb, struct dsdb_schema *schema)
{
	struct dsdb_attribute *attribute;

	/* setup fast access to one_way_link and DN format */
	for (attribute=schema->attributes; attribute; attribute=attribute->next) {
		attribute->dn_format = dsdb_dn_oid_to_format(attribute->syntax->ldap_oid);

		if (attribute->dn_format == DSDB_INVALID_DN) {
			attribute->one_way_link = false;
			continue;
		}

		/* these are not considered to be one way links for
		   the purpose of DN link fixups */
		if (ldb_attr_cmp("distinguishedName", attribute->lDAPDisplayName) == 0 ||
		    ldb_attr_cmp("objectCategory", attribute->lDAPDisplayName) == 0) {
			attribute->one_way_link = false;
			continue;
		}

		if (attribute->linkID == 0) {
			attribute->one_way_link = true;
			continue;
		}
		/* handle attributes with a linkID but no backlink */
		if ((attribute->linkID & 1) == 0 &&
		    dsdb_attribute_by_linkID(schema, attribute->linkID + 1) == NULL) {
			attribute->one_way_link = true;
			continue;
		}
		attribute->one_way_link = false;
	}
}

static int uint32_cmp(uint32_t c1, uint32_t c2)
{
	if (c1 == c2) return 0;
	return c1 > c2 ? 1 : -1;
}

static int dsdb_compare_class_by_lDAPDisplayName(struct dsdb_class **c1, struct dsdb_class **c2)
{
	return strcasecmp((*c1)->lDAPDisplayName, (*c2)->lDAPDisplayName);
}
static int dsdb_compare_class_by_governsID_id(struct dsdb_class **c1, struct dsdb_class **c2)
{
	return uint32_cmp((*c1)->governsID_id, (*c2)->governsID_id);
}
static int dsdb_compare_class_by_governsID_oid(struct dsdb_class **c1, struct dsdb_class **c2)
{
	return strcasecmp((*c1)->governsID_oid, (*c2)->governsID_oid);
}
static int dsdb_compare_class_by_cn(struct dsdb_class **c1, struct dsdb_class **c2)
{
	return strcasecmp((*c1)->cn, (*c2)->cn);
}

static int dsdb_compare_attribute_by_lDAPDisplayName(struct dsdb_attribute **a1, struct dsdb_attribute **a2)
{
	return strcasecmp((*a1)->lDAPDisplayName, (*a2)->lDAPDisplayName);
}
static int dsdb_compare_attribute_by_attributeID_id(struct dsdb_attribute **a1, struct dsdb_attribute **a2)
{
	return uint32_cmp((*a1)->attributeID_id, (*a2)->attributeID_id);
}
static int dsdb_compare_attribute_by_msDS_IntId(struct dsdb_attribute **a1, struct dsdb_attribute **a2)
{
	return uint32_cmp((*a1)->msDS_IntId, (*a2)->msDS_IntId);
}
static int dsdb_compare_attribute_by_attributeID_oid(struct dsdb_attribute **a1, struct dsdb_attribute **a2)
{
	return strcasecmp((*a1)->attributeID_oid, (*a2)->attributeID_oid);
}
static int dsdb_compare_attribute_by_linkID(struct dsdb_attribute **a1, struct dsdb_attribute **a2)
{
	return uint32_cmp((*a1)->linkID, (*a2)->linkID);
}

/**
 * Clean up Classes and Attributes accessor arrays
 */
static void dsdb_sorted_accessors_free(struct dsdb_schema *schema)
{
	/* free classes accessors */
	TALLOC_FREE(schema->classes_by_lDAPDisplayName);
	TALLOC_FREE(schema->classes_by_governsID_id);
	TALLOC_FREE(schema->classes_by_governsID_oid);
	TALLOC_FREE(schema->classes_by_cn);
	/* free attribute accessors */
	TALLOC_FREE(schema->attributes_by_lDAPDisplayName);
	TALLOC_FREE(schema->attributes_by_attributeID_id);
	TALLOC_FREE(schema->attributes_by_msDS_IntId);
	TALLOC_FREE(schema->attributes_by_attributeID_oid);
	TALLOC_FREE(schema->attributes_by_linkID);
}

/*
  create the sorted accessor arrays for the schema
 */
int dsdb_setup_sorted_accessors(struct ldb_context *ldb,
				struct dsdb_schema *schema)
{
	struct dsdb_class *cur;
	struct dsdb_attribute *a;
	unsigned int i;
	unsigned int num_int_id;
	int ret;

	for (i=0; i < schema->classes_to_remove_size; i++) {
		DLIST_REMOVE(schema->classes, schema->classes_to_remove[i]);
		TALLOC_FREE(schema->classes_to_remove[i]);
	}
	for (i=0; i < schema->attributes_to_remove_size; i++) {
		DLIST_REMOVE(schema->attributes, schema->attributes_to_remove[i]);
		TALLOC_FREE(schema->attributes_to_remove[i]);
	}

	TALLOC_FREE(schema->classes_to_remove);
	schema->classes_to_remove_size = 0;
	TALLOC_FREE(schema->attributes_to_remove);
	schema->attributes_to_remove_size = 0;

	/* free all caches */
	dsdb_sorted_accessors_free(schema);

	/* count the classes */
	for (i=0, cur=schema->classes; cur; i++, cur=cur->next) /* noop */ ;
	schema->num_classes = i;

	/* setup classes_by_* */
	schema->classes_by_lDAPDisplayName = talloc_array(schema, struct dsdb_class *, i);
	schema->classes_by_governsID_id    = talloc_array(schema, struct dsdb_class *, i);
	schema->classes_by_governsID_oid   = talloc_array(schema, struct dsdb_class *, i);
	schema->classes_by_cn              = talloc_array(schema, struct dsdb_class *, i);
	if (schema->classes_by_lDAPDisplayName == NULL ||
	    schema->classes_by_governsID_id == NULL ||
	    schema->classes_by_governsID_oid == NULL ||
	    schema->classes_by_cn == NULL) {
		goto failed;
	}

	for (i=0, cur=schema->classes; cur; i++, cur=cur->next) {
		schema->classes_by_lDAPDisplayName[i] = cur;
		schema->classes_by_governsID_id[i]    = cur;
		schema->classes_by_governsID_oid[i]   = cur;
		schema->classes_by_cn[i]              = cur;
	}

	/* sort the arrays */
	TYPESAFE_QSORT(schema->classes_by_lDAPDisplayName, schema->num_classes, dsdb_compare_class_by_lDAPDisplayName);
	TYPESAFE_QSORT(schema->classes_by_governsID_id, schema->num_classes, dsdb_compare_class_by_governsID_id);
	TYPESAFE_QSORT(schema->classes_by_governsID_oid, schema->num_classes, dsdb_compare_class_by_governsID_oid);
	TYPESAFE_QSORT(schema->classes_by_cn, schema->num_classes, dsdb_compare_class_by_cn);

	/* now build the attribute accessor arrays */

	/* count the attributes
	 * and attributes with msDS-IntId set */
	num_int_id = 0;
	for (i=0, a=schema->attributes; a; i++, a=a->next) {
		if (a->msDS_IntId != 0) {
			num_int_id++;
		}
	}
	schema->num_attributes = i;
	schema->num_int_id_attr = num_int_id;

	/* setup attributes_by_* */
	schema->attributes_by_lDAPDisplayName = talloc_array(schema, struct dsdb_attribute *, i);
	schema->attributes_by_attributeID_id    = talloc_array(schema, struct dsdb_attribute *, i);
	schema->attributes_by_msDS_IntId        = talloc_array(schema,
	                                                       struct dsdb_attribute *, num_int_id);
	schema->attributes_by_attributeID_oid   = talloc_array(schema, struct dsdb_attribute *, i);
	schema->attributes_by_linkID              = talloc_array(schema, struct dsdb_attribute *, i);
	if (schema->attributes_by_lDAPDisplayName == NULL ||
	    schema->attributes_by_attributeID_id == NULL ||
	    schema->attributes_by_msDS_IntId == NULL ||
	    schema->attributes_by_attributeID_oid == NULL ||
	    schema->attributes_by_linkID == NULL) {
		goto failed;
	}

	num_int_id = 0;
	for (i=0, a=schema->attributes; a; i++, a=a->next) {
		schema->attributes_by_lDAPDisplayName[i] = a;
		schema->attributes_by_attributeID_id[i]    = a;
		schema->attributes_by_attributeID_oid[i]   = a;
		schema->attributes_by_linkID[i]          = a;
		/* append attr-by-msDS-IntId values */
		if (a->msDS_IntId != 0) {
			schema->attributes_by_msDS_IntId[num_int_id] = a;
			num_int_id++;
		}
	}
	SMB_ASSERT(num_int_id == schema->num_int_id_attr);

	/* sort the arrays */
	TYPESAFE_QSORT(schema->attributes_by_lDAPDisplayName, schema->num_attributes, dsdb_compare_attribute_by_lDAPDisplayName);
	TYPESAFE_QSORT(schema->attributes_by_attributeID_id, schema->num_attributes, dsdb_compare_attribute_by_attributeID_id);
	TYPESAFE_QSORT(schema->attributes_by_msDS_IntId, schema->num_int_id_attr, dsdb_compare_attribute_by_msDS_IntId);
	TYPESAFE_QSORT(schema->attributes_by_attributeID_oid, schema->num_attributes, dsdb_compare_attribute_by_attributeID_oid);
	TYPESAFE_QSORT(schema->attributes_by_linkID, schema->num_attributes, dsdb_compare_attribute_by_linkID);

	dsdb_setup_attribute_shortcuts(ldb, schema);

	ret = schema_fill_constructed(schema);
	if (ret != LDB_SUCCESS) {
		dsdb_sorted_accessors_free(schema);
		return ret;
	}

	return LDB_SUCCESS;

failed:
	dsdb_sorted_accessors_free(schema);
	return ldb_oom(ldb);
}

/**
 * Attach the schema to an opaque pointer on the ldb,
 * so ldb modules can find it
 */
int dsdb_set_schema_refresh_function(struct ldb_context *ldb,
				     dsdb_schema_refresh_fn refresh_fn,
				     struct ldb_module *module)
{
	int ret = ldb_set_opaque(ldb, "dsdb_schema_refresh_fn", refresh_fn);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_set_opaque(ldb, "dsdb_schema_refresh_fn_private_data", module);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return LDB_SUCCESS;
}

/**
 * Attach the schema to an opaque pointer on the ldb,
 * so ldb modules can find it
 */
int dsdb_set_schema(struct ldb_context *ldb,
		    struct dsdb_schema *schema,
		    enum schema_set_enum write_indices_and_attributes)
{
	struct dsdb_schema *old_schema;
	int ret;

	ret = dsdb_setup_sorted_accessors(ldb, schema);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	old_schema = ldb_get_opaque(ldb, "dsdb_schema");

	ret = ldb_set_opaque(ldb, "dsdb_use_global_schema", NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_set_opaque(ldb, "dsdb_schema", schema);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	talloc_steal(ldb, schema);

	/* Set the new attributes based on the new schema */
	ret = dsdb_schema_set_indices_and_attributes(ldb, schema,
						     write_indices_and_attributes);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/*
	 * Remove the reference to the schema we just overwrote - if there was
	 * none, NULL is harmless here.
	 */
	if (old_schema != schema) {
		talloc_unlink(ldb, old_schema);
	}

	return ret;
}

/**
 * Global variable to hold one copy of the schema, used to avoid memory bloat
 */
static struct dsdb_schema *global_schema;

/**
 * Make this ldb use a specified schema, already fully calculated and belonging to another ldb
 *
 * The write_indices_and_attributes controls writing of the @ records
 * because we cannot write to a database that does not yet exist on
 * disk.
 */
int dsdb_reference_schema(struct ldb_context *ldb, struct dsdb_schema *schema,
			  enum schema_set_enum write_indices_and_attributes)
{
	int ret;
	void *ptr;
	void *schema_parent = NULL;
	bool is_already_parent;
	struct dsdb_schema *old_schema;
	old_schema = ldb_get_opaque(ldb, "dsdb_schema");
	ret = ldb_set_opaque(ldb, "dsdb_schema", schema);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* Remove the reference to the schema we just overwrote - if there was
	 * none, NULL is harmless here */
	talloc_unlink(ldb, old_schema);

	/* Reference schema on ldb if it wasn't done already */
	schema_parent = talloc_parent(schema);
	is_already_parent = (schema_parent == ldb);
	if (!is_already_parent) {
		ptr = talloc_reference(ldb, schema);
		if (ptr == NULL) {
			return ldb_oom(ldb);
		}
	}

	/* Make this ldb use local schema preferably */
	ret = ldb_set_opaque(ldb, "dsdb_use_global_schema", NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_set_opaque(ldb, "dsdb_refresh_fn", NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_set_opaque(ldb, "dsdb_refresh_fn_private_data", NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = dsdb_schema_set_indices_and_attributes(ldb, schema, write_indices_and_attributes);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}

/**
 * Make this ldb use the 'global' schema, setup to avoid having multiple copies in this process
 */
int dsdb_set_global_schema(struct ldb_context *ldb)
{
	int ret;
	void *use_global_schema = (void *)1;
	void *ptr;
	struct dsdb_schema *old_schema = ldb_get_opaque(ldb, "dsdb_schema");

	ret = ldb_set_opaque(ldb, "dsdb_use_global_schema", use_global_schema);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (global_schema == NULL) {
		return LDB_SUCCESS;
	}

	/* Remove any pointer to a previous schema */
	ret = ldb_set_opaque(ldb, "dsdb_schema", NULL);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* Remove the reference to the schema we just overwrote - if there was
	 * none, NULL is harmless here */
	talloc_unlink(ldb, old_schema);

	/* Set the new attributes based on the new schema */
	/* Don't write indices and attributes, it's expensive */
	ret = dsdb_schema_set_indices_and_attributes(ldb, global_schema, SCHEMA_MEMORY_ONLY);
	if (ret == LDB_SUCCESS) {
		void *schema_parent = talloc_parent(global_schema);
		bool is_already_parent =
			(schema_parent == ldb);
		if (!is_already_parent) {
			ptr = talloc_reference(ldb, global_schema);
			if (ptr == NULL) {
				return ldb_oom(ldb);
			}
			ret = ldb_set_opaque(ldb, "dsdb_schema", global_schema);
		}
	}

	return ret;
}

bool dsdb_uses_global_schema(struct ldb_context *ldb)
{
	return (ldb_get_opaque(ldb, "dsdb_use_global_schema") != NULL);
}

/**
 * Find the schema object for this ldb
 *
 * If reference_ctx is not NULL, then talloc_reference onto that context
 */

struct dsdb_schema *dsdb_get_schema(struct ldb_context *ldb, TALLOC_CTX *reference_ctx)
{
	const void *p;
	struct dsdb_schema *schema_out = NULL;
	struct dsdb_schema *schema_in = NULL;
	dsdb_schema_refresh_fn refresh_fn;
	struct ldb_module *loaded_from_module;
	bool use_global_schema;
	TALLOC_CTX *tmp_ctx = talloc_new(reference_ctx);
	if (tmp_ctx == NULL) {
		return NULL;
	}

	/* see if we have a cached copy */
	use_global_schema = dsdb_uses_global_schema(ldb);
	if (use_global_schema) {
		schema_in = global_schema;
	} else {
		p = ldb_get_opaque(ldb, "dsdb_schema");
		if (p != NULL) {
			schema_in = talloc_get_type_abort(p, struct dsdb_schema);
		}
	}

	refresh_fn = ldb_get_opaque(ldb, "dsdb_schema_refresh_fn");
	if (refresh_fn) {
		loaded_from_module = ldb_get_opaque(ldb, "dsdb_schema_refresh_fn_private_data");

		SMB_ASSERT(loaded_from_module && (ldb_module_get_ctx(loaded_from_module) == ldb));
	}

	if (refresh_fn) {
		/* We need to guard against recursive calls here */
		if (ldb_set_opaque(ldb, "dsdb_schema_refresh_fn", NULL) != LDB_SUCCESS) {
			ldb_debug_set(ldb, LDB_DEBUG_FATAL,
				      "dsdb_get_schema: clearing dsdb_schema_refresh_fn failed");
		} else {
			schema_out = refresh_fn(loaded_from_module,
						ldb_get_event_context(ldb),
						schema_in,
						use_global_schema);
		}
		if (ldb_set_opaque(ldb, "dsdb_schema_refresh_fn", refresh_fn) != LDB_SUCCESS) {
			ldb_debug_set(ldb, LDB_DEBUG_FATAL,
				      "dsdb_get_schema: re-setting dsdb_schema_refresh_fn failed");
		}
		if (!schema_out) {
			schema_out = schema_in;
			ldb_debug_set(ldb, LDB_DEBUG_FATAL,
				      "dsdb_get_schema: refresh_fn() failed");
		}
	} else {
		schema_out = schema_in;
	}

	/* This removes the extra reference above */
	talloc_free(tmp_ctx);

	/*
	 * If ref ctx exists and doesn't already reference schema, then add
	 * a reference.  Otherwise, just return schema.
	 *
	 * We must use talloc_parent(), which is not quite free (there
	 * is no direct parent pointer in talloc, only one on the
	 * first child within a linked list), but is much cheaper than
	 * talloc_is_parent() which walks the whole tree up to the top
	 * looking for a potential grand-grand(etc)-parent.
	 */
	if (reference_ctx == NULL) {
		return schema_out;
	} else {
		void *schema_parent = talloc_parent(schema_out);
		bool is_already_parent =
			schema_parent == reference_ctx;
		if (is_already_parent) {
			return schema_out;
		} else {
			return talloc_reference(reference_ctx,
						schema_out);
		}
	}
}

/**
 * Make the schema found on this ldb the 'global' schema
 */

void dsdb_make_schema_global(struct ldb_context *ldb, struct dsdb_schema *schema)
{
	if (!schema) {
		return;
	}

	if (global_schema) {
		talloc_unlink(NULL, global_schema);
	}

	/* we want the schema to be around permanently */
	talloc_reparent(ldb, NULL, schema);
	global_schema = schema;

	/* This calls the talloc_reference() of the global schema back onto the ldb */
	dsdb_set_global_schema(ldb);
}

/**
 * When loading the schema from LDIF files, we don't get the extended DNs.
 *
 * We need to set these up, so that from the moment we start the provision,
 * the defaultObjectCategory links are set up correctly.
 */
int dsdb_schema_fill_extended_dn(struct ldb_context *ldb, struct dsdb_schema *schema)
{
	struct dsdb_class *cur;
	const struct dsdb_class *target_class;
	for (cur = schema->classes; cur; cur = cur->next) {
		const struct ldb_val *rdn;
		struct ldb_val guid;
		NTSTATUS status;
		int ret;
		struct ldb_dn *dn = ldb_dn_new(NULL, ldb, cur->defaultObjectCategory);

		if (!dn) {
			return LDB_ERR_INVALID_DN_SYNTAX;
		}
		rdn = ldb_dn_get_component_val(dn, 0);
		if (!rdn) {
			talloc_free(dn);
			return LDB_ERR_INVALID_DN_SYNTAX;
		}
		target_class = dsdb_class_by_cn_ldb_val(schema, rdn);
		if (!target_class) {
			talloc_free(dn);
			return LDB_ERR_CONSTRAINT_VIOLATION;
		}

		status = GUID_to_ndr_blob(&target_class->objectGUID, dn, &guid);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(dn);
			return ldb_operr(ldb);
		}
		ret = ldb_dn_set_extended_component(dn, "GUID", &guid);
		if (ret != LDB_SUCCESS) {
			ret = ldb_error(ldb, ret, "Could not set GUID");
			talloc_free(dn);
			return ret;
		}

		cur->defaultObjectCategory = ldb_dn_get_extended_linearized(cur, dn, 1);
		talloc_free(dn);
	}
	return LDB_SUCCESS;
}

/**
 * @brief Add a new element to the schema and checks if it's a duplicate
 *
 * This function will add a new element to the schema and checks for existing
 * duplicates.
 *
 * @param[in]  ldb                A pointer to an LDB context
 *
 * @param[in]  schema             A pointer to the dsdb_schema where the element
 *                                will be added.
 *
 * @param[in]  msg                The ldb_message object representing the element
 *                                to add.
 *
 * @param[in]  checkdups          A boolean to indicate if checks for duplicates
 *                                should be done.
 *
 * @return                        A WERROR code
 */
WERROR dsdb_schema_set_el_from_ldb_msg_dups(struct ldb_context *ldb, struct dsdb_schema *schema,
					    struct ldb_message *msg, bool checkdups)
{
	const char* tstring;
	time_t ts;
	tstring = ldb_msg_find_attr_as_string(msg, "whenChanged", NULL);
	/* keep a trace of the ts of the most recently changed object */
	if (tstring) {
		ts = ldb_string_to_time(tstring);
		if (ts > schema->ts_last_change) {
			schema->ts_last_change = ts;
		}
	}
	if (samdb_find_attribute(ldb, msg,
				 "objectclass", "attributeSchema") != NULL) {

		return dsdb_set_attribute_from_ldb_dups(ldb, schema, msg, checkdups);
	} else if (samdb_find_attribute(ldb, msg,
				 "objectclass", "classSchema") != NULL) {
		return dsdb_set_class_from_ldb_dups(schema, msg, checkdups);
	}
	/* Don't fail on things not classes or attributes */
	return WERR_OK;
}

WERROR dsdb_schema_set_el_from_ldb_msg(struct ldb_context *ldb,
				       struct dsdb_schema *schema,
				       struct ldb_message *msg)
{
	return dsdb_schema_set_el_from_ldb_msg_dups(ldb, schema, msg, false);
}

/**
 * Rather than read a schema from the LDB itself, read it from an ldif
 * file.  This allows schema to be loaded and used while adding the
 * schema itself to the directory.
 *
 * Should be called with a transaction (or failing that, have no concurrent
 * access while called).
 */

WERROR dsdb_set_schema_from_ldif(struct ldb_context *ldb,
				 const char *pf, const char *df,
				 const char *dn)
{
	struct ldb_ldif *ldif;
	struct ldb_message *msg;
	TALLOC_CTX *mem_ctx;
	WERROR status;
	int ret;
	struct dsdb_schema *schema;
	const struct ldb_val *prefix_val;
	const struct ldb_val *info_val;
	struct ldb_val info_val_default;


	mem_ctx = talloc_new(ldb);
	if (!mem_ctx) {
		goto nomem;
	}

	schema = dsdb_new_schema(mem_ctx);
	if (!schema) {
		goto nomem;
	}
	schema->fsmo.we_are_master = true;
	schema->fsmo.update_allowed = true;
	schema->fsmo.master_dn = ldb_dn_new(schema, ldb, "@PROVISION_SCHEMA_MASTER");
	if (!schema->fsmo.master_dn) {
		goto nomem;
	}

	/*
	 * load the prefixMap attribute from pf
	 */
	ldif = ldb_ldif_read_string(ldb, &pf);
	if (!ldif) {
		status = WERR_INVALID_PARAMETER;
		goto failed;
	}
	talloc_steal(mem_ctx, ldif);

	ret = ldb_msg_normalize(ldb, mem_ctx, ldif->msg, &msg);
	if (ret != LDB_SUCCESS) {
		goto nomem;
	}
	talloc_free(ldif);

	prefix_val = ldb_msg_find_ldb_val(msg, "prefixMap");
	if (!prefix_val) {
		status = WERR_INVALID_PARAMETER;
		goto failed;
	}

	info_val = ldb_msg_find_ldb_val(msg, "schemaInfo");
	if (!info_val) {
		status = dsdb_schema_info_blob_new(mem_ctx, &info_val_default);
		W_ERROR_NOT_OK_GOTO(status, failed);
		info_val = &info_val_default;
	}

	status = dsdb_load_oid_mappings_ldb(schema, prefix_val, info_val);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0,("ERROR: dsdb_load_oid_mappings_ldb() failed with %s\n", win_errstr(status)));
		goto failed;
	}

	schema->ts_last_change = 0;
	/* load the attribute and class definitions out of df */
	while ((ldif = ldb_ldif_read_string(ldb, &df))) {
		talloc_steal(mem_ctx, ldif);

		ret = ldb_msg_normalize(ldb, ldif, ldif->msg, &msg);
		if (ret != LDB_SUCCESS) {
			goto nomem;
		}

		status = dsdb_schema_set_el_from_ldb_msg(ldb, schema, msg);
		talloc_free(ldif);
		if (!W_ERROR_IS_OK(status)) {
			goto failed;
		}
	}

	/*
	 * TODO We may need a transaction here, otherwise this causes races.
	 *
	 * To do so may require an ldb_in_transaction function. In the
	 * meantime, assume that this is always called with a transaction or in
	 * isolation.
	 */
	ret = dsdb_set_schema(ldb, schema, SCHEMA_WRITE);
	if (ret != LDB_SUCCESS) {
		status = WERR_FOOBAR;
		DEBUG(0,("ERROR: dsdb_set_schema() failed with %s / %s\n",
			 ldb_strerror(ret), ldb_errstring(ldb)));
		goto failed;
	}

	ret = dsdb_schema_fill_extended_dn(ldb, schema);
	if (ret != LDB_SUCCESS) {
		status = WERR_FOOBAR;
		goto failed;
	}

	goto done;

nomem:
	status = WERR_NOT_ENOUGH_MEMORY;
failed:
done:
	talloc_free(mem_ctx);
	return status;
}

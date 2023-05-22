/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004-2005
   Copyright (C) Simo Sorce            2005

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

/*
 *  Name: ldb
 *
 *  Component: ldb expression matching
 *
 *  Description: ldb expression matching 
 *
 *  Author: Andrew Tridgell
 */

#include "ldb_private.h"
#include "dlinklist.h"
#include "ldb_handlers.h"

/*
  check if the scope matches in a search result
*/
int ldb_match_scope(struct ldb_context *ldb,
		    struct ldb_dn *base,
		    struct ldb_dn *dn,
		    enum ldb_scope scope)
{
	int ret = 0;

	if (base == NULL || dn == NULL) {
		return 1;
	}

	switch (scope) {
	case LDB_SCOPE_BASE:
		if (ldb_dn_compare(base, dn) == 0) {
			ret = 1;
		}
		break;

	case LDB_SCOPE_ONELEVEL:
		if (ldb_dn_get_comp_num(dn) == (ldb_dn_get_comp_num(base) + 1)) {
			if (ldb_dn_compare_base(base, dn) == 0) {
				ret = 1;
			}
		}
		break;
		
	case LDB_SCOPE_SUBTREE:
	default:
		if (ldb_dn_compare_base(base, dn) == 0) {
			ret = 1;
		}
		break;
	}

	return ret;
}


/*
  match if node is present
*/
static int ldb_match_present(struct ldb_context *ldb, 
			     const struct ldb_message *msg,
			     const struct ldb_parse_tree *tree,
			     enum ldb_scope scope, bool *matched)
{
	const struct ldb_schema_attribute *a;
	struct ldb_message_element *el;

	if (ldb_attr_dn(tree->u.present.attr) == 0) {
		*matched = true;
		return LDB_SUCCESS;
	}

	el = ldb_msg_find_element(msg, tree->u.present.attr);
	if (el == NULL) {
		*matched = false;
		return LDB_SUCCESS;
	}

	a = ldb_schema_attribute_by_name(ldb, el->name);
	if (!a) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}

	if (a->syntax->operator_fn) {
		unsigned int i;
		for (i = 0; i < el->num_values; i++) {
			int ret = a->syntax->operator_fn(ldb, LDB_OP_PRESENT, a, &el->values[i], NULL, matched);
			if (ret != LDB_SUCCESS) return ret;
			if (*matched) return LDB_SUCCESS;
		}
		*matched = false;
		return LDB_SUCCESS;
	}

	*matched = true;
	return LDB_SUCCESS;
}

static int ldb_match_comparison(struct ldb_context *ldb, 
				const struct ldb_message *msg,
				const struct ldb_parse_tree *tree,
				enum ldb_scope scope,
				enum ldb_parse_op comp_op, bool *matched)
{
	unsigned int i;
	struct ldb_message_element *el;
	const struct ldb_schema_attribute *a;

	/* FIXME: APPROX comparison not handled yet */
	if (comp_op == LDB_OP_APPROX) {
		return LDB_ERR_INAPPROPRIATE_MATCHING;
	}

	el = ldb_msg_find_element(msg, tree->u.comparison.attr);
	if (el == NULL) {
		*matched = false;
		return LDB_SUCCESS;
	}

	a = ldb_schema_attribute_by_name(ldb, el->name);
	if (!a) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}

	for (i = 0; i < el->num_values; i++) {
		if (a->syntax->operator_fn) {
			int ret;
			ret = a->syntax->operator_fn(ldb, comp_op, a, &el->values[i], &tree->u.comparison.value, matched);
			if (ret != LDB_SUCCESS) return ret;
			if (*matched) return LDB_SUCCESS;
		} else {
			int ret = a->syntax->comparison_fn(ldb, ldb, &el->values[i], &tree->u.comparison.value);

			if (ret == 0) {
				*matched = true;
				return LDB_SUCCESS;
			}
			if (ret > 0 && comp_op == LDB_OP_GREATER) {
				*matched = true;
				return LDB_SUCCESS;
			}
			if (ret < 0 && comp_op == LDB_OP_LESS) {
				*matched = true;
				return LDB_SUCCESS;
			}
		}
	}

	*matched = false;
	return LDB_SUCCESS;
}

/*
  match a simple leaf node
*/
static int ldb_match_equality(struct ldb_context *ldb, 
			      const struct ldb_message *msg,
			      const struct ldb_parse_tree *tree,
			      enum ldb_scope scope,
			      bool *matched)
{
	unsigned int i;
	struct ldb_message_element *el;
	const struct ldb_schema_attribute *a;
	struct ldb_dn *valuedn;
	int ret;

	if (ldb_attr_dn(tree->u.equality.attr) == 0) {
		valuedn = ldb_dn_from_ldb_val(ldb, ldb, &tree->u.equality.value);
		if (valuedn == NULL) {
			return LDB_ERR_INVALID_DN_SYNTAX;
		}

		ret = ldb_dn_compare(msg->dn, valuedn);

		talloc_free(valuedn);

		*matched = (ret == 0);
		return LDB_SUCCESS;
	}

	/* TODO: handle the "*" case derived from an extended search
	   operation without the attibute type defined */
	el = ldb_msg_find_element(msg, tree->u.equality.attr);
	if (el == NULL) {
		*matched = false;
		return LDB_SUCCESS;
	}

	a = ldb_schema_attribute_by_name(ldb, el->name);
	if (a == NULL) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}

	for (i=0;i<el->num_values;i++) {
		if (a->syntax->operator_fn) {
			ret = a->syntax->operator_fn(ldb, LDB_OP_EQUALITY, a,
						     &tree->u.equality.value, &el->values[i], matched);
			if (ret != LDB_SUCCESS) return ret;
			if (*matched) return LDB_SUCCESS;
		} else {
			if (a->syntax->comparison_fn(ldb, ldb, &tree->u.equality.value,
						     &el->values[i]) == 0) {
				*matched = true;
				return LDB_SUCCESS;
			}
		}
	}

	*matched = false;
	return LDB_SUCCESS;
}

static int ldb_wildcard_compare(struct ldb_context *ldb,
				const struct ldb_parse_tree *tree,
				const struct ldb_val value, bool *matched)
{
	const struct ldb_schema_attribute *a;
	struct ldb_val val;
	struct ldb_val cnk;
	struct ldb_val *chunk;
	uint8_t *save_p = NULL;
	unsigned int c = 0;

	if (tree->operation != LDB_OP_SUBSTRING) {
		*matched = false;
		return LDB_ERR_INAPPROPRIATE_MATCHING;
	}

	a = ldb_schema_attribute_by_name(ldb, tree->u.substring.attr);
	if (!a) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}

	if (tree->u.substring.chunks == NULL) {
		*matched = false;
		return LDB_SUCCESS;
	}

	/* No need to just copy this value for a binary match */
	if (a->syntax->canonicalise_fn != ldb_handler_copy) {
		if (a->syntax->canonicalise_fn(ldb, ldb, &value, &val) != 0) {
			return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
		}

		/*
		 * Only set save_p if we allocate (call
		 * a->syntax->canonicalise_fn()), as we
		 * talloc_free(save_p) below to clean up
		 */
		save_p = val.data;
	} else {
		val = value;
	}

	cnk.data = NULL;

	if ( ! tree->u.substring.start_with_wildcard ) {
		uint8_t *cnk_to_free = NULL;

		chunk = tree->u.substring.chunks[c];
		/* No need to just copy this value for a binary match */
		if (a->syntax->canonicalise_fn != ldb_handler_copy) {
			if (a->syntax->canonicalise_fn(ldb, ldb, chunk, &cnk) != 0) {
				goto mismatch;
			}

			cnk_to_free = cnk.data;
		} else {
			cnk = *chunk;
		}

		/* This deals with wildcard prefix searches on binary attributes (eg objectGUID) */
		if (cnk.length > val.length) {
			TALLOC_FREE(cnk_to_free);
			goto mismatch;
		}
		/*
		 * Empty strings are returned as length 0. Ensure
		 * we can cope with this.
		 */
		if (cnk.length == 0) {
			TALLOC_FREE(cnk_to_free);
			goto mismatch;
		}

		if (memcmp((char *)val.data, (char *)cnk.data, cnk.length) != 0) {
			TALLOC_FREE(cnk_to_free);
			goto mismatch;
		}

		val.length -= cnk.length;
		val.data += cnk.length;
		c++;
		TALLOC_FREE(cnk_to_free);
		cnk.data = NULL;
	}

	while (tree->u.substring.chunks[c]) {
		uint8_t *p;
		uint8_t *cnk_to_free = NULL;

		chunk = tree->u.substring.chunks[c];
		/* No need to just copy this value for a binary match */
		if (a->syntax->canonicalise_fn != ldb_handler_copy) {
			if (a->syntax->canonicalise_fn(ldb, ldb, chunk, &cnk) != 0) {
				goto mismatch;
			}

			cnk_to_free = cnk.data;
		} else {
			cnk = *chunk;
		}
		/*
		 * Empty strings are returned as length 0. Ensure
		 * we can cope with this.
		 */
		if (cnk.length == 0) {
			TALLOC_FREE(cnk_to_free);
			goto mismatch;
		}
		if (cnk.length > val.length) {
			TALLOC_FREE(cnk_to_free);
			goto mismatch;
		}

		if ( (tree->u.substring.chunks[c + 1]) == NULL &&
		     (! tree->u.substring.end_with_wildcard) ) {
			/*
			 * The last bit, after all the asterisks, must match
			 * exactly the last bit of the string.
			 */
			int cmp;
			p = val.data + val.length - cnk.length;
			cmp = memcmp(p,
				     cnk.data,
				     cnk.length);
			TALLOC_FREE(cnk_to_free);

			if (cmp != 0) {
				goto mismatch;
			}
		} else {
			/*
			 * Values might be binary blobs. Don't use string
			 * search, but memory search instead.
			 */
			p = memmem((const void *)val.data, val.length,
				   (const void *)cnk.data, cnk.length);
			if (p == NULL) {
				TALLOC_FREE(cnk_to_free);
				goto mismatch;
			}
			/* move val to the end of the match */
			p += cnk.length;
			val.length -= (p - val.data);
			val.data = p;
			TALLOC_FREE(cnk_to_free);
		}
		c++;
	}

	talloc_free(save_p);
	*matched = true;
	return LDB_SUCCESS;

mismatch:
	*matched = false;
	talloc_free(save_p);
	return LDB_SUCCESS;
}

/*
  match a simple leaf node
*/
static int ldb_match_substring(struct ldb_context *ldb, 
			       const struct ldb_message *msg,
			       const struct ldb_parse_tree *tree,
			       enum ldb_scope scope, bool *matched)
{
	unsigned int i;
	struct ldb_message_element *el;

	el = ldb_msg_find_element(msg, tree->u.substring.attr);
	if (el == NULL) {
		*matched = false;
		return LDB_SUCCESS;
	}

	for (i = 0; i < el->num_values; i++) {
		int ret;
		ret = ldb_wildcard_compare(ldb, tree, el->values[i], matched);
		if (ret != LDB_SUCCESS) return ret;
		if (*matched) return LDB_SUCCESS;
	}

	*matched = false;
	return LDB_SUCCESS;
}


/*
  bitwise and/or comparator depending on oid
*/
static int ldb_comparator_bitmask(const char *oid, const struct ldb_val *v1, const struct ldb_val *v2,
				  bool *matched)
{
	uint64_t i1, i2;
	char ibuf[100];
	char *endptr = NULL;

	if (v1->length >= sizeof(ibuf)-1) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}
	memcpy(ibuf, (char *)v1->data, v1->length);
	ibuf[v1->length] = 0;
	i1 = strtoull(ibuf, &endptr, 0);
	if (endptr != NULL) {
		if (endptr == ibuf || *endptr != 0) {
			return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
		}
	}

	if (v2->length >= sizeof(ibuf)-1) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}
	endptr = NULL;
	memcpy(ibuf, (char *)v2->data, v2->length);
	ibuf[v2->length] = 0;
	i2 = strtoull(ibuf, &endptr, 0);
	if (endptr != NULL) {
		if (endptr == ibuf || *endptr != 0) {
			return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
		}
	}
	if (strcmp(LDB_OID_COMPARATOR_AND, oid) == 0) {
		*matched = ((i1 & i2) == i2);
	} else if (strcmp(LDB_OID_COMPARATOR_OR, oid) == 0) {
		*matched = ((i1 & i2) != 0);
	} else {
		return LDB_ERR_INAPPROPRIATE_MATCHING;
	}
	return LDB_SUCCESS;
}

static int ldb_match_bitmask(struct ldb_context *ldb,
			     const char *oid,
			     const struct ldb_message *msg,
			     const char *attribute_to_match,
			     const struct ldb_val *value_to_match,
			     bool *matched)
{
	unsigned int i;
	struct ldb_message_element *el;

	/* find the message element */
	el = ldb_msg_find_element(msg, attribute_to_match);
	if (el == NULL) {
		*matched = false;
		return LDB_SUCCESS;
	}

	for (i=0;i<el->num_values;i++) {
		int ret;
		struct ldb_val *v = &el->values[i];

		ret = ldb_comparator_bitmask(oid, v, value_to_match, matched);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		if (*matched) {
			return LDB_SUCCESS;
		}
	}

	*matched = false;
	return LDB_SUCCESS;
}

/*
  always return false
*/
static int ldb_comparator_false(struct ldb_context *ldb,
				const char *oid,
				const struct ldb_message *msg,
				const char *attribute_to_match,
				const struct ldb_val *value_to_match,
				bool *matched)
{
	*matched = false;
	return LDB_SUCCESS;
}


static const struct ldb_extended_match_rule *ldb_find_extended_match_rule(struct ldb_context *ldb,
									  const char *oid)
{
	struct ldb_extended_match_entry *extended_match_rule;

	for (extended_match_rule = ldb->extended_match_rules;
	     extended_match_rule;
	     extended_match_rule = extended_match_rule->next) {
		if (strcmp(extended_match_rule->rule->oid, oid) == 0) {
			return extended_match_rule->rule;
		}
	}

	return NULL;
}


/*
  extended match, handles things like bitops
*/
static int ldb_match_extended(struct ldb_context *ldb, 
			      const struct ldb_message *msg,
			      const struct ldb_parse_tree *tree,
			      enum ldb_scope scope, bool *matched)
{
	const struct ldb_extended_match_rule *rule;

	if (tree->u.extended.dnAttributes) {
		/* FIXME: We really need to find out what this ":dn" part in
		 * an extended match means and how to handle it. For now print
		 * only a warning to have s3 winbind and other tools working
		 * against us. - Matthias */
		ldb_debug(ldb, LDB_DEBUG_WARNING, "ldb: dnAttributes extended match not supported yet");
	}
	if (tree->u.extended.rule_id == NULL) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "ldb: no-rule extended matches not supported yet");
		return LDB_ERR_INAPPROPRIATE_MATCHING;
	}
	if (tree->u.extended.attr == NULL) {
		ldb_debug(ldb, LDB_DEBUG_ERROR, "ldb: no-attribute extended matches not supported yet");
		return LDB_ERR_INAPPROPRIATE_MATCHING;
	}

	rule = ldb_find_extended_match_rule(ldb, tree->u.extended.rule_id);
	if (rule == NULL) {
		*matched = false;
		ldb_debug(ldb, LDB_DEBUG_ERROR, "ldb: unknown extended rule_id %s",
			  tree->u.extended.rule_id);
		return LDB_SUCCESS;
	}

	return rule->callback(ldb, rule->oid, msg,
			      tree->u.extended.attr,
			      &tree->u.extended.value, matched);
}

static bool ldb_must_suppress_match(const struct ldb_message *msg,
				    const struct ldb_parse_tree *tree)
{
	const char *attr = NULL;
	struct ldb_message_element *el = NULL;

	attr = ldb_parse_tree_get_attr(tree);
	if (attr == NULL) {
		return false;
	}

	/* find the message element */
	el = ldb_msg_find_element(msg, attr);
	if (el == NULL) {
		return false;
	}

	return ldb_msg_element_is_inaccessible(el);
}

/*
  Check if a particular message will match the given filter

  set *matched to true if it matches, false otherwise

  returns LDB_SUCCESS or an error

  this is a recursive function, and does short-circuit evaluation
 */
int ldb_match_message(struct ldb_context *ldb,
		      const struct ldb_message *msg,
		      const struct ldb_parse_tree *tree,
		      enum ldb_scope scope, bool *matched)
{
	unsigned int i;
	int ret;

	*matched = false;

	if (scope != LDB_SCOPE_BASE && ldb_dn_is_special(msg->dn)) {
		/* don't match special records except on base searches */
		return LDB_SUCCESS;
	}

	/*
	 * Suppress matches on confidential attributes (handled
	 * manually in extended matches as these can do custom things
	 * like read other parts of the DB or other attributes).
	 */
	if (tree->operation != LDB_OP_EXTENDED) {
		if (ldb_must_suppress_match(msg, tree)) {
			return LDB_SUCCESS;
		}
	}

	switch (tree->operation) {
	case LDB_OP_AND:
		for (i=0;i<tree->u.list.num_elements;i++) {
			ret = ldb_match_message(ldb, msg, tree->u.list.elements[i], scope, matched);
			if (ret != LDB_SUCCESS) return ret;
			if (!*matched) return LDB_SUCCESS;
		}
		*matched = true;
		return LDB_SUCCESS;

	case LDB_OP_OR:
		for (i=0;i<tree->u.list.num_elements;i++) {
			ret = ldb_match_message(ldb, msg, tree->u.list.elements[i], scope, matched);
			if (ret != LDB_SUCCESS) return ret;
			if (*matched) return LDB_SUCCESS;
		}
		*matched = false;
		return LDB_SUCCESS;

	case LDB_OP_NOT:
		ret = ldb_match_message(ldb, msg, tree->u.isnot.child, scope, matched);
		if (ret != LDB_SUCCESS) return ret;
		*matched = ! *matched;
		return LDB_SUCCESS;

	case LDB_OP_EQUALITY:
		return ldb_match_equality(ldb, msg, tree, scope, matched);

	case LDB_OP_SUBSTRING:
		return ldb_match_substring(ldb, msg, tree, scope, matched);

	case LDB_OP_GREATER:
		return ldb_match_comparison(ldb, msg, tree, scope, LDB_OP_GREATER, matched);

	case LDB_OP_LESS:
		return ldb_match_comparison(ldb, msg, tree, scope, LDB_OP_LESS, matched);

	case LDB_OP_PRESENT:
		return ldb_match_present(ldb, msg, tree, scope, matched);

	case LDB_OP_APPROX:
		return ldb_match_comparison(ldb, msg, tree, scope, LDB_OP_APPROX, matched);

	case LDB_OP_EXTENDED:
		return ldb_match_extended(ldb, msg, tree, scope, matched);
	}

	return LDB_ERR_INAPPROPRIATE_MATCHING;
}

/*
  return 0 if the given parse tree matches the given message. Assumes
  the message is in sorted order

  return 1 if it matches, and 0 if it doesn't match
*/

int ldb_match_msg(struct ldb_context *ldb,
		  const struct ldb_message *msg,
		  const struct ldb_parse_tree *tree,
		  struct ldb_dn *base,
		  enum ldb_scope scope)
{
	bool matched;
	int ret;

	if ( ! ldb_match_scope(ldb, base, msg->dn, scope) ) {
		return 0;
	}

	ret = ldb_match_message(ldb, msg, tree, scope, &matched);
	if (ret != LDB_SUCCESS) {
		/* to match the old API, we need to consider this a
		   failure to match */
		return 0;
	}
	return matched?1:0;
}

int ldb_match_msg_error(struct ldb_context *ldb,
			const struct ldb_message *msg,
			const struct ldb_parse_tree *tree,
			struct ldb_dn *base,
			enum ldb_scope scope,
			bool *matched)
{
	if ( ! ldb_match_scope(ldb, base, msg->dn, scope) ) {
		*matched = false;
		return LDB_SUCCESS;
	}

	return ldb_match_message(ldb, msg, tree, scope, matched);
}

int ldb_match_msg_objectclass(const struct ldb_message *msg,
			      const char *objectclass)
{
	unsigned int i;
	struct ldb_message_element *el = ldb_msg_find_element(msg, "objectClass");
	if (!el) {
		return 0;
	}
	for (i=0; i < el->num_values; i++) {
		if (ldb_attr_cmp((const char *)el->values[i].data, objectclass) == 0) {
			return 1;
		}
	}
	return 0;
}

_PRIVATE_ int ldb_register_extended_match_rules(struct ldb_context *ldb)
{
	struct ldb_extended_match_rule *bitmask_and;
	struct ldb_extended_match_rule *bitmask_or;
	struct ldb_extended_match_rule *always_false;
	int ret;

	/* Register bitmask-and match */
	bitmask_and = talloc_zero(ldb, struct ldb_extended_match_rule);
	if (bitmask_and == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	bitmask_and->oid = LDB_OID_COMPARATOR_AND;
	bitmask_and->callback = ldb_match_bitmask;

	ret = ldb_register_extended_match_rule(ldb, bitmask_and);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* Register bitmask-or match */
	bitmask_or = talloc_zero(ldb, struct ldb_extended_match_rule);
	if (bitmask_or == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	bitmask_or->oid = LDB_OID_COMPARATOR_OR;
	bitmask_or->callback = ldb_match_bitmask;

	ret = ldb_register_extended_match_rule(ldb, bitmask_or);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* Register always-false match */
	always_false = talloc_zero(ldb, struct ldb_extended_match_rule);
	if (always_false == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	always_false->oid = SAMBA_LDAP_MATCH_ALWAYS_FALSE;
	always_false->callback = ldb_comparator_false;

	ret = ldb_register_extended_match_rule(ldb, always_false);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}

/*
  register a new ldb extended matching rule
*/
int ldb_register_extended_match_rule(struct ldb_context *ldb,
				     const struct ldb_extended_match_rule *rule)
{
	const struct ldb_extended_match_rule *lookup_rule;
	struct ldb_extended_match_entry *entry;

	lookup_rule = ldb_find_extended_match_rule(ldb, rule->oid);
	if (lookup_rule) {
		return LDB_ERR_ENTRY_ALREADY_EXISTS;
	}

	entry = talloc_zero(ldb, struct ldb_extended_match_entry);
	if (!entry) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	entry->rule = rule;
	DLIST_ADD_END(ldb->extended_match_rules, entry);

	return LDB_SUCCESS;
}

int ldb_register_redact_callback(struct ldb_context *ldb,
				 ldb_redact_fn redact_fn,
				 struct ldb_module *module)
{
	if (ldb->redact.callback != NULL) {
		return LDB_ERR_ENTRY_ALREADY_EXISTS;
	}

	ldb->redact.callback = redact_fn;
	ldb->redact.module = module;
	return LDB_SUCCESS;
}

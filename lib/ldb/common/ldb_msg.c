/*
   ldb database library

   Copyright (C) Andrew Tridgell  2004

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
 *  Component: ldb message component utility functions
 *
 *  Description: functions for manipulating ldb_message structures
 *
 *  Author: Andrew Tridgell
 */

#include "ldb_private.h"

/*
  create a new ldb_message in a given memory context (NULL for top level)
*/
struct ldb_message *ldb_msg_new(TALLOC_CTX *mem_ctx)
{
	return talloc_zero(mem_ctx, struct ldb_message);
}

/*
  find an element in a message by attribute name
*/
struct ldb_message_element *ldb_msg_find_element(const struct ldb_message *msg,
						 const char *attr_name)
{
	unsigned int i;
	for (i=0;i<msg->num_elements;i++) {
		if (ldb_attr_cmp(msg->elements[i].name, attr_name) == 0) {
			return &msg->elements[i];
		}
	}
	return NULL;
}

/*
  see if two ldb_val structures contain exactly the same data
  return 1 for a match, 0 for a mis-match
*/
int ldb_val_equal_exact(const struct ldb_val *v1, const struct ldb_val *v2)
{
	if (v1->length != v2->length) return 0;
	if (v1->data == v2->data) return 1;
	if (v1->length == 0) return 1;

	if (memcmp(v1->data, v2->data, v1->length) == 0) {
		return 1;
	}

	return 0;
}

/*
  find a value in an element
  assumes case sensitive comparison
*/
struct ldb_val *ldb_msg_find_val(const struct ldb_message_element *el,
				 struct ldb_val *val)
{
	unsigned int i;
	for (i=0;i<el->num_values;i++) {
		if (ldb_val_equal_exact(val, &el->values[i])) {
			return &el->values[i];
		}
	}
	return NULL;
}


static int ldb_val_cmp(const struct ldb_val *v1, const struct ldb_val *v2)
{
	if (v1->length != v2->length) {
		return v1->length - v2->length;
	}
	return memcmp(v1->data, v2->data, v1->length);
}


/*
  ldb_msg_find_duplicate_val() will set the **duplicate pointer to the first
  duplicate value it finds. It does a case sensitive comparison (memcmp).

  LDB_ERR_OPERATIONS_ERROR indicates an allocation failure or an unknown
  options flag, otherwise LDB_SUCCESS.
*/
#define LDB_DUP_QUADRATIC_THRESHOLD 10

int ldb_msg_find_duplicate_val(struct ldb_context *ldb,
			       TALLOC_CTX *mem_ctx,
			       const struct ldb_message_element *el,
			       struct ldb_val **duplicate,
			       uint32_t options)
{
	unsigned int i, j;
	struct ldb_val *val;

	if (options != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*duplicate = NULL;

	/*
	   If there are not many values, it is best to avoid the talloc
	   overhead and just do a brute force search.
	 */
	if (el->num_values < LDB_DUP_QUADRATIC_THRESHOLD) {
		for (j = 0; j < el->num_values; j++) {
			val = &el->values[j];
			for ( i = j + 1; i < el->num_values; i++) {
				if (ldb_val_equal_exact(val, &el->values[i])) {
					*duplicate = val;
					return LDB_SUCCESS;
				}
			}
		}
	} else {
		struct ldb_val *values;
		values = talloc_array(mem_ctx, struct ldb_val, el->num_values);
		if (values == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		memcpy(values, el->values,
		       el->num_values * sizeof(struct ldb_val));
		TYPESAFE_QSORT(values, el->num_values, ldb_val_cmp);
		for (i = 1; i < el->num_values; i++) {
			if (ldb_val_equal_exact(&values[i],
						&values[i - 1])) {
				/* find the original location */
				for (j = 0; j < el->num_values; j++) {
					if (ldb_val_equal_exact(&values[i],
								&el->values[j])
						) {
						*duplicate = &el->values[j];
						break;
					}
				}
				talloc_free(values);
				if (*duplicate == NULL) {
					/* how we got here, I don't know */
					return LDB_ERR_OPERATIONS_ERROR;
				}
				return LDB_SUCCESS;
			}
		}
		talloc_free(values);
	}
	return LDB_SUCCESS;
}


/*
  Determine whether the values in an element are also in another element.

  Without any flags, return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS if the elements
  share values, or LDB_SUCCESS if they don't. In this case, the function
  simply determines the set intersection and it doesn't matter in which order
  the elements are provided.

  With the LDB_MSG_FIND_COMMON_REMOVE_DUPLICATES flag, any values in common are
  removed from the first element and LDB_SUCCESS is returned.

  LDB_ERR_OPERATIONS_ERROR indicates an allocation failure or an unknown option.
  LDB_ERR_INAPPROPRIATE_MATCHING is returned if the elements differ in name.
*/

int ldb_msg_find_common_values(struct ldb_context *ldb,
			       TALLOC_CTX *mem_ctx,
			       struct ldb_message_element *el,
			       struct ldb_message_element *el2,
			       uint32_t options)
{
	struct ldb_val *values;
	struct ldb_val *values2;
	unsigned int i, j, k, n_values;

	bool remove_duplicates = options & LDB_MSG_FIND_COMMON_REMOVE_DUPLICATES;

	if ((options & ~LDB_MSG_FIND_COMMON_REMOVE_DUPLICATES) != 0) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (strcmp(el->name, el2->name) != 0) {
		return LDB_ERR_INAPPROPRIATE_MATCHING;
	}
	if (el->num_values == 0 || el2->num_values == 0) {
		return LDB_SUCCESS;
	}
	/*
	   With few values, it is better to do the brute-force search than the
	   clever search involving tallocs, memcpys, sorts, etc.
	*/
	if (MIN(el->num_values, el2->num_values) == 1 ||
	    MAX(el->num_values, el2->num_values) < LDB_DUP_QUADRATIC_THRESHOLD) {
		for (i = 0; i < el2->num_values; i++) {
			for (j = 0; j < el->num_values; j++) {
				if (ldb_val_equal_exact(&el->values[j],
							&el2->values[i])) {
					if (! remove_duplicates) {
					    return			\
					      LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
					}
					/*
					  With the remove_duplicates flag, we
					  resolve the intersection by removing
					  the offending one from el.
					*/
					el->num_values--;
					for (k = j; k < el->num_values; k++) {
						el->values[k] = \
							el->values[k + 1];
					}
					j--; /* rewind */
				}
			}
		}
		return LDB_SUCCESS;
	}

	values = talloc_array(mem_ctx, struct ldb_val, el->num_values);
	if (values == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	values2 = talloc_array(mem_ctx, struct ldb_val,
				    el2->num_values);
	if (values2 == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	memcpy(values, el->values,
	       el->num_values * sizeof(struct ldb_val));
	memcpy(values2, el2->values,
	       el2->num_values * sizeof(struct ldb_val));
	TYPESAFE_QSORT(values, el->num_values, ldb_val_cmp);
	TYPESAFE_QSORT(values2, el2->num_values, ldb_val_cmp);

	/*
	   el->n_values may diverge from the number of values in the sorted
	   list when the remove_duplicates flag is used.
	*/
	n_values = el->num_values;
	i = 0;
	j = 0;
	while (i != n_values && j < el2->num_values) {
		int ret = ldb_val_cmp(&values[i], &values2[j]);
		if (ret < 0) {
			i++;
		} else if (ret > 0) {
			j++;
		} else {
			/* we have a collision */
			if (! remove_duplicates) {
				TALLOC_FREE(values);
				TALLOC_FREE(values2);
				return LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS;
			}
			/*
			   With the remove_duplicates flag we need to find
			   this in the original list and remove it, which is
			   inefficient but hopefully rare.
			*/
			for (k = 0; k < el->num_values; k++) {
				if (ldb_val_equal_exact(&el->values[k],
							&values[i])) {
					break;
				}
			}
			el->num_values--;
			for (; k < el->num_values; k++) {
				el->values[k] = el->values[k + 1];
			}
			i++;
		}
	}
	TALLOC_FREE(values);
	TALLOC_FREE(values2);

	return LDB_SUCCESS;
}

/*
  duplicate a ldb_val structure
*/
struct ldb_val ldb_val_dup(TALLOC_CTX *mem_ctx, const struct ldb_val *v)
{
	struct ldb_val v2;
	v2.length = v->length;
	if (v->data == NULL) {
		v2.data = NULL;
		return v2;
	}

	/* the +1 is to cope with buggy C library routines like strndup
	   that look one byte beyond */
	v2.data = talloc_array(mem_ctx, uint8_t, v->length+1);
	if (!v2.data) {
		v2.length = 0;
		return v2;
	}

	memcpy(v2.data, v->data, v->length);
	((char *)v2.data)[v->length] = 0;
	return v2;
}

/**
 * Adds new empty element to msg->elements
 */
static int _ldb_msg_add_el(struct ldb_message *msg,
			   struct ldb_message_element **return_el)
{
	struct ldb_message_element *els;

	/*
	 * TODO: Find out a way to assert on input parameters.
	 * msg and return_el must be valid
	 */

	els = talloc_realloc(msg, msg->elements,
			     struct ldb_message_element, msg->num_elements + 1);
	if (!els) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ZERO_STRUCT(els[msg->num_elements]);

	msg->elements = els;
	msg->num_elements++;

	*return_el = &els[msg->num_elements-1];

	return LDB_SUCCESS;
}

/**
 * Add an empty element with a given name to a message
 */
int ldb_msg_add_empty(struct ldb_message *msg,
		      const char *attr_name,
		      int flags,
		      struct ldb_message_element **return_el)
{
	int ret;
	struct ldb_message_element *el;

	ret = _ldb_msg_add_el(msg, &el);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	/* initialize newly added element */
	el->flags = flags;
	el->name = talloc_strdup(msg->elements, attr_name);
	if (!el->name) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (return_el) {
		*return_el = el;
	}

	return LDB_SUCCESS;
}

/**
 * Adds an element to a message.
 *
 * NOTE: Ownership of ldb_message_element fields
 *       is NOT transferred. Thus, if *el pointer
 *       is invalidated for some reason, this will
 *       corrupt *msg contents also
 */
int ldb_msg_add(struct ldb_message *msg,
		const struct ldb_message_element *el,
		int flags)
{
	int ret;
	struct ldb_message_element *el_new;
	/* We have to copy this, just in case *el is a pointer into
	 * what ldb_msg_add_empty() is about to realloc() */
	struct ldb_message_element el_copy = *el;

	ret = _ldb_msg_add_el(msg, &el_new);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	el_new->flags      = flags;
	el_new->name       = el_copy.name;
	el_new->num_values = el_copy.num_values;
	el_new->values     = el_copy.values;

	return LDB_SUCCESS;
}

/*
 * add a value to a message element
 */
int ldb_msg_element_add_value(TALLOC_CTX *mem_ctx,
			      struct ldb_message_element *el,
			      const struct ldb_val *val)
{
	struct ldb_val *vals;

	if (el->flags & LDB_FLAG_INTERNAL_SHARED_VALUES) {
		/*
		 * Another message is using this message element's values array,
		 * so we don't want to make any modifications to the original
		 * message, or potentially invalidate its own values by calling
		 * talloc_realloc(). Make a copy instead.
		 */
		el->flags &= ~LDB_FLAG_INTERNAL_SHARED_VALUES;

		vals = talloc_array(mem_ctx, struct ldb_val,
				    el->num_values + 1);
		if (vals == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}

		if (el->values != NULL) {
			memcpy(vals, el->values, el->num_values * sizeof(struct ldb_val));
		}
	} else {
		vals = talloc_realloc(mem_ctx, el->values, struct ldb_val,
				      el->num_values + 1);
		if (vals == NULL) {
			return LDB_ERR_OPERATIONS_ERROR;
		}
	}
	el->values = vals;
	el->values[el->num_values] = *val;
	el->num_values++;

	return LDB_SUCCESS;
}

/*
  add a value to a message
*/
int ldb_msg_add_value(struct ldb_message *msg,
		      const char *attr_name,
		      const struct ldb_val *val,
		      struct ldb_message_element **return_el)
{
	struct ldb_message_element *el;
	int ret;

	el = ldb_msg_find_element(msg, attr_name);
	if (!el) {
		ret = ldb_msg_add_empty(msg, attr_name, 0, &el);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
	}

	ret = ldb_msg_element_add_value(msg->elements, el, val);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (return_el) {
		*return_el = el;
	}

	return LDB_SUCCESS;
}


/*
  add a value to a message, stealing it into the 'right' place
*/
int ldb_msg_add_steal_value(struct ldb_message *msg,
			    const char *attr_name,
			    struct ldb_val *val)
{
	int ret;
	struct ldb_message_element *el;

	ret = ldb_msg_add_value(msg, attr_name, val, &el);
	if (ret == LDB_SUCCESS) {
		talloc_steal(el->values, val->data);
	}
	return ret;
}


/*
  add a string element to a message, specifying flags
*/
int ldb_msg_add_string_flags(struct ldb_message *msg,
			     const char *attr_name, const char *str,
			     int flags)
{
	struct ldb_val val;
	int ret;
	struct ldb_message_element *el = NULL;

	val.data = discard_const_p(uint8_t, str);
	val.length = strlen(str);

	if (val.length == 0) {
		/* allow empty strings as non-existent attributes */
		return LDB_SUCCESS;
	}

	ret = ldb_msg_add_value(msg, attr_name, &val, &el);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (flags != 0) {
		el->flags = flags;
	}

	return LDB_SUCCESS;
}

/*
  add a string element to a message
*/
int ldb_msg_add_string(struct ldb_message *msg,
		       const char *attr_name, const char *str)
{
	return ldb_msg_add_string_flags(msg, attr_name, str, 0);
}

/*
  add a string element to a message, stealing it into the 'right' place
*/
int ldb_msg_add_steal_string(struct ldb_message *msg,
			     const char *attr_name, char *str)
{
	struct ldb_val val;

	val.data = (uint8_t *)str;
	val.length = strlen(str);

	if (val.length == 0) {
		/* allow empty strings as non-existent attributes */
		return LDB_SUCCESS;
	}

	return ldb_msg_add_steal_value(msg, attr_name, &val);
}

/*
  add a DN element to a message
  WARNING: this uses the linearized string from the dn, and does not
  copy the string.
*/
int ldb_msg_add_linearized_dn(struct ldb_message *msg, const char *attr_name,
			      struct ldb_dn *dn)
{
	char *str = ldb_dn_alloc_linearized(msg, dn);

	if (str == NULL) {
		/* we don't want to have unknown DNs added */
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return ldb_msg_add_steal_string(msg, attr_name, str);
}

/*
  add a printf formatted element to a message
*/
int ldb_msg_add_fmt(struct ldb_message *msg,
		    const char *attr_name, const char *fmt, ...)
{
	struct ldb_val val;
	va_list ap;
	char *str;

	va_start(ap, fmt);
	str = talloc_vasprintf(msg, fmt, ap);
	va_end(ap);

	if (str == NULL) return LDB_ERR_OPERATIONS_ERROR;

	val.data   = (uint8_t *)str;
	val.length = strlen(str);

	return ldb_msg_add_steal_value(msg, attr_name, &val);
}

static int ldb_msg_append_value_impl(struct ldb_message *msg,
				     const char *attr_name,
				     const struct ldb_val *val,
				     int flags,
				     struct ldb_message_element **return_el)
{
	struct ldb_message_element *el = NULL;
	int ret;

	ret = ldb_msg_add_empty(msg, attr_name, flags, &el);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_msg_element_add_value(msg->elements, el, val);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	if (return_el != NULL) {
		*return_el = el;
	}

	return LDB_SUCCESS;
}

/*
  append a value to a message
*/
int ldb_msg_append_value(struct ldb_message *msg,
			 const char *attr_name,
			 const struct ldb_val *val,
			 int flags)
{
	return ldb_msg_append_value_impl(msg, attr_name, val, flags, NULL);
}

/*
  append a value to a message, stealing it into the 'right' place
*/
int ldb_msg_append_steal_value(struct ldb_message *msg,
			       const char *attr_name,
			       struct ldb_val *val,
			       int flags)
{
	int ret;
	struct ldb_message_element *el = NULL;

	ret = ldb_msg_append_value_impl(msg, attr_name, val, flags, &el);
	if (ret == LDB_SUCCESS) {
		talloc_steal(el->values, val->data);
	}
	return ret;
}

/*
  append a string element to a message, stealing it into the 'right' place
*/
int ldb_msg_append_steal_string(struct ldb_message *msg,
				const char *attr_name, char *str,
				int flags)
{
	struct ldb_val val;

	val.data = (uint8_t *)str;
	val.length = strlen(str);

	if (val.length == 0) {
		/* allow empty strings as non-existent attributes */
		return LDB_SUCCESS;
	}

	return ldb_msg_append_steal_value(msg, attr_name, &val, flags);
}

/*
  append a string element to a message
*/
int ldb_msg_append_string(struct ldb_message *msg,
			  const char *attr_name, const char *str, int flags)
{
	struct ldb_val val;

	val.data = discard_const_p(uint8_t, str);
	val.length = strlen(str);

	if (val.length == 0) {
		/* allow empty strings as non-existent attributes */
		return LDB_SUCCESS;
	}

	return ldb_msg_append_value(msg, attr_name, &val, flags);
}

/*
  append a DN element to a message
  WARNING: this uses the linearized string from the dn, and does not
  copy the string.
*/
int ldb_msg_append_linearized_dn(struct ldb_message *msg, const char *attr_name,
				 struct ldb_dn *dn, int flags)
{
	char *str = ldb_dn_alloc_linearized(msg, dn);

	if (str == NULL) {
		/* we don't want to have unknown DNs added */
		return LDB_ERR_OPERATIONS_ERROR;
	}

	return ldb_msg_append_steal_string(msg, attr_name, str, flags);
}

/*
  append a printf formatted element to a message
*/
int ldb_msg_append_fmt(struct ldb_message *msg, int flags,
		       const char *attr_name, const char *fmt, ...)
{
	struct ldb_val val;
	va_list ap;
	char *str = NULL;

	va_start(ap, fmt);
	str = talloc_vasprintf(msg, fmt, ap);
	va_end(ap);

	if (str == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	val.data   = (uint8_t *)str;
	val.length = strlen(str);

	return ldb_msg_append_steal_value(msg, attr_name, &val, flags);
}

/*
  compare two ldb_message_element structures
  assumes case sensitive comparison
*/
int ldb_msg_element_compare(struct ldb_message_element *el1,
			    struct ldb_message_element *el2)
{
	unsigned int i;

	if (el1->num_values != el2->num_values) {
		return el1->num_values - el2->num_values;
	}

	for (i=0;i<el1->num_values;i++) {
		if (!ldb_msg_find_val(el2, &el1->values[i])) {
			return -1;
		}
	}

	return 0;
}

/*
  compare two ldb_message_element structures.
  Different ordering is considered a mismatch
*/
bool ldb_msg_element_equal_ordered(const struct ldb_message_element *el1,
				   const struct ldb_message_element *el2)
{
	unsigned i;
	if (el1->num_values != el2->num_values) {
		return false;
	}
	for (i=0;i<el1->num_values;i++) {
		if (ldb_val_equal_exact(&el1->values[i],
					&el2->values[i]) != 1) {
			return false;
		}
	}
	return true;
}

/*
  compare two ldb_message_element structures
  comparing by element name
*/
int ldb_msg_element_compare_name(struct ldb_message_element *el1,
				 struct ldb_message_element *el2)
{
	return ldb_attr_cmp(el1->name, el2->name);
}

void ldb_msg_element_mark_inaccessible(struct ldb_message_element *el)
{
	el->flags |= LDB_FLAG_INTERNAL_INACCESSIBLE_ATTRIBUTE;
}

bool ldb_msg_element_is_inaccessible(const struct ldb_message_element *el)
{
	return (el->flags & LDB_FLAG_INTERNAL_INACCESSIBLE_ATTRIBUTE) != 0;
}

void ldb_msg_remove_inaccessible(struct ldb_message *msg)
{
	unsigned i;
	unsigned num_del = 0;

	for (i = 0; i < msg->num_elements; ++i) {
		if (ldb_msg_element_is_inaccessible(&msg->elements[i])) {
			++num_del;
		} else if (num_del) {
			msg->elements[i - num_del] = msg->elements[i];
		}
	}

	msg->num_elements -= num_del;
}

/*
  convenience functions to return common types from a message
  these return the first value if the attribute is multi-valued
*/
const struct ldb_val *ldb_msg_find_ldb_val(const struct ldb_message *msg,
					   const char *attr_name)
{
	struct ldb_message_element *el = ldb_msg_find_element(msg, attr_name);
	if (!el || el->num_values == 0) {
		return NULL;
	}
	return &el->values[0];
}

int ldb_msg_find_attr_as_int(const struct ldb_message *msg,
			     const char *attr_name,
			     int default_value)
{
	const struct ldb_val *v = ldb_msg_find_ldb_val(msg, attr_name);
	char buf[sizeof("-2147483648")];
	char *end = NULL;
	int ret;

	if (!v || !v->data) {
		return default_value;
	}

	ZERO_STRUCT(buf);
	if (v->length >= sizeof(buf)) {
		return default_value;
	}

	memcpy(buf, v->data, v->length);
	errno = 0;
	ret = (int) strtoll(buf, &end, 10);
	if (errno != 0) {
		return default_value;
	}
	if (end && end[0] != '\0') {
		return default_value;
	}
	return ret;
}

unsigned int ldb_msg_find_attr_as_uint(const struct ldb_message *msg,
				       const char *attr_name,
				       unsigned int default_value)
{
	const struct ldb_val *v = ldb_msg_find_ldb_val(msg, attr_name);
	char buf[sizeof("-2147483648")];
	char *end = NULL;
	unsigned int ret;

	if (!v || !v->data) {
		return default_value;
	}

	ZERO_STRUCT(buf);
	if (v->length >= sizeof(buf)) {
		return default_value;
	}

	memcpy(buf, v->data, v->length);
	errno = 0;
	ret = (unsigned int) strtoll(buf, &end, 10);
	if (errno != 0) {
		errno = 0;
		ret = (unsigned int) strtoull(buf, &end, 10);
		if (errno != 0) {
			return default_value;
		}
	}
	if (end && end[0] != '\0') {
		return default_value;
	}
	return ret;
}

int64_t ldb_msg_find_attr_as_int64(const struct ldb_message *msg,
				   const char *attr_name,
				   int64_t default_value)
{
	const struct ldb_val *v = ldb_msg_find_ldb_val(msg, attr_name);
	char buf[sizeof("-9223372036854775808")];
	char *end = NULL;
	int64_t ret;

	if (!v || !v->data) {
		return default_value;
	}

	ZERO_STRUCT(buf);
	if (v->length >= sizeof(buf)) {
		return default_value;
	}

	memcpy(buf, v->data, v->length);
	errno = 0;
	ret = (int64_t) strtoll(buf, &end, 10);
	if (errno != 0) {
		return default_value;
	}
	if (end && end[0] != '\0') {
		return default_value;
	}
	return ret;
}

uint64_t ldb_msg_find_attr_as_uint64(const struct ldb_message *msg,
				     const char *attr_name,
				     uint64_t default_value)
{
	const struct ldb_val *v = ldb_msg_find_ldb_val(msg, attr_name);
	char buf[sizeof("-9223372036854775808")];
	char *end = NULL;
	uint64_t ret;

	if (!v || !v->data) {
		return default_value;
	}

	ZERO_STRUCT(buf);
	if (v->length >= sizeof(buf)) {
		return default_value;
	}

	memcpy(buf, v->data, v->length);
	errno = 0;
	ret = (uint64_t) strtoll(buf, &end, 10);
	if (errno != 0) {
		errno = 0;
		ret = (uint64_t) strtoull(buf, &end, 10);
		if (errno != 0) {
			return default_value;
		}
	}
	if (end && end[0] != '\0') {
		return default_value;
	}
	return ret;
}

double ldb_msg_find_attr_as_double(const struct ldb_message *msg,
				   const char *attr_name,
				   double default_value)
{
	const struct ldb_val *v = ldb_msg_find_ldb_val(msg, attr_name);
	char *buf;
	char *end = NULL;
	double ret;

	if (!v || !v->data) {
		return default_value;
	}
	buf = talloc_strndup(msg, (const char *)v->data, v->length);
	if (buf == NULL) {
		return default_value;
	}

	errno = 0;
	ret = strtod(buf, &end);
	talloc_free(buf);
	if (errno != 0) {
		return default_value;
	}
	if (end && end[0] != '\0') {
		return default_value;
	}
	return ret;
}

int ldb_msg_find_attr_as_bool(const struct ldb_message *msg,
			      const char *attr_name,
			      int default_value)
{
	const struct ldb_val *v = ldb_msg_find_ldb_val(msg, attr_name);
	if (!v || !v->data) {
		return default_value;
	}
	if (v->length == 5 && strncasecmp((const char *)v->data, "FALSE", 5) == 0) {
		return 0;
	}
	if (v->length == 4 && strncasecmp((const char *)v->data, "TRUE", 4) == 0) {
		return 1;
	}
	return default_value;
}

const char *ldb_msg_find_attr_as_string(const struct ldb_message *msg,
					const char *attr_name,
					const char *default_value)
{
	const struct ldb_val *v = ldb_msg_find_ldb_val(msg, attr_name);
	if (!v || !v->data) {
		return default_value;
	}
	if (v->data[v->length] != '\0') {
		return default_value;
	}
	return (const char *)v->data;
}

struct ldb_dn *ldb_msg_find_attr_as_dn(struct ldb_context *ldb,
				       TALLOC_CTX *mem_ctx,
				       const struct ldb_message *msg,
				       const char *attr_name)
{
	struct ldb_dn *res_dn;
	const struct ldb_val *v;

	v = ldb_msg_find_ldb_val(msg, attr_name);
	if (!v || !v->data) {
		return NULL;
	}
	res_dn = ldb_dn_from_ldb_val(mem_ctx, ldb, v);
	if ( ! ldb_dn_validate(res_dn)) {
		talloc_free(res_dn);
		return NULL;
	}
	return res_dn;
}

/*
  sort the elements of a message by name
*/
void ldb_msg_sort_elements(struct ldb_message *msg)
{
	TYPESAFE_QSORT(msg->elements, msg->num_elements,
		       ldb_msg_element_compare_name);
}

static struct ldb_message *ldb_msg_copy_shallow_impl(TALLOC_CTX *mem_ctx,
					 const struct ldb_message *msg)
{
	struct ldb_message *msg2;
	unsigned int i;

	msg2 = talloc(mem_ctx, struct ldb_message);
	if (msg2 == NULL) return NULL;

	*msg2 = *msg;

	msg2->elements = talloc_array(msg2, struct ldb_message_element,
				      msg2->num_elements);
	if (msg2->elements == NULL) goto failed;

	for (i=0;i<msg2->num_elements;i++) {
		msg2->elements[i] = msg->elements[i];
	}

	return msg2;

failed:
	talloc_free(msg2);
	return NULL;
}

/*
  shallow copy a message - copying only the elements array so that the caller
  can safely add new elements without changing the message
*/
struct ldb_message *ldb_msg_copy_shallow(TALLOC_CTX *mem_ctx,
					 const struct ldb_message *msg)
{
	struct ldb_message *msg2;
	unsigned int i;

	msg2 = ldb_msg_copy_shallow_impl(mem_ctx, msg);
	if (msg2 == NULL) {
		return NULL;
	}

	for (i = 0; i < msg2->num_elements; ++i) {
		/*
		 * Mark this message's elements as sharing their values with the
		 * original message, so that we don't inadvertently modify or
		 * free them. We don't mark the original message element as
		 * shared, so the original message element should not be
		 * modified or freed while the shallow copy lives.
		 */
		struct ldb_message_element *el = &msg2->elements[i];
		el->flags |= LDB_FLAG_INTERNAL_SHARED_VALUES;
	}

        return msg2;
}

/*
  copy a message, allocating new memory for all parts
*/
struct ldb_message *ldb_msg_copy(TALLOC_CTX *mem_ctx,
				 const struct ldb_message *msg)
{
	struct ldb_message *msg2;
	unsigned int i, j;

	msg2 = ldb_msg_copy_shallow_impl(mem_ctx, msg);
	if (msg2 == NULL) return NULL;

	if (msg2->dn != NULL) {
		msg2->dn = ldb_dn_copy(msg2, msg2->dn);
		if (msg2->dn == NULL) goto failed;
	}

	for (i=0;i<msg2->num_elements;i++) {
		struct ldb_message_element *el = &msg2->elements[i];
		struct ldb_val *values = el->values;
		el->name = talloc_strdup(msg2->elements, el->name);
		if (el->name == NULL) goto failed;
		el->values = talloc_array(msg2->elements, struct ldb_val, el->num_values);
		if (el->values == NULL) goto failed;
		for (j=0;j<el->num_values;j++) {
			el->values[j] = ldb_val_dup(el->values, &values[j]);
			if (el->values[j].data == NULL && values[j].length != 0) {
				goto failed;
			}
		}

                /*
                 * Since we copied this element's values, we can mark them as
                 * not shared.
		 */
		el->flags &= ~LDB_FLAG_INTERNAL_SHARED_VALUES;
	}

	return msg2;

failed:
	talloc_free(msg2);
	return NULL;
}


/**
 * Canonicalize a message, merging elements of the same name
 */
struct ldb_message *ldb_msg_canonicalize(struct ldb_context *ldb,
					 const struct ldb_message *msg)
{
	int ret;
	struct ldb_message *msg2;

	/*
	 * Preserve previous behavior and allocate
	 * *msg2 into *ldb context
	 */
	ret = ldb_msg_normalize(ldb, ldb, msg, &msg2);
	if (ret != LDB_SUCCESS) {
		return NULL;
	}

	return msg2;
}

/**
 * Canonicalize a message, merging elements of the same name
 */
int ldb_msg_normalize(struct ldb_context *ldb,
		      TALLOC_CTX *mem_ctx,
		      const struct ldb_message *msg,
		      struct ldb_message **_msg_out)
{
	unsigned int i;
	struct ldb_message *msg2;

	msg2 = ldb_msg_copy(mem_ctx, msg);
	if (msg2 == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ldb_msg_sort_elements(msg2);

	for (i=1; i < msg2->num_elements; i++) {
		struct ldb_message_element *el1 = &msg2->elements[i-1];
		struct ldb_message_element *el2 = &msg2->elements[i];

		if (ldb_msg_element_compare_name(el1, el2) == 0) {
			el1->values = talloc_realloc(msg2->elements,
			                             el1->values, struct ldb_val,
			                             el1->num_values + el2->num_values);
			if (el1->num_values + el2->num_values > 0 && el1->values == NULL) {
				talloc_free(msg2);
				return LDB_ERR_OPERATIONS_ERROR;
			}
			memcpy(el1->values + el1->num_values,
			       el2->values,
			       sizeof(struct ldb_val) * el2->num_values);
			el1->num_values += el2->num_values;
			talloc_free(discard_const_p(char, el2->name));
			if ((i+1) < msg2->num_elements) {
				memmove(el2, el2+1, sizeof(struct ldb_message_element) *
					(msg2->num_elements - (i+1)));
			}
			msg2->num_elements--;
			i--;
		}
	}

	*_msg_out = msg2;
	return LDB_SUCCESS;
}


/**
 * return a ldb_message representing the differences between msg1 and msg2.
 * If you then use this in a ldb_modify() call,
 * it can be used to save edits to a message
 */
struct ldb_message *ldb_msg_diff(struct ldb_context *ldb,
				 struct ldb_message *msg1,
				 struct ldb_message *msg2)
{
	int ldb_ret;
	struct ldb_message *mod;

	ldb_ret = ldb_msg_difference(ldb, ldb, msg1, msg2, &mod);
	if (ldb_ret != LDB_SUCCESS) {
		return NULL;
	}

	return mod;
}

/**
 * return a ldb_message representing the differences between msg1 and msg2.
 * If you then use this in a ldb_modify() call it can be used to save edits to a message
 *
 * Result message is constructed as follows:
 * - LDB_FLAG_MOD_ADD     - elements found only in msg2
 * - LDB_FLAG_MOD_REPLACE - elements in msg2 that have different value in msg1
 *                          Value for msg2 element is used
 * - LDB_FLAG_MOD_DELETE  - elements found only in msg2
 *
 * @return LDB_SUCCESS or LDB_ERR_OPERATIONS_ERROR
 */
int ldb_msg_difference(struct ldb_context *ldb,
		       TALLOC_CTX *mem_ctx,
		       struct ldb_message *msg1,
		       struct ldb_message *msg2,
		       struct ldb_message **_msg_out)
{
	int ldb_res;
	unsigned int i;
	struct ldb_message *mod;
	struct ldb_message_element *el;
	TALLOC_CTX *temp_ctx;

	temp_ctx = talloc_new(mem_ctx);
	if (!temp_ctx) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	mod = ldb_msg_new(temp_ctx);
	if (mod == NULL) {
		goto failed;
	}

	mod->dn = msg1->dn;
	mod->num_elements = 0;
	mod->elements = NULL;

	/*
	 * Canonicalize *msg2 so we have no repeated elements
	 * Resulting message is allocated in *mod's mem context,
	 * as we are going to move some elements from *msg2 to
	 * *mod object later
	 */
	ldb_res = ldb_msg_normalize(ldb, mod, msg2, &msg2);
	if (ldb_res != LDB_SUCCESS) {
		goto failed;
	}

	/* look in msg2 to find elements that need to be added or modified */
	for (i=0;i<msg2->num_elements;i++) {
		el = ldb_msg_find_element(msg1, msg2->elements[i].name);

		if (el && ldb_msg_element_compare(el, &msg2->elements[i]) == 0) {
			continue;
		}

		ldb_res = ldb_msg_add(mod,
		                      &msg2->elements[i],
		                      el ? LDB_FLAG_MOD_REPLACE : LDB_FLAG_MOD_ADD);
		if (ldb_res != LDB_SUCCESS) {
			goto failed;
		}
	}

	/* look in msg1 to find elements that need to be deleted */
	for (i=0;i<msg1->num_elements;i++) {
		el = ldb_msg_find_element(msg2, msg1->elements[i].name);
		if (el == NULL) {
			ldb_res = ldb_msg_add_empty(mod,
			                            msg1->elements[i].name,
			                            LDB_FLAG_MOD_DELETE, NULL);
			if (ldb_res != LDB_SUCCESS) {
				goto failed;
			}
		}
	}

	/* steal resulting message into supplied context */
	talloc_steal(mem_ctx, mod);
	*_msg_out = mod;

	talloc_free(temp_ctx);
	return LDB_SUCCESS;

failed:
	talloc_free(temp_ctx);
	return LDB_ERR_OPERATIONS_ERROR;
}


int ldb_msg_sanity_check(struct ldb_context *ldb,
			 const struct ldb_message *msg)
{
	unsigned int i, j;

	/* basic check on DN */
	if (msg->dn == NULL) {
		ldb_set_errstring(ldb, "ldb message lacks a DN!");
		return LDB_ERR_INVALID_DN_SYNTAX;
	}

	/* basic syntax checks */
	for (i = 0; i < msg->num_elements; i++) {
		for (j = 0; j < msg->elements[i].num_values; j++) {
			if (msg->elements[i].values[j].length == 0) {
				/* an attribute cannot be empty */
				ldb_asprintf_errstring(ldb, "Element %s has empty attribute in ldb message (%s)!",
							    msg->elements[i].name,
							    ldb_dn_get_linearized(msg->dn));
				return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
			}
		}
	}

	return LDB_SUCCESS;
}




/*
  copy an attribute list. This only copies the array, not the elements
  (ie. the elements are left as the same pointers)
*/
const char **ldb_attr_list_copy(TALLOC_CTX *mem_ctx, const char * const *attrs)
{
	const char **ret;
	unsigned int i;

	for (i=0;attrs && attrs[i];i++) /* noop */ ;
	ret = talloc_array(mem_ctx, const char *, i+1);
	if (ret == NULL) {
		return NULL;
	}
	for (i=0;attrs && attrs[i];i++) {
		ret[i] = attrs[i];
	}
	ret[i] = attrs[i];
	return ret;
}


/*
  copy an attribute list. This only copies the array, not the elements
  (ie. the elements are left as the same pointers).  The new attribute is added to the list.
*/
const char **ldb_attr_list_copy_add(TALLOC_CTX *mem_ctx, const char * const *attrs, const char *new_attr)
{
	const char **ret;
	unsigned int i;
	bool found = false;

	for (i=0;attrs && attrs[i];i++) {
		if (ldb_attr_cmp(attrs[i], new_attr) == 0) {
			found = true;
		}
	}
	if (found) {
		return ldb_attr_list_copy(mem_ctx, attrs);
	}
	ret = talloc_array(mem_ctx, const char *, i+2);
	if (ret == NULL) {
		return NULL;
	}
	for (i=0;attrs && attrs[i];i++) {
		ret[i] = attrs[i];
	}
	ret[i] = new_attr;
	ret[i+1] = NULL;
	return ret;
}


/*
  return 1 if an attribute is in a list of attributes, or 0 otherwise
*/
int ldb_attr_in_list(const char * const *attrs, const char *attr)
{
	unsigned int i;
	for (i=0;attrs && attrs[i];i++) {
		if (ldb_attr_cmp(attrs[i], attr) == 0) {
			return 1;
		}
	}
	return 0;
}


/*
  rename the specified attribute in a search result
*/
int ldb_msg_rename_attr(struct ldb_message *msg, const char *attr, const char *replace)
{
	struct ldb_message_element *el = ldb_msg_find_element(msg, attr);
	if (el == NULL) {
		return LDB_SUCCESS;
	}
	el->name = talloc_strdup(msg->elements, replace);
	if (el->name == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	return LDB_SUCCESS;
}


/*
  copy the specified attribute in a search result to a new attribute
*/
int ldb_msg_copy_attr(struct ldb_message *msg, const char *attr, const char *replace)
{
	struct ldb_message_element *el = ldb_msg_find_element(msg, attr);
	int ret;

	if (el == NULL) {
		return LDB_SUCCESS;
	}
	ret = ldb_msg_add(msg, el, 0);
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	return ldb_msg_rename_attr(msg, attr, replace);
}

/*
  remove the specified element in a search result
*/
void ldb_msg_remove_element(struct ldb_message *msg, struct ldb_message_element *el)
{
	ptrdiff_t n = (el - msg->elements);
	if (n >= msg->num_elements || n < 0) {
		/* the element is not in the list. the caller is crazy. */
		return;
	}
	msg->num_elements--;
	if (n != msg->num_elements) {
		memmove(el, el+1, (msg->num_elements - n)*sizeof(*el));
	}
}


/*
  remove the specified attribute in a search result
*/
void ldb_msg_remove_attr(struct ldb_message *msg, const char *attr)
{
	struct ldb_message_element *el;

	while ((el = ldb_msg_find_element(msg, attr)) != NULL) {
		ldb_msg_remove_element(msg, el);
	}
}

/* Reallocate elements to drop any excess capacity. */
void ldb_msg_shrink_to_fit(struct ldb_message *msg)
{
	if (msg->num_elements > 0) {
		struct ldb_message_element *elements = talloc_realloc(msg,
								      msg->elements,
								      struct ldb_message_element,
								      msg->num_elements);
		if (elements != NULL) {
			msg->elements = elements;
		}
	} else {
		TALLOC_FREE(msg->elements);
	}
}

/*
  return a LDAP formatted GeneralizedTime string
*/
char *ldb_timestring(TALLOC_CTX *mem_ctx, time_t t)
{
	struct tm *tm = gmtime(&t);
	char *ts;
	int r;

	if (!tm) {
		return NULL;
	}

	/* we now excatly how long this string will be */
	ts = talloc_array(mem_ctx, char, 18);

	/* formatted like: 20040408072012.0Z */
	r = snprintf(ts, 18,
			"%04u%02u%02u%02u%02u%02u.0Z",
			tm->tm_year+1900, tm->tm_mon+1,
			tm->tm_mday, tm->tm_hour, tm->tm_min,
			tm->tm_sec);

	if (r != 17) {
		talloc_free(ts);
		errno = EOVERFLOW;
		return NULL;
	}

	return ts;
}

/*
  convert a LDAP GeneralizedTime string to a time_t. Return 0 if unable to convert
*/
time_t ldb_string_to_time(const char *s)
{
	struct tm tm;

	if (s == NULL) return 0;

	memset(&tm, 0, sizeof(tm));
	if (sscanf(s, "%04u%02u%02u%02u%02u%02u.0Z",
		   &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
		   &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
		return 0;
	}
	tm.tm_year -= 1900;
	tm.tm_mon -= 1;

	return timegm(&tm);
}

/*
  convert a LDAP GeneralizedTime string in ldb_val format to a
  time_t.
*/
int ldb_val_to_time(const struct ldb_val *v, time_t *t)
{
	char val[15] = {0};
	struct tm tm = {
		.tm_year = 0,
	};

	if (v == NULL) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}

	if (v->data == NULL) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}

	if (v->length < 16 && v->length != 13) {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}

	if (v->data[v->length - 1] != 'Z') {
		return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
	}

	if (v->length == 13) {
		memcpy(val, v->data, 12);

		if (sscanf(val, "%02u%02u%02u%02u%02u%02u",
			&tm.tm_year, &tm.tm_mon, &tm.tm_mday,
			&tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
			return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
		}
		if (tm.tm_year < 50) {
			tm.tm_year += 100;
		}
	} else {

		/*
		 * anything between '.' and 'Z' is silently ignored.
		 */
		if (v->data[14] != '.') {
			return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
		}

		memcpy(val, v->data, 14);

		if (sscanf(val, "%04u%02u%02u%02u%02u%02u",
			&tm.tm_year, &tm.tm_mon, &tm.tm_mday,
			&tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
			return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
		}
		tm.tm_year -= 1900;
	}
	tm.tm_mon -= 1;

	*t = timegm(&tm);

	return LDB_SUCCESS;
}

/*
  return a LDAP formatted UTCTime string
*/
char *ldb_timestring_utc(TALLOC_CTX *mem_ctx, time_t t)
{
	struct tm *tm = gmtime(&t);
	char *ts;
	int r;

	if (!tm) {
		return NULL;
	}

	/* we now excatly how long this string will be */
	ts = talloc_array(mem_ctx, char, 14);

	/* formatted like: 20040408072012.0Z => 040408072012Z */
	r = snprintf(ts, 14,
			"%02u%02u%02u%02u%02u%02uZ",
			(tm->tm_year+1900)%100, tm->tm_mon+1,
			tm->tm_mday, tm->tm_hour, tm->tm_min,
			tm->tm_sec);

	if (r != 13) {
		talloc_free(ts);
		return NULL;
	}

	return ts;
}

/*
  convert a LDAP UTCTime string to a time_t. Return 0 if unable to convert
*/
time_t ldb_string_utc_to_time(const char *s)
{
	struct tm tm;

	if (s == NULL) return 0;

	memset(&tm, 0, sizeof(tm));
	if (sscanf(s, "%02u%02u%02u%02u%02u%02uZ",
		   &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
		   &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
		return 0;
	}
	if (tm.tm_year < 50) {
		tm.tm_year += 100;
	}
	tm.tm_mon -= 1;

	return timegm(&tm);
}


/*
  dump a set of results to a file. Useful from within gdb
*/
void ldb_dump_results(struct ldb_context *ldb, struct ldb_result *result, FILE *f)
{
	unsigned int i;

	for (i = 0; i < result->count; i++) {
		struct ldb_ldif ldif;
		fprintf(f, "# record %d\n", i+1);
		ldif.changetype = LDB_CHANGETYPE_NONE;
		ldif.msg = result->msgs[i];
		ldb_ldif_write_file(ldb, f, &ldif);
	}
}

/*
  checks for a string attribute. Returns "1" on match and otherwise "0".
*/
int ldb_msg_check_string_attribute(const struct ldb_message *msg,
				   const char *name, const char *value)
{
	struct ldb_message_element *el;
	struct ldb_val val;

	el = ldb_msg_find_element(msg, name);
	if (el == NULL) {
		return 0;
	}

	val.data = discard_const_p(uint8_t, value);
	val.length = strlen(value);

	if (ldb_msg_find_val(el, &val)) {
		return 1;
	}

	return 0;
}


/*
  compare a ldb_val to a string
*/
int ldb_val_string_cmp(const struct ldb_val *v, const char *str)
{
	size_t len = strlen(str);
	if (len != v->length) {
		return len - v->length;
	}
	return strncmp((const char *)v->data, str, len);
}

/*
   common routines for audit logging

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018

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
#ifndef _AUDIT_LOGGING_H_
#define _AUDIT_LOGGING_H_
#include <talloc.h>

_WARN_UNUSED_RESULT_ char *audit_get_timestamp(TALLOC_CTX *frame);
#ifdef HAVE_JANSSON
#include <jansson.h>
/*
 * Wrapper for jannson JSON object
 *
 */
struct json_object {
	json_t *root;
	bool valid;
};
extern const struct json_object json_empty_object;

#define JSON_ERROR -1

void audit_log_json(struct json_object *message,
		    int debug_class,
		    int debug_level);
_WARN_UNUSED_RESULT_ struct json_object json_new_object(void);
_WARN_UNUSED_RESULT_ struct json_object json_new_array(void);
void json_free(struct json_object *object);
void json_assert_is_array(struct json_object *array);
_WARN_UNUSED_RESULT_ bool json_is_invalid(const struct json_object *object);

_WARN_UNUSED_RESULT_ int json_add_int(struct json_object *object,
				      const char *name,
				      const int value);
_WARN_UNUSED_RESULT_ int json_add_bool(struct json_object *object,
				       const char *name,
				       const bool value);
_WARN_UNUSED_RESULT_ int json_add_string(struct json_object *object,
					 const char *name,
					 const char *value);
_WARN_UNUSED_RESULT_ int json_add_object(struct json_object *object,
					 const char *name,
					 struct json_object *value);
_WARN_UNUSED_RESULT_ int json_add_stringn(struct json_object *object,
					  const char *name,
					  const char *value,
					  const size_t len);
_WARN_UNUSED_RESULT_ int json_add_version(struct json_object *object,
					  int major,
					  int minor);
_WARN_UNUSED_RESULT_ int json_add_timestamp(struct json_object *object);

_WARN_UNUSED_RESULT_ struct json_object json_get_array(
    struct json_object *object, const char *name);
_WARN_UNUSED_RESULT_ struct json_object json_get_object(
    struct json_object *object, const char *name);
_WARN_UNUSED_RESULT_ char *json_to_string(TALLOC_CTX *mem_ctx,
					  const struct json_object *object);

_WARN_UNUSED_RESULT_ int iter_json_array(struct json_object *object,
					 bool (*fn)(int index,
						    struct json_object *entry,
						    void *private_data),
					 void *private_data);

_WARN_UNUSED_RESULT_ int iter_json_object(struct json_object *object,
					  bool (*fn)(const char *key,
						     struct json_object *value,
						     void *private_data),
					  void *private_data);

_WARN_UNUSED_RESULT_ int json_get_string_value(
    const struct json_object *object, const char *key, const char **valp);
_WARN_UNUSED_RESULT_ int json_get_bool_value(
    const struct json_object *object, const char *key, bool *valp);
_WARN_UNUSED_RESULT_ int json_get_int_value(
    const struct json_object *object, const char *key, int *valp);
_WARN_UNUSED_RESULT_ int json_get_array_value(
    const struct json_object *object, const char *key, struct json_object *valp);

_WARN_UNUSED_RESULT_ struct json_object load_json(const char *text);

#endif
#endif

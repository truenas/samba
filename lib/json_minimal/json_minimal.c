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

/*
 * Error handling:
 *
 */

#include "includes.h"

#include "json_minimal.h"

/*
 * @brief Get a human readable timestamp.
 *
 * Returns the current time formatted as
 *  "Tue, 14 Mar 2017 08:38:42.209028 NZDT"
 *
 * The returned string is allocated by talloc in the supplied context.
 * It is the callers responsibility to free it.
 *
 * @param mem_ctx talloc memory context that owns the returned string.
 *
 * @return a human readable time stamp, or NULL in the event of an error.
 *
 */
char* audit_get_timestamp(TALLOC_CTX *frame)
{
	char buffer[40];	/* formatted time less usec and timezone */
	char tz[10];		/* formatted time zone			 */
	struct tm* tm_info;	/* current local time			 */
	struct timeval tv;	/* current system time			 */
	int ret;		/* response code			 */
	char * ts;		/* formatted time stamp			 */

	ret = gettimeofday(&tv, NULL);
	if (ret != 0) {
		DBG_ERR("Unable to get time of day: (%d) %s\n",
			errno,
			strerror(errno));
		return NULL;
	}

	tm_info = localtime(&tv.tv_sec);
	if (tm_info == NULL) {
		DBG_ERR("Unable to determine local time\n");
		return NULL;
	}

	strftime(buffer, sizeof(buffer)-1, "%a, %d %b %Y %H:%M:%S", tm_info);
	strftime(tz, sizeof(tz)-1, "%Z", tm_info);
	ts = talloc_asprintf(frame, "%s.%06ld %s", buffer, tv.tv_usec, tz);
	if (ts == NULL) {
		DBG_ERR("Out of memory formatting time stamp\n");
	}
	return ts;
}

#ifdef HAVE_JANSSON
/*
 * Constant for empty json object initialisation
 */
const struct json_object json_empty_object = {.valid = false, .root = NULL};

/*
 * @brief Create a new struct json_object, wrapping a JSON Object.
 *
 * Create a new json object, the json_object wraps the underlying json
 * implementations JSON Object representation.
 *
 * Free with a call to json_free_object, note that the jansson inplementation
 * allocates memory with malloc and not talloc.
 *
 * @return a struct json_object, valid will be set to false if the object
 *         could not be created.
 *
 */
struct json_object json_new_object(void) {

	struct json_object object = json_empty_object;

	object.root = json_object();
	if (object.root == NULL) {
		object.valid = false;
		DBG_ERR("Unable to create JSON object\n");
		return object;
	}
	object.valid = true;
	return object;
}

/*
 * @brief Create a new struct json_object wrapping a JSON Array.
 *
 * Create a new json object, the json_object wraps the underlying json
 * implementations JSON Array representation.
 *
 * Free with a call to json_free_object, note that the jansson inplementation
 * allocates memory with malloc and not talloc.
 *
 * @return a struct json_object, error will be set to true if the array
 *         could not be created.
 *
 */
struct json_object json_new_array(void) {

	struct json_object array = json_empty_object;

	array.root = json_array();
	if (array.root == NULL) {
		array.valid = false;
		DBG_ERR("Unable to create JSON array\n");
		return array;
	}
	array.valid = true;
	return array;
}


/*
 * @brief free and invalidate a previously created JSON object.
 *
 * Release any resources owned by a json_object, and then mark the structure
 * as invalid.  It is safe to call this multiple times on an object.
 *
 */
void json_free(struct json_object *object)
{
	if (object->root != NULL) {
		json_decref(object->root);
	}
	object->root = NULL;
	object->valid = false;
}

/*
 * @brief is the current JSON object invalid?
 *
 * Check the state of the object to determine if it is invalid.
 *
 * @return is the object valid?
 *
 */
bool json_is_invalid(const struct json_object *object)
{
	return !object->valid;
}

/*
 * @brief Add an integer value to a JSON object.
 *
 * Add an integer value named 'name' to the json object.
 *
 * @param object the JSON object to be updated.
 * @param name the name of the value.
 * @param value the value.
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 *
 */
int json_add_int(struct json_object *object, const char *name, const int value)
{
	int ret = 0;
	json_t *integer = NULL;

	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add int [%s] value [%d], "
			"target object is invalid\n",
			name,
			value);
		return JSON_ERROR;
	}

	integer = json_integer(value);
	if (integer == NULL) {
		DBG_ERR("Unable to create integer value [%s] value [%d]\n",
			name,
			value);
		return JSON_ERROR;
	}

	ret = json_object_set_new(object->root, name, integer);
	if (ret != 0) {
		json_decref(integer);
		DBG_ERR("Unable to add int [%s] value [%d]\n", name, value);
	}
	return ret;
}

/*
 * @brief Add a boolean value to a JSON object.
 *
 * Add a boolean value named 'name' to the json object.
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param value the value.
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 *
 */
int json_add_bool(struct json_object *object,
		  const char *name,
		  const bool value)
{
	int ret = 0;

	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add boolean [%s] value [%d], "
			"target object is invalid\n",
			name,
			value);
		return JSON_ERROR;
	}

	ret = json_object_set_new(object->root, name, json_boolean(value));
	if (ret != 0) {
		DBG_ERR("Unable to add boolean [%s] value [%d]\n", name, value);
	}
	return ret;
}

/*
 * @brief Add a string value to a JSON object.
 *
 * Add a string value named 'name' to the json object.
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param value the value.
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 *
 */
int json_add_string(struct json_object *object,
		    const char *name,
		    const char *value)
{
	int ret = 0;

	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add string [%s], target object is invalid\n",
			name);
		return JSON_ERROR;
	}
	if (value) {
		json_t *string = json_string(value);
		if (string == NULL) {
			DBG_ERR("Unable to add string [%s], "
				"could not create string object\n",
				name);
			return JSON_ERROR;
		}
		ret = json_object_set_new(object->root, name, string);
		if (ret != 0) {
			json_decref(string);
			DBG_ERR("Unable to add string [%s]\n", name);
			return ret;
		}
	} else {
		ret = json_object_set_new(object->root, name, json_null());
		if (ret != 0) {
			DBG_ERR("Unable to add null string [%s]\n", name);
			return ret;
		}
	}
	return ret;
}

/*
 * @brief Assert that the current JSON object is an array.
 *
 * Check that the current object is a JSON array, and if not
 * invalidate the object. We also log an error message as this indicates
 * bug in the calling code.
 *
 * @param object the JSON object to be validated.
 */
void json_assert_is_array(struct json_object *array) {

	if (json_is_invalid(array)) {
		return;
	}

	if (json_is_array(array->root) == false) {
		DBG_ERR("JSON object is not an array\n");
		array->valid = false;
		return;
	}
}

/*
 * @brief Add a JSON object to a JSON object.
 *
 * Add a JSON object named 'name' to the json object.
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param value the value.
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 *
 */
int json_add_object(struct json_object *object,
		    const char *name,
		    struct json_object *value)
{
	int ret = 0;
	json_t *jv = NULL;

	if (value != NULL && json_is_invalid(value)) {
		DBG_ERR("Invalid JSON object [%s] supplied\n", name);
		return JSON_ERROR;
	}
	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add object [%s], target object is invalid\n",
			name);
		return JSON_ERROR;
	}

	jv = value == NULL ? json_null() : value->root;

	if (json_is_array(object->root)) {
		ret = json_array_append_new(object->root, jv);
	} else if (json_is_object(object->root)) {
		ret = json_object_set_new(object->root, name, jv);
	} else {
		DBG_ERR("Invalid JSON object type\n");
		ret = JSON_ERROR;
	}
	if (ret != 0) {
		DBG_ERR("Unable to add object [%s]\n", name);
	}
	return ret;
}

/*
 * @brief Add a string to a JSON object, truncating if necessary.
 *
 *
 * Add a string value named 'name' to the json object, the string will be
 * truncated if it is more than len characters long. If len is 0 the value
 * is encoded as a JSON null.
 *
 *
 * @param object the JSON object to be updated.
 * @param name the name.
 * @param value the value.
 * @param len the maximum number of characters to be copied.
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 *
 */
int json_add_stringn(struct json_object *object,
		     const char *name,
		     const char *value,
		     const size_t len)
{

	int ret = 0;
	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add string [%s], target object is invalid\n",
			name);
		return JSON_ERROR;
	}

	if (value != NULL && len > 0) {
		json_t *string = NULL;
		char buffer[len+1];

		strncpy(buffer, value, len);
		buffer[len] = '\0';

		string = json_string(buffer);
		if (string == NULL) {
			DBG_ERR("Unable to add string [%s], "
				"could not create string object\n",
				name);
			return JSON_ERROR;
		}
		ret = json_object_set_new(object->root, name, string);
		if (ret != 0) {
			json_decref(string);
			DBG_ERR("Unable to add string [%s]\n", name);
			return ret;
		}
	} else {
		ret = json_object_set_new(object->root, name, json_null());
		if (ret != 0) {
			DBG_ERR("Unable to add null string [%s]\n", name);
			return ret;
		}
	}
	return ret;
}

/*
 * @brief Add a version object to a JSON object
 *
 * Add a version object to the JSON object
 * 	"version":{"major":1, "minor":0}
 *
 * The version tag is intended to aid the processing of the JSON messages
 * The major version number should change when an attribute is:
 *  - renamed
 *  - removed
 *  - its meaning changes
 *  - its contents change format
 * The minor version should change whenever a new attribute is added and for
 * minor bug fixes to an attributes content.
 *
 *
 * @param object the JSON object to be updated.
 * @param major the major version number
 * @param minor the minor version number
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 */
int json_add_version(struct json_object *object, int major, int minor)
{
	int ret = 0;
	struct json_object version;

	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add version, target object is invalid\n");
		return JSON_ERROR;
	}

	version = json_new_object();
	if (json_is_invalid(&version)) {
		DBG_ERR("Unable to add version, failed to create object\n");
		return JSON_ERROR;
	}
	ret = json_add_int(&version, "major", major);
	if (ret != 0) {
		json_free(&version);
		return ret;
	}
	ret = json_add_int(&version, "minor", minor);
	if (ret != 0) {
		json_free(&version);
		return ret;
	}
	ret = json_add_object(object, "version", &version);
	if (ret != 0) {
		json_free(&version);
		return ret;
	}
	return ret;
}

/*
 * @brief add an ISO 8601 timestamp to the object.
 *
 * Add the current date and time as a timestamp in ISO 8601 format
 * to a JSON object
 *
 * "timestamp":"2017-03-06T17:18:04.455081+1300"
 *
 *
 * @param object the JSON object to be updated.
 *
 * @return 0 the operation was successful
 *        -1 the operation failed
 */
int json_add_timestamp(struct json_object *object)
{
	char buffer[40];	/* formatted time less usec and timezone */
	char timestamp[65];	/* the formatted ISO 8601 time stamp	 */
	char tz[10];		/* formatted time zone			 */
	struct tm* tm_info;	/* current local time			 */
	struct timeval tv;	/* current system time			 */
	int r;			/* response code from gettimeofday	 */
	int ret;		/* return code from json operations	*/

	if (json_is_invalid(object)) {
		DBG_ERR("Unable to add time stamp, target object is invalid\n");
		return JSON_ERROR;
	}

	r = gettimeofday(&tv, NULL);
	if (r) {
		DBG_ERR("Unable to get time of day: (%d) %s\n",
			errno,
			strerror(errno));
		return JSON_ERROR;
	}

	tm_info = localtime(&tv.tv_sec);
	if (tm_info == NULL) {
		DBG_ERR("Unable to determine local time\n");
		return JSON_ERROR;
	}

	strftime(buffer, sizeof(buffer)-1, "%Y-%m-%dT%T", tm_info);
	strftime(tz, sizeof(tz)-1, "%z", tm_info);
	snprintf(
		timestamp,
		sizeof(timestamp),
		"%s.%06ld%s",
		buffer,
		tv.tv_usec,
		tz);
	ret = json_add_string(object, "timestamp", timestamp);
	if (ret != 0) {
		DBG_ERR("Unable to add time stamp to JSON object\n");
	}
	return ret;
}

/*
 * @brief Convert a JSON object into a string
 *
 * Convert the jsom object into a string suitable for printing on a log line,
 * i.e. with no embedded line breaks.
 *
 * If the object is invalid it logs an error and returns NULL.
 *
 * @param mem_ctx the talloc memory context owning the returned string
 * @param object the json object.
 *
 * @return A string representation of the object or NULL if the object
 *         is invalid.
 */
char *json_to_string(TALLOC_CTX *mem_ctx, const struct json_object *object)
{
	char *json = NULL;
	char *json_string = NULL;

	if (json_is_invalid(object)) {
		DBG_ERR("Invalid JSON object, unable to convert to string\n");
		return NULL;
	}

	if (object->root == NULL) {
		return NULL;
	}

	/*
	 * json_dumps uses malloc, so need to call free(json) to release
	 * the memory
	 */
	json = json_dumps(object->root, 0);
	if (json == NULL) {
		DBG_ERR("Unable to convert JSON object to string\n");
		return NULL;
	}

	json_string = talloc_strdup(mem_ctx, json);
	if (json_string == NULL) {
		free(json);
		DBG_ERR("Unable to copy JSON object string to talloc string\n");
		return NULL;
	}
	free(json);

	return json_string;
}

/*
 * @brief get a json array named "name" from the json object.
 *
 * Get the array attribute named name, creating it if it does not exist.
 *
 * @param object the json object.
 * @param name the name of the array attribute
 *
 * @return The array object, will be created if it did not exist.
 */
struct json_object json_get_array(struct json_object *object, const char *name)
{

	struct json_object array = json_empty_object;
	json_t *a = NULL;
	int ret = 0;

	if (json_is_invalid(object)) {
		DBG_ERR("Invalid JSON object, unable to get array [%s]\n",
			name);
		json_free(&array);
		return array;
	}

	array = json_new_array();
	if (json_is_invalid(&array)) {
		DBG_ERR("Unable to create new array for [%s]\n", name);
		return array;
	}

	a = json_object_get(object->root, name);
	if (a == NULL) {
		return array;
	}

	ret = json_array_extend(array.root, a);
	if (ret != 0) {
		DBG_ERR("Unable to get array [%s]\n", name);
		json_free(&array);
		return array;
	}

	return array;
}

/*
 * @brief get a json object named "name" from the json object.
 *
 * Get the object attribute named name, creating it if it does not exist.
 *
 * @param object the json object.
 * @param name the name of the object attribute
 *
 * @return The object, will be created if it did not exist.
 */
struct json_object json_get_object(struct json_object *object, const char *name)
{

	struct json_object o = json_new_object();
	json_t *v = NULL;
	int ret = 0;

	if (json_is_invalid(object)) {
		DBG_ERR("Invalid JSON object, unable to get object [%s]\n",
			name);
		json_free(&o);
		return o;
	}

	v = json_object_get(object->root, name);
	if (v == NULL) {
		return o;
	}
	ret = json_object_update(o.root, v);
	if (ret != 0) {
		DBG_ERR("Unable to get object [%s]\n", name);
		json_free(&o);
		return o;
	}
	return o;
}

/*
 * @brief iterate through objects in a json array
 *
 * Iterate through elements of json array and call callback
 * function for each of them.
 *
 * @param object the json object
 * @param fn callback function
 * @param private_data private data to pass to callback function
 *
 * @return 0 on success -1 on failure
 */
int iter_json_array(struct json_object *object,
		    bool (*fn)(int index,
			       struct json_object *entry,
			       void *state),
		    void *private_data)
{
	int i;
	size_t array_size;

	if (json_is_invalid(object)) {
		DBG_ERR("Invalid JSON object.\n");
		return -1;
	}
	if (!json_is_array(object->root)) {
		DBG_ERR("JSON object is not an array\n");
		return -1;
	}

	array_size = json_array_size(object->root);
	for (i = 0; i < array_size; i++) {
		bool ok;
		json_t *entry = NULL;
		struct json_object jsobj = json_empty_object;

		entry = json_array_get(object->root, i);
		if (entry == NULL) {
			DBG_ERR("Idx [%d] in JSON array is invalid\n", i);
			return -1;
		}

		jsobj = (struct json_object) {
			.root = entry,
			.valid = true,
		};

		ok = fn(i, &jsobj, private_data);
		if (!ok) {
			return -1;
		}
	}
	return 0;
}

/*
 * @brief iterate through keys in a json object
 *
 * Iterate through keys in a json object, and call callback
 * function for each of them.
 *
 * @param object the json object
 * @param fn callback function
 * @param private_data private data to pass to callback function
 *
 * @return 0 on success -1 on failure
 */
int iter_json_object(struct json_object *object,
		     bool (*fn)(const char *key,
				struct json_object *value,
				void *state),
		     void *private_data)
{
	void *tmp = NULL;
	const char *key = NULL;
	json_t *value = NULL;

	if (json_is_invalid(object)) {
		DBG_ERR("Invalid JSON object.\n");
		return -1;
	}

	json_object_foreach_safe(object->root, tmp, key, value) {
		bool ok;
		struct json_object jsobj = json_empty_object;

		jsobj = (struct json_object) {
			.root = value,
			.valid = true,
		};

		ok = fn(key, &jsobj, private_data);
		if (!ok) {
			return -1;
		}
	}
	return 0;
}

int json_get_string_value(const struct json_object *object,
			  const char *key,
			  const char **valp)
{
	json_t *to_check = NULL;
	const char *value = NULL;

	if (json_is_invalid(object)) {
		errno = EINVAL;
		return -1;
	}

	to_check = json_object_get(object->root, key);
	if (to_check == NULL) {
		errno = ENOENT;
		return -1;
	}

	if (!json_is_string(to_check)) {
		DBG_ERR("%s: Unexpected JSON type: %d\n",
			key, json_typeof(to_check));
		errno = EINVAL;
		return -1;
	}

	value = json_string_value(to_check);
	*valp = value;
	return 0;
}

int json_get_bool_value(const struct json_object *object,
			const char *key,
			bool *valp)
{
	json_t *to_check = NULL;
	bool value;

	if (json_is_invalid(object)) {
		errno = EINVAL;
		return -1;
	}

	to_check = json_object_get(object->root, key);
	if (to_check == NULL) {
		errno = ENOENT;
		return -1;
	}

	if (!json_is_boolean(to_check)) {
		DBG_ERR("%s: unexpected JSON type: %d\n",
			key, json_typeof(to_check));
		errno = EINVAL;
		return -1;
	}

	value = json_boolean_value(to_check);
	*valp = value;
	return 0;
}

int json_get_int_value(const struct json_object *object,
		       const char *key,
		       int *valp)
{
	json_t *to_check = NULL;
	int value;

	if (json_is_invalid(object)) {
		errno = EINVAL;
		return -1;
	}

	to_check = json_object_get(object->root, key);
	if (to_check == NULL) {
		errno = ENOENT;
		return -1;
	}

	if (!json_is_integer(to_check)) {
		DBG_ERR("%d: unexpected JSON type: %d\n",
			key, json_typeof(to_check));
		errno = EINVAL;
		return -1;
	}

	value = json_integer_value(to_check);
	*valp = value;
	return 0;
}

int json_get_array_value(const struct json_object *object,
			 const char *key,
			 struct json_object *valp)
{
	json_t *to_check = NULL;
	int value;

	if (json_is_invalid(object)) {
		errno = EINVAL;
		valp->valid = false;
		return -1;
	}

	to_check = json_object_get(object->root, key);
	if (to_check == NULL) {
		errno = ENOENT;
		valp->valid = false;
		return -1;
	}

	if (!json_is_array(to_check)) {
		DBG_ERR("%d: unexpected JSON type: %d\n",
			key, json_typeof(to_check));
		errno = EINVAL;
		valp->valid = false;
		return -1;
	}

	valp->root = to_check;
	valp->valid = true;
	return 0;
}

/*
 * @brief convert text into a json object
 *
 * Load json from text. This is primarily useful for adding
 * json input support for utilities. libjansson will perform
 * validation and report errors, which we print at DBG_ERR.
 *
 * @param text string to convert to struct json object
 *
 * @return a struct json_object, valid will be set to false if the object
 *         could not be created.
 */
struct json_object load_json(const char *text)
{
	struct json_object object = json_empty_object;
	json_t *root = NULL;
	json_error_t error;

	root = json_loads(text, 0, &error);
	if (root == NULL) {
		DBG_ERR("JSON error on line %d: %s\n",
			error.line, error.text);
		object.valid = false;
		return object;
	}
	object = (struct json_object) {
		.root = root,
		.valid = true,
	};
	return object;
}
#endif

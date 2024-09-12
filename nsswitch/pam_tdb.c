/* pam_tdb module

   Copyright (c) Andrew Walker <awalker@ixsystems.com> 2024.

   largely based on pam_winbind and pam_unix. See copyright
   reproduced below
*/

#include "pam_tdb.h"

/* Allow options to expand the functions provided by this module */
enum pam_tdb_request_type {
	PAM_TDB_AUTHENTICATE,
};

typedef struct {
	const char *name;
	gnutls_mac_algorithm_t algo;
	uint32_t min_iter;
} pam_tdb_algo_t;


pam_tdb_algo_t algo_table[] = {
	{"pbkdf2-sha256", GNUTLS_MAC_SHA256, 29000},
	{"pbkdf2-sha512", GNUTLS_MAC_SHA512, 300000},
};

/* lifted from internal pam_macros in linux-pam */
static inline int
pam_tdb_consttime_streq(const char *userinput, const char *secret) {
	volatile const char *u = userinput, *s = secret;
	volatile int ret = 0;

	do {
		ret |= *u ^ *s;

		s += !!*s;
	} while (*u++ != '\0');

	return ret == 0;
}
/* end pam_macros */

static bool _pam_log_is_silent(int ctrl)
{
	return ctrl & PAM_TDB_SILENT;
}

static bool _pam_log_is_debug_enabled(int ctrl)
{
	if (ctrl == -1) {
		return false;
	}

	if (_pam_log_is_silent(ctrl)) {
		return false;
	}

	if (!(ctrl & PAM_TDB_DEBUG_ARG)) {
		return false;
	}

	return true;
}

static bool _pam_log_is_debug_state_enabled(int ctrl)
{
	if (!(ctrl & PAM_TDB_DEBUG_STATE)) {
		return false;
	}

	return _pam_log_is_debug_enabled(ctrl);
}

// Logging macros
#define PAM_TDB_LOG(pamh, pri, fmt, ...) \
	pam_syslog(pamh, pri, fmt, ##__VA_ARGS__)

#define PAM_TDB_DEBUG(pamh, ctrl, pri, fmt, ...)           \
do {                                                       \
	if (_pam_log_is_debug_enabled(ctrl))               \
		PAM_TDB_LOG(pamh, pri, fmt, ##__VA_ARGS__);\
} while(0)

#define PAM_CTX_DEBUG(ctx, pri, fmt, ...) \
	PAM_TDB_DEBUG(ctx->pamh, ctx->ctrl, pri, fmt, ##__VA_ARGS__)

static uint32_t _pam_parse(const pam_handle_t *pamh,
			   int flags,
			   int argc,
			   const char **argv,
			   char *admin_user)
{
	int ctrl = 0;
	int i;
	const char **v;

	if (flags & PAM_SILENT) {
		ctrl |= PAM_TDB_SILENT;
	}

	/* step through arguments */
	for (i=argc,v=argv; i-- > 0; ++v) {

		/* generic options */
		if (!strcmp(*v,"debug"))
			ctrl |= PAM_TDB_DEBUG_ARG;
		else if (!strcasecmp(*v, "debug_state"))
			ctrl |= PAM_TDB_DEBUG_STATE;
		else if (!strcasecmp(*v, "silent"))
			ctrl |= PAM_TDB_SILENT;
		else if (!strncmp(*v, "truenas_admin=", strlen("truenas_admin="))) {
			strlcpy(admin_user, *v + strlen("truenas_admin="),
			    PAM_TDB_MAX_ADMIN_USER);
		}
	}

	return ctrl;
};

/**
 * destructor function for struct ptdb_context that ensures
 * the tdb handle is closed
 */
static int _pam_tdb_free_context(struct ptdb_context *ctx)
{
	if (!ctx) {
		return 0;
	}

	if (ctx->tdb_ctx) {
		tdb_close(ctx->tdb_ctx);
		ctx->tdb_ctx = NULL;
	}

	return 0;
}

static int _pam_tdb_init_context(pam_handle_t *pamh,
				 int flags,
				 int argc,
				 const char **argv,
				 enum pam_tdb_request_type type,
				 struct ptdb_context **ctx_p)
{
	struct ptdb_context *r = NULL;
	const char *service = NULL;
	int ctrl_code;

	r = talloc_zero(NULL, struct ptdb_context);
	if (!r) {
		return PAM_BUF_ERR;
	}

	talloc_set_destructor(r, _pam_tdb_free_context);

	r->pamh = pamh;
	r->argc = argc;
	r->argv = argv;
	r->ctrl = _pam_parse(pamh, flags, argc, argv, r->admin_user);

	r->tdb_ctx = tdb_open(PAM_TDB_FILE, 0, 0,
			      O_RDONLY,
			      0600);

	if (r->tdb_ctx == NULL) {
		PAM_CTX_DEBUG(r, LOG_ERR,
			      "%s: failed to open tdb file: %d\n",
			      PAM_TDB_FILE, errno);
		TALLOC_FREE(r);
		return PAM_SYSTEM_ERR;
	}

	pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
	if (strcmp(service, SERVICE_FILE_NAME) != 0) {
		PAM_CTX_DEBUG(r, LOG_ERR,
			      "%s: invalid PAM service file. This service "
			      "module is only valid for the [%s] service.\n",
			      service, SERVICE_FILE_NAME);
		TALLOC_FREE(r);
		return PAM_SYSTEM_ERR;
	}

	/* set minimum 2 second delay on failure */
	pam_fail_delay(pamh, 2000000);

	*ctx_p = r;
	return PAM_SUCCESS;
}

/**
 * Convert token that _should_ contain the iteration count used to generate
 * the hash into an unsigned integer.
 *
 * @param[in] ctx ptdb_context (used for logging purposes)
 * @param[in] str_in token containing iteration count
 * @param[out] iter_out strtoul of iter_str (if successful)
 *
 * @return boolean Returns true if all characters were converted successfully
 * false if not.
 */
static bool _pam_tdb_parse_uint_str(struct ptdb_context *ctx,
				    char *str_in,
				    unsigned int *val_out)
{
	uint64_t lval;
	char *end = NULL;

	// strtoul requires explicitly setting errno to zero
	errno = 0;
	lval = strtoul(str_in, &end, 0);
	if (errno != 0) {
		PAM_CTX_DEBUG(ctx, LOG_ERR, "%s: strtoul failed: %s",
			      str_in, strerror(errno));
		return false;
	}

	/*
	 * If there were no digits at all then end == str_in
	 * If all characters were digits then *end will be '\0'
	 * Otherwise *end will be the first invalid character.
	 */
	if ((end == str_in) && (*end != '\0')) {
		PAM_CTX_DEBUG(ctx, LOG_ERR, "%s: not an integer: %c",
			      str_in, *end);
		return false;
	}

	// Set some non-insane upper bound on count
	if (lval >= INT32_MAX) {
		PAM_CTX_DEBUG(ctx, LOG_ERR, "%lu: value too large", lval);
		return false;
	}

	*val_out = lval;
	return true;
}

/**
 * check that the hash of the user-provided password matches the hash we have
 * on record.
 *
 * @param[in] ctx ptdb_context (to support logging if needed)
 * @param[in] to_check hash token from tdb entry
 * @param[in] hash_blob hash generated from user-supplied password based on
 *     specification in the tdb entry
 * @param[in] hash_blob_len length of hash_blob
 *
 * @returns boolean Returns true if hashes match else false.
 */
static bool _pam_tdb_validate_pbkdf2(struct ptdb_context *ctx,
				     char *to_check,
				     bool is_legacy,
				     uint8_t *hash_blob,
				     size_t hash_blob_len)
{
	char *found = NULL;
	gnutls_datum_t to_encode = (gnutls_datum_t) {
		.data = hash_blob,
		.size = hash_blob_len,
	};
	gnutls_datum_t result = { 0 };
	int error;
	bool rval = false;

	/*
	 * NOTE: the below function allocates memory in result.data that
	 * must be freed after hash comparison
	 */
	error = gnutls_base64_encode2(&to_encode, &result);
	if (error) {
		PAM_CTX_DEBUG(ctx, LOG_ERR,
			      "gnutls_base64_encode2() of hashed password "
			      "failed: %s", gnutls_strerror(error));
		return false;
	}

	if (is_legacy) {
		/* Perform some in-place replacements in b64 string */
		/*
		 * Keep passlib behavior of replacing `+` with `.` after b64encode
		 */
		for (found = strchr(result.data, '+'); found; found = strchr(found, '+')) {
			*found = '.';
		}

		/*
		 * trim off padding bytes from newly b64-encoded hash
		 */
		if ((found = strchr(result.data, '=')) != NULL)
			*found = '\0';
	}

	/* Now we do actual comparison of hashes */
	if (pam_tdb_consttime_streq(result.data, to_check)) {
		rval = true;
	}

	/* Zero out the hash before freeing it */
	pam_overwrite_n(result.data, result.size);
	gnutls_free(result.data);

	return rval;
}

/**
 * Extract salt bytes from base64 string in tdb entry. This is somewhat
 * complicated by the fact that historically the library generating the string
 * removed padding and replaced the character "+" with "."; however,
 * gnutls / nettle base64 functions require padding to be present.
 *
 * @param[in] ctx ptdb_context (to support logging if needed)
 * @param[in] salt_ptr null-terminated string containing b64-encoded salt
 *     information.
 * @param[in] is_legacy means salt_ptr is munged by passlib and we need
 *     to fix it up before decode.
 * @param[out] salt_data results of base64 decode of salt_ptr. salt_data
 *     must not be NULL. salt_data->data must be freed by caller if
 *     successful.
 *
 * @returns boolean Returns true on success with salt_data containing
 *     the results of gnutls_base64_decode2.
 */
static bool _pam_tdb_userhash_get_salt(struct ptdb_context *ctx,
				       char *salt_ptr,
				       bool is_legacy,
				       gnutls_datum_t *salt_data)
{
	/*
	 * convert base64-encoded salt to bytes
	 * caller must free salt_out
	 */
	int error, pad_cnt, i;
	char *tmp = salt_ptr;
	char *found;


	if (is_legacy) {
		/*
		 * gnutls base64-related functions require padding that passlib
		 * unfortunately strips when generating hash strings. This means
		 * we need to re-add it based on length of the salt in the
		 * token.
		 */
		pad_cnt = 4 - (strlen(salt_ptr) % 4);
		if (pad_cnt > 2) {
			PAM_CTX_DEBUG(ctx, LOG_ERR, "salt has invalid length.");
			return false;
		}

		/*
		 * Since we have to add padding bytes back in we have to make a
		 * copy of the salt token.
		 */
		tmp = calloc(1, strlen(salt_ptr) + 3);
		if (tmp == NULL) {
			return false;
		}

		strlcpy(tmp, salt_ptr, strlen(salt_ptr) + 1);

		/*
		 * Append padding as-needed. We're transitioning to a library that
		 * doesn't strip the padding.
		 */
		for (i = 0; i < pad_cnt; i++)
			tmp[strlen(salt_ptr) + i] = '=';

		/*
		 * passlib replaced `.` character with `+` after b64 encoding
		 * data. Reverse the process before attempting to b64decode.
		 */
		for (found = strchr(tmp, '.'); found; found = strchr(found, '.')) {
			*found = '+';
		}
	}

	gnutls_datum_t encoded = (gnutls_datum_t) {
		.data = tmp,
		.size = strlen(tmp)
	};

	error = gnutls_base64_decode2(&encoded, salt_data);
	if (error != GNUTLS_E_SUCCESS) {
		PAM_CTX_DEBUG(ctx, LOG_ERR, "Failed to decode salt: %s",
			      gnutls_strerror(error));

		if (is_legacy) {
			pam_overwrite_string(tmp);
			free(tmp);
		}
		return false;
	}

	if (is_legacy) {
		pam_overwrite_string(tmp);
		free(tmp);
	}

	return true;
}

static bool _pam_tdb_lookup_algo(const char *algo_name, pam_tdb_algo_t **out)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(algo_table); i++) {
		if (strcmp(algo_table[i].name, algo_name) == 0) {
			*out = &algo_table[i];
			return true;
		}
	}

	return false;
}

#define MIN_KEY_LEN 64
#define MIN_SALT_LEN 16	// SP 800-132 5.1
#define MIN_ITER 500000 // SP 800-132 5.2 specifies 1K, our legacy API keys have 26K
#define HASH_SEPARATOR "$"

/*
 * sample hash pbkdf2-sha256:
 * $pbkdf2-sha256$29000$iXHOGUOoda415jzHmPP.3w$38DX7r.ek2EeOLFT5uWLEdr6VSVte.Pyp.bN8hnE/Dc
 *
 * sample hash pbkdf2-sha512:
 * $pbkdf2-sha256$29000$iXHOGUOoda415jzHmPP.3w$38DX7r.ek2EeOLFT5uWLEdr6VSVte.Pyp.bN8hnE/Dc
 * $pbkdf2-sha512$500000$OWRPdUNNcUxvU3FISjNMZQ==$rwWADzQM5r+4typ0brQNuOP7o/SjMWmgkbu1dizsaCFI/+Fdd8a0hhm8H8ILaqkuofdGEAfQdCe74M3sR77pXA==
 */

enum ptdb_hash_field {
	PTDB_FIELD_ALGO,
	PTDB_FIELD_ITER,
	PTDB_FIELD_SALT,
	PTDB_FIELD_HASH
};

/**
 * Validate and compare passlib-style pbkdf2 hash string with provided
 * password string.
 *
 * @param[in] ctx ptdb_context (to support logging if needed)
 * @param[in] pass plain-text password provided by PAM
 * @param[in] hash_in full pbkdf2 hash string
 * @param[in] is_admin bool indicating whether username is for admin user
 *     This is used to determine whether legacy hash is allowed
 *
 * @returns boolean Returns true if resulting password hatch matches expected
 *     value.
 */
static bool _pam_tdb_handle_pbkdf2(struct ptdb_context *ctx,
				   const char *pass,
				   char *hash_in,
				   bool is_admin)
{
	char *saveptr = NULL;
	char *tok = NULL;
	char *hash = NULL;
	pam_tdb_algo_t *tp = NULL;
	uint i;
	gnutls_datum_t key, salt = { 0 };
	unsigned int iter = 0;
	bool ok, legacy = is_admin;
	int ret;
	uint8_t hashbuf[64] = { 0 };
	size_t bufsz;

	if (hash_in == NULL) {
		return false;
	}

	/*
	 * Process hash string components that are separated into tokens via
	 * strtok_r.
	 */
	for (i=0, tok = strtok_r(hash_in, HASH_SEPARATOR, &saveptr); tok;
	     i++, tok = strtok_r(NULL, HASH_SEPARATOR, &saveptr)) {
		switch (i) {
		case PTDB_FIELD_ALGO:
			if (!_pam_tdb_lookup_algo(tok, &tp)) {
				PAM_CTX_DEBUG(ctx, LOG_ERR,
					      "%s: unsupported algorithm",
					      tok);
				return false;
			}

			/*
			 * Our admin user may have legacy hashlib hash or
			 * newer one. Non-admin users may only use newer
			 * algorithm.
			 */
			if (tp->algo == GNUTLS_MAC_SHA512) {
				legacy = false;
			} else if ((tp->algo == GNUTLS_MAC_SHA256) && !is_admin) {
				PAM_CTX_DEBUG(ctx, LOG_ERR,
					      "Unsupported user for legacy "
					      "algorithm");
				return false;
			}
			break;
		case PTDB_FIELD_ITER:
			if (!_pam_tdb_parse_uint_str(ctx, tok, &iter)) {
				return false;
			}

			if (iter < tp->min_iter) {
				PAM_CTX_DEBUG(ctx, LOG_ERR,
					      "%u: too few iterations",
					      iter);
				return false;
			}
			break;
		case PTDB_FIELD_SALT:
			/* NOTE: salt.data must be freed if this is successful */
			if (!_pam_tdb_userhash_get_salt(ctx, tok, legacy, &salt)) {
				return false;
			}
			break;
		case PTDB_FIELD_HASH:
			// this will be handled below
			hash = tok;
			break;
		default:
			// too many fields
			PAM_CTX_DEBUG(ctx, LOG_ERR, "malformed hash string");
			return false;
		};
	}

	/* We may have too few fields, which is indicated by NULL hash */
	if (hash == NULL) {
		/* memory may have been allocated for salt.data */
		if (salt.data != NULL) {
			pam_overwrite_n(salt.data, salt.size);
			gnutls_free(salt.data);
		}
		PAM_CTX_DEBUG(ctx, LOG_ERR,
			      "%u: unexpected element count in hash", i);
		return false;
	}

	key = (gnutls_datum_t) {
		.data = discard_const(pass),
		.size = strlen(pass)
	};

	switch(tp->algo) {
	case GNUTLS_MAC_SHA512:
		bufsz = sizeof(uint8_t) * 64;
		break;
	case GNUTLS_MAC_SHA256:
		bufsz = sizeof(uint8_t) * 32;
		break;
	default:
		PAM_CTX_DEBUG(ctx, LOG_ERR,
			      "%s [%u]: unexpected gnutls algorithm",
			      tp->name, tp->algo);
		pam_overwrite_n(salt.data, salt.size);
		gnutls_free(salt.data);
		return false;
	};

	/*
	 * generate hash based on password and salt + iterations in pam_tdb entry
	 * NOTE: does _not_ allocate memory
	 */

	ret = gnutls_pbkdf2(tp->algo,
			    &key,
			    &salt,
			    iter,
			    hashbuf,
			    bufsz);

	/* explicitly overwrite our salt before free */
	pam_overwrite_n(salt.data, salt.size);
	gnutls_free(salt.data);

	if (ret < 0) {
		PAM_CTX_DEBUG(ctx, LOG_ERR,
			      "%s: gnutls_pbkdf2() failed for algorithm: %s",
			      tp->name, gnutls_strerror(ret));
		return false;
	}

	/* compare the hash we generated and the one retrieved from string */
	ok = _pam_tdb_validate_pbkdf2(ctx,
				      hash,
				      legacy,
				      hashbuf,
				      bufsz);

	/* overwrite the hash we generated */
	pam_overwrite_array(hashbuf);

	return ok;
}

/**
 * Unpack a single user entry token from the specified TDB data.
 *
 * @param[in] ctx pdb_context for logging purposes
 * @param[in] username username for authentication attempt this
 *     is provided to make more useful log messages
 * @param[in] pass PAM-provided password for user
 * @param[in] is_admin username matches one of TrueNAS sys admin account names.
 * @param[in] idx the index for the specific entry in the user TDB
 *     entry. This helps make more useful log messages.
 * @param[in] expected_db_id is the account_api_key primary key
 *     value, which is stored in tdb file to uniquely identify the
 *     key to check against to avoid having to do O(N) hashes per auth
 *     attempt.
 * @param[in] data pointer of beginning of hash string
 * @param[in] endp pointer to end of user TDB entry so that overflow
 *     via truncated pascal string can be detected.
 *
 * @param[out] expiry_out the expiration time (unix timestamp UTC)
 *     of the stored password / API key.
 * @param[out] password_valid_out indicates whether the password
 *     matches the hash contained in the entry.
 * @param[out] bytes_read_out the total bytes read starting at datap
 *     so that next entry can be checked if required.
 *
 * @returns boolean Returns true if the entry was properly parsed.
 */
static bool unpack_user_entry_token(struct ptdb_context *ctx,
				    const char *username,
				    const char *pass,
				    bool is_admin,
				    uint32_t idx,
				    unsigned int expected_db_id,
				    const char *data,
				    const char *endp,
				    time_t *expiry_out,
				    bool *password_valid_out,
				    uint32_t *bytes_read_out)
{
	time_t expiry;
	uint8_t hashlen;
	uint32_t entry_db_id;
	const char *datap = data;
	char *unixhash = NULL;

	// First validate that our data is long enough to actually
	// contain our required fields
	if ((data + sizeof(int64_t) + sizeof(uint8_t)) > endp) {
		PAM_CTX_DEBUG(ctx, LOG_INFO,
			      "%s: overflow reading expiry value "
			      "in user token %u\n",
			      username, idx);
		return false;
	}

	expiry = PULL_LE_I64(data, 0);
	entry_db_id = PULL_LE_U32(data, sizeof(int64_t));
	hashlen = PULL_LE_U8(data, sizeof(int64_t) + sizeof(uint32_t));
	if (hashlen == 0) {
		PAM_CTX_DEBUG(ctx, LOG_INFO,
			      "%s: zero-length hash in user token %u\n",
			      username, idx);
		return false;
	}

	datap += sizeof(int64_t);
	datap += sizeof(uint32_t);
	datap += sizeof(uint8_t);

	if ((datap + hashlen - 1) > endp) {
		PAM_CTX_DEBUG(ctx, LOG_INFO,
			      "%s: overflow reading unixhash value "
			      "in user token %u\n",
			      username, idx);
		return false;
	}

	/*
	 * only do hash check if db id matches. We rely on PAM
	 * fail delay to do the right thing here
	 */
	if (entry_db_id == expected_db_id) {
		// Ensure we always NULL-terminate the unixhash
		unixhash = calloc(1, hashlen + 1);
		if (unixhash == NULL) {
			return false;
		}

		memcpy(unixhash, datap, hashlen);
		*password_valid_out = _pam_tdb_handle_pbkdf2(ctx, pass,
							     unixhash, is_admin);
		pam_overwrite_string(unixhash);
		free(unixhash);
	} else {
		// flag password as invalid due to not matching
		// expected DB id
		*password_valid_out = false;
	}

	*bytes_read_out = sizeof(int64_t) + sizeof(uint32_t) + sizeof(uint8_t) + hashlen;
	*expiry_out = expiry;

	return true;
}

/**
 * Check whether any API key entries in the user's TDB data match the
 * provided password.
 *
 * @param[in] ctx ptdb_context provides logging and PAM handle if required
 * @param[in] username to generate log messages
 * @param[in] pass plain-text password of user
 * @param[in] data pointer of beginning of hash string
 * @param[in] endp pointer to end of user TDB entry so that overflow
 *     via truncated pascal string can be detected.
 * @param[out] expiry_out the expiration time (unix timestamp UTC)
 *     of the stored password / API key.
 *
 * @returns int Returns PAM_SUCCESS (0) on success or one of following errors
 *     PAM_AUTH_ERR TDB data valid but no entries match
 *     PAM_AUTHINFO_UNAVAIL malformed entry - force middleware to regenerate
 */
static int tdb_data_check_password(struct ptdb_context *ctx,
				   const char *username,
				   char *pass,
				   const char *data,
				   const char *endp,
				   time_t *expiry_out)
{
	uint32_t version;
	uint32_t token_cnt;
	uint32_t cnt, db_id;
	size_t bytes_read = 0;
	bool is_admin;
	char *key_ptr = NULL;

	if ((data + sizeof(version) + sizeof(token_cnt)) > endp) {
		PAM_CTX_DEBUG(ctx, LOG_ERR,
			      "%s: entry is too small\n",
			      username);
		return PAM_AUTHINFO_UNAVAIL;
	}

	version = PULL_LE_U32(data, 0);
	token_cnt = PULL_LE_U32(data, sizeof(version));

	if (version != PAM_TDB_VERSION_CURRENT) {
		PAM_CTX_DEBUG(ctx, LOG_INFO,
			      "%u: unexpected pam_tdb version for user: %s\n",
			      version, username);
		return PAM_AUTHINFO_UNAVAIL;
	}

	if (token_cnt == 0) {
		// no tokens, nothing to do
		return PAM_AUTH_ERR;
	} else if (token_cnt > 10) {
		PAM_CTX_DEBUG(ctx, LOG_INFO,
			      "%u: token count too large\n",
			      token_cnt);
		return PAM_AUTH_ERR;
	}

	bytes_read += (sizeof(version) + sizeof(token_cnt));
	is_admin = strcmp(ctx->admin_user, username) == 0;

	/* We expect password to be in form <db_id>-<key> */
	if ((key_ptr = strchr(pass, '-')) == NULL) {
		// malformed key. Force a PAM delay via PAM_AUTH_ERR
		PAM_CTX_DEBUG(ctx, LOG_ERR,
			      "malformed password lacks DB ID separator");
		return PAM_AUTH_ERR;
	}

	/*
	 * Split the string from PAM into DB ID and key
	 * This null-terminates what we assume is the DB ID before
	 * we pass it eventually to a strtoul() call.
	 */
	*key_ptr = '\0';

	// advance pointer to where the key is actually located
	key_ptr++;
	if (strlen(key_ptr) < MIN_KEY_LEN) {
		// this is not the key we're looking for.
		PAM_CTX_DEBUG(ctx, LOG_ERR,
			      "%zu: unexpected key length. API keys are minimum "
			      "of 64 characters.", strlen(key_ptr));
		return PAM_AUTH_ERR;
	}

	if (!_pam_tdb_parse_uint_str(ctx, pass, &db_id)) {
		// malformed DB ID. Force a PAM delay via PAM_AUTH_ERR
		return PAM_AUTH_ERR;
	}

	for (cnt = 0; cnt < token_cnt; cnt++) {
		char *unixhash = NULL;
		time_t expiry = 0;
		uint32_t entry_bytes_read = 0;
		bool password_match = false;
		bool ok;

		if ((data + bytes_read) > endp) {
			PAM_CTX_DEBUG(ctx, LOG_INFO,
				      "%u: TDB data too small for entry\n",
				      cnt);
			return PAM_AUTHINFO_UNAVAIL;
		}

		ok = unpack_user_entry_token(ctx,
					     username,
					     key_ptr,
					     is_admin,
					     cnt,
					     db_id,
					     data + bytes_read,
					     endp,
					     &expiry,
					     &password_match,
					     &entry_bytes_read);
		if (!ok) {
			/*
			 * Failure here means that our entry is malformed and
			 * so we should stop trying to parse.
			 */
			return PAM_AUTHINFO_UNAVAIL;
		}

		if (password_match) {
			*expiry_out = expiry;
			return PAM_SUCCESS;
		}

		bytes_read += entry_bytes_read;
	}

	return PAM_AUTH_ERR;
}

/**
 * handle authentication request
 *
 * @param[in] user username provided to PAM
 * @param[in] pass password provided to PAM
 * @param[out] username_ret copy of validated username
 *     This is allocated under a talloc context that is freed
 *     at end of pam_sm_authenticate().
 *
 * @returns int Returns PAM_SUCCESS on successful authentication or:
 *     PAM_USER_UNKNOWN: no TDB entry for the specified user
 *     PAM_AUTHINFO_UNAVAIL: TDB failure or malformed entry
 *     PAM_AUTH_ERR: No TDB entries matched or expired entry
 *     PAM_BUF_ERR: malloc failure
 */
static int tdb_auth_request(struct ptdb_context *ctx,
			    const char *user,
			    const char *pass,
			    char **username_ret)
{
	TDB_DATA key, val;
	time_t expiry = 0;
	int pam_ret;
	enum TDB_ERROR tdberr;
	char *pass_copy = NULL;

	key = (TDB_DATA){
		.dptr = (void *)user,
		.dsize = strlen(user)
	};

	val = tdb_fetch(ctx->tdb_ctx, key);
	if (val.dptr == NULL) {
		tdberr = tdb_error(ctx->tdb_ctx);
		switch (tdberr) {
		case TDB_ERR_NOEXIST:
			PAM_CTX_DEBUG(ctx, LOG_DEBUG,
				      "%s: entry does not exist\n",
				      user);

			return PAM_USER_UNKNOWN;
		default:
			PAM_CTX_DEBUG(ctx, LOG_ERR,
				      "%s: failed to fetch entry: %d: %s\n",
				      user, tdberr,
				      tdb_errorstr(ctx->tdb_ctx));
			return PAM_AUTHINFO_UNAVAIL;
		}
	}

	/*
	 * The password string from PAM is potentially concatenation of
	 * a database primary key (uint) and the actual key/password we
	 * need to check. The password from the PAM handle must not be
	 * altered and so we make a temporary copy to split on the
	 * delimiter for further processing in tdb_data_check_password.
	 */
	pass_copy = strdup(pass);
	if (pass_copy == NULL) {
		return PAM_BUF_ERR;
	}

	pam_ret = tdb_data_check_password(ctx, user, pass_copy,
					  val.dptr, val.dptr + val.dsize - 1,
					  &expiry);

	/*
	 * Wipe copy of password using origin string length because
	 * the string may have been manipulated and we want to wipe
	 * all those bytes.
	 */
	pam_overwrite_n(pass_copy, strlen(pass));
	free(pass_copy);

	/*
	 *  Wipe our copy of TDB entry since it's no longer needed
	 *  This contains iterations, salt, and hash.
	 */
	pam_overwrite_n(val.dptr, val.dsize);
	free(val.dptr);

	if (pam_ret == PAM_SUCCESS) {
		if (expiry) {
			struct timespec now;
			if (clock_gettime(CLOCK_REALTIME, &now)) {
				return PAM_SERVICE_ERR;
			}
			if (now.tv_sec > expiry) {
				PAM_TDB_LOG(ctx->pamh, LOG_INFO,
					    "%s: entry is expired",
					    user);
				return PAM_AUTH_ERR;
			}
		}
		*username_ret = talloc_strdup(ctx, user);
		return pam_ret;
	}

	PAM_CTX_DEBUG(ctx, LOG_DEBUG, "%s: authentication failed: %s",
		      user, pam_strerror(ctx->pamh, pam_ret));
	return pam_ret;
}

/*
 * Obtain a password from PAM authtok. Based on pam_unix
 * @param[in] ctx ptdb_context
 * @param[in] user username provided to PAM
 * @param[out] pass password provided by PAM.
 *
 * @returns int Returns PAM_SUCCESS if successful else one of following:
 *     PAM_INCOMPLETE: failure to get via pam conversation
 */
static int _tdb_read_password(struct ptdb_context *ctx,
			      const char *user,
			      const char **pass)
{
	int retval;
	const char *item;

	retval = pam_get_authtok(ctx->pamh, PAM_AUTHTOK, &item , NULL);
	if (retval == PAM_SUCCESS) {
		*pass = item;
		item = NULL;

		PAM_CTX_DEBUG(ctx, LOG_DEBUG,
			      "pam_get_item returned a password");
	} else {
		if (retval != PAM_CONV_AGAIN) {
			PAM_TDB_LOG(ctx->pamh, LOG_CRIT,
				    "auth could not identify password for [%s]",
				    user);
		} else {
			PAM_TDB_LOG(ctx->pamh, LOG_DEBUG,
				    "conversation function is not ready yet");
			/*
			 * it is safe to resume this function so we translate this
			 * retval to the value that indicates we're happy to resume.
			 */
			retval = PAM_INCOMPLETE;
		}
	}

	return retval;
}

_PUBLIC_ PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags,
			int argc, const char **argv)
{
	const char *username = NULL;
	const char *password = NULL;
	int retval = PAM_AUTH_ERR;
	char *username_ret = NULL;
	struct ptdb_context *ctx = NULL;

	retval = _pam_tdb_init_context(pamh, flags, argc, argv,
				       PAM_TDB_AUTHENTICATE, &ctx);
	if (retval != PAM_SUCCESS) {
		return retval;
	}

	PAM_CTX_DEBUG(ctx, LOG_DEBUG, "[pamh: %p] ENTER: %s\n",
		      ctx, "pam_sm_authenticate");

	/* Get the username */
	retval = pam_get_user(pamh, &username, NULL);
	if ((retval != PAM_SUCCESS) || (!username)) {
		PAM_CTX_DEBUG(ctx, LOG_DEBUG,
			      "can not get the username");
		retval = PAM_SERVICE_ERR;
		goto out;
	}

	retval = _tdb_read_password(ctx, username, &password);
	if (retval != PAM_SUCCESS) {
		PAM_CTX_DEBUG(ctx, LOG_ERR,
			      "Could not retrieve user's password");
		retval = PAM_AUTHTOK_ERR;
		goto out;
	}

	PAM_CTX_DEBUG(ctx, LOG_INFO,
		      "Verify user '%s'", username);

	/* Now use the username to look up password */
	retval = tdb_auth_request(ctx, username, password, &username_ret);
	if (username_ret) {
		pam_set_item (pamh, PAM_USER, username_ret);
		PAM_CTX_DEBUG(ctx, LOG_INFO,
			      "Returned user was '%s'", username_ret);
	}
	password = NULL;

out:
	PAM_CTX_DEBUG(ctx, LOG_DEBUG, "[pamh: %p] LEAVE: %s\n",
		      ctx, "pam_sm_authenticate");

	TALLOC_FREE(ctx);
	return retval;
}

/* stub-out remaining PAM functions */
_PUBLIC_ PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags,
		   int argc, const char **argv)
{
	// not implemeented
	return PAM_IGNORE;
}

_PUBLIC_ PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
	// not implemeented
	return PAM_IGNORE;
}

_PUBLIC_ PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh, int flags,
			int argc, const char **argv)
{
	// not implemeented
	return PAM_IGNORE;
}

_PUBLIC_ PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh, int flags,
			 int argc, const char **argv)
{
	// not implemeented
	return PAM_IGNORE;
}

_PUBLIC_ PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
	// not implemeented
	return PAM_IGNORE;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_tdb_modstruct = {
	MODULE_NAME,
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok
};

#endif

/*
 * Copyright (c) Andrew Tridgell  <tridge@samba.org>   2000
 * Copyright (c) Tim Potter       <tpot@samba.org>     2000
 * Copyright (c) Andrew Bartlettt <abartlet@samba.org> 2002
 * Copyright (c) Guenther Deschner <gd@samba.org>      2005-2008
 * Copyright (c) Jan Rêkorajski 1999.
 * Copyright (c) Andrew G. Morgan 1996-8.
 * Copyright (c) Alex O. Yuriev, 1996.
 * Copyright (c) Cristian Gafton 1996.
 * Copyright (C) Elliot Lee <sopwith@redhat.com> 1996, Red Hat Software.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED `AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

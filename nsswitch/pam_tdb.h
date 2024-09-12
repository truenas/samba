/*
 * Copyright (c) Andrew Walker <awalker@ixsystems.com> 2024.
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

#ifndef _NSSWITCH_PAM_TDB_H_
#define _NSSWITCH_PAM_TDB_H_

#include "../lib/replace/replace.h"
#include "../lib/util/bytearray.h"
#include "system/syslog.h"
#include "system/time.h"
#include <fcntl.h>
#include <talloc.h>
#include <tdb.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#define MODULE_NAME "pam_tdb"
#define SERVICE_FILE_NAME "middleware-api-key"
#define PAM_SM_AUTH
#define PAM_TDB_DIR "/var/run/pam_tdb/"
#define PAM_TDB_FILE PAM_TDB_DIR "pam_tdb.tdb"

/*
 * PAM_TDB_VERSION defines version number of current TDB value
 * The TDB values are currently written as packed struct
 *
 * Version 1 entry:
 * version: 4 bytes uint32_t
 * token_cnt: 4 bytes uint32_t
 * tokens: <varies>
 *
 * Each token:
 * expiry: 8 bytes int64_t (time_t)
 * db_id: 4 bytes uint32_t
 * hashlen: 1 bytes unsigned
 * hash: <varies>
 */
#define PAM_TDB_VERSION_1 1
#define PAM_TDB_VERSION_CURRENT PAM_TDB_VERSION_1

#define PAM_TDB_DEBUG_ARG		0x00000001
#define PAM_TDB_SILENT			0x00000002
#define PAM_TDB_DEBUG_STATE		0x00000004

/* Following are from pam_inline.h */
#ifdef HAVE_MEMSET_EXPLICIT
static inline void pam_overwrite_n(void *ptr, size_t len)
{
	if (ptr)
		memset_explicit(ptr, '\0', len);
}
#else
static inline void pam_overwrite_n(void *ptr, size_t len)
{
	if (ptr)
		explicit_bzero(ptr, len);
}
#endif

# define PAM_IS_SAME_TYPE(x_, y_) \
	__builtin_types_compatible_p(__typeof__(x_), __typeof__(y_))

/*
 * Evaluates to
 * - a syntax error if the argument is 0,
 * 0, otherwise.
 */
#define PAM_FAIL_BUILD_ON_ZERO(e_)	(sizeof(int[-1 + 2 * !!(e_)]) * 0)

/*
 * Evaluates to
 * 1, if the given type is known to be a non-array type
 * 0, otherwise.
 */
#define PAM_IS_NOT_ARRAY(a_)		PAM_IS_SAME_TYPE((a_), &(a_)[0])

/*
 * Evaluates to
 * - a syntax error if the argument is not an array,
 * 0, otherwise.
 */
#define PAM_MUST_BE_ARRAY(a_)		PAM_FAIL_BUILD_ON_ZERO(!PAM_IS_NOT_ARRAY(a_))
/*
 * Evaluates to
 * - a syntax error if the argument is an array,
 * 0, otherwise.
 */
#define PAM_MUST_NOT_BE_ARRAY(a_)	PAM_FAIL_BUILD_ON_ZERO(PAM_IS_NOT_ARRAY(a_))

#define pam_overwrite_array(x) pam_overwrite_n(x, sizeof(x) + PAM_MUST_BE_ARRAY(x))
#define pam_overwrite_object(x) pam_overwrite_n(x, sizeof(*(x)) + PAM_MUST_NOT_BE_ARRAY(x))
#define pam_overwrite_string(x)                      \
do {                                                 \
	char *xx__ = (x) + PAM_MUST_NOT_BE_ARRAY(x); \
	if (xx__)                                    \
		pam_overwrite_n(xx__, strlen(xx__)); \
} while(0)

/* end pam_inline.h */

#define PAM_TDB_MAX_ADMIN_USER 32
struct ptdb_context {
	pam_handle_t *pamh;
	int argc;
	const char **argv;
	uint32_t ctrl;
	char admin_user[PAM_TDB_MAX_ADMIN_USER + 1];
	struct tdb_context *tdb_ctx;
};

#endif /* _NSSWITCH_PAM_TDB_H_ */

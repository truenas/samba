/*
   Unix SMB/CIFS implementation.

   security descriptor utility functions

   Copyright (C) Andrew Tridgell 		2004
   Copyright (C) Andrew Bartlett 		2010
   Copyright (C) Stefan Metzmacher 		2005

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
#include "libcli/security/security_token.h"
#include "libcli/security/dom_sid.h"
#include "libcli/security/privileges.h"

/*
  return a blank security token
*/
struct security_token *security_token_initialise(TALLOC_CTX *mem_ctx)
{
	struct security_token *st = talloc_zero(
		mem_ctx, struct security_token);
	return st;
}

/****************************************************************************
 prints a struct security_token to debug output.
****************************************************************************/
void security_token_debug(int dbg_class, int dbg_lev, const struct security_token *token)
{
	uint32_t i;

	if (!token) {
		DEBUGC(dbg_class, dbg_lev, ("Security token: (NULL)\n"));
		return;
	}

	DEBUGC(dbg_class, dbg_lev, ("Security token SIDs (%lu):\n",
				       (unsigned long)token->num_sids));
	for (i = 0; i < token->num_sids; i++) {
		struct dom_sid_buf sidbuf;
		DEBUGADDC(dbg_class,
			  dbg_lev,
			  ("  SID[%3lu]: %s\n", (unsigned long)i,
			   dom_sid_str_buf(&token->sids[i], &sidbuf)));
	}

	security_token_debug_privileges(dbg_class, dbg_lev, token);
}

/* These really should be cheaper... */

bool security_token_is_sid(const struct security_token *token, const struct dom_sid *sid)
{
	if (token->sids == NULL) {
		return false;
	}
	if (dom_sid_equal(&token->sids[PRIMARY_USER_SID_INDEX], sid)) {
		return true;
	}
	return false;
}

bool security_token_is_system(const struct security_token *token)
{
	return security_token_is_sid(token, &global_sid_System);
}

bool security_token_is_anonymous(const struct security_token *token)
{
	return security_token_is_sid(token, &global_sid_Anonymous);
}

bool security_token_has_sid(const struct security_token *token, const struct dom_sid *sid)
{
	uint32_t i;
	for (i = 0; i < token->num_sids; i++) {
		if (dom_sid_equal(&token->sids[i], sid)) {
			return true;
		}
	}
	return false;
}

size_t security_token_count_flag_sids(const struct security_token *token,
				      const struct dom_sid *prefix_sid,
				      size_t num_flags,
				      const struct dom_sid **_flag_sid)
{
	const size_t num_auths_expected = prefix_sid->num_auths + num_flags;
	const struct dom_sid *found = NULL;
	size_t num = 0;
	uint32_t i;

	SMB_ASSERT(num_auths_expected <= ARRAY_SIZE(prefix_sid->sub_auths));

	for (i = 0; i < token->num_sids; i++) {
		const struct dom_sid *sid = &token->sids[i];
		int cmp;

		if ((size_t)sid->num_auths != num_auths_expected) {
			continue;
		}

		cmp = dom_sid_compare_domain(sid, prefix_sid);
		if (cmp != 0) {
			continue;
		}

		num += 1;
		found = sid;
	}

	if ((num == 1) && (_flag_sid != NULL)) {
		*_flag_sid = found;
	}

	return num;
}

bool security_token_has_builtin_guests(const struct security_token *token)
{
	return security_token_has_sid(token, &global_sid_Builtin_Guests);
}

bool security_token_has_builtin_administrators(const struct security_token *token)
{
	return security_token_has_sid(token, &global_sid_Builtin_Administrators);
}

bool security_token_has_nt_authenticated_users(const struct security_token *token)
{
	return security_token_has_sid(token, &global_sid_Authenticated_Users);
}

bool security_token_has_enterprise_dcs(const struct security_token *token)
{
	return security_token_has_sid(token, &global_sid_Enterprise_DCs);
}

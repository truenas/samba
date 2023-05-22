/*
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) Andrew Tridgell 2010
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

#ifndef __DSDB_COMMON_UTIL_H__
#define __DSDB_COMMON_UTIL_H__

/*
   flags for dsdb_request_add_controls(). For the module functions,
   the upper 16 bits are in dsdb/samdb/ldb_modules/util.h
*/
#define DSDB_SEARCH_SEARCH_ALL_PARTITIONS     0x00001
#define DSDB_SEARCH_SHOW_DELETED              0x00002
#define DSDB_SEARCH_SHOW_DN_IN_STORAGE_FORMAT 0x00004
#define DSDB_SEARCH_REVEAL_INTERNALS          0x00008
#define DSDB_SEARCH_SHOW_EXTENDED_DN          0x00010
#define DSDB_MODIFY_RELAX		      0x00020
#define DSDB_MODIFY_PERMISSIVE		      0x00040
#define DSDB_FLAG_AS_SYSTEM		      0x00080
#define DSDB_TREE_DELETE		      0x00100
#define DSDB_SEARCH_ONE_ONLY		      0x00200 /* give an error unless 1 record */
#define DSDB_SEARCH_SHOW_RECYCLED	      0x00400
#define DSDB_PROVISION			      0x00800
#define DSDB_BYPASS_PASSWORD_HASH	      0x01000
#define DSDB_SEARCH_NO_GLOBAL_CATALOG	      0x02000
#define DSDB_MODIFY_PARTIAL_REPLICA	      0x04000
#define DSDB_PASSWORD_BYPASS_LAST_SET         0x08000
#define DSDB_REPLMD_VANISH_LINKS              0x10000
#define DSDB_MARK_REQ_UNTRUSTED               0x20000

bool is_attr_in_list(const char * const * attrs, const char *attr);

#define DSDB_SECRET_ATTRIBUTES_EX(sep) \
	"pekList" sep \
	"msDS-ExecuteScriptPassword" sep \
	"currentValue" sep \
	"dBCSPwd" sep \
	"initialAuthIncoming" sep \
	"initialAuthOutgoing" sep \
	"lmPwdHistory" sep \
	"ntPwdHistory" sep \
	"priorValue" sep \
	"supplementalCredentials" sep \
	"trustAuthIncoming" sep \
	"trustAuthOutgoing" sep \
	"unicodePwd" sep \
	"clearTextPassword"

#define DSDB_SECRET_ATTRIBUTES_COMMA ,
#define DSDB_SECRET_ATTRIBUTES DSDB_SECRET_ATTRIBUTES_EX(DSDB_SECRET_ATTRIBUTES_COMMA)

#define DSDB_PASSWORD_ATTRIBUTES \
	"userPassword", \
	"clearTextPassword", \
	"unicodePwd", \
	"dBCSPwd"

/*
 * ldb opaque values used to pass the user session information to ldb modules
 */
#define DSDB_SESSION_INFO "sessionInfo"
#define DSDB_NETWORK_SESSION_INFO "networkSessionInfo"

struct GUID;

struct ldb_context;

int dsdb_werror_at(struct ldb_context *ldb, int ldb_ecode, WERROR werr,
		   const char *location, const char *func,
		   const char *reason);

#define dsdb_module_werror(module, ldb_ecode, werr, reason) \
	dsdb_werror_at(ldb_module_get_ctx(module), ldb_ecode, werr, \
		       __location__, __func__, reason)


struct dsdb_ldb_dn_list_node {
	struct dsdb_ldb_dn_list_node *prev, *next;

	/* the dn of the partition */
	struct ldb_dn *dn;
};



#endif /* __DSDB_COMMON_UTIL_H__ */

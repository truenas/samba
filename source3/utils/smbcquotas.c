/* 
   Unix SMB/CIFS implementation.
   QUOTA get/set utility

   Copyright (C) Andrew Tridgell		2000
   Copyright (C) Tim Potter			2000
   Copyright (C) Jeremy Allison			2000
   Copyright (C) Stefan (metze) Metzmacher	2003

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
#include "lib/cmdline/cmdline.h"
#include "rpc_client/cli_pipe.h"
#include "../librpc/gen_ndr/ndr_lsa.h"
#include "rpc_client/cli_lsarpc.h"
#include "fake_file.h"
#include "../libcli/security/security.h"
#include "libsmb/libsmb.h"

static char *server;

/* numeric is set when the user wants numeric SIDs and ACEs rather
   than going via LSA calls to resolve them */
static bool numeric;
static bool verbose;

enum todo_values {NOOP_QUOTA=0,FS_QUOTA,USER_QUOTA,LIST_QUOTA,SET_QUOTA};
enum exit_values {EXIT_OK, EXIT_FAILED, EXIT_PARSE_ERROR};

static struct cli_state *cli_ipc;
static struct rpc_pipe_client *global_pipe_hnd;
static struct policy_handle pol;
static bool got_policy_hnd;

static struct cli_state *connect_one(const char *share);

/* Open cli connection and policy handle */

static bool cli_open_policy_hnd(void)
{
	/* Initialise cli LSA connection */

	if (!cli_ipc) {
		NTSTATUS ret;
		cli_ipc = connect_one("IPC$");
		ret = cli_rpc_pipe_open_noauth(cli_ipc,
					       &ndr_table_lsarpc,
					       &global_pipe_hnd);
		if (!NT_STATUS_IS_OK(ret)) {
				return False;
		}
	}

	/* Open policy handle */

	if (!got_policy_hnd) {

		/* Some systems don't support SEC_FLAG_MAXIMUM_ALLOWED,
		   but NT sends 0x2000000 so we might as well do it too. */

		if (!NT_STATUS_IS_OK(rpccli_lsa_open_policy(global_pipe_hnd, talloc_tos(), True, 
							 GENERIC_EXECUTE_ACCESS, &pol))) {
			return False;
		}

		got_policy_hnd = True;
	}

	return True;
}

/* convert a SID to a string, either numeric or username/group */
static void SidToString(fstring str, struct dom_sid *sid, bool _numeric)
{
	char **domains = NULL;
	char **names = NULL;
	enum lsa_SidType *types = NULL;

	sid_to_fstring(str, sid);

	if (_numeric) return;

	/* Ask LSA to convert the sid to a name */

	if (!cli_open_policy_hnd() ||
	    !NT_STATUS_IS_OK(rpccli_lsa_lookup_sids(global_pipe_hnd, talloc_tos(),
						 &pol, 1, sid, &domains, 
						 &names, &types)) ||
	    !domains || !domains[0] || !names || !names[0]) {
		return;
	}

	/* Converted OK */

	slprintf(str, sizeof(fstring) - 1, "%s%s%s",
		 domains[0], lp_winbind_separator(),
		 names[0]);
}

/* convert a string to a SID, either numeric or username/group */
static bool StringToSid(struct dom_sid *sid, const char *str)
{
	enum lsa_SidType *types = NULL;
	struct dom_sid *sids = NULL;
	bool result = True;

	if (string_to_sid(sid, str)) {
		return true;
	}

	if (!cli_open_policy_hnd() ||
	    !NT_STATUS_IS_OK(rpccli_lsa_lookup_names(global_pipe_hnd, talloc_tos(),
						  &pol, 1, &str, NULL, 1, &sids, 
						  &types))) {
		result = False;
		goto done;
	}

	sid_copy(sid, &sids[0]);
 done:

	return result;
}

#define QUOTA_GET 1
#define QUOTA_SETLIM 2
#define QUOTA_SETFLAGS 3
#define QUOTA_LIST 4

enum {PARSE_FLAGS,PARSE_LIM};

static int parse_quota_set(TALLOC_CTX *ctx,
			char *set_str,
			char **pp_username_str,
			enum SMB_QUOTA_TYPE *qtype,
			int *cmd,
			SMB_NTQUOTA_STRUCT *pqt)
{
	char *p = set_str,*p2;
	int todo;
	bool stop = False;
	bool enable = False;
	bool deny = False;

	*pp_username_str = NULL;
	if (strnequal(set_str,"UQLIM:",6)) {
		p += 6;
		*qtype = SMB_USER_QUOTA_TYPE;
		*cmd = QUOTA_SETLIM;
		todo = PARSE_LIM;
		if ((p2=strstr(p,":"))==NULL) {
			return -1;
		}

		*p2 = '\0';
		p2++;

		*pp_username_str = talloc_strdup(ctx, p);
		p = p2;
	} else if (strnequal(set_str,"FSQLIM:",7)) {
		p +=7;
		*qtype = SMB_USER_FS_QUOTA_TYPE;
		*cmd = QUOTA_SETLIM;
		todo = PARSE_LIM;
	} else if (strnequal(set_str,"FSQFLAGS:",9)) {
		p +=9;
		todo = PARSE_FLAGS;
		*qtype = SMB_USER_FS_QUOTA_TYPE;
		*cmd = QUOTA_SETFLAGS;
	} else {
		return -1;
	}

	switch (todo) {
		case PARSE_LIM:
			if (sscanf(p,"%"SCNu64"/%"SCNu64,&pqt->softlim,
			    &pqt->hardlim) != 2)
			{
				return -1;
			}

			break;
		case PARSE_FLAGS:
			while (!stop) {

				if ((p2=strstr(p,"/"))==NULL) {
					stop = True;
				} else {
					*p2 = '\0';
					p2++;
				}

				if (strnequal(p,"QUOTA_ENABLED",13)) {
					enable = True;
				} else if (strnequal(p,"DENY_DISK",9)) {
					deny = True;
				} else if (strnequal(p,"LOG_SOFTLIMIT",13)) {
					pqt->qflags |= QUOTAS_LOG_THRESHOLD;
				} else if (strnequal(p,"LOG_HARDLIMIT",13)) {
					pqt->qflags |= QUOTAS_LOG_LIMIT;
				} else {
					return -1;
				}

				p=p2;
			}

			if (deny) {
				pqt->qflags |= QUOTAS_DENY_DISK;
			} else if (enable) {
				pqt->qflags |= QUOTAS_ENABLED;
			}

			break;
	}

	return 0;
}


static const char *quota_str_static(uint64_t val, bool special, bool _numeric)
{
	const char *result;

	if (!_numeric && special && val == 0) {
		return "NO LIMIT";
	}
	result = talloc_asprintf(talloc_tos(), "%"PRIu64, val);
	SMB_ASSERT(result != NULL);
	return result;
}

static void dump_ntquota(SMB_NTQUOTA_STRUCT *qt, bool _verbose,
			 bool _numeric,
			 void (*_sidtostring)(fstring str,
					      struct dom_sid *sid,
					      bool _numeric))
{
	TALLOC_CTX *frame = talloc_stackframe();

	if (!qt) {
		smb_panic("dump_ntquota() called with NULL pointer");
	}

	switch (qt->qtype) {
	case SMB_USER_FS_QUOTA_TYPE:
	{
		d_printf("File System QUOTAS:\n");
		d_printf("Limits:\n");
		d_printf(" Default Soft Limit: %15s\n",
			 quota_str_static(qt->softlim,True,_numeric));
		d_printf(" Default Hard Limit: %15s\n",
			 quota_str_static(qt->hardlim,True,_numeric));
		d_printf("Quota Flags:\n");
		d_printf(" Quotas Enabled: %s\n",
			 ((qt->qflags&QUOTAS_ENABLED)
			  ||(qt->qflags&QUOTAS_DENY_DISK))?"On":"Off");
		d_printf(" Deny Disk:      %s\n",
			 (qt->qflags&QUOTAS_DENY_DISK)?"On":"Off");
		d_printf(" Log Soft Limit: %s\n",
			 (qt->qflags&QUOTAS_LOG_THRESHOLD)?"On":"Off");
		d_printf(" Log Hard Limit: %s\n",
			 (qt->qflags&QUOTAS_LOG_LIMIT)?"On":"Off");
	}
	break;
	case SMB_USER_QUOTA_TYPE:
	{
		fstring username_str = {0};

		if (_sidtostring) {
			_sidtostring(username_str,&qt->sid,_numeric);
		} else {
			sid_to_fstring(username_str, &qt->sid);
		}

		if (_verbose) {
			d_printf("Quotas for User: %s\n",username_str);
			d_printf("Used Space: %15s\n",
				 quota_str_static(qt->usedspace,False,
						  _numeric));
			d_printf("Soft Limit: %15s\n",
				 quota_str_static(qt->softlim,True,
						  _numeric));
			d_printf("Hard Limit: %15s\n",
				 quota_str_static(qt->hardlim,True,_numeric));
		} else {
			d_printf("%-30s: ",username_str);
			d_printf("%15s/",quota_str_static(
					 qt->usedspace,False,_numeric));
			d_printf("%15s/",quota_str_static(
					 qt->softlim,True,_numeric));
			d_printf("%15s\n",quota_str_static(
					 qt->hardlim,True,_numeric));
		}
	}
	break;
	default:
		d_printf("dump_ntquota() invalid qtype(%d)\n",qt->qtype);
	}
	TALLOC_FREE(frame);
	return;
}

static void dump_ntquota_list(SMB_NTQUOTA_LIST **qtl, bool _verbose,
			      bool _numeric,
			      void (*_sidtostring)(fstring str,
						   struct dom_sid *sid,
						   bool _numeric))
{
	SMB_NTQUOTA_LIST *cur;

	for (cur = *qtl;cur;cur = cur->next) {
		if (cur->quotas)
			dump_ntquota(cur->quotas,_verbose,_numeric,
				     _sidtostring);
	}
}

static int do_quota(struct cli_state *cli,
		enum SMB_QUOTA_TYPE qtype,
		uint16_t cmd,
		const char *username_str,
		SMB_NTQUOTA_STRUCT *pqt)
{
	uint32_t fs_attrs = 0;
	uint16_t quota_fnum = 0;
	SMB_NTQUOTA_LIST *qtl = NULL;
	TALLOC_CTX *qtl_ctx = NULL;
	SMB_NTQUOTA_STRUCT qt;
	NTSTATUS status;

	ZERO_STRUCT(qt);

	status = cli_get_fs_attr_info(cli, &fs_attrs);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Failed to get the filesystem attributes %s.\n",
			 nt_errstr(status));
		return -1;
	}

	if (!(fs_attrs & FILE_VOLUME_QUOTAS)) {
		d_printf("Quotas are not supported by the server.\n");
		return 0;
	}

	status = cli_get_quota_handle(cli, &quota_fnum);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Quotas are not enabled on this share.\n");
		d_printf("Failed to open %s  %s.\n",
			 FAKE_FILE_NAME_QUOTA_WIN32,
			 nt_errstr(status));
		return -1;
	}

	switch(qtype) {
		case SMB_USER_QUOTA_TYPE:
			if (!StringToSid(&qt.sid, username_str)) {
				d_printf("StringToSid() failed for [%s]\n",username_str);
				return -1;
			}

			switch(cmd) {
				case QUOTA_GET:
					status = cli_get_user_quota(
						cli, quota_fnum, &qt);
					if (!NT_STATUS_IS_OK(status)) {
						d_printf("%s cli_get_user_quota %s\n",
							 nt_errstr(status),
							 username_str);
						return -1;
					}
					dump_ntquota(&qt,verbose,numeric,SidToString);
					break;
				case QUOTA_SETLIM:
					pqt->sid = qt.sid;
					if ((qtl_ctx = talloc_init(
						 "SMB_USER_QUOTA_SET")) ==
					    NULL) {
						return -1;
					}

					if (!add_record_to_ntquota_list(
						qtl_ctx, pqt, &qtl)) {
						TALLOC_FREE(qtl_ctx);
						return -1;
					}

					status = cli_set_user_quota(
					    cli, quota_fnum, qtl);
					free_ntquota_list(&qtl);
					if (!NT_STATUS_IS_OK(status)) {
						d_printf("%s cli_set_user_quota %s\n",
							 nt_errstr(status),
							 username_str);
						return -1;
					}
					status = cli_get_user_quota(
						cli, quota_fnum, &qt);
					if (!NT_STATUS_IS_OK(status)) {
						d_printf("%s cli_get_user_quota %s\n",
							 nt_errstr(status),
							 username_str);
						return -1;
					}
					dump_ntquota(&qt,verbose,numeric,SidToString);
					break;
				case QUOTA_LIST:
					status = cli_list_user_quota(
						cli, quota_fnum, &qtl);
					if (!NT_STATUS_IS_OK(status)) {
						d_printf(
						    "%s cli_list_user_quota\n",
						    nt_errstr(status));
						return -1;
					}
					dump_ntquota_list(&qtl,verbose,numeric,SidToString);
					free_ntquota_list(&qtl);
					break;
				default:
					d_printf("Unknown Error\n");
					return -1;
			}
			break;
		case SMB_USER_FS_QUOTA_TYPE:
			switch(cmd) {
				case QUOTA_GET:
					status = cli_get_fs_quota_info(
						cli, quota_fnum, &qt);
					if (!NT_STATUS_IS_OK(status)) {
						d_printf("%s cli_get_fs_quota_info\n",
							 nt_errstr(status));
						return -1;
					}
					dump_ntquota(&qt,True,numeric,NULL);
					break;
				case QUOTA_SETLIM:
					status = cli_get_fs_quota_info(
						cli, quota_fnum, &qt);
					if (!NT_STATUS_IS_OK(status)) {
						d_printf("%s cli_get_fs_quota_info\n",
							 nt_errstr(status));
						return -1;
					}
					qt.softlim = pqt->softlim;
					qt.hardlim = pqt->hardlim;
					status = cli_set_fs_quota_info(
						cli, quota_fnum, &qt);
					if (!NT_STATUS_IS_OK(status)) {
						d_printf("%s cli_set_fs_quota_info\n",
							 nt_errstr(status));
						return -1;
					}
					status = cli_get_fs_quota_info(
						cli, quota_fnum, &qt);
					if (!NT_STATUS_IS_OK(status)) {
						d_printf("%s cli_get_fs_quota_info\n",
							 nt_errstr(status));
						return -1;
					}
					dump_ntquota(&qt,True,numeric,NULL);
					break;
				case QUOTA_SETFLAGS:
					status = cli_get_fs_quota_info(
						cli, quota_fnum, &qt);
					if (!NT_STATUS_IS_OK(status)) {
						d_printf("%s cli_get_fs_quota_info\n",
							 nt_errstr(status));
						return -1;
					}
					qt.qflags = pqt->qflags;
					status = cli_set_fs_quota_info(
						cli, quota_fnum, &qt);
					if (!NT_STATUS_IS_OK(status)) {
						d_printf("%s cli_set_fs_quota_info\n",
							 nt_errstr(status));
						return -1;
					}
					status = cli_get_fs_quota_info(
						cli, quota_fnum, &qt);
					if (!NT_STATUS_IS_OK(status)) {
						d_printf("%s cli_get_fs_quota_info\n",
							 nt_errstr(status));
						return -1;
					}
					dump_ntquota(&qt,True,numeric,NULL);
					break;
				default:
					d_printf("Unknown Error\n");
					return -1;
			}
			break;
		default:
			d_printf("Unknown Error\n");
			return -1;
	}

	cli_close(cli, quota_fnum);

	return 0;
}

/*****************************************************
 Return a connection to a server.
*******************************************************/

static struct cli_state *connect_one(const char *share)
{
	struct cli_state *c;
	NTSTATUS nt_status;
	uint32_t flags = 0;

	nt_status = cli_full_connection_creds(&c, lp_netbios_name(), server,
					    NULL, 0,
					    share, "?????",
					    samba_cmdline_get_creds(),
					    flags);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0,("cli_full_connection failed! (%s)\n", nt_errstr(nt_status)));
		return NULL;
	}

	return c;
}

/****************************************************************************
  main program
****************************************************************************/
int main(int argc, char *argv[])
{
	const char **argv_const = discard_const_p(const char *, argv);
	char *share;
	int opt;
	int result;
	int todo = 0;
	char *username_str = NULL;
	char *path = NULL;
	char *set_str = NULL;
	enum SMB_QUOTA_TYPE qtype = SMB_INVALID_QUOTA_TYPE;
	int cmd = 0;
	static bool test_args = False;
	struct cli_state *cli;
	bool fix_user = False;
	SMB_NTQUOTA_STRUCT qt;
	TALLOC_CTX *frame = talloc_stackframe();
	poptContext pc;
	struct cli_credentials *creds = NULL;
	bool ok;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{
			.longName   = "quota-user",
			.shortName  = 'u',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'u',
			.descrip    = "Show quotas for user",
			.argDescrip = "USER",
		},
		{
			.longName   = "list",
			.shortName  = 'L',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'L',
			.descrip    = "List user quotas",
		},
		{
			.longName   = "fs",
			.shortName  = 'F',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'F',
			.descrip    = "Show filesystem quotas",
		},
		{
			.longName   = "set",
			.shortName  = 'S',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'S',
			.descrip    = "Set acls\n"
				      "SETSTRING:\n"
				      "UQLIM:<username>/<softlimit>/<hardlimit> for user quotas\n"
				      "FSQLIM:<softlimit>/<hardlimit> for filesystem defaults\n"
				      "FSQFLAGS:QUOTA_ENABLED/DENY_DISK/LOG_SOFTLIMIT/LOG_HARD_LIMIT",
			.argDescrip = "SETSTRING",
		},
		{
			.longName   = "numeric",
			.shortName  = 'n',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'n',
			.descrip    = "Don't resolve sids or limits to names",
		},
		{
			.longName   = "verbose",
			.shortName  = 'v',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'v',
			.descrip    = "be verbose",
		},
		{
			.longName   = "test-args",
			.shortName  = 't',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 't',
			.descrip    = "Test arguments"
		},
		{
			.longName   = "max-protocol",
			.shortName  = 'm',
			.argInfo    = POPT_ARG_STRING,
			.arg        = NULL,
			.val        = 'm',
			.descrip    = "Set the max protocol level",
			.argDescrip = "LEVEL"
		},
		POPT_COMMON_SAMBA
		POPT_COMMON_CREDENTIALS
		POPT_LEGACY_S3
		POPT_COMMON_VERSION
		POPT_TABLEEND
	};

	smb_init_locale();

	ZERO_STRUCT(qt);

	ok = samba_cmdline_init(frame,
				SAMBA_CMDLINE_CONFIG_CLIENT,
				false /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Failed to init cmdline parser!\n");
		TALLOC_FREE(frame);
		exit(1);
	}
	/* set default debug level to 1 regardless of what smb.conf sets */
	lp_set_cmdline("log level", "1");

	setlinebuf(stdout);

	pc = samba_popt_get_context(getprogname(),
				    argc,
				    argv_const,
				    long_options, 0);
	if (pc == NULL) {
		DBG_ERR("Failed to setup popt context!\n");
		TALLOC_FREE(frame);
		exit(1);
	}

	poptSetOtherOptionHelp(pc, "//server1/share1");

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 'n':
			numeric = true;
			break;
		case 'v':
			verbose = true;
			break;
		case 't':
			test_args = true;
			break;
		case 'L':
			if (todo != 0) {
				d_printf("Please specify only one option of <-L|-F|-S|-u>\n");
				exit(EXIT_PARSE_ERROR);
			}
			todo = LIST_QUOTA;
			break;

		case 'F':
			if (todo != 0) {
				d_printf("Please specify only one option of <-L|-F|-S|-u>\n");
				exit(EXIT_PARSE_ERROR);
			}
			todo = FS_QUOTA;
			break;

		case 'u':
			if (todo != 0) {
				d_printf("Please specify only one option of <-L|-F|-S|-u>\n");
				exit(EXIT_PARSE_ERROR);
			}
			username_str = talloc_strdup(frame, poptGetOptArg(pc));
			if (!username_str) {
				exit(EXIT_PARSE_ERROR);
			}
			todo = USER_QUOTA;
			fix_user = True;
			break;

		case 'S':
			if (todo != 0) {
				d_printf("Please specify only one option of <-L|-F|-S|-u>\n");
				exit(EXIT_PARSE_ERROR);
			}
			set_str = talloc_strdup(frame, poptGetOptArg(pc));
			if (!set_str) {
				exit(EXIT_PARSE_ERROR);
			}
			todo = SET_QUOTA;
			break;
		case 'm':
			lp_set_cmdline("client max protocol",
				       poptGetOptArg(pc));
			break;
		case POPT_ERROR_BADOPT:
			fprintf(stderr, "\nInvalid option %s: %s\n\n",
				poptBadOption(pc, 0), poptStrerror(opt));
			poptPrintUsage(pc, stderr, 0);
			exit(1);
		}
	}

	creds = samba_cmdline_get_creds();

	if (todo == 0)
		todo = USER_QUOTA;

	if (!fix_user) {
		const char *user = cli_credentials_get_username(creds);
		if (user == NULL) {
			exit(EXIT_PARSE_ERROR);
		}

		username_str = talloc_strdup(frame, user);
		if (!username_str) {
			exit(EXIT_PARSE_ERROR);
		}
	}

	/* Make connection to server */
	if(!poptPeekArg(pc)) {
		poptPrintUsage(pc, stderr, 0);
		exit(EXIT_PARSE_ERROR);
	}

	path = talloc_strdup(frame, poptGetArg(pc));
	if (!path) {
		printf("Out of memory\n");
		exit(EXIT_PARSE_ERROR);
	}

	if (strncmp(path, "\\\\", 2) && strncmp(path, "//", 2)) {
		printf("Invalid argument: %s\n", path);
		return -1;
	}

	poptFreeContext(pc);
	samba_cmdline_burn(argc, argv);

	string_replace(path, '/', '\\');

	server = SMB_STRDUP(path+2);
	if (!server) {
		printf("Out of memory\n");
		exit(EXIT_PARSE_ERROR);
	}
	share = strchr_m(server,'\\');
	if (share == NULL) {
		printf("Invalid argument\n");
		exit(EXIT_PARSE_ERROR);
	}

	*share = 0;
	share++;

	if (todo == SET_QUOTA) {
		if (parse_quota_set(talloc_tos(), set_str, &username_str, &qtype, &cmd, &qt)) {
			printf("Invalid argument: -S %s\n", set_str);
			exit(EXIT_PARSE_ERROR);
		}
	}

	if (!test_args) {
		cli = connect_one(share);
		if (!cli) {
			exit(EXIT_FAILED);
		}
	} else {
		exit(EXIT_OK);
	}


	/* Perform requested action */

	switch (todo) {
		case FS_QUOTA:
			result = do_quota(cli,SMB_USER_FS_QUOTA_TYPE, QUOTA_GET, username_str, NULL);
			break;
		case LIST_QUOTA:
			result = do_quota(cli,SMB_USER_QUOTA_TYPE, QUOTA_LIST, username_str, NULL);
			break;
		case USER_QUOTA:
			result = do_quota(cli,SMB_USER_QUOTA_TYPE, QUOTA_GET, username_str, NULL);
			break;
		case SET_QUOTA:
			result = do_quota(cli, qtype, cmd, username_str, &qt);
			break;
		default: 
			result = EXIT_FAILED;
			break;
	}

	talloc_free(frame);

	return result;
}

/*
   Unix SMB/CIFS implementation.

   SMB torture tester - header file

   Copyright (C) Andrew Tridgell 1997-1998
   Copyright (C) Jeremy Allison 2009

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

#ifndef __TORTURE_H__
#define __TORTURE_H__

struct cli_state;

/* The following definitions come from torture/denytest.c  */

bool torture_denytest1(int dummy);
bool torture_denytest2(int dummy);

/* The following definitions come from torture/mangle_test.c  */

bool torture_mangle(int dummy);

/* The following definitions come from torture/nbio.c  */

double nbio_total(void);
void nb_alarm(int ignore);
void nbio_shmem(int n);
void nb_setup(struct cli_state *cli);
void nb_unlink(const char *fname);
void nb_createx(const char *fname,
		unsigned create_options, unsigned create_disposition, int handle);
void nb_writex(int handle, int offset, int size, int ret_size);
void nb_readx(int handle, int offset, int size, int ret_size);
void nb_close(int handle);
void nb_rmdir(const char *fname);
void nb_rename(const char *oldname, const char *newname);
void nb_qpathinfo(const char *fname);
void nb_qfileinfo(int fnum);
void nb_qfsinfo(int level);
void nb_findfirst(const char *mask);
void nb_flush(int fnum);
void nb_deltree(const char *dname);
void nb_cleanup(void);

/* The following definitions come from torture/scanner.c  */

bool torture_trans2_scan(int dummy);
bool torture_nttrans_scan(int dummy);

/* The following definitions come from torture/torture.c  */

bool smbcli_parse_unc(const char *unc_name, TALLOC_CTX *mem_ctx,
		      char **hostname, char **sharename);
bool torture_open_connection_flags(struct cli_state **c, int conn_index, int flags);
bool torture_open_connection(struct cli_state **c, int conn_index);
bool torture_init_connection(struct cli_state **pcli);
bool torture_cli_session_setup2(struct cli_state *cli, uint16_t *new_vuid);
bool torture_close_connection(struct cli_state *c);
bool torture_ioctl_test(int dummy);
bool torture_chkpath_test(int dummy);
NTSTATUS torture_setup_unix_extensions(struct cli_state *cli);
void torture_conn_set_sockopt(struct cli_state *cli);
void torture_deltree(struct cli_state *cli, const char *dname);

/* The following definitions come from torture/utable.c  */

bool torture_utable(int dummy);
bool torture_casetable(int dummy);

/*
 * Misc
 */

bool run_posix_append(int dummy);
bool run_posix_ls_wildcard_test(int dummy);
bool run_posix_ls_single_test(int dummy);
bool run_posix_readlink_test(int dummy);
bool run_posix_stat_test(int dummy);
bool run_posix_symlink_parent_test(int dummy);
bool run_posix_symlink_chmod_test(int dummy);
bool run_posix_dir_default_acl_test(int dummy);
bool run_case_insensitive_create(int dummy);
bool run_posix_symlink_rename_test(int dummy);
bool run_posix_symlink_getpathinfo_test(int dummy);
bool run_posix_symlink_setpathinfo_test(int dummy);

bool run_nbench2(int dummy);
bool run_async_echo(int dummy);
bool run_smb_any_connect(int dummy);
bool run_addrchange(int dummy);
bool run_str_match_mswild(int dummy);
bool run_str_match_regex_sub1(int dummy);
bool run_notify_online(int dummy);
bool run_nttrans_create(int dummy);
bool run_nttrans_fsctl(int dummy);
bool run_smb2_basic(int dummy);
bool run_smb2_negprot(int dummy);
bool run_smb2_anonymous(int dummy);
bool run_smb2_session_reconnect(int dummy);
bool run_smb2_tcon_dependence(int dummy);
bool run_smb2_multi_channel(int dummy);
bool run_smb2_session_reauth(int dummy);
bool run_smb2_ftruncate(int dummy);
bool run_smb2_dir_fsync(int dummy);
bool run_smb2_path_slash(int dummy);
bool run_smb2_sacl(int dummy);
bool run_smb2_quota1(int dummy);
bool run_smb2_stream_acl(int dummy);
bool run_smb2_dfs_paths(int dummy);
bool run_smb2_non_dfs_share(int dummy);
bool run_smb2_dfs_share_non_dfs_path(int dummy);
bool run_smb2_dfs_filename_leading_backslash(int dummy);
bool run_smb2_pipe_read_async_disconnect(int dummy);
bool run_smb2_invalid_pipename(int dummy);
bool run_smb1_dfs_paths(int dummy);
bool run_smb1_dfs_search_paths(int dummy);
bool run_smb1_dfs_operations(int dummy);
bool run_smb1_dfs_check_badpath(int dummy);
bool run_list_dir_async_test(int dummy);
bool run_delete_on_close_non_empty(int dummy);
bool run_delete_on_close_nonwrite_delete_yes_test(int dummy);
bool run_delete_on_close_nonwrite_delete_no_test(int dummy);
bool run_chain3(int dummy);
bool run_local_conv_auth_info(int dummy);
bool run_local_sprintf_append(int dummy);
bool run_cleanup1(int dummy);
bool run_cleanup2(int dummy);
bool run_cleanup4(int dummy);
bool run_notify_bench2(int dummy);
bool run_notify_bench3(int dummy);
bool run_dbwrap_watch1(int dummy);
bool run_dbwrap_watch2(int dummy);
bool run_dbwrap_watch3(int dummy);
bool run_dbwrap_watch4(int dummy);
bool run_dbwrap_do_locked1(int dummy);
bool run_idmap_tdb_common_test(int dummy);
bool run_local_dbwrap_ctdb1(int dummy);
bool run_qpathinfo_bufsize(int dummy);
bool run_bench_pthreadpool(int dummy);
bool run_messaging_read1(int dummy);
bool run_messaging_read2(int dummy);
bool run_messaging_read3(int dummy);
bool run_messaging_read4(int dummy);
bool run_messaging_fdpass1(int dummy);
bool run_messaging_fdpass2(int dummy);
bool run_messaging_fdpass2a(int dummy);
bool run_messaging_fdpass2b(int dummy);
bool run_messaging_send_all(int dummy);
bool run_oplock_cancel(int dummy);
bool run_pthreadpool_tevent(int dummy);
bool run_g_lock1(int dummy);
bool run_g_lock2(int dummy);
bool run_g_lock3(int dummy);
bool run_g_lock4(int dummy);
bool run_g_lock4a(int dummy);
bool run_g_lock5(int dummy);
bool run_g_lock6(int dummy);
bool run_g_lock7(int dummy);
bool run_g_lock8(int dummy);
bool run_g_lock_ping_pong(int dummy);
bool run_local_namemap_cache1(int dummy);
bool run_local_idmap_cache1(int dummy);
bool run_hidenewfiles(int dummy);
bool run_hidenewfiles_showdirs(int dummy);
bool run_readdir_timestamp(int dummy);
bool run_ctdbd_conn1(int dummy);
bool run_rpc_scale(int dummy);
bool run_tdb_validate(int dummy);

#endif /* __TORTURE_H__ */

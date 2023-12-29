/*
   Unix SMB/CIFS implementation.
   SMB client generic functions
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Jeremy Allison 2007.

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
#include "libsmb/libsmb.h"
#include "../lib/util/tevent_ntstatus.h"
#include "../libcli/smb/smb_signing.h"
#include "../libcli/smb/smb_seal.h"
#include "async_smb.h"
#include "../libcli/smb/smbXcli_base.h"
#include "../libcli/smb/smb2_negotiate_context.h"
#include "../librpc/ndr/libndr.h"
#include "../include/client.h"

/****************************************************************************
 Change the timeout (in milliseconds).
****************************************************************************/

unsigned int cli_set_timeout(struct cli_state *cli, unsigned int timeout)
{
	unsigned int old_timeout = cli->timeout;
	DBG_DEBUG("Changing connection timeout for server '%s' from %d (ms) to "
		  "%d (ms).\n",
		  smbXcli_conn_remote_name(cli->conn),
		  cli->timeout,
		  timeout);
	cli->timeout = timeout;
	return old_timeout;
}

/****************************************************************************
 Set the 'backup_intent' flag.
****************************************************************************/

bool cli_set_backup_intent(struct cli_state *cli, bool flag)
{
	bool old_state = cli->backup_intent;
	cli->backup_intent = flag;
	return old_state;
}

/****************************************************************************
 Initialise a client structure. Always returns a talloc'ed struct.
 Set the signing state (used from the command line).
****************************************************************************/

struct GUID cli_state_client_guid;

struct cli_state *cli_state_create(TALLOC_CTX *mem_ctx,
				   int fd,
				   const char *remote_name,
				   enum smb_signing_setting signing_state,
				   int flags)
{
	struct cli_state *cli = NULL;
	bool use_spnego = lp_client_use_spnego();
	bool force_dos_errors = false;
	bool force_ascii = false;
	bool use_level_II_oplocks = false;
	uint32_t smb1_capabilities = 0;
	uint32_t smb2_capabilities = 0;
	struct smb311_capabilities smb3_capabilities =
		smb311_capabilities_parse("client",
			lp_client_smb3_signing_algorithms(),
			lp_client_smb3_encryption_algorithms());
	struct GUID client_guid;

	if (!GUID_all_zero(&cli_state_client_guid)) {
		client_guid = cli_state_client_guid;
	} else {
		const char *str = NULL;

		str = lp_parm_const_string(-1, "libsmb", "client_guid", NULL);
		if (str != NULL) {
			GUID_from_string(str, &client_guid);
		} else {
			client_guid = GUID_random();
		}
	}

	/* Check the effective uid - make sure we are not setuid */
	if (is_setuid_root()) {
		DEBUG(0,("libsmb based programs must *NOT* be setuid root.\n"));
		return NULL;
	}

	cli = talloc_zero(mem_ctx, struct cli_state);
	if (!cli) {
		return NULL;
	}

	cli->server_domain = talloc_strdup(cli, "");
	if (!cli->server_domain) {
		goto error;
	}
	cli->server_os = talloc_strdup(cli, "");
	if (!cli->server_os) {
		goto error;
	}
	cli->server_type = talloc_strdup(cli, "");
	if (!cli->server_type) {
		goto error;
	}

	cli->raw_status = NT_STATUS_INTERNAL_ERROR;
	cli->map_dos_errors = true; /* remove this */
	cli->timeout = CLIENT_TIMEOUT;

	/* Set the CLI_FORCE_DOSERR environment variable to test
	   client routines using DOS errors instead of STATUS32
	   ones.  This intended only as a temporary hack. */
	if (getenv("CLI_FORCE_DOSERR")) {
		force_dos_errors = true;
	}
	if (flags & CLI_FULL_CONNECTION_FORCE_DOS_ERRORS) {
		force_dos_errors = true;
	}

	if (getenv("CLI_FORCE_ASCII")) {
		force_ascii = true;
	}
	if (!lp_unicode()) {
		force_ascii = true;
	}
	if (flags & CLI_FULL_CONNECTION_FORCE_ASCII) {
		force_ascii = true;
	}

	if (flags & CLI_FULL_CONNECTION_DONT_SPNEGO) {
		use_spnego = false;
	}

	if (flags & CLI_FULL_CONNECTION_OPLOCKS) {
		cli->use_oplocks = true;
	}
	if (flags & CLI_FULL_CONNECTION_LEVEL_II_OPLOCKS) {
		use_level_II_oplocks = true;
	}

	if (signing_state == SMB_SIGNING_IPC_DEFAULT) {
		/*
		 * Ensure for IPC/RPC the default is to require
		 * signing unless explicitly turned off by the
		 * administrator.
		 */
		signing_state = lp_client_ipc_signing();
	}

	if (signing_state == SMB_SIGNING_DEFAULT) {
		signing_state = lp_client_signing();
	}

	smb1_capabilities = 0;
	smb1_capabilities |= CAP_LARGE_FILES;
	smb1_capabilities |= CAP_NT_SMBS | CAP_RPC_REMOTE_APIS;
	smb1_capabilities |= CAP_LOCK_AND_READ | CAP_NT_FIND;
	smb1_capabilities |= CAP_DFS | CAP_W2K_SMBS;
	smb1_capabilities |= CAP_LARGE_READX|CAP_LARGE_WRITEX;
	smb1_capabilities |= CAP_LWIO;

	if (!force_dos_errors) {
		smb1_capabilities |= CAP_STATUS32;
	}

	if (!force_ascii) {
		smb1_capabilities |= CAP_UNICODE;
	}

	if (use_spnego) {
		smb1_capabilities |= CAP_EXTENDED_SECURITY;
	}

	if (use_level_II_oplocks) {
		smb1_capabilities |= CAP_LEVEL_II_OPLOCKS;
	}

	smb2_capabilities = SMB2_CAP_ALL;

	cli->conn = smbXcli_conn_create(cli, fd, remote_name,
					signing_state,
					smb1_capabilities,
					&client_guid,
					smb2_capabilities,
					&smb3_capabilities);
	if (cli->conn == NULL) {
		goto error;
	}

	cli->smb1.pid = (uint32_t)getpid();
	cli->smb1.vc_num = cli->smb1.pid;
	cli->smb1.session = smbXcli_session_create(cli, cli->conn);
	if (cli->smb1.session == NULL) {
		goto error;
	}

	cli->initialised = 1;
	return cli;

        /* Clean up after malloc() error */

 error:

	TALLOC_FREE(cli);
        return NULL;
}

/****************************************************************************
 Close all pipes open on this session.
****************************************************************************/

static void cli_nt_pipes_close(struct cli_state *cli)
{
	while (cli->pipe_list != NULL) {
		/*
		 * No TALLOC_FREE here!
		 */
		talloc_free(cli->pipe_list);
	}
}

/****************************************************************************
 Shutdown a client structure.
****************************************************************************/

static void _cli_shutdown(struct cli_state *cli)
{
	cli_nt_pipes_close(cli);

	/*
	 * tell our peer to free his resources.  Without this, when an
	 * application attempts to do a graceful shutdown and calls
	 * smbc_free_context() to clean up all connections, some connections
	 * can remain active on the peer end, until some (long) timeout period
	 * later.  This tree disconnect forces the peer to clean up, since the
	 * connection will be going away.
	 */
	if (cli_state_has_tcon(cli)) {
		cli_tdis(cli);
	}

	smbXcli_conn_disconnect(cli->conn, NT_STATUS_OK);

	TALLOC_FREE(cli);
}

void cli_shutdown(struct cli_state *cli)
{
	struct cli_state *cli_head;
	if (cli == NULL) {
		return;
	}
	DLIST_HEAD(cli, cli_head);
	if (cli_head == cli) {
		/*
		 * head of a DFS list, shutdown all subsidiary DFS
		 * connections.
		 */
		struct cli_state *p, *next;

		for (p = cli_head->next; p; p = next) {
			next = p->next;
			DLIST_REMOVE(cli_head, p);
			_cli_shutdown(p);
		}
	} else {
		DLIST_REMOVE(cli_head, cli);
	}

	_cli_shutdown(cli);
}

uint16_t cli_state_get_vc_num(struct cli_state *cli)
{
	return cli->smb1.vc_num;
}

/****************************************************************************
 Set the PID to use for smb messages. Return the old pid.
****************************************************************************/

uint32_t cli_setpid(struct cli_state *cli, uint32_t pid)
{
	uint32_t ret = cli->smb1.pid;
	cli->smb1.pid = pid;
	return ret;
}

uint32_t cli_getpid(struct cli_state *cli)
{
	return cli->smb1.pid;
}

bool cli_state_is_encryption_on(struct cli_state *cli)
{
	if (smbXcli_conn_protocol(cli->conn) < PROTOCOL_SMB2_02) {
		return smb1cli_conn_encryption_on(cli->conn);
	}

	if (cli->smb2.tcon == NULL) {
		return false;
	}

	return smb2cli_tcon_is_encryption_on(cli->smb2.tcon);
}

bool cli_state_has_tcon(struct cli_state *cli)
{
	uint32_t tid;
	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		if (cli->smb2.tcon == NULL) {
			return false;
		}
		tid = cli_state_get_tid(cli);
		if (tid == UINT32_MAX) {
			return false;
		}
	} else {
		if (cli->smb1.tcon == NULL) {
			return false;
		}
		tid = cli_state_get_tid(cli);
		if (tid == UINT16_MAX) {
			return false;
		}
	}
	return true;
}

uint32_t cli_state_get_tid(struct cli_state *cli)
{
	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		return smb2cli_tcon_current_id(cli->smb2.tcon);
	} else {
		return (uint32_t)smb1cli_tcon_current_id(cli->smb1.tcon);
	}
}

uint32_t cli_state_set_tid(struct cli_state *cli, uint32_t tid)
{
	uint32_t ret;
	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		ret = smb2cli_tcon_current_id(cli->smb2.tcon);
		smb2cli_tcon_set_id(cli->smb2.tcon, tid);
	} else {
		ret = smb1cli_tcon_current_id(cli->smb1.tcon);
		smb1cli_tcon_set_id(cli->smb1.tcon, tid);
	}
	return ret;
}

static struct smbXcli_tcon *cli_state_save_tcon(struct cli_state *cli)
{
	/*
	 * Note. This used to make a deep copy of either
	 * cli->smb2.tcon or cli->smb1.tcon, but this leaves
	 * the original pointer in place which will then get
	 * TALLOC_FREE()'d when the new connection is made on
	 * this cli_state.
	 *
	 * As there may be pipes open on the old connection with
	 * talloc'ed state allocated using the tcon pointer as a
	 * parent we can't deep copy and then free this as that
	 * closes the open pipes.
	 *
	 * This call is used to temporarily swap out a tcon pointer
	 * to allow a new tcon on the same cli_state.
	 *
	 * Just return the raw pointer and set the old value to NULL.
	 * We know we MUST be calling cli_state_restore_tcon() below
	 * to restore before closing the session.
	 *
	 * See BUG: https://bugzilla.samba.org/show_bug.cgi?id=13992
	 */
	struct smbXcli_tcon *tcon_ret = NULL;

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		tcon_ret = cli->smb2.tcon;
		cli->smb2.tcon = NULL; /* *Not* TALLOC_FREE(). */
	} else {
		tcon_ret = cli->smb1.tcon;
		cli->smb1.tcon = NULL; /* *Not* TALLOC_FREE(). */
	}
	return tcon_ret;
}

void cli_state_save_tcon_share(struct cli_state *cli,
			       struct smbXcli_tcon **_tcon_ret,
			       char **_sharename_ret)
{
	*_tcon_ret = cli_state_save_tcon(cli);
	/*
	 * No talloc_copy as cli->share is already
	 * allocated off cli.
	 */
	*_sharename_ret = cli->share;
	cli->share = NULL;
}

static void cli_state_restore_tcon(struct cli_state *cli,
				   struct smbXcli_tcon *tcon)
{
	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		TALLOC_FREE(cli->smb2.tcon);
		cli->smb2.tcon = tcon;
	} else {
		TALLOC_FREE(cli->smb1.tcon);
		cli->smb1.tcon = tcon;
	}
}

void cli_state_restore_tcon_share(struct cli_state *cli,
				  struct smbXcli_tcon *tcon,
				  char *share)
{
	/* cli->share will have been replaced by a cli_tree_connect() call. */
	TALLOC_FREE(cli->share);
	cli->share = share;
	cli_state_restore_tcon(cli, tcon);
}

uint16_t cli_state_get_uid(struct cli_state *cli)
{
	return smb1cli_session_current_id(cli->smb1.session);
}

uint16_t cli_state_set_uid(struct cli_state *cli, uint16_t uid)
{
	uint16_t ret = smb1cli_session_current_id(cli->smb1.session);
	smb1cli_session_set_id(cli->smb1.session, uid);
	return ret;
}

/****************************************************************************
 Set the case sensitivity flag on the packets. Returns old state.
****************************************************************************/

bool cli_set_case_sensitive(struct cli_state *cli, bool case_sensitive)
{
	bool ret;
	uint32_t fs_attrs;
	struct smbXcli_tcon *tcon;

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		tcon = cli->smb2.tcon;
	} else {
		tcon = cli->smb1.tcon;
	}

	fs_attrs = smbXcli_tcon_get_fs_attributes(tcon);
	if (fs_attrs & FILE_CASE_SENSITIVE_SEARCH) {
		ret = true;
	} else {
		ret = false;
	}
	if (case_sensitive) {
		fs_attrs |= FILE_CASE_SENSITIVE_SEARCH;
	} else {
		fs_attrs &= ~FILE_CASE_SENSITIVE_SEARCH;
	}
	smbXcli_tcon_set_fs_attributes(tcon, fs_attrs);

	return ret;
}

uint32_t cli_state_available_size(struct cli_state *cli, uint32_t ofs)
{
	uint32_t ret = smb1cli_conn_max_xmit(cli->conn);

	if (ofs >= ret) {
		return 0;
	}

	ret -= ofs;

	return ret;
}

time_t cli_state_server_time(struct cli_state *cli)
{
	NTTIME nt;
	time_t t;

	nt = smbXcli_conn_server_system_time(cli->conn);
	t = nt_time_to_unix(nt);

	return t;
}

struct cli_echo_state {
	uint8_t dummy;
};

static void cli_echo_done1(struct tevent_req *subreq);
static void cli_echo_done2(struct tevent_req *subreq);

struct tevent_req *cli_echo_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				 struct cli_state *cli, uint16_t num_echos,
				 DATA_BLOB data)
{
	struct tevent_req *req, *subreq;
	struct cli_echo_state *state;

	req = tevent_req_create(mem_ctx, &state, struct cli_echo_state);
	if (req == NULL) {
		return NULL;
	}

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		subreq = smb2cli_echo_send(
			state, ev, cli->conn, cli->timeout);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, cli_echo_done2, req);
		return req;
	}

	subreq = smb1cli_echo_send(
		state, ev, cli->conn, cli->timeout, num_echos, data);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_echo_done1, req);

	return req;
}

static void cli_echo_done1(struct tevent_req *subreq)
{
	NTSTATUS status = smb1cli_echo_recv(subreq);
	return tevent_req_simple_finish_ntstatus(subreq, status);
}

static void cli_echo_done2(struct tevent_req *subreq)
{
	NTSTATUS status = smb2cli_echo_recv(subreq);
	return tevent_req_simple_finish_ntstatus(subreq, status);
}

/**
 * Get the result out from an echo request
 * @param[in] req	The async_req from cli_echo_send
 * @retval Did the server reply correctly?
 */

NTSTATUS cli_echo_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

/**
 * @brief Send/Receive SMBEcho requests
 * @param[in] mem_ctx	The memory context to put the async_req on
 * @param[in] ev	The event context that will call us back
 * @param[in] cli	The connection to send the echo to
 * @param[in] num_echos	How many times do we want to get the reply?
 * @param[in] data	The data we want to get back
 * @retval Did the server reply correctly?
 */

NTSTATUS cli_echo(struct cli_state *cli, uint16_t num_echos, DATA_BLOB data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = cli_echo_send(frame, ev, cli, num_echos, data);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}

	status = cli_echo_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

NTSTATUS cli_smb(TALLOC_CTX *mem_ctx, struct cli_state *cli,
		 uint8_t smb_command, uint8_t additional_flags,
		 uint8_t wct, uint16_t *vwv,
		 uint32_t num_bytes, const uint8_t *bytes,
		 struct tevent_req **result_parent,
		 uint8_t min_wct, uint8_t *pwct, uint16_t **pvwv,
		 uint32_t *pnum_bytes, uint8_t **pbytes)
{
        struct tevent_context *ev;
        struct tevent_req *req = NULL;
        NTSTATUS status = NT_STATUS_NO_MEMORY;

        if (smbXcli_conn_has_async_calls(cli->conn)) {
                return NT_STATUS_INVALID_PARAMETER;
        }
        ev = samba_tevent_context_init(mem_ctx);
        if (ev == NULL) {
                goto fail;
        }
        req = cli_smb_send(mem_ctx, ev, cli, smb_command, additional_flags, 0,
			   wct, vwv, num_bytes, bytes);
        if (req == NULL) {
                goto fail;
        }
        if (!tevent_req_poll_ntstatus(req, ev, &status)) {
                goto fail;
        }
        status = cli_smb_recv(req, NULL, NULL, min_wct, pwct, pvwv,
			      pnum_bytes, pbytes);
fail:
        TALLOC_FREE(ev);
	if (NT_STATUS_IS_OK(status) && (result_parent != NULL)) {
		*result_parent = req;
	}
        return status;
}

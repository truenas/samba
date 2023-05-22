/*
 *  Unix SMB/CIFS implementation.
 *
 *  RPC Pipe client routines
 *
 *  Copyright (c) 2005      Jeremy Allison
 *  Copyright (c) 2010      Simo Sorce
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _CLI_PIPE_H
#define _CLI_PIPE_H

#include "rpc_client/rpc_client.h"
#include "auth/credentials/credentials.h"

/* The following definitions come from rpc_client/cli_pipe.c  */

struct tevent_req *rpc_pipe_bind_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct rpc_pipe_client *cli,
				      struct pipe_auth_data *auth);

NTSTATUS rpc_pipe_bind_recv(struct tevent_req *req);

NTSTATUS rpc_pipe_bind(struct rpc_pipe_client *cli,
		       struct pipe_auth_data *auth);

struct tevent_req *rpc_pipe_open_np_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	const struct ndr_interface_table *table);
NTSTATUS rpc_pipe_open_np_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct rpc_pipe_client **_result);
NTSTATUS rpc_pipe_open_np(struct cli_state *cli,
			  const struct ndr_interface_table *table,
			  struct rpc_pipe_client **presult);

unsigned int rpccli_set_timeout(struct rpc_pipe_client *cli,
				unsigned int timeout);

bool rpccli_is_connected(struct rpc_pipe_client *rpc_cli);

NTSTATUS rpccli_ncalrpc_bind_data(TALLOC_CTX *mem_ctx,
				  struct pipe_auth_data **presult);

NTSTATUS rpccli_anon_bind_data(TALLOC_CTX *mem_ctx,
			       struct pipe_auth_data **presult);

NTSTATUS rpc_pipe_open_ncalrpc(TALLOC_CTX *mem_ctx,
			       const struct ndr_interface_table *table,
			       struct rpc_pipe_client **presult);

NTSTATUS rpc_pipe_open_local_np(
	TALLOC_CTX *mem_ctx,
	const struct ndr_interface_table *table,
	const char *remote_client_name,
	const struct tsocket_address *remote_client_addr,
	const char *local_server_name,
	const struct tsocket_address *local_server_addr,
	const struct auth_session_info *session_info,
	struct rpc_pipe_client **presult);

struct dcerpc_binding_handle *rpccli_bh_create(struct rpc_pipe_client *c,
					const struct GUID *object,
					const struct ndr_interface_table *table);

NTSTATUS cli_rpc_pipe_open_noauth(struct cli_state *cli,
				  const struct ndr_interface_table *table,
				  struct rpc_pipe_client **presult);

NTSTATUS cli_rpc_pipe_open_noauth_transport(struct cli_state *cli,
					    enum dcerpc_transport_t transport,
					    const struct ndr_interface_table *table,
					    const char *remote_name,
					    const struct sockaddr_storage *remote_sockaddr,
					    struct rpc_pipe_client **presult);

/****************************************************************************
 Open a named pipe to an SMB server and bind using the mech specified

 This routine steals the creds pointer that is passed in
 ****************************************************************************/

NTSTATUS cli_rpc_pipe_open_with_creds(struct cli_state *cli,
				      const struct ndr_interface_table *table,
				      enum dcerpc_transport_t transport,
				      enum dcerpc_AuthType auth_type,
				      enum dcerpc_AuthLevel auth_level,
				      const char *server,
				      const struct sockaddr_storage *remote_sockaddr,
				      struct cli_credentials *creds,
				      struct rpc_pipe_client **presult);

NTSTATUS cli_rpc_pipe_open_bind_schannel(
	struct cli_state *cli,
	const struct ndr_interface_table *table,
	enum dcerpc_transport_t transport,
	struct netlogon_creds_cli_context *netlogon_creds,
	const char *remote_name,
	const struct sockaddr_storage *remote_sockaddr,
	struct rpc_pipe_client **_rpccli);
NTSTATUS cli_rpc_pipe_open_schannel_with_creds(struct cli_state *cli,
					       const struct ndr_interface_table *table,
					       enum dcerpc_transport_t transport,
					       struct netlogon_creds_cli_context *netlogon_creds,
					       const char *remote_name,
					       const struct sockaddr_storage *remote_sockaddr,
					       struct rpc_pipe_client **_rpccli);

NTSTATUS cli_rpc_pipe_open_schannel(struct cli_state *cli,
				    struct messaging_context *msg_ctx,
				    const struct ndr_interface_table *table,
				    enum dcerpc_transport_t transport,
				    const char *domain,
				    const char *remote_name,
				    const struct sockaddr_storage *remote_sockaddr,
				    struct rpc_pipe_client **presult,
				    TALLOC_CTX *mem_ctx,
				    struct netlogon_creds_cli_context **pcreds);

NTSTATUS cli_get_session_key(TALLOC_CTX *mem_ctx,
			     struct rpc_pipe_client *cli,
			     DATA_BLOB *session_key);

#endif /* _CLI_PIPE_H */

/* vim: set ts=8 sw=8 noet cindent ft=c.doxygen: */

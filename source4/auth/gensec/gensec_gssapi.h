/*
   Unix SMB/CIFS implementation.

   Kerberos backend for GENSEC

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   Copyright (C) Stefan Metzmacher <metze@samba.org> 2004-2005

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

/* This structure described here, so the RPC-PAC test can get at the PAC provided */

enum gensec_gssapi_sasl_state
{
	STAGE_GSS_NEG,
	STAGE_SASL_SSF_NEG,
	STAGE_SASL_SSF_ACCEPT,
	STAGE_DONE
};

#define NEG_SEAL 0x4
#define NEG_SIGN 0x2
#define NEG_NONE 0x1

struct gensec_gssapi_state {
	gss_ctx_id_t gssapi_context;
	gss_name_t server_name;
	gss_name_t client_name;
	OM_uint32 gss_want_flags, gss_got_flags;

	gss_cred_id_t delegated_cred_handle;

	NTTIME expire_time;

	/* gensec_gssapi only */
	gss_OID gss_oid;

	struct gss_channel_bindings_struct _input_chan_bindings;
	struct gss_channel_bindings_struct *input_chan_bindings;
	struct smb_krb5_context *smb_krb5_context;
	struct gssapi_creds_container *client_cred;
	struct gssapi_creds_container *server_cred;

	bool sasl; /* We have two different mechs in this file: One
		    * for SASL wrapped GSSAPI and another for normal
		    * GSSAPI */
	enum gensec_gssapi_sasl_state sasl_state;
	uint8_t sasl_protection; /* What was negotiated at the SASL
				  * layer, independent of the GSSAPI
				  * layer... */

	size_t max_wrap_buf_size;
	int gss_exchange_count;
	size_t sig_size;

	char *target_principal;
};

/*
   Unix SMB/CIFS implementation.

   PAC Glue between Samba and the KDC

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2009
   Copyright (C) Simo Sorce <idra@samba.org> 2010

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
#include "kdc/kdc-glue.h"
#include "kdc/db-glue.h"
#include "kdc/pac-glue.h"
#include "sdb.h"
#include "sdb_hdb.h"
#include "librpc/gen_ndr/auth.h"
#include <krb5_locl.h>

static bool samba_wdc_is_s4u2self_req(astgs_request_t r)
{
	krb5_kdc_configuration *config = kdc_request_get_config((kdc_request_t)r);
	const KDC_REQ *req = kdc_request_get_req(r);
	const PA_DATA *pa_for_user = NULL;

	if (req->msg_type != krb_tgs_req) {
		return false;
	}

	if (config->enable_fast && req->padata != NULL) {
		const PA_DATA *pa_fx_fast = NULL;
		int idx = 0;

		pa_fx_fast = krb5_find_padata(req->padata->val,
					      req->padata->len,
					      KRB5_PADATA_FX_FAST,
					      &idx);
		if (pa_fx_fast != NULL) {
			/*
			 * We're in the outer request
			 * with KRB5_PADATA_FX_FAST
			 * if fast is enabled we'll
			 * process the s4u2self
			 * request only in the
			 * inner request.
			 */
			return false;
		}
	}

	if (req->padata != NULL) {
		int idx = 0;

		pa_for_user = krb5_find_padata(req->padata->val,
					       req->padata->len,
					       KRB5_PADATA_FOR_USER,
					       &idx);
	}

	if (pa_for_user != NULL) {
		return true;
	}

	return false;
}

/*
 * Given the right private pointer from hdb_samba4,
 * get a PAC from the attached ldb messages.
 *
 * For PKINIT we also get pk_reply_key and can add PAC_CREDENTIAL_INFO.
 */
static krb5_error_code samba_wdc_get_pac(void *priv,
					 astgs_request_t r,
					 hdb_entry *client,
					 hdb_entry *server,
					 const krb5_keyblock *pk_reply_key,
					 uint64_t pac_attributes,
					 krb5_pac *pac)
{
	krb5_context context = kdc_request_get_context((kdc_request_t)r);
	TALLOC_CTX *mem_ctx;
	DATA_BLOB *logon_blob = NULL;
	DATA_BLOB *cred_ndr = NULL;
	DATA_BLOB **cred_ndr_ptr = NULL;
	DATA_BLOB _cred_blob = data_blob_null;
	DATA_BLOB *cred_blob = NULL;
	DATA_BLOB *upn_blob = NULL;
	DATA_BLOB *pac_attrs_blob = NULL;
	DATA_BLOB *requester_sid_blob = NULL;
	krb5_error_code ret;
	NTSTATUS nt_status;
	struct samba_kdc_entry *skdc_entry =
		talloc_get_type_abort(client->context,
		struct samba_kdc_entry);
	bool is_krbtgt;
	bool is_s4u2self = samba_wdc_is_s4u2self_req(r);
	enum samba_asserted_identity asserted_identity =
		(is_s4u2self) ?
			SAMBA_ASSERTED_IDENTITY_SERVICE :
			SAMBA_ASSERTED_IDENTITY_AUTHENTICATION_AUTHORITY;

	mem_ctx = talloc_named(client->context, 0, "samba_get_pac context");
	if (!mem_ctx) {
		return ENOMEM;
	}

	if (pk_reply_key != NULL) {
		cred_ndr_ptr = &cred_ndr;
	}

	is_krbtgt = krb5_principal_is_krbtgt(context, server->principal);

	nt_status = samba_kdc_get_pac_blobs(mem_ctx, skdc_entry,
					    asserted_identity,
					    &logon_blob,
					    cred_ndr_ptr,
					    &upn_blob,
					    is_krbtgt ? &pac_attrs_blob : NULL,
					    pac_attributes,
					    is_krbtgt ? &requester_sid_blob : NULL);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(mem_ctx);
		return EINVAL;
	}

	if (pk_reply_key != NULL && cred_ndr != NULL) {
		ret = samba_kdc_encrypt_pac_credentials(context,
							pk_reply_key,
							cred_ndr,
							mem_ctx,
							&_cred_blob);
		if (ret != 0) {
			talloc_free(mem_ctx);
			return ret;
		}
		cred_blob = &_cred_blob;
	}

	ret = krb5_pac_init(context, pac);
	if (ret != 0) {
		talloc_free(mem_ctx);
		return ret;
	}

	ret = samba_make_krb5_pac(context, logon_blob, cred_blob,
				  upn_blob, pac_attrs_blob,
				  requester_sid_blob, NULL, *pac);

	talloc_free(mem_ctx);
	return ret;
}

static krb5_error_code samba_wdc_reget_pac2(astgs_request_t r,
					    const krb5_principal delegated_proxy_principal,
					    hdb_entry *client,
					    hdb_entry *server,
					    hdb_entry *krbtgt,
					    krb5_pac *pac,
					    krb5_cksumtype ctype)
{
	krb5_context context = kdc_request_get_context((kdc_request_t)r);
	struct samba_kdc_entry *client_skdc_entry = NULL;
	struct samba_kdc_entry *server_skdc_entry =
		talloc_get_type_abort(server->context, struct samba_kdc_entry);
	struct samba_kdc_entry *krbtgt_skdc_entry =
		talloc_get_type_abort(krbtgt->context, struct samba_kdc_entry);
	TALLOC_CTX *mem_ctx = NULL;
	krb5_pac new_pac = NULL;
	krb5_error_code ret;
	bool is_s4u2self = samba_wdc_is_s4u2self_req(r);
	bool is_in_db = false;
	bool is_untrusted = false;
	uint32_t flags = 0;

	mem_ctx = talloc_named(NULL, 0, "samba_kdc_reget_pac2 context");
	if (mem_ctx == NULL) {
		return ENOMEM;
	}

	if (client != NULL) {
		client_skdc_entry = talloc_get_type_abort(client->context,
							  struct samba_kdc_entry);
	}

	/*
	 * If the krbtgt was generated by an RODC, and we are not that
	 * RODC, then we need to regenerate the PAC - we can't trust
	 * it, and confirm that the RODC was permitted to print this ticket
	 *
	 * Becasue of the samba_kdc_validate_pac_blob() step we can be
	 * sure that the record in 'client' matches the SID in the
	 * original PAC.
	 */
	ret = samba_krbtgt_is_in_db(krbtgt_skdc_entry, &is_in_db, &is_untrusted);
	if (ret != 0) {
		goto out;
	}

	if (is_s4u2self) {
		flags |= SAMBA_KDC_FLAG_PROTOCOL_TRANSITION;
	}

	if (delegated_proxy_principal != NULL) {
		krb5_enctype etype;
		Key *key = NULL;

		if (!is_in_db) {
			/*
			 * The RODC-issued PAC was signed by a KDC entry that we
			 * don't have a key for. The server signature is not
			 * trustworthy, since it could have been created by the
			 * server we got the ticket from. We must not proceed as
			 * otherwise the ticket signature is unchecked.
			 */
			ret = HDB_ERR_NOT_FOUND_HERE;
			goto out;
		}

		/* Fetch the correct key depending on the checksum type. */
		if (ctype == CKSUMTYPE_HMAC_MD5) {
			etype = ENCTYPE_ARCFOUR_HMAC;
		} else {
			ret = krb5_cksumtype_to_enctype(context,
							ctype,
							&etype);
			if (ret != 0) {
				goto out;
			}
		}
		ret = hdb_enctype2key(context, krbtgt, NULL, etype, &key);
		if (ret != 0) {
			goto out;
		}

		/* Check the KDC, whole-PAC and ticket signatures. */
		ret = krb5_pac_verify(context,
				      *pac,
				      0,
				      NULL,
				      NULL,
				      &key->key);
		if (ret != 0) {
			DEBUG(1, ("PAC KDC signature failed to verify\n"));
			goto out;
		}

		flags |= SAMBA_KDC_FLAG_CONSTRAINED_DELEGATION;
	}

	if (is_untrusted) {
		flags |= SAMBA_KDC_FLAG_KRBTGT_IS_UNTRUSTED;
	}

	if (is_in_db) {
		flags |= SAMBA_KDC_FLAG_KRBTGT_IN_DB;
	}

	ret = krb5_pac_init(context, &new_pac);
	if (ret != 0) {
		new_pac = NULL;
		goto out;
	}

	ret = samba_kdc_update_pac(mem_ctx,
				   context,
				   krbtgt_skdc_entry->kdc_db_ctx->samdb,
				   flags,
				   client_skdc_entry,
				   server->principal,
				   server_skdc_entry,
				   krbtgt_skdc_entry,
				   delegated_proxy_principal,
				   *pac,
				   new_pac);
	if (ret != 0) {
		krb5_pac_free(context, new_pac);
		if (ret == ENODATA) {
			krb5_pac_free(context, *pac);
			*pac = NULL;
			ret = 0;
		}
		goto out;
	}

	/* Replace the pac */
	krb5_pac_free(context, *pac);
	*pac = new_pac;

out:
	talloc_free(mem_ctx);
	return ret;
}

/* Resign (and reform, including possibly new groups) a PAC */

static krb5_error_code samba_wdc_reget_pac(void *priv, astgs_request_t r,
					   const krb5_principal client_principal,
					   const krb5_principal delegated_proxy_principal,
					   hdb_entry *client,
					   hdb_entry *server,
					   hdb_entry *krbtgt,
					   krb5_pac *pac)
{
	krb5_context context = kdc_request_get_context((kdc_request_t)r);
	krb5_kdc_configuration *config = kdc_request_get_config((kdc_request_t)r);
	struct samba_kdc_entry *krbtgt_skdc_entry =
		talloc_get_type_abort(krbtgt->context,
				      struct samba_kdc_entry);
	krb5_error_code ret;
	krb5_cksumtype ctype = CKSUMTYPE_NONE;
	hdb_entry signing_krbtgt_hdb;

	if (delegated_proxy_principal) {
		uint16_t rodc_id;
		unsigned int my_krbtgt_number;

		/*
		 * We're using delegated_proxy_principal for the moment to
		 * indicate cases where the ticket was encrypted with the server
		 * key, and not a krbtgt key. This cannot be trusted, so we need
		 * to find a krbtgt key that signs the PAC in order to trust the
		 * ticket.
		 *
		 * The krbtgt passed in to this function refers to the krbtgt
		 * used to decrypt the ticket of the server requesting
		 * S4U2Proxy.
		 *
		 * When we implement service ticket renewal, we need to check
		 * the PAC, and this will need to be updated.
		 */
		ret = krb5_pac_get_kdc_checksum_info(context,
						     *pac,
						     &ctype,
						     &rodc_id);
		if (ret != 0) {
			DEBUG(1, ("Failed to get PAC checksum info\n"));
			return ret;
		}

		/*
		 * We need to check the KDC and ticket signatures, fetching the
		 * correct key based on the enctype.
		 */

		my_krbtgt_number = krbtgt_skdc_entry->kdc_db_ctx->my_krbtgt_number;

		if (my_krbtgt_number != 0) {
			/*
			 * If we are an RODC, and we are not the KDC that signed
			 * the evidence ticket, then we need to proxy the
			 * request.
			 */
			if (rodc_id != my_krbtgt_number) {
				return HDB_ERR_NOT_FOUND_HERE;
			}
		} else {
			/*
			 * If we are a DC, the ticket may have been signed by a
			 * different KDC than the one that issued the header
			 * ticket.
			 */
			if (rodc_id != krbtgt->kvno >> 16) {
				struct sdb_entry signing_krbtgt_sdb;

				/*
				 * If we didn't sign the ticket, then return an
				 * error.
				 */
				if (rodc_id != 0) {
					return KRB5KRB_AP_ERR_MODIFIED;
				}

				/*
				 * Fetch our key from the database. To support
				 * key rollover, we're going to need to try
				 * multiple keys by trial and error. For now,
				 * krbtgt keys aren't assumed to change.
				 */
				ret = samba_kdc_fetch(context,
						      krbtgt_skdc_entry->kdc_db_ctx,
						      krbtgt->principal,
						      SDB_F_GET_KRBTGT | SDB_F_CANON,
						      0,
						      &signing_krbtgt_sdb);
				if (ret != 0) {
					return ret;
				}

				ret = sdb_entry_to_hdb_entry(context,
							     &signing_krbtgt_sdb,
							     &signing_krbtgt_hdb);
				sdb_entry_free(&signing_krbtgt_sdb);
				if (ret != 0) {
					return ret;
				}

				/*
				 * Replace the krbtgt entry with our own entry
				 * for further processing.
				 */
				krbtgt = &signing_krbtgt_hdb;
			}
		}
	} else if (!krbtgt_skdc_entry->is_trust) {
		/*
		 * We expect to have received a TGT, so check that we haven't
		 * been given a kpasswd ticket instead. We don't need to do this
		 * check for an incoming trust, as they use a different secret
		 * and can't be confused with a normal TGT.
		 */
		krb5_ticket *tgt = kdc_request_get_ticket(r);

		struct timeval now = krb5_kdc_get_time();

		/*
		 * Check if the ticket is in the last two minutes of its
		 * life.
		 */
		KerberosTime lifetime = rk_time_sub(tgt->ticket.endtime, now.tv_sec);
		if (lifetime <= CHANGEPW_LIFETIME) {
			/*
			 * This ticket has at most two minutes left to live. It
			 * may be a kpasswd ticket rather than a TGT, so don't
			 * accept it.
			 */
			kdc_audit_addreason((kdc_request_t)r,
					    "Ticket is not a ticket-granting ticket");
			return KRB5KRB_AP_ERR_TKT_EXPIRED;
		}
	}

	ret = samba_wdc_reget_pac2(r,
				   delegated_proxy_principal,
				   client,
				   server,
				   krbtgt,
				   pac,
				   ctype);

	if (krbtgt == &signing_krbtgt_hdb) {
		hdb_free_entry(context, config->db[0], &signing_krbtgt_hdb);
	}

	return ret;
}

static char *get_netbios_name(TALLOC_CTX *mem_ctx, HostAddresses *addrs)
{
	char *nb_name = NULL;
	size_t len;
	unsigned int i;

	for (i = 0; addrs && i < addrs->len; i++) {
		if (addrs->val[i].addr_type != KRB5_ADDRESS_NETBIOS) {
			continue;
		}
		len = MIN(addrs->val[i].address.length, 15);
		nb_name = talloc_strndup(mem_ctx,
					 addrs->val[i].address.data, len);
		if (nb_name) {
			break;
		}
	}

	if ((nb_name == NULL) || (nb_name[0] == '\0')) {
		return NULL;
	}

	/* Strip space padding */
	for (len = strlen(nb_name) - 1;
	     (len > 0) && (nb_name[len] == ' ');
	     --len) {
		nb_name[len] = '\0';
	}

	return nb_name;
}

/* this function allocates 'data' using malloc.
 * The caller is responsible for freeing it */
static void samba_kdc_build_edata_reply(NTSTATUS nt_status, krb5_data *e_data)
{
	e_data->data = malloc(12);
	if (e_data->data == NULL) {
		e_data->length = 0;
		e_data->data = NULL;
		return;
	}
	e_data->length = 12;

	SIVAL(e_data->data, 0, NT_STATUS_V(nt_status));
	SIVAL(e_data->data, 4, 0);
	SIVAL(e_data->data, 8, 1);

	return;
}

static krb5_error_code samba_wdc_check_client_access(void *priv,
						     astgs_request_t r)
{
	struct samba_kdc_entry *kdc_entry;
	bool password_change;
	char *workstation;
	NTSTATUS nt_status;


	kdc_entry = talloc_get_type(kdc_request_get_client(r)->context, struct samba_kdc_entry);
	password_change = (kdc_request_get_server(r) && kdc_request_get_server(r)->flags.change_pw);
	workstation = get_netbios_name((TALLOC_CTX *)kdc_request_get_client(r)->context,
				       kdc_request_get_req(r)->req_body.addresses);

	nt_status = samba_kdc_check_client_access(kdc_entry,
						  kdc_request_get_cname((kdc_request_t)r),
						  workstation,
						  password_change);

	if (!NT_STATUS_IS_OK(nt_status)) {
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_MEMORY)) {
			return ENOMEM;
		}

		if (kdc_request_get_rep(r)->padata) {
			int ret;
			krb5_data kd;

			samba_kdc_build_edata_reply(nt_status, &kd);
			ret = krb5_padata_add(kdc_request_get_context((kdc_request_t)r), kdc_request_get_rep(r)->padata,
					      KRB5_PADATA_PW_SALT,
					      kd.data, kd.length);
			if (ret != 0) {
				/*
				 * So we do not leak the allocated
				 * memory on kd in the error case
				 */
				krb5_data_free(&kd);
			}
		}

		return samba_kdc_map_policy_err(nt_status);
	}

	/* Now do the standard Heimdal check */
	return KRB5_PLUGIN_NO_HANDLE;
}

/* this function allocates 'data' using malloc.
 * The caller is responsible for freeing it */
static krb5_error_code samba_kdc_build_supported_etypes(uint32_t supported_etypes,
							krb5_data *e_data)
{
	e_data->data = malloc(4);
	if (e_data->data == NULL) {
		return ENOMEM;
	}
	e_data->length = 4;

	PUSH_LE_U32(e_data->data, 0, supported_etypes);

	return 0;
}

static krb5_error_code samba_wdc_finalize_reply(void *priv,
						astgs_request_t r)
{
	struct samba_kdc_entry *server_kdc_entry;
	uint32_t supported_enctypes;

	server_kdc_entry = talloc_get_type(kdc_request_get_server(r)->context, struct samba_kdc_entry);

	/*
	 * If the canonicalize flag is set, add PA-SUPPORTED-ENCTYPES padata
	 * type to indicate what encryption types the server supports.
	 */
	supported_enctypes = server_kdc_entry->supported_enctypes;
	if (kdc_request_get_req(r)->req_body.kdc_options.canonicalize && supported_enctypes != 0) {
		krb5_error_code ret;

		PA_DATA md;

		ret = samba_kdc_build_supported_etypes(supported_enctypes, &md.padata_value);
		if (ret != 0) {
			return ret;
		}

		md.padata_type = KRB5_PADATA_SUPPORTED_ETYPES;

		ret = kdc_request_add_encrypted_padata(r, &md);
		if (ret != 0) {
			/*
			 * So we do not leak the allocated
			 * memory on kd in the error case
			 */
			krb5_data_free(&md.padata_value);
		}
	}

	return 0;
}

static krb5_error_code samba_wdc_plugin_init(krb5_context context, void **ptr)
{
	*ptr = NULL;
	return 0;
}

static void samba_wdc_plugin_fini(void *ptr)
{
	return;
}

static krb5_error_code samba_wdc_referral_policy(void *priv,
						 astgs_request_t r)
{
	return kdc_request_get_error_code((kdc_request_t)r);
}

struct krb5plugin_kdc_ftable kdc_plugin_table = {
	.minor_version = KRB5_PLUGIN_KDC_VERSION_10,
	.init = samba_wdc_plugin_init,
	.fini = samba_wdc_plugin_fini,
	.pac_verify = samba_wdc_reget_pac,
	.client_access = samba_wdc_check_client_access,
	.finalize_reply = samba_wdc_finalize_reply,
	.pac_generate = samba_wdc_get_pac,
	.referral_policy = samba_wdc_referral_policy,
};



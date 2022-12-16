/*
   Samba Unix/Linux SMB client library
   net join commands
   Copyright (C) 2021 Guenther Deschner (gd@samba.org)

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
#include "utils/net.h"
#include <netapi.h>
#include "netapi/netapi_net.h"
#include "libcli/registry/util_reg.h"

int net_offlinejoin_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf(_("\nnet offlinejoin [misc. options]\n"
		   "\tjoins a computer to a domain\n"));
	d_printf(_("Valid commands:\n"));
	d_printf(_("\tprovision\t\t\tProvision machine account in AD\n"));
	d_printf(_("\trequestodj\t\t\tRequest offline domain join\n"));
	net_common_flags_usage(c, argc, argv);
	return -1;
}

int net_offlinejoin(struct net_context *c, int argc, const char **argv)
{
	int ret;
	NET_API_STATUS status;

	if ((argc > 0) && (strcasecmp_m(argv[0], "HELP") == 0)) {
		net_offlinejoin_usage(c, argc, argv);
		return 0;
	}

	if (argc == 0) {
		net_offlinejoin_usage(c, argc, argv);
		return -1;
	}

	net_warn_member_options();

	status = libnetapi_net_init(&c->netapi_ctx);
	if (status != 0) {
		return -1;
	}

	status = libnetapi_set_creds(c->netapi_ctx, c->creds);
	if (status != 0) {
		return -1;
	}

	if (c->opt_kerberos) {
		libnetapi_set_use_kerberos(c->netapi_ctx);
	}

	if (strcasecmp_m(argv[0], "provision") == 0) {
		ret = net_offlinejoin_provision(c, argc, argv);
		if (ret != 0) {
			return ret;
		}
	}

	if (strcasecmp_m(argv[0], "requestodj") == 0) {
		ret = net_offlinejoin_requestodj(c, argc, argv);
		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}

static int net_offlinejoin_provision_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf(_("\nnet offlinejoin provision [misc. options]\n"
		   "\tProvisions machine account in AD\n"));
	d_printf(_("Valid options:\n"));
	d_printf(_("\tdomain=<DOMAIN>\t\t\t\tDefines AD Domain to join\n"));
	d_printf(_("\tmachine_name=<MACHINE_NAME>\t\tDefines the machine account name\n"));
	d_printf(_("\tmachine_account_ou=<OU>\t\t\tDefines the machine account organizational unit DN\n"));
	d_printf(_("\tdcname=<DCNAME>\t\t\t\tSpecifices a Domain Controller to join to\n"));
	d_printf(_("\tdefpwd\t\t\t\t\tUse default machine account password\n"));
	d_printf(_("\treuse\t\t\t\t\tReuse existing machine account in AD\n"));
	d_printf(_("\tsavefile=<FILENAME>\t\t\tFile to store the ODJ data\n"));
	d_printf(_("\tprintblob\t\t\t\tPrint the base64 encoded ODJ data on stdout\n"));
	net_common_flags_usage(c, argc, argv);
	return -1;
}

int net_offlinejoin_provision(struct net_context *c,
			      int argc, const char **argv)
{
	NET_API_STATUS status;
	const char *dcname = NULL;
	const char *domain = NULL;
	const char *machine_name = NULL;
	const char *machine_account_ou = NULL;
	const char *provision_text_data = NULL;
	uint32_t options = 0;
	const char *savefile = NULL;
	bool printblob = false;
	int i;

	if (c->display_usage || argc == 1) {
		return net_offlinejoin_provision_usage(c, argc, argv);
	}

	/* process additional command line args */

	for (i = 0; i < argc; i++) {

		if (strnequal(argv[i], "domain", strlen("domain"))) {
			domain = get_string_param(argv[i]);
			if (domain == NULL) {
				return -1;
			}
		}
		if (strnequal(argv[i], "machine_name", strlen("machine_name"))) {
			machine_name = get_string_param(argv[i]);
			if (machine_name == NULL) {
				return -1;
			}
		}
		if (strnequal(argv[i], "machine_account_ou", strlen("machine_account_ou"))) {
			machine_account_ou = get_string_param(argv[i]);
			if (machine_account_ou == NULL) {
				return -1;
			}
		}
		if (strnequal(argv[i], "dcname", strlen("dcname"))) {
			dcname = get_string_param(argv[i]);
			if (dcname == NULL) {
				return -1;
			}
		}
		if (strnequal(argv[i], "defpwd", strlen("defpwd"))) {
			options |= NETSETUP_PROVISION_USE_DEFAULT_PASSWORD;
		}
		if (strnequal(argv[i], "reuse", strlen("reuse"))) {
			options |= NETSETUP_PROVISION_REUSE_ACCOUNT;
		}
		if (strnequal(argv[i], "savefile", strlen("savefile"))) {
			savefile = get_string_param(argv[i]);
			if (savefile == NULL) {
				return -1;
			}
		}
		if (strnequal(argv[i], "printblob", strlen("printblob"))) {
			printblob = true;
		}
	}

	if (domain == NULL) {
		d_printf("Failed to provision computer account: %s\n",
			 libnetapi_errstr(W_ERROR_V(WERR_INVALID_DOMAINNAME)));
		return -1;
	}

	if (machine_name == NULL) {
		d_printf("Failed to provision computer account: %s\n",
			 libnetapi_errstr(W_ERROR_V(WERR_INVALID_COMPUTERNAME)));
		return -1;
	}

	status = NetProvisionComputerAccount(domain,
					     machine_name,
					     machine_account_ou,
					     dcname,
					     options,
					     NULL,
					     0,
					     &provision_text_data);
	if (status != 0) {
		d_printf("Failed to provision computer account: %s\n",
			libnetapi_get_error_string(c->netapi_ctx, status));
		return status;
	}

	if (savefile != NULL) {

		DATA_BLOB ucs2_blob, blob;
		bool ok;

		ok = push_reg_sz(c, &ucs2_blob, provision_text_data);
		if (!ok) {
			return -1;
		}

		blob = data_blob_talloc(c, NULL, ucs2_blob.length + 2);

		blob.data[0] = 0xff;
		blob.data[1] = 0xfe;

		memcpy(blob.data + 2, ucs2_blob.data, ucs2_blob.length);

		ok = file_save(savefile, blob.data, blob.length);
		if (!ok) {
			d_printf("Failed to save %s: %s\n", savefile,
					strerror(errno));
			return -1;
		}
	}

	d_printf("Successfully provisioned computer '%s' in domain '%s'\n",
			machine_name, domain);

	if (printblob) {
		printf("%s\n", provision_text_data);
	}

	return 0;
}

static int net_offlinejoin_requestodj_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf(_("\nnet offlinejoin requestodj [misc. options]\n"
		   "\tRequests offline domain join\n"));
	d_printf(_("Valid options:\n"));
	d_printf(_("\tloadfile=<FILENAME>\t\t\tFile that provides the ODJ data\n"));
	/*d_printf(_("\tlocalos\t\t\t\t\tModify the local machine\n"));*/
	net_common_flags_usage(c, argc, argv);
	return -1;
}

int net_offlinejoin_requestodj(struct net_context *c,
			       int argc, const char **argv)
{
	NET_API_STATUS status;
	uint8_t *provision_bin_data = NULL;
	size_t provision_bin_data_size = 0;
	uint32_t options = NETSETUP_PROVISION_ONLINE_CALLER;
	const char *loadfile = NULL;
	const char *windows_path = NULL;
	int i;

	if (c->display_usage || argc == 1) {
		return net_offlinejoin_requestodj_usage(c, argc, argv);
	}

	/* process additional command line args */

	for (i = 0; i < argc; i++) {

		if (strnequal(argv[i], "loadfile", strlen("loadfile"))) {
			loadfile = get_string_param(argv[i]);
			if (loadfile == NULL) {
				return -1;
			}
		}
#if 0
		if (strnequal(argv[i], "localos", strlen("localos"))) {
			options |= NETSETUP_PROVISION_ONLINE_CALLER;
		}
#endif
	}

	provision_bin_data =
		(uint8_t *)file_load(loadfile, &provision_bin_data_size, 0, c);
	if (provision_bin_data == NULL) {
		d_printf("Failed to read loadfile: %s\n", loadfile);
		return -1;
	}
	if (provision_bin_data_size > UINT32_MAX) {
		d_printf("provision binary data size too big: %zu\n",
			 provision_bin_data_size);
		return -1;
	}

	status = NetRequestOfflineDomainJoin(provision_bin_data,
					     provision_bin_data_size,
					     options,
					     windows_path);
	if (status != 0 && status != 0x00000a99) {
		/* NERR_JoinPerformedMustRestart */
		printf("Failed to call NetRequestOfflineDomainJoin: %s\n",
			libnetapi_get_error_string(c->netapi_ctx, status));
		return -1;
	}

	d_printf("Successfully requested Offline Domain Join\n");

	return 0;
}

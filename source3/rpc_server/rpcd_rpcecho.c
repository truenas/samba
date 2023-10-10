/*
 *  Unix SMB/CIFS implementation.
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

#include "replace.h"
#include "rpc_worker.h"
#include "librpc/gen_ndr/ndr_echo.h"
#include "librpc/gen_ndr/ndr_echo_scompat.h"
#include "param/loadparm.h"
#include "libds/common/roles.h"

static size_t rpcecho_interfaces(
	const struct ndr_interface_table ***pifaces,
	void *private_data)
{
	static const struct ndr_interface_table *ifaces[] = {
		&ndr_table_rpcecho,
	};
	size_t num_ifaces = ARRAY_SIZE(ifaces);

	switch(lp_server_role()) {
	case ROLE_ACTIVE_DIRECTORY_DC:
		/*
		 * On the AD DC rpcecho is provided by the 'samba'
		 * binary from source4/
		 */
		num_ifaces = 0;
		break;
	default:
		break;
	}

	*pifaces = ifaces;
	return num_ifaces;
}

static size_t rpcecho_servers(
	struct dcesrv_context *dce_ctx,
	const struct dcesrv_endpoint_server ***_ep_servers,
	void *private_data)
{
	static const struct dcesrv_endpoint_server *ep_servers[1] = { NULL };
	size_t num_servers = ARRAY_SIZE(ep_servers);

	ep_servers[0] = rpcecho_get_ep_server();

	switch(lp_server_role()) {
	case ROLE_ACTIVE_DIRECTORY_DC:
		/*
		 * On the AD DC rpcecho is provided by the 'samba'
		 * binary from source4/
		 */
		num_servers = 0;
		break;
	default:
		break;
	}

	*_ep_servers = ep_servers;
	return num_servers;
}

int main(int argc, const char *argv[])
{
	return rpc_worker_main(
		argc,
		argv,
		"rpcd_rpcecho",
		1,
		1,
		rpcecho_interfaces,
		rpcecho_servers,
		NULL);
}

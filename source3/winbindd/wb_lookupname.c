/*
   Unix SMB/CIFS implementation.
   async lookupname
   Copyright (C) Volker Lendecke 2009

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
#include "winbindd.h"
#include "librpc/gen_ndr/ndr_winbind_c.h"
#include "passdb/lookup_sid.h" /* only for LOOKUP flags */
#include "passdb/machine_sid.h"
#include "../libcli/security/security.h"

struct wb_lookupname_state {
	struct tevent_context *ev;
	const char *dom_name;
	const char *name;
	uint32_t flags;
	struct dom_sid sid;
	enum lsa_SidType type;
};

static void wb_lookupname_done(struct tevent_req *subreq);

struct tevent_req *wb_lookupname_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      const char *namespace,
				      const char *dom_name,
				      const char *name,
				      uint32_t flags)
{
	struct tevent_req *req, *subreq;
	struct wb_lookupname_state *state;
	struct winbindd_domain *domain;

	req = tevent_req_create(mem_ctx, &state, struct wb_lookupname_state);
	if (req == NULL) {
		return NULL;
	}

	D_INFO("WB command lookupname start.\n"
	       "Search namespace '%s' and domain '%s' for name '%s'.\n",
		namespace, dom_name, name);
	state->ev = ev;
	state->flags = flags;

	/*
	 * Uppercase domain and name so that we become cache-friendly
	 */
	state->dom_name = talloc_strdup_upper(state, dom_name);
	if (tevent_req_nomem(state->dom_name, req)) {
		return tevent_req_post(req, ev);
	}
	state->name = talloc_strdup_upper(state, name);
	if (tevent_req_nomem(state->name, req)) {
		return tevent_req_post(req, ev);
	}

	domain = find_lookup_domain_from_name(namespace);
	if (domain == NULL) {
		D_WARNING("Could not find domain for %s\n", namespace);
		tevent_req_nterror(req, NT_STATUS_NONE_MAPPED);
		return tevent_req_post(req, ev);
	}

	if (flags == (LOOKUP_NAME_NO_NSS | LOOKUP_NAME_REMOTE)) {
		if (dom_sid_compare_domain(&domain->sid,
		    get_global_sam_sid()) == 0) {
			D_NOTICE("Domain [%s] is our local domain, "
				 "skipping recursive lookup\n",
				 dom_name);

			tevent_req_nterror(req, NT_STATUS_NONE_MAPPED);
			return tevent_req_post(req, ev);
		}

		flags &= ~LOOKUP_NAME_REMOTE;
	}

	subreq = dcerpc_wbint_LookupName_send(
		state, ev, dom_child_handle(domain),
		state->dom_name, state->name,
		flags, &state->type, &state->sid);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wb_lookupname_done, req);
	return req;
}

static void wb_lookupname_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_lookupname_state *state = tevent_req_data(
		req, struct wb_lookupname_state);
	NTSTATUS status, result;

	status = dcerpc_wbint_LookupName_recv(subreq, state, &result);
	TALLOC_FREE(subreq);
	if (any_nt_status_not_ok(status, result, &status)) {
		tevent_req_nterror(req, status);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS wb_lookupname_recv(struct tevent_req *req, struct dom_sid *sid,
			    enum lsa_SidType *type)
{
	struct wb_lookupname_state *state = tevent_req_data(
		req, struct wb_lookupname_state);
	NTSTATUS status;
	struct dom_sid_buf buf;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	sid_copy(sid, &state->sid);
	*type = state->type;
	D_INFO("WB command lookupname end.\n"
	       "Found SID %s with SID type %d.\n",
	       dom_sid_str_buf(sid, &buf),
	       *type);
	return NT_STATUS_OK;
}

#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
# Copyright (C) 2021 Catalyst.Net Ltd
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import sys
import os

sys.path.insert(0, "bin/python")
os.environ["PYTHONUNBUFFERED"] = "1"

import ldb

from samba import NTSTATUSError, credentials
from samba.dcerpc import lsa
from samba.ntstatus import (
    NT_STATUS_ACCESS_DENIED,
    NT_STATUS_NO_IMPERSONATION_TOKEN
)

from samba.tests.krb5.kdc_base_test import KDCBaseTest

global_asn1_print = False
global_hexdump = False


class RpcTests(KDCBaseTest):
    """Test for RPC authentication using Kerberos credentials stored in a
       credentials cache file.
    """

    def test_rpc(self):
        self._run_rpc_test()

    def test_rpc_rename(self):
        self._run_rpc_test(rename=True)

    def test_rpc_no_pac(self):
        self._run_rpc_test(include_pac=False,
                           expect_anon=True, allow_error=True)

    def _run_rpc_test(self, rename=False, include_pac=True,
                      expect_anon=False, allow_error=False):
        # Create a user account and a machine account, along with a Kerberos
        # credentials cache file where the service ticket authenticating the
        # user are stored.

        samdb = self.get_samdb()

        mach_name = self.host
        service = "cifs"

        # Create the user account.
        user_credentials = self.get_cached_creds(
            account_type=self.AccountType.USER,
            use_cache=False)
        user_name = user_credentials.get_username()

        mach_credentials = self.get_server_creds()

        # Talk to the KDC to obtain the service ticket, which gets placed into
        # the cache. The machine account name has to match the name in the
        # ticket, to ensure that the krbtgt ticket doesn't also need to be
        # stored.
        (creds, cachefile) = self.create_ccache_with_user(user_credentials,
                                                          mach_credentials,
                                                          service,
                                                          mach_name,
                                                          pac=include_pac)
        # Remove the cached credentials file.
        self.addCleanup(os.remove, cachefile.name)

        if rename:
            # Rename the account.

            new_name = self.get_new_username()

            msg = ldb.Message(user_credentials.get_dn())
            msg['sAMAccountName'] = ldb.MessageElement(new_name,
                                                       ldb.FLAG_MOD_REPLACE,
                                                       'sAMAccountName')
            samdb.modify(msg)

        # Authenticate in-process to the machine account using the user's
        # cached credentials.

        binding_str = "ncacn_np:%s[\\pipe\\lsarpc]" % mach_name
        try:
            conn = lsa.lsarpc(binding_str, self.get_lp(), creds)
        except NTSTATUSError as e:
            if not allow_error:
                self.fail()

            enum, _ = e.args
            self.assertIn(enum, {NT_STATUS_ACCESS_DENIED,
                                 NT_STATUS_NO_IMPERSONATION_TOKEN})
            return

        (account_name, _) = conn.GetUserName(None, None, None)

        if expect_anon:
            self.assertNotEqual(user_name, account_name.string)
        else:
            self.assertEqual(user_name, account_name.string)

    def test_rpc_anonymous(self):
        mach_name = self.host

        anon_creds = credentials.Credentials()
        anon_creds.set_anonymous()

        binding_str = "ncacn_np:%s[\\pipe\\lsarpc]" % mach_name
        conn = lsa.lsarpc(binding_str, self.get_lp(), anon_creds)

        (account_name, _) = conn.GetUserName(None, None, None)

        self.assertEqual('ANONYMOUS LOGON', account_name.string.upper())


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()

#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
# Copyright (C) Stefan Metzmacher 2020
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

from samba.tests import DynamicTestCase
from samba.tests.krb5.kdc_base_test import KDCBaseTest
import samba.tests.krb5.kcrypto as kcrypto
import samba.tests.krb5.rfc4120_pyasn1 as krb5_asn1
from samba.tests.krb5.rfc4120_constants import (
    KDC_ERR_C_PRINCIPAL_UNKNOWN,
    KDC_ERR_S_PRINCIPAL_UNKNOWN,
    KDC_ERR_ETYPE_NOSUPP,
    KDC_ERR_PREAUTH_REQUIRED,
    KU_PA_ENC_TIMESTAMP,
    NT_ENTERPRISE_PRINCIPAL,
    NT_PRINCIPAL,
    NT_SRV_INST,
    PADATA_ENC_TIMESTAMP
)

global_asn1_print = False
global_hexdump = False


class AsReqBaseTest(KDCBaseTest):
    def _run_as_req_enc_timestamp(self, client_creds, client_account=None,
                                  expected_cname=None, sname=None,
                                  name_type=NT_PRINCIPAL, etypes=None,
                                  expected_error=None, expect_edata=None,
                                  expected_pa_error=None, expect_pa_edata=None,
                                  kdc_options=None, till=None):
        user_name = client_creds.get_username()
        if client_account is None:
            client_account = user_name
        client_as_etypes = self.get_default_enctypes()
        client_kvno = client_creds.get_kvno()
        krbtgt_creds = self.get_krbtgt_creds(require_strongest_key=True)
        krbtgt_account = krbtgt_creds.get_username()
        krbtgt_supported_etypes = krbtgt_creds.tgs_supported_enctypes
        realm = krbtgt_creds.get_realm()

        cname = self.PrincipalName_create(name_type=name_type,
                                          names=client_account.split('/'))
        if sname is None:
            sname = self.PrincipalName_create(name_type=NT_SRV_INST,
                                              names=[krbtgt_account, realm])

        expected_crealm = realm
        if expected_cname is None:
            expected_cname = cname
        expected_srealm = realm
        expected_sname = sname
        expected_salt = client_creds.get_salt()

        if till is None:
            till = self.get_KerberosTime(offset=36000)

        if etypes is None:
            etypes = client_as_etypes
        if kdc_options is None:
            kdc_options = krb5_asn1.KDCOptions('forwardable')
        if expected_error is not None:
            initial_error_mode = expected_error
        else:
            initial_error_mode = KDC_ERR_PREAUTH_REQUIRED

        rep, kdc_exchange_dict = self._test_as_exchange(
            cname,
            realm,
            sname,
            till,
            client_as_etypes,
            initial_error_mode,
            expected_crealm,
            expected_cname,
            expected_srealm,
            expected_sname,
            expected_salt,
            etypes,
            None,
            kdc_options,
            expected_supported_etypes=krbtgt_supported_etypes,
            expected_account_name=user_name,
            pac_request=True,
            expect_edata=expect_edata)

        if expected_error is not None:
            return None

        etype_info2 = kdc_exchange_dict['preauth_etype_info2']
        self.assertIsNotNone(etype_info2)

        preauth_key = self.PasswordKey_from_etype_info2(client_creds,
                                                        etype_info2[0],
                                                        kvno=client_kvno)

        (patime, pausec) = self.get_KerberosTimeWithUsec()
        pa_ts = self.PA_ENC_TS_ENC_create(patime, pausec)
        pa_ts = self.der_encode(pa_ts, asn1Spec=krb5_asn1.PA_ENC_TS_ENC())

        enc_pa_ts_usage = KU_PA_ENC_TIMESTAMP
        pa_ts = self.EncryptedData_create(preauth_key, enc_pa_ts_usage, pa_ts)
        pa_ts = self.der_encode(pa_ts, asn1Spec=krb5_asn1.EncryptedData())

        pa_ts = self.PA_DATA_create(PADATA_ENC_TIMESTAMP, pa_ts)

        preauth_padata = [pa_ts]
        preauth_error_mode = 0 # AS-REP
        if expected_pa_error is not None:
            preauth_error_mode = expected_pa_error

        krbtgt_decryption_key = (
            self.TicketDecryptionKey_from_creds(krbtgt_creds))

        as_rep, kdc_exchange_dict = self._test_as_exchange(
            cname,
            realm,
            sname,
            till,
            client_as_etypes,
            preauth_error_mode,
            expected_crealm,
            expected_cname,
            expected_srealm,
            expected_sname,
            expected_salt,
            etypes,
            preauth_padata,
            kdc_options,
            expected_supported_etypes=krbtgt_supported_etypes,
            expected_account_name=user_name,
            expect_edata=expect_pa_edata,
            preauth_key=preauth_key,
            ticket_decryption_key=krbtgt_decryption_key,
            pac_request=True)
        self.assertIsNotNone(as_rep)

        return etype_info2


@DynamicTestCase
class AsReqKerberosTests(AsReqBaseTest):

    @classmethod
    def setUpDynamicTestCases(cls):
        for (name, idx) in cls.etype_test_permutation_name_idx():
            for pac in [None, True, False]:
                tname = "%s_pac_%s" % (name, pac)
                targs = (idx, pac)
                cls.generate_dynamic_test("test_as_req_no_preauth", tname, *targs)

    def setUp(self):
        super(AsReqKerberosTests, self).setUp()
        self.do_asn1_print = global_asn1_print
        self.do_hexdump = global_hexdump

    def _test_as_req_nopreauth(self,
                               initial_etypes,
                               pac=None,
                               initial_kdc_options=None):
        client_creds = self.get_client_creds()
        client_account = client_creds.get_username()
        client_as_etypes = self.get_default_enctypes()
        krbtgt_creds = self.get_krbtgt_creds(require_keys=False)
        krbtgt_account = krbtgt_creds.get_username()
        realm = krbtgt_creds.get_realm()

        cname = self.PrincipalName_create(name_type=NT_PRINCIPAL,
                                          names=[client_account])
        sname = self.PrincipalName_create(name_type=NT_SRV_INST,
                                          names=[krbtgt_account, realm])

        expected_crealm = realm
        expected_cname = cname
        expected_srealm = realm
        expected_sname = sname
        expected_salt = client_creds.get_salt()

        if any(etype in client_as_etypes and etype in initial_etypes
               for etype in (kcrypto.Enctype.AES256,
                             kcrypto.Enctype.AES128,
                             kcrypto.Enctype.RC4)):
            expected_error_mode = KDC_ERR_PREAUTH_REQUIRED
        else:
            expected_error_mode = KDC_ERR_ETYPE_NOSUPP

        kdc_exchange_dict = self.as_exchange_dict(
            expected_crealm=expected_crealm,
            expected_cname=expected_cname,
            expected_srealm=expected_srealm,
            expected_sname=expected_sname,
            generate_padata_fn=None,
            check_error_fn=self.generic_check_kdc_error,
            check_rep_fn=None,
            expected_error_mode=expected_error_mode,
            client_as_etypes=client_as_etypes,
            expected_salt=expected_salt,
            kdc_options=str(initial_kdc_options),
            pac_request=pac)

        self._generic_kdc_exchange(kdc_exchange_dict,
                                   cname=cname,
                                   realm=realm,
                                   sname=sname,
                                   etypes=initial_etypes)

    def _test_as_req_no_preauth_with_args(self, etype_idx, pac):
        name, etypes = self.etype_test_permutation_by_idx(etype_idx)
        self._test_as_req_nopreauth(
                     pac=pac,
                     initial_etypes=etypes,
                     initial_kdc_options=krb5_asn1.KDCOptions('forwardable'))

    def test_as_req_enc_timestamp(self):
        client_creds = self.get_client_creds()
        self._run_as_req_enc_timestamp(client_creds)

    def test_as_req_enc_timestamp_mac(self):
        client_creds = self.get_mach_creds()
        self._run_as_req_enc_timestamp(client_creds)

    def test_as_req_enc_timestamp_rc4(self):
        client_creds = self.get_client_creds()
        self._run_as_req_enc_timestamp(
            client_creds,
            etypes={kcrypto.Enctype.RC4})

    def test_as_req_enc_timestamp_mac_rc4(self):
        client_creds = self.get_mach_creds()
        self._run_as_req_enc_timestamp(
            client_creds,
            etypes={kcrypto.Enctype.RC4})

    def test_as_req_enc_timestamp_rc4_dummy(self):
        client_creds = self.get_client_creds()
        self._run_as_req_enc_timestamp(
            client_creds,
            etypes={kcrypto.Enctype.RC4,
                    -1111})

    def test_as_req_enc_timestamp_mac_rc4_dummy(self):
        client_creds = self.get_mach_creds()
        self._run_as_req_enc_timestamp(
            client_creds,
            etypes={kcrypto.Enctype.RC4,
                    -1111})

    def test_as_req_enc_timestamp_aes128_rc4(self):
        client_creds = self.get_client_creds()
        self._run_as_req_enc_timestamp(
            client_creds,
            etypes={kcrypto.Enctype.AES128,
                    kcrypto.Enctype.RC4})

    def test_as_req_enc_timestamp_mac_aes128_rc4(self):
        client_creds = self.get_mach_creds()
        self._run_as_req_enc_timestamp(
            client_creds,
            etypes={kcrypto.Enctype.AES128,
                    kcrypto.Enctype.RC4})

    def test_as_req_enc_timestamp_spn(self):
        client_creds = self.get_mach_creds()
        spn = client_creds.get_spn()
        self._run_as_req_enc_timestamp(
            client_creds, client_account=spn,
            expected_error=KDC_ERR_C_PRINCIPAL_UNKNOWN,
            expect_edata=False)

    def test_as_req_enc_timestamp_spn_realm(self):
        samdb = self.get_samdb()
        realm = samdb.domain_dns_name().upper()

        client_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': f'host/{{account}}.{realm}@{realm}'})
        spn = client_creds.get_spn()
        self._run_as_req_enc_timestamp(
            client_creds, client_account=spn,
            expected_error=KDC_ERR_C_PRINCIPAL_UNKNOWN,
            expect_edata=False)

    def test_as_req_enc_timestamp_spn_upn(self):
        samdb = self.get_samdb()
        realm = samdb.domain_dns_name().upper()

        client_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': f'host/{{account}}.{realm}@{realm}',
                  'spn': f'host/{{account}}.{realm}'})
        spn = client_creds.get_spn()
        self._run_as_req_enc_timestamp(client_creds, client_account=spn)

    def test_as_req_enc_timestamp_spn_enterprise(self):
        client_creds = self.get_mach_creds()
        spn = client_creds.get_spn()
        self._run_as_req_enc_timestamp(
            client_creds, client_account=spn,
            name_type=NT_ENTERPRISE_PRINCIPAL,
            expected_error=KDC_ERR_C_PRINCIPAL_UNKNOWN,
            expect_edata=False)

    def test_as_req_enc_timestamp_spn_enterprise_realm(self):
        samdb = self.get_samdb()
        realm = samdb.domain_dns_name().upper()

        client_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': f'host/{{account}}.{realm}@{realm}'})
        spn = client_creds.get_spn()
        self._run_as_req_enc_timestamp(
            client_creds,
            name_type=NT_ENTERPRISE_PRINCIPAL,
            client_account=spn,
            expected_error=KDC_ERR_C_PRINCIPAL_UNKNOWN,
            expect_edata=False)

    def test_as_req_enc_timestamp_spn_upn_enterprise(self):
        samdb = self.get_samdb()
        realm = samdb.domain_dns_name().upper()

        client_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': f'host/{{account}}.{realm}@{realm}',
                  'spn': f'host/{{account}}.{realm}'})
        spn = client_creds.get_spn()
        self._run_as_req_enc_timestamp(
            client_creds,
            name_type=NT_ENTERPRISE_PRINCIPAL,
            client_account=spn,
            expected_error=KDC_ERR_C_PRINCIPAL_UNKNOWN,
            expect_edata=False)

    def test_as_req_enterprise_canon(self):
        upn = self.get_new_username()
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={'upn': upn})

        user_name = client_creds.get_username()
        realm = client_creds.get_realm()
        client_account = f'{user_name}@{realm}'

        expected_cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[user_name])

        self._run_as_req_enc_timestamp(
            client_creds,
            client_account=client_account,
            expected_cname=expected_cname,
            name_type=NT_ENTERPRISE_PRINCIPAL,
            kdc_options=krb5_asn1.KDCOptions('canonicalize'))

    def test_as_req_enterprise_canon_case(self):
        upn = self.get_new_username()
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={'upn': upn})

        user_name = client_creds.get_username()
        realm = client_creds.get_realm().lower()
        client_account = f'{user_name}@{realm}'

        expected_cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[user_name])

        self._run_as_req_enc_timestamp(
            client_creds,
            client_account=client_account,
            expected_cname=expected_cname,
            name_type=NT_ENTERPRISE_PRINCIPAL,
            kdc_options=krb5_asn1.KDCOptions('canonicalize'))

    def test_as_req_enterprise_canon_mac(self):
        upn = self.get_new_username()
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': upn})

        user_name = client_creds.get_username()
        realm = client_creds.get_realm()
        client_account = f'{user_name}@{realm}'

        expected_cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[user_name])

        self._run_as_req_enc_timestamp(
            client_creds,
            client_account=client_account,
            expected_cname=expected_cname,
            name_type=NT_ENTERPRISE_PRINCIPAL,
            kdc_options=krb5_asn1.KDCOptions('canonicalize'))

    def test_as_req_enterprise_canon_mac_case(self):
        upn = self.get_new_username()
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': upn})

        user_name = client_creds.get_username()
        realm = client_creds.get_realm().lower()
        client_account = f'{user_name}@{realm}'

        expected_cname = self.PrincipalName_create(
            name_type=NT_PRINCIPAL,
            names=[user_name])

        self._run_as_req_enc_timestamp(
            client_creds,
            client_account=client_account,
            expected_cname=expected_cname,
            name_type=NT_ENTERPRISE_PRINCIPAL,
            kdc_options=krb5_asn1.KDCOptions('canonicalize'))

    def test_as_req_enterprise_no_canon(self):
        upn = self.get_new_username()
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={'upn': upn})

        user_name = client_creds.get_username()
        realm = client_creds.get_realm()
        client_account = f'{user_name}@{realm}'

        self._run_as_req_enc_timestamp(
            client_creds,
            client_account=client_account,
            name_type=NT_ENTERPRISE_PRINCIPAL,
            kdc_options=0)

    def test_as_req_enterprise_no_canon_case(self):
        upn = self.get_new_username()
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.USER,
            opts={'upn': upn})

        user_name = client_creds.get_username()
        realm = client_creds.get_realm().lower()
        client_account = f'{user_name}@{realm}'

        self._run_as_req_enc_timestamp(
            client_creds,
            client_account=client_account,
            name_type=NT_ENTERPRISE_PRINCIPAL,
            kdc_options=0)

    def test_as_req_enterprise_no_canon_mac(self):
        upn = self.get_new_username()
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': upn})

        user_name = client_creds.get_username()
        realm = client_creds.get_realm()
        client_account = f'{user_name}@{realm}'

        self._run_as_req_enc_timestamp(
            client_creds,
            client_account=client_account,
            name_type=NT_ENTERPRISE_PRINCIPAL,
            kdc_options=0)

    def test_as_req_enterprise_no_canon_mac_case(self):
        upn = self.get_new_username()
        client_creds = self.get_cached_creds(
            account_type=self.AccountType.COMPUTER,
            opts={'upn': upn})

        user_name = client_creds.get_username()
        realm = client_creds.get_realm().lower()
        client_account = f'{user_name}@{realm}'

        self._run_as_req_enc_timestamp(
            client_creds,
            client_account=client_account,
            name_type=NT_ENTERPRISE_PRINCIPAL,
            kdc_options=0)

    # Ensure we can't use truncated well-known principals such as krb@REALM
    # instead of krbtgt@REALM.
    def test_krbtgt_wrong_principal(self):
        client_creds = self.get_client_creds()

        krbtgt_creds = self.get_krbtgt_creds()

        krbtgt_account = krbtgt_creds.get_username()
        realm = krbtgt_creds.get_realm()

        # Truncate the name of the krbtgt principal.
        krbtgt_account = krbtgt_account[:3]

        wrong_krbtgt_princ = self.PrincipalName_create(
            name_type=NT_SRV_INST,
            names=[krbtgt_account, realm])

        if self.strict_checking:
            self._run_as_req_enc_timestamp(
                client_creds,
                sname=wrong_krbtgt_princ,
                expected_pa_error=KDC_ERR_S_PRINCIPAL_UNKNOWN,
                expect_pa_edata=False)
        else:
            self._run_as_req_enc_timestamp(
                client_creds,
                sname=wrong_krbtgt_princ,
                expected_error=KDC_ERR_S_PRINCIPAL_UNKNOWN)

    # Test that we can make a request for a ticket expiring post-2038.
    def test_future_till(self):
        client_creds = self.get_client_creds()

        self._run_as_req_enc_timestamp(
            client_creds,
            till='99990913024805Z')


if __name__ == "__main__":
    global_asn1_print = False
    global_hexdump = False
    import unittest
    unittest.main()


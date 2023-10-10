#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This is unit with tests for LDAP access checks

import optparse
import sys
import base64
import re
sys.path.insert(0, "bin/python")
import samba

from samba.tests import DynamicTestCase
from samba.tests.subunitrun import SubunitOptions, TestProgram
from samba.common import get_string

import samba.getopt as options
from samba.join import DCJoinContext

from ldb import (
    SCOPE_BASE, SCOPE_ONELEVEL, SCOPE_SUBTREE, LdbError, ERR_NO_SUCH_OBJECT,
    ERR_UNWILLING_TO_PERFORM, ERR_INSUFFICIENT_ACCESS_RIGHTS)
from ldb import ERR_CONSTRAINT_VIOLATION
from ldb import ERR_OPERATIONS_ERROR
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_REPLACE, FLAG_MOD_ADD, FLAG_MOD_DELETE
from samba.dcerpc import security, drsuapi, misc

from samba.auth import system_session
from samba import gensec, sd_utils, werror
from samba.samdb import SamDB
from samba.credentials import Credentials, DONT_USE_KERBEROS
import samba.tests
from samba.tests import delete_force
import samba.dsdb
from samba.tests.password_test import PasswordCommon
from samba.ndr import ndr_pack

parser = optparse.OptionParser("acl.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
subunitopts = SubunitOptions(parser)
parser.add_option_group(subunitopts)

opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]
if "://" not in host:
    ldaphost = "ldap://%s" % host
else:
    ldaphost = host
    start = host.rindex("://")
    host = host.lstrip(start + 3)

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)
creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)

#
# Tests start here
#


class AclTests(samba.tests.TestCase):

    def setUp(self):
        super(AclTests, self).setUp()

        strict_checking = samba.tests.env_get_var_value('STRICT_CHECKING', allow_missing=True)
        if strict_checking is None:
            strict_checking = '1'
        self.strict_checking = bool(int(strict_checking))

        self.ldb_admin = SamDB(ldaphost, credentials=creds, session_info=system_session(lp), lp=lp)
        self.base_dn = self.ldb_admin.domain_dn()
        self.domain_sid = security.dom_sid(self.ldb_admin.get_domain_sid())
        self.user_pass = "samba123@"
        self.configuration_dn = self.ldb_admin.get_config_basedn().get_linearized()
        self.sd_utils = sd_utils.SDUtils(self.ldb_admin)
        self.addCleanup(self.delete_admin_connection)
        # used for anonymous login
        self.creds_tmp = Credentials()
        self.creds_tmp.set_username("")
        self.creds_tmp.set_password("")
        self.creds_tmp.set_domain(creds.get_domain())
        self.creds_tmp.set_realm(creds.get_realm())
        self.creds_tmp.set_workstation(creds.get_workstation())
        print("baseDN: %s" % self.base_dn)

        # set AttributeAuthorizationOnLDAPAdd and BlockOwnerImplicitRights
        self.set_heuristic(samba.dsdb.DS_HR_ATTR_AUTHZ_ON_LDAP_ADD, b'11')

    def set_heuristic(self, index, values):
        self.assertGreater(index, 0)
        self.assertLess(index, 30)
        self.assertIsInstance(values, bytes)

        # Get the old "dSHeuristics" if it was set
        dsheuristics = self.ldb_admin.get_dsheuristics()
        # Reset the "dSHeuristics" as they were before
        self.addCleanup(self.ldb_admin.set_dsheuristics, dsheuristics)
        # Set the "dSHeuristics" to activate the correct behaviour
        default_heuristics = b"000000000100000000020000000003"
        if dsheuristics is None:
            dsheuristics = b""
        dsheuristics += default_heuristics[len(dsheuristics):]
        dsheuristics = (dsheuristics[:index - 1] +
                        values +
                        dsheuristics[index - 1 + len(values):])
        self.ldb_admin.set_dsheuristics(dsheuristics)

    def get_user_dn(self, name):
        return "CN=%s,CN=Users,%s" % (name, self.base_dn)

    def get_ldb_connection(self, target_username, target_password):
        creds_tmp = Credentials()
        creds_tmp.set_username(target_username)
        creds_tmp.set_password(target_password)
        creds_tmp.set_domain(creds.get_domain())
        creds_tmp.set_realm(creds.get_realm())
        creds_tmp.set_workstation(creds.get_workstation())
        creds_tmp.set_gensec_features(creds_tmp.get_gensec_features()
                                      | gensec.FEATURE_SEAL)
        creds_tmp.set_kerberos_state(DONT_USE_KERBEROS)  # kinit is too expensive to use in a tight loop
        ldb_target = SamDB(url=ldaphost, credentials=creds_tmp, lp=lp)
        return ldb_target

    # Test if we have any additional groups for users than default ones
    def assert_user_no_group_member(self, username):
        res = self.ldb_admin.search(self.base_dn, expression="(distinguishedName=%s)" % self.get_user_dn(username))
        try:
            self.assertEqual(res[0]["memberOf"][0], "")
        except KeyError:
            pass
        else:
            self.fail()

    def delete_admin_connection(self):
        del self.sd_utils
        del self.ldb_admin

# tests on ldap add operations


class AclAddTests(AclTests):

    def setUp(self):
        super(AclAddTests, self).setUp()
        # Domain admin that will be creator of OU parent-child structure
        self.usr_admin_owner = "acl_add_user1"
        # Second domain admin that will not be creator of OU parent-child structure
        self.usr_admin_not_owner = "acl_add_user2"
        # Regular user
        self.regular_user = "acl_add_user3"
        self.regular_user2 = "acl_add_user4"
        self.regular_user3 = "acl_add_user5"
        self.test_user1 = "test_add_user1"
        self.test_user2 = "test_add_user2"
        self.test_user3 = "test_add_user3"
        self.test_user4 = "test_add_user4"
        self.test_group1 = "test_add_group1"
        self.ou1 = "OU=test_add_ou1"
        self.ou2 = "OU=test_add_ou2,%s" % self.ou1
        delete_force(self.ldb_admin, self.get_user_dn(self.usr_admin_owner))
        delete_force(self.ldb_admin, self.get_user_dn(self.usr_admin_not_owner))
        delete_force(self.ldb_admin, self.get_user_dn(self.regular_user))
        delete_force(self.ldb_admin, self.get_user_dn(self.regular_user2))
        self.ldb_admin.newuser(self.usr_admin_owner, self.user_pass)
        self.ldb_admin.newuser(self.usr_admin_not_owner, self.user_pass)
        self.ldb_admin.newuser(self.regular_user, self.user_pass)
        self.ldb_admin.newuser(self.regular_user2, self.user_pass)

        # add admins to the Domain Admins group
        self.ldb_admin.add_remove_group_members("Domain Admins", [self.usr_admin_owner],
                                                add_members_operation=True)
        self.ldb_admin.add_remove_group_members("Domain Admins", [self.usr_admin_not_owner],
                                                add_members_operation=True)

        self.ldb_owner = self.get_ldb_connection(self.usr_admin_owner, self.user_pass)
        self.ldb_notowner = self.get_ldb_connection(self.usr_admin_not_owner, self.user_pass)
        self.ldb_user = self.get_ldb_connection(self.regular_user, self.user_pass)
        self.ldb_user2 = self.get_ldb_connection(self.regular_user2, self.user_pass)

    def tearDown(self):
        super(AclAddTests, self).tearDown()
        delete_force(self.ldb_admin, "CN=%s,%s,%s" %
                     (self.test_user1, self.ou2, self.base_dn))
        delete_force(self.ldb_admin, "CN=%s,%s,%s" %
                     (self.test_user1, self.ou1, self.base_dn))
        delete_force(self.ldb_admin, "CN=%s,%s,%s" %
                     (self.test_user2, self.ou1, self.base_dn))
        delete_force(self.ldb_admin, "CN=%s,%s,%s" %
                     (self.test_user3, self.ou1, self.base_dn))
        delete_force(self.ldb_admin, "CN=%s,%s,%s" %
                     (self.test_user4, self.ou1, self.base_dn))
        delete_force(self.ldb_admin, "CN=%s,%s,%s" %
                     (self.test_group1, self.ou2, self.base_dn))
        delete_force(self.ldb_admin, "CN=test_computer2,%s,%s" %
                     (self.ou1, self.base_dn))
        delete_force(self.ldb_admin, "CN=test_computer1,%s,%s" %
                     (self.ou1, self.base_dn))
        delete_force(self.ldb_admin, "%s,%s" % (self.ou2, self.base_dn))
        delete_force(self.ldb_admin, "%s,%s" % (self.ou1, self.base_dn))
        delete_force(self.ldb_admin, self.get_user_dn(self.usr_admin_owner))
        delete_force(self.ldb_admin, self.get_user_dn(self.usr_admin_not_owner))
        delete_force(self.ldb_admin, self.get_user_dn(self.regular_user))
        delete_force(self.ldb_admin, self.get_user_dn(self.regular_user2))
        delete_force(self.ldb_admin, self.get_user_dn("test_add_anonymous"))

        del self.ldb_notowner
        del self.ldb_owner
        del self.ldb_user
        del self.ldb_user2

    # Make sure top OU is deleted (and so everything under it)
    def assert_top_ou_deleted(self):
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s,%s)" % (
                                        "OU=test_add_ou1", self.base_dn))
        self.assertEqual(len(res), 0)

    def test_add_u1(self):
        """Testing OU with the rights of Domain Admin not creator of the OU """
        self.assert_top_ou_deleted()
        # Change descriptor for top level OU
        self.ldb_owner.create_ou("OU=test_add_ou1," + self.base_dn)
        self.ldb_owner.create_ou("OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        user_sid = self.sd_utils.get_object_sid(self.get_user_dn(self.usr_admin_not_owner))
        mod = "(D;CI;WPCC;;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        # Test user and group creation with another domain admin's credentials
        self.ldb_notowner.newuser(self.test_user1, self.user_pass, userou=self.ou2)
        self.ldb_notowner.newgroup("test_add_group1", groupou="OU=test_add_ou2,OU=test_add_ou1",
                                   grouptype=samba.dsdb.GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP)
        # Make sure we HAVE created the two objects -- user and group
        # !!! We should not be able to do that, but however because of ACE ordering our inherited Deny ACE
        # !!! comes after explicit (A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA) that comes from somewhere
        res = self.ldb_admin.search(self.base_dn, expression="(distinguishedName=%s,%s)" % ("CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1", self.base_dn))
        self.assertGreater(len(res), 0)
        res = self.ldb_admin.search(self.base_dn, expression="(distinguishedName=%s,%s)" % ("CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1", self.base_dn))
        self.assertGreater(len(res), 0)

    def test_add_u2(self):
        """Testing OU with the regular user that has no rights granted over the OU """
        self.assert_top_ou_deleted()
        # Create a parent-child OU structure with domain admin credentials
        self.ldb_owner.create_ou("OU=test_add_ou1," + self.base_dn)
        self.ldb_owner.create_ou("OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        # Test user and group creation with regular user credentials
        try:
            self.ldb_user.newuser(self.test_user1, self.user_pass, userou=self.ou2)
            self.ldb_user.newgroup("test_add_group1", groupou="OU=test_add_ou2,OU=test_add_ou1",
                                   grouptype=samba.dsdb.GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP)
        except LdbError as e:
            (num, _) = e.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()
        # Make sure we HAVEN'T created any of two objects -- user or group
        res = self.ldb_admin.search(self.base_dn, expression="(distinguishedName=%s,%s)" % ("CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1", self.base_dn))
        self.assertEqual(len(res), 0)
        res = self.ldb_admin.search(self.base_dn, expression="(distinguishedName=%s,%s)" % ("CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1", self.base_dn))
        self.assertEqual(len(res), 0)

    def test_add_u3(self):
        """Testing OU with the rights of regular user granted the right 'Create User child objects' """
        self.assert_top_ou_deleted()
        # Change descriptor for top level OU
        self.ldb_owner.create_ou("OU=test_add_ou1," + self.base_dn)
        user_sid = self.sd_utils.get_object_sid(self.get_user_dn(self.regular_user))
        mod = "(OA;CI;CC;bf967aba-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        self.ldb_owner.create_ou("OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        # Test user and group creation with granted user only to one of the objects
        self.ldb_user.newuser(self.test_user1, self.user_pass, userou=self.ou2, setpassword=False)
        try:
            self.ldb_user.newgroup("test_add_group1", groupou="OU=test_add_ou2,OU=test_add_ou1",
                                   grouptype=samba.dsdb.GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP)
        except LdbError as e1:
            (num, _) = e1.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()
        # Make sure we HAVE created the one of two objects -- user
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s,%s)" %
                                    ("CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1",
                                     self.base_dn))
        self.assertNotEqual(len(res), 0)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s,%s)" %
                                    ("CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1",
                                     self.base_dn))
        self.assertEqual(len(res), 0)

    def test_add_u4(self):
        """ 4 Testing OU with the rights of Domain Admin creator of the OU"""
        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou("OU=test_add_ou1," + self.base_dn)
        self.ldb_owner.create_ou("OU=test_add_ou2,OU=test_add_ou1," + self.base_dn)
        self.ldb_owner.newuser(self.test_user1, self.user_pass, userou=self.ou2)
        self.ldb_owner.newgroup("test_add_group1", groupou="OU=test_add_ou2,OU=test_add_ou1",
                                grouptype=samba.dsdb.GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP)
        # Make sure we have successfully created the two objects -- user and group
        res = self.ldb_admin.search(self.base_dn, expression="(distinguishedName=%s,%s)" % ("CN=test_add_user1,OU=test_add_ou2,OU=test_add_ou1", self.base_dn))
        self.assertGreater(len(res), 0)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s,%s)" % ("CN=test_add_group1,OU=test_add_ou2,OU=test_add_ou1", self.base_dn))
        self.assertGreater(len(res), 0)

    def test_add_c1(self):
        """Testing adding a computer object with the rights of regular user granted the right 'Create Computer child objects' """
        self.assert_top_ou_deleted()
        # Change descriptor for top level OU
        self.ldb_owner.create_ou("OU=test_add_ou1," + self.base_dn)
        user_sid = self.sd_utils.get_object_sid(self.get_user_dn(self.regular_user))
        mod = f"(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})"
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        mod = f"(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_SERVICE_PRINCIPAL_NAME};;{user_sid})"
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)

        # Add a computer object, specifying an explicit SD to grant WP to the creator
        print("Test adding a user with explicit nTSecurityDescriptor")
        wp_ace = "(A;;WP;;;%s)" % str(user_sid)
        tmp_desc = security.descriptor.from_sddl("D:%s" % wp_ace, self.domain_sid)
        dn = "CN=%s,OU=test_add_ou1,%s" % (self.test_user1, self.base_dn)
        samaccountname = self.test_user1 + "$"
        # This should fail, the user has no WD or WO
        try:
            self.ldb_user.add({
                "dn": dn,
                "objectclass": "computer",
                "sAMAccountName": samaccountname,
                "userAccountControl": str(samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT),
                "servicePrincipalName": "host/" + self.test_user1,
                "nTSecurityDescriptor": ndr_pack(tmp_desc)})
        except LdbError as e3:
            (num, _) = e3.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()

    def test_add_c2(self):
        """Testing adding a computer object with the rights of regular user granted the right 'Create User child objects' and WO"""
        self.assert_top_ou_deleted()
        # Change descriptor for top level OU
        self.ldb_owner.create_ou("OU=test_add_ou1," + self.base_dn)
        user_sid = self.sd_utils.get_object_sid(self.get_user_dn(self.regular_user))
        mod = f"(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})"
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        mod = f"(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_SERVICE_PRINCIPAL_NAME};;{user_sid})"
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        # Grant WO, we should still not be able to specify a DACL
        mod = "(A;CI;WO;;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        # Add a computer object, specifying an explicit SD to grant WP to the creator
        print("Test adding a user with explicit nTSecurityDescriptor")
        wp_ace = "(A;;WP;;;%s)" % str(user_sid)
        tmp_desc = security.descriptor.from_sddl("D:%s" % wp_ace, self.domain_sid)
        dn = "CN=%s,OU=test_add_ou1,%s" % (self.test_user1, self.base_dn)
        samaccountname = self.test_user1 + "$"
        # This should fail, the user has no WD
        try:
            self.ldb_user.add({
                "dn": dn,
                "objectclass": "computer",
                "sAMAccountName": samaccountname,
                "userAccountControl": str(samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT),
                "servicePrincipalName": "host/" + self.test_user1,
                "nTSecurityDescriptor": ndr_pack(tmp_desc)})
        except LdbError as e3:
            (num, _) = e3.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()

        # We still cannot modify the owner or group
        sd_sddl = f"O:{user_sid}G:{user_sid}"
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        try:
            self.ldb_user.add({
                "dn": dn,
                "objectclass": "computer",
                "sAMAccountName": samaccountname,
                "userAccountControl": str(samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT),
                "servicePrincipalName": "host/" + self.test_user1,
                "nTSecurityDescriptor": ndr_pack(tmp_desc)})
        except LdbError as e3:
            (num, _) = e3.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()

    def test_add_c3(self):
        """Testing adding a computer object with the rights of regular user granted the right 'Create Computer child objects' and WD"""
        self.assert_top_ou_deleted()
        # Change descriptor for top level OU
        self.ldb_owner.create_ou("OU=test_add_ou1," + self.base_dn)
        user_sid = self.sd_utils.get_object_sid(self.get_user_dn(self.regular_user))
        mod = f"(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})"
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        mod = f"(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_SERVICE_PRINCIPAL_NAME};;{user_sid})"
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        # Grant WD, we should still not be able to specify a DACL
        mod = "(A;CI;WD;;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        # Add a computer object, specifying an explicit SD to grant WP to the creator
        print("Test adding a user with explicit nTSecurityDescriptor")
        wp_ace = "(A;;WP;;;%s)" % str(user_sid)
        sd_sddl = f"O:{user_sid}G:BA"
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        dn = "CN=%s,OU=test_add_ou1,%s" % (self.test_user1, self.base_dn)
        samaccountname = self.test_user1 + "$"
        # The user has no WO, but this succeeds, because WD means we skip further per-attribute checks
        try:
            self.ldb_user.add({
                "dn": dn,
                "objectclass": "computer",
                "sAMAccountName": samaccountname,
                "userAccountControl": str(samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT),
                "servicePrincipalName": "host/" + self.test_user1,
                "nTSecurityDescriptor": ndr_pack(tmp_desc)})
        except LdbError as e3:
            self.fail(str(e3))

        # we should be able to modify the DACL
        tmp_desc = security.descriptor.from_sddl("D:%s" % wp_ace, self.domain_sid)
        dn = "CN=%s,OU=test_add_ou1,%s" % (self.test_user2, self.base_dn)
        samaccountname = self.test_user2 + "$"
        try:
            self.ldb_user.add({
                "dn": dn,
                "objectclass": "computer",
                "sAMAccountName": samaccountname,
                "userAccountControl": str(samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT),
                "servicePrincipalName": "host/" + self.test_user2,
                "nTSecurityDescriptor": ndr_pack(tmp_desc)})
        except LdbError as e3:
            self.fail(str(e3))

        # verify the ace is present
        new_sd = self.sd_utils.get_sd_as_sddl("CN=test_add_user2,OU=test_add_ou1,%s" %
                                              self.base_dn)
        self.assertIn(wp_ace, new_sd)

    def test_add_c4(self):
        """Testing adding a computer object with the rights of regular user granted the right 'Create User child objects' and WDWO"""
        self.assert_top_ou_deleted()
        # Change descriptor for top level OU
        self.ldb_owner.create_ou("OU=test_add_ou1," + self.base_dn)
        user_sid = self.sd_utils.get_object_sid(self.get_user_dn(self.regular_user))
        mod = f"(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})"
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        mod = f"(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_SERVICE_PRINCIPAL_NAME};;{user_sid})"
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        # Grant WD and WO, we should be able to update the SD
        mod = "(A;CI;WDWO;;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        # Add a computer object, specifying an explicit SD to grant WP to the creator
        print("Test adding a user with explicit nTSecurityDescriptor")
        wp_ace = "(A;;WP;;;%s)" % str(user_sid)
        sd_sddl = "O:%sG:BAD:(A;;WP;;;%s)" % (str(user_sid), str(user_sid))
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        dn = "CN=%s,OU=test_add_ou1,%s" % (self.test_user1, self.base_dn)
        samaccountname = self.test_user1 + "$"
        try:
            self.ldb_user.add({
                "dn": dn,
                "objectclass": "computer",
                "sAMAccountName": samaccountname,
                "userAccountControl": str(samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT),
                "servicePrincipalName": "host/" + self.test_user1,
                "nTSecurityDescriptor": ndr_pack(tmp_desc)})
        except LdbError as e3:
            self.fail(str(e3))

        # verify the owner and group is present
        new_sd = self.sd_utils.get_sd_as_sddl("CN=test_add_user1,OU=test_add_ou1,%s" %
                                              self.base_dn)
        self.assertIn(f"O:{user_sid}G:BA", new_sd)
        self.assertIn(wp_ace, new_sd)

    def test_add_c5(self):
        """Testing adding a computer with an optional attribute """
        self.assert_top_ou_deleted()
        # Change descriptor for top level OU
        self.ldb_owner.create_ou("OU=test_add_ou1," + self.base_dn)
        user_sid = self.sd_utils.get_object_sid(self.get_user_dn(self.regular_user))
        mod = f"(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})"
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        # servicePrincipalName
        mod = f"(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_SERVICE_PRINCIPAL_NAME};;{user_sid})"
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        dn = "CN=%s,OU=test_add_ou1,%s" % (self.test_user3, self.base_dn)
        samaccountname = self.test_user3 + "$"
        try:
            self.ldb_user.add({
                "dn": dn,
                "objectclass": "computer",
                "sAMAccountName": samaccountname,
                "userAccountControl": str(samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT),
                "servicePrincipalName": "host/" + self.test_user3,
                "department": "Ministry of Silly Walks"})
        except LdbError as e3:
            (num, _) = e3.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()

        # grant WP for that attribute and try again
        mod = f"(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_DEPARTMENT};;{user_sid})"
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        try:
            self.ldb_user.add({
                "dn": dn,
                "objectclass": "computer",
                "sAMAccountName": samaccountname,
                "userAccountControl": str(samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT),
                "servicePrincipalName": "host/" + self.test_user3,
                "department": "Ministry of Silly Walks"})
        except LdbError as e3:
            self.fail(str(e3))

    def test_add_c6(self):
        """Test creating a computer with a mandatory attribute(sAMAccountName)"""
        self.ldb_owner.create_ou("OU=test_add_ou1," + self.base_dn)
        user_sid = self.sd_utils.get_object_sid(self.get_user_dn(self.regular_user))
        mod = f"(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})"
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        # servicePrincipalName
        mod = f"(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_SERVICE_PRINCIPAL_NAME};;{user_sid})"
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        # userAccountControl
        mod = f"(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_USER_ACCOUNT_CONTROL};;{user_sid})"
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        dn = "CN=%s,OU=test_add_ou1,%s" % (self.test_user4, self.base_dn)
        samaccountname = self.test_user4 + "$"
        try:
            self.ldb_user.add({
                "dn": dn,
                "objectclass": "computer",
                "sAMAccountName": samaccountname,
                "userAccountControl": str(samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT),
                "servicePrincipalName": "host/" + self.test_user4})
        except LdbError as e3:
            self.fail(str(e3))

    def test_add_computer1(self):
        """Testing Computer with the rights of regular user granted the right 'Create Computer child objects' """
        self.assert_top_ou_deleted()
        # Change descriptor for top level OU
        self.ldb_owner.create_ou("OU=test_add_ou1," + self.base_dn)
        user_sid = self.sd_utils.get_object_sid(self.get_user_dn(self.regular_user))
        mod = f"(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})"
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        mod = f"(OA;CI;SW;{samba.dsdb.DS_GUID_SCHEMA_ATTR_SERVICE_PRINCIPAL_NAME};;CO)"
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)

        # add a Computer object with servicePrincipalName
        # Creator-Owner has SW from the default SD
        dn = "CN=test_computer1,OU=test_add_ou1,%s" % (self.base_dn)
        samaccountname = "test_computer1$"
        try:
            self.ldb_user.add({
                "dn": dn,
                "objectclass": "computer",
                "sAMAccountName": samaccountname,
                "userAccountControl": str(samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT),
                "servicePrincipalName": "nosuchservice/abcd/abcd"})
        except LdbError as e3:
            (num, _) = e3.args
            if self.strict_checking:
                self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
            else:
                self.assertIn(num, (ERR_INSUFFICIENT_ACCESS_RIGHTS,
                                    ERR_CONSTRAINT_VIOLATION))
        else:
            self.fail()

        # Inherited Deny from the parent will not work, because of ordering rules
        mod = f"(OD;CI;SW;{samba.dsdb.DS_GUID_SCHEMA_ATTR_SERVICE_PRINCIPAL_NAME};;{user_sid})"
        self.sd_utils.dacl_add_ace("OU=test_add_ou1," + self.base_dn, mod)
        try:
            self.ldb_user.add({
                "dn": dn,
                "objectclass": "computer",
                "sAMAccountName": samaccountname,
                "userAccountControl": str(samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT),
                "servicePrincipalName": "nosuchservice/abcd/abcd"})
        except LdbError as e3:
            (num, _) = e3.args
            if self.strict_checking:
                self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
            else:
                self.assertIn(num, (ERR_INSUFFICIENT_ACCESS_RIGHTS,
                                    ERR_CONSTRAINT_VIOLATION))
        else:
            self.fail()

    def test_add_optional_attr(self):
        '''Show that adding a computer object with an optional attribute is disallowed'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'msSFU30Name': 'foo',
            })
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
            if self.strict_checking:
                self.assertIn('000021CC', estr)
        else:
            self.fail('expected to fail')

    def test_add_domain_admins(self):
        '''Show that adding a computer object with an optional attribute is allowed if the user is a Domain Administrator'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.ldb_admin.add_remove_group_members('Domain Admins',
                                                [self.regular_user],
                                                add_members_operation=True)
        ldb_domain_admin = self.get_ldb_connection(self.regular_user,
                                                   self.user_pass)

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        try:
            ldb_domain_admin.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'msSFU30Name': 'foo',
            })
        except LdbError as err:
            self.fail(err)

    def test_add_enterprise_admins(self):
        '''Show that adding a computer object with an optional attribute is allowed if the user is an Enterprise Administrator'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.ldb_admin.add_remove_group_members('Enterprise Admins',
                                                [self.regular_user],
                                                add_members_operation=True)
        ldb_enterprise_admin = self.get_ldb_connection(self.regular_user,
                                                       self.user_pass)

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        try:
            ldb_enterprise_admin.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'msSFU30Name': 'foo',
            })
        except LdbError as err:
            self.fail(err)

    def test_add_non_computer(self):
        '''Show that adding a non-computer object with an optional attribute is allowed'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_USER};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = self.test_user1
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'user',
                'sAMAccountName': account_name,
                'msSFU30Name': 'foo',
            })
        except LdbError as err:
            self.fail(err)

    def test_add_derived_computer(self):
        '''Show that adding an object derived from computer with an optional attribute is disallowed'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_MANAGED_SERVICE_ACCOUNT};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'msDS-ManagedServiceAccount',
                'sAMAccountName': account_name,
                'msSFU30Name': 'foo',
            })
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
            if self.strict_checking:
                self.assertIn('000021CC', estr)
        else:
            self.fail('expected to fail')

    def test_add_write_dac(self):
        '''Show that adding a computer object with an optional attribute is allowed if the security descriptor gives WRITE_DAC access'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(A;CI;WD;;;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'msSFU30Name': 'foo',
            })
        except LdbError as err:
            self.fail(err)

    def test_add_system_must_contain(self):
        '''Show that adding a computer object with only systemMustContain attributes is allowed'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'instanceType': '4',
            })
        except LdbError as err:
            self.fail(err)

    def test_add_system_must_contain_denied(self):
        '''Show that adding a computer object with only systemMustContain attributes is allowed, even when explicitly denied'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(D;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_INSTANCE_TYPE};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'instanceType': '4',
            })
        except LdbError as err:
            self.fail(err)

    def test_add_unicode_pwd(self):
        '''Show that adding a computer object with a unicodePwd is allowed'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        password = 'Secret007'
        utf16pw = f'"{password}"'.encode('utf-16-le')
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'unicodePwd': utf16pw,
            })
        except LdbError as err:
            self.fail(err)

    def test_add_user_password(self):
        '''Show that adding a computer object with a userPassword is allowed'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        password = 'Secret007'
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'userPassword': password,
            })
        except LdbError as err:
            self.fail(err)

    def test_add_user_password_denied(self):
        '''Show that adding a computer object with a userPassword is allowed, even when explicitly denied'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(D;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_USER_PASSWORD};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        password = 'Secret007'
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'userPassword': password,
            })
        except LdbError as err:
            self.fail(err)

    def test_add_clear_text_password(self):
        '''Show that adding a computer object with a clearTextPassword is allowed

Note: this does not work on Windows.'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        password = 'Secret007'.encode('utf-16-le')
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'clearTextPassword': password,
            })
        except LdbError as err:
            self.fail(err)

    def test_add_disallowed_attr(self):
        '''Show that adding a computer object with a denied attribute is disallowed'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(D;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_MS_SFU_30};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'msSFU30Name': 'foo',
            })
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
            if self.strict_checking:
                self.assertIn('000021CC', estr)
        else:
            self.fail('expected to fail')

    def test_add_allowed_attr(self):
        '''Show that adding a computer object with an allowed attribute is allowed'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_MS_SFU_30};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'msSFU30Name': 'foo',
            })
        except LdbError as err:
            self.fail(err)

    def test_add_optional_attr_heuristic_0(self):
        '''Show that adding a computer object with an optional attribute is allowed when AttributeAuthorizationOnLDAPAdd == 0'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_ATTR_AUTHZ_ON_LDAP_ADD, b'0')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'msSFU30Name': 'foo',
            })
        except LdbError as err:
            self.fail(err)

    def test_add_optional_attr_heuristic_2(self):
        '''Show that adding a computer object with an optional attribute is allowed when AttributeAuthorizationOnLDAPAdd == 2'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_ATTR_AUTHZ_ON_LDAP_ADD, b'2')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'msSFU30Name': 'foo',
            })
        except LdbError as err:
            self.fail(err)

    def test_add_security_descriptor_implicit_right(self):
        '''Show that adding a computer object with a security descriptor is allowed when BlockOwnerImplicitRights != 1'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'0')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        sd_sddl = f'O:{user_sid}G:{user_sid}'
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'ntSecurityDescriptor': ndr_pack(tmp_desc),
            })
        except LdbError as err:
            self.fail(err)

    def test_add_security_descriptor_implicit_right_optional_attr(self):
        '''Show that adding a computer object with a security descriptor and an optional attribute is disallowed when BlockOwnerImplicitRights != 1'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'0')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        sd_sddl = f'O:{user_sid}G:{user_sid}'
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'msSFU30Name': 'foo',
                'ntSecurityDescriptor': ndr_pack(tmp_desc),
            })
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
            if self.strict_checking:
                self.assertIn('000021CC', estr)
        else:
            self.fail('expected to fail')

    def test_add_security_descriptor_explicit_right(self):
        '''Show that a computer object with a security descriptor can be added if BlockOwnerImplicitRights == 1 and WRITE_DAC is granted'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'1')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(A;CI;WD;;;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        sd_sddl = (f'O:{user_sid}G:{user_sid}'
                   f'D:(A;;WP;;;{user_sid})')
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'ntSecurityDescriptor': ndr_pack(tmp_desc),
            })
        except LdbError as err:
            self.fail(err)

    def test_add_security_descriptor_explicit_right_no_owner_disallow(self):
        '''Show that a computer object with a security descriptor can be added if BlockOwnerImplicitRights == 1, WRITE_DAC is granted, and WRITE_OWNER is denied'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'1')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(A;CI;WD;;;{user_sid})')
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(D;CI;WO;;;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        sd_sddl = f'D:(A;;WP;;;{user_sid})'
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'ntSecurityDescriptor': ndr_pack(tmp_desc),
            })
        except LdbError as err:
            self.fail(err)

    def test_add_security_descriptor_explicit_right_owner_disallow(self):
        '''Show that a computer object with a security descriptor containing an owner and group can be added if BlockOwnerImplicitRights == 1, WRITE_DAC is granted, and WRITE_OWNER is denied'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'1')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(A;CI;WD;;;{user_sid})')
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(D;CI;WO;;;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        sd_sddl = (f'O:{user_sid}G:{user_sid}'
                   f'D:(A;;WP;;;{user_sid})')
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'ntSecurityDescriptor': ndr_pack(tmp_desc),
            })
        except LdbError as err:
            self.fail(err)

    def test_add_security_descriptor_explicit_right_sacl(self):
        '''Show that adding a computer object with a security descriptor containing a SACL is disallowed if BlockOwnerImplicitRights == 1 and WRITE_DAC is granted'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'1')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(A;CI;WD;;;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        sd_sddl = (f'O:{user_sid}G:{user_sid}'
                   f'D:(A;;WP;;;{user_sid})S:(A;;WP;;;{user_sid})')
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'ntSecurityDescriptor': ndr_pack(tmp_desc),
            })
        except LdbError as err:
            num, estr = err.args
            if self.strict_checking:
                self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
                self.assertIn(f'{werror.WERR_PRIVILEGE_NOT_HELD:08X}', estr)
            else:
                self.assertIn(num, (ERR_CONSTRAINT_VIOLATION,
                                    ERR_INSUFFICIENT_ACCESS_RIGHTS))
        else:
            self.fail('expected to fail')

    def test_add_security_descriptor_explicit_right_owner_not_us(self):
        '''Show that adding a computer object with a security descriptor owned by another is disallowed if BlockOwnerImplicitRights == 1 and WRITE_DAC is granted'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'1')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(A;CI;WD;;;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        sd_sddl = 'O:BA'
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'ntSecurityDescriptor': ndr_pack(tmp_desc),
            })
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
            self.assertIn(f'{werror.WERR_INVALID_OWNER:08X}', estr)
        else:
            self.fail('expected to fail')

    def test_add_security_descriptor_explicit_right_owner_not_us_admin(self):
        '''Show that adding a computer object with a security descriptor owned by another is allowed if BlockOwnerImplicitRights == 1, WRITE_DAC is granted, and we are in Domain Admins'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'1')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(A;CI;WD;;;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        sd_sddl = 'O:BA'
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        try:
            self.ldb_admin.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'ntSecurityDescriptor': ndr_pack(tmp_desc),
            })
        except LdbError as err:
            self.fail(err)

    def test_add_no_implicit_right(self):
        '''Show that adding a computer object without a security descriptor is allowed when BlockOwnerImplicitRights == 1'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'1')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
            })
        except LdbError as err:
            self.fail(err)

    def test_add_security_descriptor_owner(self):
        '''Show that adding a computer object with a security descriptor containing an owner is disallowed when BlockOwnerImplicitRights == 1'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'1')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        sd_sddl = f'O:{user_sid}'
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'ntSecurityDescriptor': ndr_pack(tmp_desc),
            })
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
            if self.strict_checking:
                self.assertIn('000021CC', estr)
        else:
            self.fail('expected to fail')

    def test_add_security_descriptor_owner_implicit(self):
        '''Show that adding a computer object with a security descriptor containing an owner is disallowed when BlockOwnerImplicitRights == 1, even when we are the owner of the OU security descriptor'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'1')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))

        ou_controls = [
            f'sd_flags:1:{security.SECINFO_OWNER|security.SECINFO_DACL}']
        ou_sddl = (f'O:{user_sid}'
                   f'D:(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.sd_utils.modify_sd_on_dn(f'{self.ou1},{self.base_dn}', ou_desc,
                                      controls=ou_controls)

        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        sd_sddl = f'O:{user_sid}'
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'ntSecurityDescriptor': ndr_pack(tmp_desc),
            })
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
            if self.strict_checking:
                self.assertIn('000021CC', estr)
        else:
            self.fail('expected to fail')

    def test_add_security_descriptor_owner_explicit_right(self):
        '''Show that adding a computer object with a security descriptor containing an owner is disallowed when BlockOwnerImplicitRights == 1, even with WO'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'1')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(A;CI;WO;;;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        sd_sddl = f'O:{user_sid}'
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'ntSecurityDescriptor': ndr_pack(tmp_desc),
            })
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
            if self.strict_checking:
                self.assertIn('000021CC', estr)
        else:
            self.fail('expected to fail')

    def test_add_security_descriptor_group(self):
        '''Show that adding a computer object with a security descriptor containing an group is disallowed when BlockOwnerImplicitRights == 1'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'1')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        sd_sddl = f'G:{user_sid}'
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'ntSecurityDescriptor': ndr_pack(tmp_desc),
            })
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
            if self.strict_checking:
                self.assertIn('000021CC', estr)
        else:
            self.fail('expected to fail')

    def test_add_security_descriptor_group_explicit_right(self):
        '''Show that adding a computer object with a security descriptor containing an group is disallowed when BlockOwnerImplicitRights == 1, even with WO'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'1')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(A;CI;WO;;;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        sd_sddl = f'G:{user_sid}'
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'ntSecurityDescriptor': ndr_pack(tmp_desc),
            })
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
            if self.strict_checking:
                self.assertIn('000021CC', estr)
        else:
            self.fail('expected to fail')

    def test_add_security_descriptor_group_implicit(self):
        '''Show that adding a computer object with a security descriptor containing an group is disallowed when BlockOwnerImplicitRights == 1, even when we are the owner of the OU security descriptor'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'1')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))

        ou_controls = [
            f'sd_flags:1:{security.SECINFO_OWNER|security.SECINFO_DACL}']
        ou_sddl = (f'O:{user_sid}'
                   f'D:(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.sd_utils.modify_sd_on_dn(f'{self.ou1},{self.base_dn}', ou_desc,
                                      controls=ou_controls)

        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        sd_sddl = f'G:{user_sid}'
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'ntSecurityDescriptor': ndr_pack(tmp_desc),
            })
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
            if self.strict_checking:
                self.assertIn('000021CC', estr)
        else:
            self.fail('expected to fail')

    def test_add_security_descriptor_dacl(self):
        '''Show that adding a computer object with a security descriptor containing a DACL is disallowed when BlockOwnerImplicitRights == 1'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'1')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        sd_sddl = f'D:(A;;WP;;;{user_sid})'
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'ntSecurityDescriptor': ndr_pack(tmp_desc),
            })
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
            if self.strict_checking:
                self.assertIn('000021CC', estr)
        else:
            self.fail('expected to fail')

    def test_add_security_descriptor_dacl_implicit(self):
        '''Show that adding a computer object with a security descriptor containing a DACL is disallowed when BlockOwnerImplicitRights == 1, even when we are the owner of the OU security descriptor'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'1')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))

        ou_controls = [
            f'sd_flags:1:{security.SECINFO_OWNER|security.SECINFO_DACL}']
        ou_sddl = (f'O:{user_sid}'
                   f'D:(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.sd_utils.modify_sd_on_dn(f'{self.ou1},{self.base_dn}', ou_desc,
                                      controls=ou_controls)

        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        sd_sddl = f'D:(A;;WP;;;{user_sid})'
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'ntSecurityDescriptor': ndr_pack(tmp_desc),
            })
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
            if self.strict_checking:
                self.assertIn('000021CC', estr)
        else:
            self.fail('expected to fail')

    def test_add_security_descriptor_sacl(self):
        '''Show that adding a computer object with a security descriptor containing a SACL is disallowed when BlockOwnerImplicitRights == 1'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'1')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(
            f'{self.ou1},{self.base_dn}',
            f'(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        sd_sddl = f'S:(A;;WP;;;{user_sid})'
        tmp_desc = security.descriptor.from_sddl(sd_sddl, self.domain_sid)
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'ntSecurityDescriptor': ndr_pack(tmp_desc),
            })
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
            if self.strict_checking:
                self.assertIn('000021CC', estr)
        else:
            self.fail('expected to fail')

    def test_add_security_descriptor_empty(self):
        '''Show that adding a computer object with an empty security descriptor is disallowed when BlockOwnerImplicitRights == 1, even when we are the owner of the OU security descriptor'''

        self.assert_top_ou_deleted()
        self.ldb_owner.create_ou(f'{self.ou1},{self.base_dn}')

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'1')

        user_sid = self.sd_utils.get_object_sid(
            self.get_user_dn(self.regular_user))

        ou_controls = [
            f'sd_flags:1:{security.SECINFO_OWNER|security.SECINFO_DACL}']
        ou_sddl = (f'O:{user_sid}'
                   f'D:(OA;CI;CC;{samba.dsdb.DS_GUID_SCHEMA_CLASS_COMPUTER};;{user_sid})')
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.sd_utils.modify_sd_on_dn(f'{self.ou1},{self.base_dn}', ou_desc,
                                      controls=ou_controls)

        dn = f'CN={self.test_user1},{self.ou1},{self.base_dn}'
        account_name = f'{self.test_user1}$'
        tmp_desc = security.descriptor.from_sddl('', self.domain_sid)
        try:
            self.ldb_user.add({
                'dn': dn,
                'objectclass': 'computer',
                'sAMAccountName': account_name,
                'ntSecurityDescriptor': ndr_pack(tmp_desc),
            })
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
            if self.strict_checking:
                self.assertIn('000021CC', estr)
        else:
            self.fail('expected to fail')

    def test_add_anonymous(self):
        """Test add operation with anonymous user"""
        anonymous = SamDB(url=ldaphost, credentials=self.creds_tmp, lp=lp)
        try:
            anonymous.newuser("test_add_anonymous", self.user_pass)
        except LdbError as e2:
            (num, _) = e2.args
            self.assertEqual(num, ERR_OPERATIONS_ERROR)
        else:
            self.fail()

# tests on ldap modify operations


class AclModifyTests(AclTests):

    def setUp(self):
        super(AclModifyTests, self).setUp()
        self.user_with_wp = "acl_mod_user1"
        self.user_with_sm = "acl_mod_user2"
        self.user_with_group_sm = "acl_mod_user3"
        self.ldb_admin.newuser(self.user_with_wp, self.user_pass)
        self.ldb_admin.newuser(self.user_with_sm, self.user_pass)
        self.ldb_admin.newuser(self.user_with_group_sm, self.user_pass)
        self.ldb_user = self.get_ldb_connection(self.user_with_wp, self.user_pass)
        self.ldb_user2 = self.get_ldb_connection(self.user_with_sm, self.user_pass)
        self.ldb_user3 = self.get_ldb_connection(self.user_with_group_sm, self.user_pass)
        self.user_sid = self.sd_utils.get_object_sid(self.get_user_dn(self.user_with_wp))
        self.ldb_admin.newgroup("test_modify_group2", grouptype=samba.dsdb.GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP)
        self.ldb_admin.newgroup("test_modify_group3", grouptype=samba.dsdb.GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP)
        self.ldb_admin.newuser("test_modify_user2", self.user_pass)

    def tearDown(self):
        super(AclModifyTests, self).tearDown()
        delete_force(self.ldb_admin, self.get_user_dn("test_modify_user1"))
        delete_force(self.ldb_admin, "CN=test_modify_group1,CN=Users," + self.base_dn)
        delete_force(self.ldb_admin, "CN=test_modify_group2,CN=Users," + self.base_dn)
        delete_force(self.ldb_admin, "CN=test_modify_group3,CN=Users," + self.base_dn)
        delete_force(self.ldb_admin, "CN=test_mod_hostname,OU=test_modify_ou1," + self.base_dn)
        delete_force(self.ldb_admin, "CN=test_modify_ou1_user,OU=test_modify_ou1," + self.base_dn)
        delete_force(self.ldb_admin, "OU=test_modify_ou1," + self.base_dn)
        delete_force(self.ldb_admin, self.get_user_dn(self.user_with_wp))
        delete_force(self.ldb_admin, self.get_user_dn(self.user_with_sm))
        delete_force(self.ldb_admin, self.get_user_dn(self.user_with_group_sm))
        delete_force(self.ldb_admin, self.get_user_dn("test_modify_user2"))
        delete_force(self.ldb_admin, self.get_user_dn("test_anonymous"))

        del self.ldb_user
        del self.ldb_user2
        del self.ldb_user3

    def get_sd_rights_effective(self, samdb, dn):
        res = samdb.search(dn,
                           scope=SCOPE_BASE,
                           attrs=['sDRightsEffective'])
        sd_rights = res[0].get('sDRightsEffective', idx=0)
        if sd_rights is not None:
            sd_rights = int(sd_rights)

        return sd_rights

    def test_modify_u1(self):
        """5 Modify one attribute if you have DS_WRITE_PROPERTY for it"""
        mod = "(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;;%s)" % str(self.user_sid)
        # First test object -- User
        print("Testing modify on User object")
        self.ldb_admin.newuser("test_modify_user1", self.user_pass)
        self.sd_utils.dacl_add_ace(self.get_user_dn("test_modify_user1"), mod)
        ldif = """
dn: """ + self.get_user_dn("test_modify_user1") + """
changetype: modify
replace: displayName
displayName: test_changed"""
        self.ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % self.get_user_dn("test_modify_user1"))
        self.assertEqual(str(res[0]["displayName"][0]), "test_changed")
        # Second test object -- Group
        print("Testing modify on Group object")
        self.ldb_admin.newgroup("test_modify_group1",
                                grouptype=samba.dsdb.GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP)
        self.sd_utils.dacl_add_ace("CN=test_modify_group1,CN=Users," + self.base_dn, mod)
        ldif = """
dn: CN=test_modify_group1,CN=Users,""" + self.base_dn + """
changetype: modify
replace: displayName
displayName: test_changed"""
        self.ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search(self.base_dn, expression="(distinguishedName=%s)" % str("CN=test_modify_group1,CN=Users," + self.base_dn))
        self.assertEqual(str(res[0]["displayName"][0]), "test_changed")
        # Third test object -- Organizational Unit
        print("Testing modify on OU object")
        #delete_force(self.ldb_admin, "OU=test_modify_ou1," + self.base_dn)
        self.ldb_admin.create_ou("OU=test_modify_ou1," + self.base_dn)
        self.sd_utils.dacl_add_ace("OU=test_modify_ou1," + self.base_dn, mod)
        ldif = """
dn: OU=test_modify_ou1,""" + self.base_dn + """
changetype: modify
replace: displayName
displayName: test_changed"""
        self.ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search(self.base_dn, expression="(distinguishedName=%s)" % str("OU=test_modify_ou1," + self.base_dn))
        self.assertEqual(str(res[0]["displayName"][0]), "test_changed")

    def test_modify_u2(self):
        """6 Modify two attributes as you have DS_WRITE_PROPERTY granted only for one of them"""
        mod = "(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;;%s)" % str(self.user_sid)
        # First test object -- User
        print("Testing modify on User object")
        #delete_force(self.ldb_admin, self.get_user_dn("test_modify_user1"))
        self.ldb_admin.newuser("test_modify_user1", self.user_pass)
        self.sd_utils.dacl_add_ace(self.get_user_dn("test_modify_user1"), mod)
        # Modify on attribute you have rights for
        ldif = """
dn: """ + self.get_user_dn("test_modify_user1") + """
changetype: modify
replace: displayName
displayName: test_changed"""
        self.ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" %
                                    self.get_user_dn("test_modify_user1"))
        self.assertEqual(str(res[0]["displayName"][0]), "test_changed")
        # Modify on attribute you do not have rights for granted
        ldif = """
dn: """ + self.get_user_dn("test_modify_user1") + """
changetype: modify
replace: url
url: www.samba.org"""
        try:
            self.ldb_user.modify_ldif(ldif)
        except LdbError as e3:
            (num, _) = e3.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()
        # Second test object -- Group
        print("Testing modify on Group object")
        self.ldb_admin.newgroup("test_modify_group1",
                                grouptype=samba.dsdb.GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP)
        self.sd_utils.dacl_add_ace("CN=test_modify_group1,CN=Users," + self.base_dn, mod)
        ldif = """
dn: CN=test_modify_group1,CN=Users,""" + self.base_dn + """
changetype: modify
replace: displayName
displayName: test_changed"""
        self.ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" %
                                    str("CN=test_modify_group1,CN=Users," + self.base_dn))
        self.assertEqual(str(res[0]["displayName"][0]), "test_changed")
        # Modify on attribute you do not have rights for granted
        ldif = """
dn: CN=test_modify_group1,CN=Users,""" + self.base_dn + """
changetype: modify
replace: url
url: www.samba.org"""
        try:
            self.ldb_user.modify_ldif(ldif)
        except LdbError as e4:
            (num, _) = e4.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()
        # Modify on attribute you do not have rights for granted while also modifying something you do have rights for
        ldif = """
dn: CN=test_modify_group1,CN=Users,""" + self.base_dn + """
changetype: modify
replace: url
url: www.samba.org
replace: displayName
displayName: test_changed"""
        try:
            self.ldb_user.modify_ldif(ldif)
        except LdbError as e5:
            (num, _) = e5.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()
        # Second test object -- Organizational Unit
        print("Testing modify on OU object")
        self.ldb_admin.create_ou("OU=test_modify_ou1," + self.base_dn)
        self.sd_utils.dacl_add_ace("OU=test_modify_ou1," + self.base_dn, mod)
        ldif = """
dn: OU=test_modify_ou1,""" + self.base_dn + """
changetype: modify
replace: displayName
displayName: test_changed"""
        self.ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % str("OU=test_modify_ou1,"
                                                                              + self.base_dn))
        self.assertEqual(str(res[0]["displayName"][0]), "test_changed")
        # Modify on attribute you do not have rights for granted
        ldif = """
dn: OU=test_modify_ou1,""" + self.base_dn + """
changetype: modify
replace: url
url: www.samba.org"""
        try:
            self.ldb_user.modify_ldif(ldif)
        except LdbError as e6:
            (num, _) = e6.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()

    def test_modify_u3(self):
        """7 Modify one attribute as you have no what so ever rights granted"""
        # First test object -- User
        print("Testing modify on User object")
        self.ldb_admin.newuser("test_modify_user1", self.user_pass)
        # Modify on attribute you do not have rights for granted
        ldif = """
dn: """ + self.get_user_dn("test_modify_user1") + """
changetype: modify
replace: url
url: www.samba.org"""
        try:
            self.ldb_user.modify_ldif(ldif)
        except LdbError as e7:
            (num, _) = e7.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()

        # Second test object -- Group
        print("Testing modify on Group object")
        self.ldb_admin.newgroup("test_modify_group1",
                                grouptype=samba.dsdb.GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP)
        # Modify on attribute you do not have rights for granted
        ldif = """
dn: CN=test_modify_group1,CN=Users,""" + self.base_dn + """
changetype: modify
replace: url
url: www.samba.org"""
        try:
            self.ldb_user.modify_ldif(ldif)
        except LdbError as e8:
            (num, _) = e8.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()

        # Second test object -- Organizational Unit
        print("Testing modify on OU object")
        #delete_force(self.ldb_admin, "OU=test_modify_ou1," + self.base_dn)
        self.ldb_admin.create_ou("OU=test_modify_ou1," + self.base_dn)
        # Modify on attribute you do not have rights for granted
        ldif = """
dn: OU=test_modify_ou1,""" + self.base_dn + """
changetype: modify
replace: url
url: www.samba.org"""
        try:
            self.ldb_user.modify_ldif(ldif)
        except LdbError as e9:
            (num, _) = e9.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()

    def test_modify_u4(self):
        """11 Grant WP to PRINCIPAL_SELF and test modify"""
        ldif = """
dn: """ + self.get_user_dn(self.user_with_wp) + """
changetype: modify
add: adminDescription
adminDescription: blah blah blah"""
        try:
            self.ldb_user.modify_ldif(ldif)
        except LdbError as e10:
            (num, _) = e10.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()

        mod = "(OA;;WP;bf967919-0de6-11d0-a285-00aa003049e2;;PS)"
        self.sd_utils.dacl_add_ace(self.get_user_dn(self.user_with_wp), mod)
        # Modify on attribute you have rights for
        self.ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search(self.base_dn, expression="(distinguishedName=%s)"
                                    % self.get_user_dn(self.user_with_wp), attrs=["adminDescription"])
        self.assertEqual(str(res[0]["adminDescription"][0]), "blah blah blah")

    def test_modify_u5(self):
        """12 test self membership"""
        ldif = """
dn: CN=test_modify_group2,CN=Users,""" + self.base_dn + """
changetype: modify
add: Member
Member: """ + self.get_user_dn(self.user_with_sm)
# the user has no rights granted, this should fail
        try:
            self.ldb_user2.modify_ldif(ldif)
        except LdbError as e11:
            (num, _) = e11.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This 'modify' operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()

# grant self-membership, should be able to add himself
        user_sid = self.sd_utils.get_object_sid(self.get_user_dn(self.user_with_sm))
        mod = "(OA;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace("CN=test_modify_group2,CN=Users," + self.base_dn, mod)
        self.ldb_user2.modify_ldif(ldif)
        res = self.ldb_admin.search(self.base_dn, expression="(distinguishedName=%s)"
                                    % ("CN=test_modify_group2,CN=Users," + self.base_dn), attrs=["Member"])
        self.assertEqual(str(res[0]["Member"][0]), self.get_user_dn(self.user_with_sm))
# but not other users
        ldif = """
dn: CN=test_modify_group2,CN=Users,""" + self.base_dn + """
changetype: modify
add: Member
Member: CN=test_modify_user2,CN=Users,""" + self.base_dn
        try:
            self.ldb_user2.modify_ldif(ldif)
        except LdbError as e12:
            (num, _) = e12.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()

    def test_modify_u6(self):
        """13 test self membership"""
        ldif = """
dn: CN=test_modify_group2,CN=Users,""" + self.base_dn + """
changetype: modify
add: Member
Member: """ + self.get_user_dn(self.user_with_sm) + """
Member: CN=test_modify_user2,CN=Users,""" + self.base_dn

# grant self-membership, should be able to add himself  but not others at the same time
        user_sid = self.sd_utils.get_object_sid(self.get_user_dn(self.user_with_sm))
        mod = "(OA;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace("CN=test_modify_group2,CN=Users," + self.base_dn, mod)
        try:
            self.ldb_user2.modify_ldif(ldif)
        except LdbError as e13:
            (num, _) = e13.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()

    def test_modify_u7(self):
        """13 User with WP modifying Member"""
# a second user is given write property permission
        user_sid = self.sd_utils.get_object_sid(self.get_user_dn(self.user_with_wp))
        mod = "(A;;WP;;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace("CN=test_modify_group2,CN=Users," + self.base_dn, mod)
        ldif = """
dn: CN=test_modify_group2,CN=Users,""" + self.base_dn + """
changetype: modify
add: Member
Member: """ + self.get_user_dn(self.user_with_wp)
        self.ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search(self.base_dn, expression="(distinguishedName=%s)"
                                    % ("CN=test_modify_group2,CN=Users," + self.base_dn), attrs=["Member"])
        self.assertEqual(str(res[0]["Member"][0]), self.get_user_dn(self.user_with_wp))
        ldif = """
dn: CN=test_modify_group2,CN=Users,""" + self.base_dn + """
changetype: modify
delete: Member"""
        self.ldb_user.modify_ldif(ldif)
        ldif = """
dn: CN=test_modify_group2,CN=Users,""" + self.base_dn + """
changetype: modify
add: Member
Member: CN=test_modify_user2,CN=Users,""" + self.base_dn
        self.ldb_user.modify_ldif(ldif)
        res = self.ldb_admin.search(self.base_dn, expression="(distinguishedName=%s)"
                                    % ("CN=test_modify_group2,CN=Users," + self.base_dn), attrs=["Member"])
        self.assertEqual(str(res[0]["Member"][0]), "CN=test_modify_user2,CN=Users," + self.base_dn)

    def test_modify_dacl_explicit_user(self):
        '''Modify the DACL of a user's security descriptor when we have RIGHT_WRITE_DAC'''

        ou_name = 'test_modify_ou1'
        ou_dn = f'OU={ou_name},{self.base_dn}'

        username = 'test_modify_ou1_user'
        user_dn = Dn(self.ldb_admin, f'CN={username},{ou_dn}')

        sd_sddl = 'D:(A;;WP;;;BA)'
        descriptor = security.descriptor.from_sddl(sd_sddl, self.domain_sid)

        ou_sddl = f'D:(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_NT_SECURITY_DESCRIPTOR};;{self.user_sid})'
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, name=ou_name, sd=ou_desc)

        self.ldb_admin.newuser(username, self.user_pass,
                               userou=f'OU={ou_name}',
                               sd=descriptor)

        new_sddl = f'D:(A;;WP;;;{self.user_sid})'
        new_desc = security.descriptor.from_sddl(new_sddl, self.domain_sid)

        controls = [f'sd_flags:1:{security.SECINFO_DACL}']

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, user_dn)
        expected_rights = 0
        self.assertEqual(expected_rights, effective_rights)

        # The user should not be able to modify the DACL.
        message = Message(user_dn)
        message['nTSecurityDescriptor'] = MessageElement(
            ndr_pack(new_desc),
            FLAG_MOD_REPLACE,
            'nTSecurityDescriptor')

        # The update fails since we don't have WRITE_DAC.
        try:
            self.ldb_user.modify(message, controls=controls)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
            if self.strict_checking:
                self.assertIn(f'{werror.WERR_ACCESS_DENIED:08X}', estr)
        else:
            self.fail()

        # Grant ourselves WRITE_DAC.
        write_dac_sddl = f'(A;CI;WD;;;{self.user_sid})'
        self.sd_utils.dacl_add_ace(ou_dn, write_dac_sddl)

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, user_dn)
        expected_rights = security.SECINFO_DACL
        self.assertEqual(expected_rights, effective_rights)

        # The update fails if we don't specify the controls.
        try:
            self.ldb_user.modify(message)
        except LdbError as err:
            if self.strict_checking:
                num, estr = err.args
                self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
                self.assertIn(f'{werror.WERR_ACCESS_DENIED:08X}', estr)
        else:
            self.fail()

        # The update succeeds when specifying the controls.
        self.ldb_user.modify(message, controls=controls)

    def test_modify_dacl_explicit_computer(self):
        '''Modify the DACL of a computer's security descriptor when we have RIGHT_WRITE_DAC'''

        ou_name = 'test_modify_ou1'
        ou_dn = f'OU={ou_name},{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = Dn(self.ldb_admin, f'CN={account_name},{ou_dn}')

        sd_sddl = 'D:(A;;WP;;;BA)'
        descriptor = security.descriptor.from_sddl(sd_sddl, self.domain_sid)

        ou_sddl = f'D:(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_NT_SECURITY_DESCRIPTOR};;{self.user_sid})'
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, name=ou_name, sd=ou_desc)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
            'nTSecurityDescriptor': ndr_pack(descriptor),
        })

        new_sddl = f'D:(A;;WP;;;{self.user_sid})'
        new_desc = security.descriptor.from_sddl(new_sddl, self.domain_sid)

        controls = [f'sd_flags:1:{security.SECINFO_DACL}']

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, dn)
        expected_rights = None
        self.assertEqual(expected_rights, effective_rights)

        # The user should not be able to modify the DACL.
        message = Message(dn)
        message['nTSecurityDescriptor'] = MessageElement(
            ndr_pack(new_desc),
            FLAG_MOD_REPLACE,
            'nTSecurityDescriptor')

        # The update fails since we don't have WRITE_DAC.
        try:
            self.ldb_user.modify(message, controls=controls)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
            if self.strict_checking:
                self.assertIn(f'{werror.WERR_ACCESS_DENIED:08X}', estr)
        else:
            self.fail()

        # Grant ourselves WRITE_DAC.
        write_dac_sddl = f'(A;CI;WD;;;{self.user_sid})'
        self.sd_utils.dacl_add_ace(ou_dn, write_dac_sddl)

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, dn)
        expected_rights = None
        self.assertEqual(expected_rights, effective_rights)

        # The update fails if we don't specify the controls.
        try:
            self.ldb_user.modify(message)
        except LdbError as err:
            if self.strict_checking:
                num, estr = err.args
                self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
                self.assertIn(f'{werror.WERR_ACCESS_DENIED:08X}', estr)
        else:
            self.fail()

        # The update succeeds when specifying the controls.
        self.ldb_user.modify(message, controls=controls)

    def test_modify_dacl_owner_user(self):
        '''Modify the DACL of a user's security descriptor when we are its owner'''

        ou_name = 'test_modify_ou1'
        ou_dn = f'OU={ou_name},{self.base_dn}'

        username = 'test_modify_ou1_user'
        user_dn = Dn(self.ldb_admin, f'CN={username},{ou_dn}')

        sd_sddl = 'O:BA'
        descriptor = security.descriptor.from_sddl(sd_sddl, self.domain_sid)

        ou_sddl = f'D:(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_NT_SECURITY_DESCRIPTOR};;{self.user_sid})'
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, name=ou_name, sd=ou_desc)

        self.ldb_admin.newuser(username, self.user_pass,
                               userou=f'OU={ou_name}',
                               sd=descriptor)

        new_sddl = f'D:(A;;WP;;;{self.user_sid})'
        new_desc = security.descriptor.from_sddl(new_sddl, self.domain_sid)

        owner_controls = [f'sd_flags:1:{security.SECINFO_OWNER}']
        dacl_controls = [f'sd_flags:1:{security.SECINFO_DACL}']

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, user_dn)
        expected_rights = 0
        self.assertEqual(expected_rights, effective_rights)

        # The user should not be able to modify the DACL.
        message = Message(user_dn)
        message['nTSecurityDescriptor'] = MessageElement(
            ndr_pack(new_desc),
            FLAG_MOD_REPLACE,
            'nTSecurityDescriptor')

        # The update fails since we are not the owner.
        try:
            self.ldb_user.modify(message, controls=dacl_controls)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
            if self.strict_checking:
                self.assertIn(f'{werror.WERR_ACCESS_DENIED:08X}', estr)
        else:
            self.fail()

        # Make ourselves the owner of the security descriptor.
        owner_sddl = f'O:{self.user_sid}'
        owner_desc = security.descriptor.from_sddl(owner_sddl, self.domain_sid)
        self.sd_utils.modify_sd_on_dn(user_dn, owner_desc,
                                      controls=owner_controls)

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, user_dn)
        expected_rights = security.SECINFO_DACL
        self.assertEqual(expected_rights, effective_rights)

        # The update fails if we don't specify the controls.
        try:
            self.ldb_user.modify(message)
        except LdbError as err:
            if self.strict_checking:
                num, estr = err.args
                self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
                self.assertIn(f'{werror.WERR_ACCESS_DENIED:08X}', estr)
        else:
            self.fail()

        # The update succeeds when specifying the controls.
        self.ldb_user.modify(message, controls=dacl_controls)

    def test_modify_dacl_owner_computer_implicit_right_blocked(self):
        '''Show that we cannot modify the DACL of a computer's security descriptor when we are its owner and BlockOwnerImplicitRights == 1'''

        ou_name = 'test_modify_ou1'
        ou_dn = f'OU={ou_name},{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = Dn(self.ldb_admin, f'CN={account_name},{ou_dn}')

        sd_sddl = 'O:BA'
        descriptor = security.descriptor.from_sddl(sd_sddl, self.domain_sid)

        ou_sddl = f'D:(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_NT_SECURITY_DESCRIPTOR};;{self.user_sid})'
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, name=ou_name, sd=ou_desc)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
            'nTSecurityDescriptor': ndr_pack(descriptor),
        })

        new_sddl = f'D:(A;;WP;;;{self.user_sid})'
        new_desc = security.descriptor.from_sddl(new_sddl, self.domain_sid)

        owner_controls = [f'sd_flags:1:{security.SECINFO_OWNER}']
        dacl_controls = [f'sd_flags:1:{security.SECINFO_DACL}']

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, dn)
        expected_rights = None
        self.assertEqual(expected_rights, effective_rights)

        # The user should not be able to modify the DACL.
        message = Message(dn)
        message['nTSecurityDescriptor'] = MessageElement(
            ndr_pack(new_desc),
            FLAG_MOD_REPLACE,
            'nTSecurityDescriptor')

        # The update fails since we are not the owner.
        try:
            self.ldb_user.modify(message, controls=dacl_controls)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
            if self.strict_checking:
                self.assertIn(f'{werror.WERR_ACCESS_DENIED:08X}', estr)
        else:
            self.fail()

        # Make ourselves the owner of the security descriptor.
        owner_sddl = f'O:{self.user_sid}'
        owner_desc = security.descriptor.from_sddl(owner_sddl, self.domain_sid)
        self.sd_utils.modify_sd_on_dn(dn, owner_desc,
                                      controls=owner_controls)

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, dn)
        expected_rights = None
        self.assertEqual(expected_rights, effective_rights)

        # The update fails even when specifying the controls.
        try:
            self.ldb_user.modify(message, controls=dacl_controls)
        except LdbError as err:
            if self.strict_checking:
                num, estr = err.args
                self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
                self.assertIn(f'{werror.WERR_ACCESS_DENIED:08X}', estr)
        else:
            self.fail()

    def test_modify_dacl_owner_computer_implicit_right_allowed(self):
        '''Modify the DACL of a computer's security descriptor when we are its owner and BlockOwnerImplicitRights != 1'''

        self.set_heuristic(samba.dsdb.DS_HR_BLOCK_OWNER_IMPLICIT_RIGHTS, b'0')

        ou_name = 'test_modify_ou1'
        ou_dn = f'OU={ou_name},{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = Dn(self.ldb_admin, f'CN={account_name},{ou_dn}')

        sd_sddl = 'O:BA'
        descriptor = security.descriptor.from_sddl(sd_sddl, self.domain_sid)

        ou_sddl = f'D:(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_NT_SECURITY_DESCRIPTOR};;{self.user_sid})'
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, name=ou_name, sd=ou_desc)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
            'nTSecurityDescriptor': ndr_pack(descriptor),
        })

        new_sddl = f'D:(A;;WP;;;{self.user_sid})'
        new_desc = security.descriptor.from_sddl(new_sddl, self.domain_sid)

        owner_controls = [f'sd_flags:1:{security.SECINFO_OWNER}']
        dacl_controls = [f'sd_flags:1:{security.SECINFO_DACL}']

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, dn)
        expected_rights = None
        self.assertEqual(expected_rights, effective_rights)

        # The user should not be able to modify the DACL.
        message = Message(dn)
        message['nTSecurityDescriptor'] = MessageElement(
            ndr_pack(new_desc),
            FLAG_MOD_REPLACE,
            'nTSecurityDescriptor')

        # The update fails since we are not the owner.
        try:
            self.ldb_user.modify(message, controls=dacl_controls)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
            if self.strict_checking:
                self.assertIn(f'{werror.WERR_ACCESS_DENIED:08X}', estr)
        else:
            self.fail()

        # Make ourselves the owner of the security descriptor.
        owner_sddl = f'O:{self.user_sid}'
        owner_desc = security.descriptor.from_sddl(owner_sddl, self.domain_sid)
        self.sd_utils.modify_sd_on_dn(dn, owner_desc,
                                      controls=owner_controls)

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, dn)
        expected_rights = None
        self.assertEqual(expected_rights, effective_rights)

        # The update fails if we don't specify the controls.
        try:
            self.ldb_user.modify(message)
        except LdbError as err:
            if self.strict_checking:
                num, estr = err.args
                self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
                self.assertIn(f'{werror.WERR_ACCESS_DENIED:08X}', estr)
        else:
            self.fail()

        # The update succeeds when specifying the controls.
        self.ldb_user.modify(message, controls=dacl_controls)

    def test_modify_owner_explicit_user(self):
        '''Modify the owner of a user's security descriptor when we have RIGHT_WRITE_OWNER'''

        ou_name = 'test_modify_ou1'
        ou_dn = f'OU={ou_name},{self.base_dn}'

        username = 'test_modify_ou1_user'
        user_dn = Dn(self.ldb_admin, f'CN={username},{ou_dn}')

        sd_sddl = 'O:BA'
        descriptor = security.descriptor.from_sddl(sd_sddl, self.domain_sid)

        ou_sddl = f'D:(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_NT_SECURITY_DESCRIPTOR};;{self.user_sid})'
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, name=ou_name, sd=ou_desc)

        self.ldb_admin.newuser(username, self.user_pass,
                               userou=f'OU={ou_name}',
                               sd=descriptor)

        # Try to modify the owner to ourselves.
        new_sddl = f'O:{self.user_sid}'
        new_desc = security.descriptor.from_sddl(new_sddl, self.domain_sid)

        owner_controls = [f'sd_flags:1:{security.SECINFO_OWNER}']

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, user_dn)
        expected_rights = 0
        self.assertEqual(expected_rights, effective_rights)

        # The user should not be able to modify the owner.
        message = Message(user_dn)
        message['nTSecurityDescriptor'] = MessageElement(
            ndr_pack(new_desc),
            FLAG_MOD_REPLACE,
            'nTSecurityDescriptor')

        # The update fails since we don't have WRITE_OWNER.
        try:
            self.ldb_user.modify(message, controls=owner_controls)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
            if self.strict_checking:
                self.assertIn(f'{werror.WERR_ACCESS_DENIED:08X}', estr)
        else:
            self.fail()

        # Grant ourselves WRITE_OWNER.
        owner_sddl = f'(A;CI;WO;;;{self.user_sid})'
        self.sd_utils.dacl_add_ace(ou_dn, owner_sddl)

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, user_dn)
        expected_rights = security.SECINFO_OWNER | security.SECINFO_GROUP
        self.assertEqual(expected_rights, effective_rights)

        # The update fails if we don't specify the controls.
        try:
            self.ldb_user.modify(message)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
            if self.strict_checking:
                self.assertIn(f'{werror.WERR_ACCESS_DENIED:08X}', estr)
        else:
            self.fail()

        # The update succeeds when specifying the controls.
        self.ldb_user.modify(message, controls=owner_controls)

    def test_modify_owner_explicit_computer(self):
        '''Modify the owner of a computer's security descriptor when we have RIGHT_WRITE_OWNER'''

        ou_name = 'test_modify_ou1'
        ou_dn = f'OU={ou_name},{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = Dn(self.ldb_admin, f'CN={account_name},{ou_dn}')

        sd_sddl = 'O:BA'
        descriptor = security.descriptor.from_sddl(sd_sddl, self.domain_sid)

        ou_sddl = f'D:(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_NT_SECURITY_DESCRIPTOR};;{self.user_sid})'
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, name=ou_name, sd=ou_desc)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
            'nTSecurityDescriptor': ndr_pack(descriptor),
        })

        # Try to modify the owner to ourselves.
        new_sddl = f'O:{self.user_sid}'
        new_desc = security.descriptor.from_sddl(new_sddl, self.domain_sid)

        owner_controls = [f'sd_flags:1:{security.SECINFO_OWNER}']

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, dn)
        expected_rights = None
        self.assertEqual(expected_rights, effective_rights)

        # The user should not be able to modify the owner.
        message = Message(dn)
        message['nTSecurityDescriptor'] = MessageElement(
            ndr_pack(new_desc),
            FLAG_MOD_REPLACE,
            'nTSecurityDescriptor')

        # The update fails since we don't have WRITE_OWNER.
        try:
            self.ldb_user.modify(message, controls=owner_controls)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
            if self.strict_checking:
                self.assertIn(f'{werror.WERR_ACCESS_DENIED:08X}', estr)
        else:
            self.fail()

        # Grant ourselves WRITE_OWNER.
        owner_sddl = f'(A;CI;WO;;;{self.user_sid})'
        self.sd_utils.dacl_add_ace(ou_dn, owner_sddl)

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, dn)
        expected_rights = None
        self.assertEqual(expected_rights, effective_rights)

        # The update fails if we don't specify the controls.
        try:
            self.ldb_user.modify(message)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
            if self.strict_checking:
                self.assertIn(f'{werror.WERR_ACCESS_DENIED:08X}', estr)
        else:
            self.fail()

        # The update succeeds when specifying the controls.
        self.ldb_user.modify(message, controls=owner_controls)

    def test_modify_group_explicit_user(self):
        '''Modify the group of a user's security descriptor when we have RIGHT_WRITE_OWNER'''

        ou_name = 'test_modify_ou1'
        ou_dn = f'OU={ou_name},{self.base_dn}'

        username = 'test_modify_ou1_user'
        user_dn = Dn(self.ldb_admin, f'CN={username},{ou_dn}')

        sd_sddl = 'O:BA'
        descriptor = security.descriptor.from_sddl(sd_sddl, self.domain_sid)

        ou_sddl = f'D:(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_NT_SECURITY_DESCRIPTOR};;{self.user_sid})'
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, name=ou_name, sd=ou_desc)

        self.ldb_admin.newuser(username, self.user_pass,
                               userou=f'OU={ou_name}',
                               sd=descriptor)

        # Try to modify the group to ourselves.
        new_sddl = f'G:{self.user_sid}'
        new_desc = security.descriptor.from_sddl(new_sddl, self.domain_sid)

        group_controls = [f'sd_flags:1:{security.SECINFO_GROUP}']

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, user_dn)
        expected_rights = 0
        self.assertEqual(expected_rights, effective_rights)

        # The user should not be able to modify the group.
        message = Message(user_dn)
        message['nTSecurityDescriptor'] = MessageElement(
            ndr_pack(new_desc),
            FLAG_MOD_REPLACE,
            'nTSecurityDescriptor')

        # The update fails since we don't have WRITE_OWNER.
        try:
            self.ldb_user.modify(message, controls=group_controls)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
            if self.strict_checking:
                self.assertIn(f'{werror.WERR_ACCESS_DENIED:08X}', estr)
        else:
            self.fail()

        # Grant ourselves WRITE_OWNER.
        owner_sddl = f'(A;CI;WO;;;{self.user_sid})'
        self.sd_utils.dacl_add_ace(ou_dn, owner_sddl)

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, user_dn)
        expected_rights = security.SECINFO_OWNER | security.SECINFO_GROUP
        self.assertEqual(expected_rights, effective_rights)

        # The update fails if we don't specify the controls.
        try:
            self.ldb_user.modify(message)
        except LdbError as err:
            if self.strict_checking:
                num, estr = err.args
                self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
                self.assertIn(f'{werror.WERR_ACCESS_DENIED:08X}', estr)
        else:
            self.fail()

        # The update succeeds when specifying the controls.
        self.ldb_user.modify(message, controls=group_controls)

    def test_modify_group_explicit_computer(self):
        '''Modify the group of a computer's security descriptor when we have RIGHT_WRITE_OWNER'''

        ou_name = 'test_modify_ou1'
        ou_dn = f'OU={ou_name},{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = Dn(self.ldb_admin, f'CN={account_name},{ou_dn}')

        sd_sddl = 'O:BA'
        descriptor = security.descriptor.from_sddl(sd_sddl, self.domain_sid)

        ou_sddl = f'D:(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_NT_SECURITY_DESCRIPTOR};;{self.user_sid})'
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, name=ou_name, sd=ou_desc)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
            'nTSecurityDescriptor': ndr_pack(descriptor),
        })

        # Try to modify the group to ourselves.
        new_sddl = f'G:{self.user_sid}'
        new_desc = security.descriptor.from_sddl(new_sddl, self.domain_sid)

        group_controls = [f'sd_flags:1:{security.SECINFO_GROUP}']

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, dn)
        expected_rights = None
        self.assertEqual(expected_rights, effective_rights)

        # The user should not be able to modify the group.
        message = Message(dn)
        message['nTSecurityDescriptor'] = MessageElement(
            ndr_pack(new_desc),
            FLAG_MOD_REPLACE,
            'nTSecurityDescriptor')

        # The update fails since we don't have WRITE_OWNER.
        try:
            self.ldb_user.modify(message, controls=group_controls)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
            if self.strict_checking:
                self.assertIn(f'{werror.WERR_ACCESS_DENIED:08X}', estr)
        else:
            self.fail()

        # Grant ourselves WRITE_OWNER.
        owner_sddl = f'(A;CI;WO;;;{self.user_sid})'
        self.sd_utils.dacl_add_ace(ou_dn, owner_sddl)

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, dn)
        expected_rights = None
        self.assertEqual(expected_rights, effective_rights)

        # The update fails if we don't specify the controls.
        try:
            self.ldb_user.modify(message)
        except LdbError as err:
            if self.strict_checking:
                num, estr = err.args
                self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
                self.assertIn(f'{werror.WERR_ACCESS_DENIED:08X}', estr)
        else:
            self.fail()

        # The update succeeds when specifying the controls.
        self.ldb_user.modify(message, controls=group_controls)

    def test_modify_owner_other_user(self):
        '''Show we cannot set the owner of a user's security descriptor to another SID'''

        ou_name = 'test_modify_ou1'
        ou_dn = f'OU={ou_name},{self.base_dn}'

        username = 'test_modify_ou1_user'
        user_dn = Dn(self.ldb_admin, f'CN={username},{ou_dn}')

        sd_sddl = 'O:BA'
        descriptor = security.descriptor.from_sddl(sd_sddl, self.domain_sid)

        ou_sddl = f'D:(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_NT_SECURITY_DESCRIPTOR};;{self.user_sid})'
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, name=ou_name, sd=ou_desc)

        self.ldb_admin.newuser(username, self.user_pass,
                               userou=f'OU={ou_name}',
                               sd=descriptor)

        # Try to modify the owner to someone other than ourselves.
        new_sddl = f'O:BA'
        new_desc = security.descriptor.from_sddl(new_sddl, self.domain_sid)

        owner_controls = [f'sd_flags:1:{security.SECINFO_OWNER}']

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, user_dn)
        expected_rights = 0
        self.assertEqual(expected_rights, effective_rights)

        # The user should not be able to modify the owner.
        message = Message(user_dn)
        message['nTSecurityDescriptor'] = MessageElement(
            ndr_pack(new_desc),
            FLAG_MOD_REPLACE,
            'nTSecurityDescriptor')

        # Grant ourselves WRITE_OWNER.
        owner_sddl = f'(A;CI;WO;;;{self.user_sid})'
        self.sd_utils.dacl_add_ace(ou_dn, owner_sddl)

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, user_dn)
        expected_rights = security.SECINFO_OWNER | security.SECINFO_GROUP
        self.assertEqual(expected_rights, effective_rights)

        # The update fails when trying to specify another user.
        try:
            self.ldb_user.modify(message, controls=owner_controls)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_CONSTRAINT_VIOLATION, num)
            if self.strict_checking:
                self.assertIn(f'{werror.WERR_INVALID_OWNER:08X}', estr)
        else:
            self.fail('expected an error')

    def test_modify_owner_other_computer(self):
        '''Show we cannot set the owner of a computer's security descriptor to another SID'''

        ou_name = 'test_modify_ou1'
        ou_dn = f'OU={ou_name},{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = Dn(self.ldb_admin, f'CN={account_name},{ou_dn}')

        sd_sddl = 'O:BA'
        descriptor = security.descriptor.from_sddl(sd_sddl, self.domain_sid)

        ou_sddl = f'D:(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_NT_SECURITY_DESCRIPTOR};;{self.user_sid})'
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, name=ou_name, sd=ou_desc)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
            'nTSecurityDescriptor': ndr_pack(descriptor),
        })

        # Try to modify the owner to someone other than ourselves.
        new_sddl = f'O:BA'
        new_desc = security.descriptor.from_sddl(new_sddl, self.domain_sid)

        owner_controls = [f'sd_flags:1:{security.SECINFO_OWNER}']

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, dn)
        expected_rights = None
        self.assertEqual(expected_rights, effective_rights)

        # The user should not be able to modify the owner.
        message = Message(dn)
        message['nTSecurityDescriptor'] = MessageElement(
            ndr_pack(new_desc),
            FLAG_MOD_REPLACE,
            'nTSecurityDescriptor')

        # Grant ourselves WRITE_OWNER.
        owner_sddl = f'(A;CI;WO;;;{self.user_sid})'
        self.sd_utils.dacl_add_ace(ou_dn, owner_sddl)

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, dn)
        expected_rights = None
        self.assertEqual(expected_rights, effective_rights)

        # The update fails when trying to specify another user.
        try:
            self.ldb_user.modify(message, controls=owner_controls)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_CONSTRAINT_VIOLATION, num)
            if self.strict_checking:
                self.assertIn(f'{werror.WERR_INVALID_OWNER:08X}', estr)
        else:
            self.fail('expected an error')

    def test_modify_owner_other_admin_user(self):
        '''Show a domain admin cannot set the owner of a user's security descriptor to another SID'''

        ou_name = 'test_modify_ou1'
        ou_dn = f'OU={ou_name},{self.base_dn}'

        username = 'test_modify_ou1_user'
        user_dn = Dn(self.ldb_admin, f'CN={username},{ou_dn}')

        sd_sddl = 'O:BA'
        descriptor = security.descriptor.from_sddl(sd_sddl, self.domain_sid)

        ou_sddl = f'D:(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_NT_SECURITY_DESCRIPTOR};;{self.user_sid})'
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, name=ou_name, sd=ou_desc)

        self.ldb_admin.newuser(username, self.user_pass,
                               userou=f'OU={ou_name}',
                               sd=descriptor)

        # Try to modify the owner to someone other than ourselves.
        new_sddl = f'O:BA'
        new_desc = security.descriptor.from_sddl(new_sddl, self.domain_sid)

        owner_controls = [f'sd_flags:1:{security.SECINFO_OWNER}']

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, user_dn)
        expected_rights = 0
        self.assertEqual(expected_rights, effective_rights)

        # The user should not be able to modify the owner.
        message = Message(user_dn)
        message['nTSecurityDescriptor'] = MessageElement(
            ndr_pack(new_desc),
            FLAG_MOD_REPLACE,
            'nTSecurityDescriptor')

        # Grant ourselves WRITE_OWNER.
        owner_sddl = f'(A;CI;WO;;;{self.user_sid})'
        self.sd_utils.dacl_add_ace(ou_dn, owner_sddl)

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, user_dn)
        expected_rights = security.SECINFO_OWNER | security.SECINFO_GROUP
        self.assertEqual(expected_rights, effective_rights)

        # The update succeeds as admin when trying to specify another user.
        self.ldb_admin.modify(message, controls=owner_controls)

    def test_modify_owner_other_admin_computer(self):
        '''Show a domain admin cannot set the owner of a computer's security descriptor to another SID'''

        ou_name = 'test_modify_ou1'
        ou_dn = f'OU={ou_name},{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = Dn(self.ldb_admin, f'CN={account_name},{ou_dn}')

        sd_sddl = 'O:BA'
        descriptor = security.descriptor.from_sddl(sd_sddl, self.domain_sid)

        ou_sddl = f'D:(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_NT_SECURITY_DESCRIPTOR};;{self.user_sid})'
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, name=ou_name, sd=ou_desc)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
            'nTSecurityDescriptor': ndr_pack(descriptor),
        })

        # Try to modify the owner to someone other than ourselves.
        new_sddl = f'O:BA'
        new_desc = security.descriptor.from_sddl(new_sddl, self.domain_sid)

        owner_controls = [f'sd_flags:1:{security.SECINFO_OWNER}']

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, dn)
        expected_rights = None
        self.assertEqual(expected_rights, effective_rights)

        # The user should not be able to modify the owner.
        message = Message(dn)
        message['nTSecurityDescriptor'] = MessageElement(
            ndr_pack(new_desc),
            FLAG_MOD_REPLACE,
            'nTSecurityDescriptor')

        # Grant ourselves WRITE_OWNER.
        owner_sddl = f'(A;CI;WO;;;{self.user_sid})'
        self.sd_utils.dacl_add_ace(ou_dn, owner_sddl)

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, dn)
        expected_rights = None
        self.assertEqual(expected_rights, effective_rights)

        # The update succeeds as admin when trying to specify another user.
        self.ldb_admin.modify(message, controls=owner_controls)

    def test_modify_owner_admin_user(self):
        '''Show a domain admin can set the owner of a user's security descriptor to Domain Admins'''

        ou_name = 'test_modify_ou1'
        ou_dn = f'OU={ou_name},{self.base_dn}'

        username = 'test_modify_ou1_user'
        user_dn = Dn(self.ldb_admin, f'CN={username},{ou_dn}')

        sd_sddl = 'O:BA'
        descriptor = security.descriptor.from_sddl(sd_sddl, self.domain_sid)

        ou_sddl = f'D:(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_NT_SECURITY_DESCRIPTOR};;{self.user_sid})'
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, name=ou_name, sd=ou_desc)

        self.ldb_admin.newuser(username, self.user_pass,
                               userou=f'OU={ou_name}',
                               sd=descriptor)

        # Try to modify the owner to Domain Admins.
        new_sddl = f'O:DA'
        new_desc = security.descriptor.from_sddl(new_sddl, self.domain_sid)

        owner_controls = [f'sd_flags:1:{security.SECINFO_OWNER}']

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, user_dn)
        expected_rights = 0
        self.assertEqual(expected_rights, effective_rights)

        # The user should not be able to modify the owner.
        message = Message(user_dn)
        message['nTSecurityDescriptor'] = MessageElement(
            ndr_pack(new_desc),
            FLAG_MOD_REPLACE,
            'nTSecurityDescriptor')

        # Grant ourselves WRITE_OWNER.
        owner_sddl = f'(A;CI;WO;;;{self.user_sid})'
        self.sd_utils.dacl_add_ace(ou_dn, owner_sddl)

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, user_dn)
        expected_rights = security.SECINFO_OWNER | security.SECINFO_GROUP
        self.assertEqual(expected_rights, effective_rights)

        # The update succeeds as admin when specifying Domain Admins.
        self.ldb_admin.modify(message, controls=owner_controls)

    def test_modify_owner_admin_computer(self):
        '''Show a domain admin can set the owner of a computer's security descriptor to Domain Admins'''

        ou_name = 'test_modify_ou1'
        ou_dn = f'OU={ou_name},{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = Dn(self.ldb_admin, f'CN={account_name},{ou_dn}')

        sd_sddl = 'O:BA'
        descriptor = security.descriptor.from_sddl(sd_sddl, self.domain_sid)

        ou_sddl = f'D:(OA;CI;WP;{samba.dsdb.DS_GUID_SCHEMA_ATTR_NT_SECURITY_DESCRIPTOR};;{self.user_sid})'
        ou_desc = security.descriptor.from_sddl(ou_sddl, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, name=ou_name, sd=ou_desc)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
            'nTSecurityDescriptor': ndr_pack(descriptor),
        })

        # Try to modify the owner to Domain Admins.
        new_sddl = f'O:DA'
        new_desc = security.descriptor.from_sddl(new_sddl, self.domain_sid)

        owner_controls = [f'sd_flags:1:{security.SECINFO_OWNER}']

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, dn)
        expected_rights = None
        self.assertEqual(expected_rights, effective_rights)

        # The user should not be able to modify the owner.
        message = Message(dn)
        message['nTSecurityDescriptor'] = MessageElement(
            ndr_pack(new_desc),
            FLAG_MOD_REPLACE,
            'nTSecurityDescriptor')

        # Grant ourselves WRITE_OWNER.
        owner_sddl = f'(A;CI;WO;;;{self.user_sid})'
        self.sd_utils.dacl_add_ace(ou_dn, owner_sddl)

        # Check our effective rights.
        effective_rights = self.get_sd_rights_effective(self.ldb_user, dn)
        expected_rights = None
        self.assertEqual(expected_rights, effective_rights)

        # The update succeeds as admin when specifying Domain Admins.
        self.ldb_admin.modify(message, controls=owner_controls)

    def test_modify_anonymous(self):
        """Test add operation with anonymous user"""
        anonymous = SamDB(url=ldaphost, credentials=self.creds_tmp, lp=lp)
        self.ldb_admin.newuser("test_anonymous", "samba123@")
        m = Message()
        m.dn = Dn(anonymous, self.get_user_dn("test_anonymous"))

        m["description"] = MessageElement("sambauser2",
                                          FLAG_MOD_ADD,
                                          "description")
        try:
            anonymous.modify(m)
        except LdbError as e14:
            (num, _) = e14.args
            self.assertEqual(num, ERR_OPERATIONS_ERROR)
        else:
            self.fail()

    def test_modify_dns_host_name(self):
        '''Test modifying dNSHostName with validated write'''

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        # Grant Validated Write.
        mod = (f'(OA;CI;SW;{security.GUID_DRS_DNS_HOST_NAME};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
        })

        host_name = f'{account_name}.{self.ldb_user.domain_dns_name()}'

        m = Message(Dn(self.ldb_user, dn))
        m['dNSHostName'] = MessageElement(host_name,
                                          FLAG_MOD_REPLACE,
                                          'dNSHostName')
        try:
            self.ldb_user.modify(m)
        except LdbError:
            self.fail()

    def test_modify_dns_host_name_no_validated_write(self):
        '''Test modifying dNSHostName without validated write'''

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
        })

        host_name = f'{account_name}.{self.ldb_user.domain_dns_name()}'

        m = Message(Dn(self.ldb_user, dn))
        m['dNSHostName'] = MessageElement(host_name,
                                          FLAG_MOD_REPLACE,
                                          'dNSHostName')
        try:
            self.ldb_user.modify(m)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
        else:
            self.fail()

    def test_modify_dns_host_name_invalid(self):
        '''Test modifying dNSHostName to an invalid value'''

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        # Grant Validated Write.
        mod = (f'(OA;CI;SW;{security.GUID_DRS_DNS_HOST_NAME};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
        })

        host_name = 'invalid'

        m = Message(Dn(self.ldb_user, dn))
        m['dNSHostName'] = MessageElement(host_name,
                                          FLAG_MOD_REPLACE,
                                          'dNSHostName')
        try:
            self.ldb_user.modify(m)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_CONSTRAINT_VIOLATION, num)
        else:
            self.fail()

    def test_modify_dns_host_name_invalid_wp(self):
        '''Test modifying dNSHostName to an invalid value when we have WP'''

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        # Grant Write Property.
        mod = (f'(OA;CI;WP;{security.GUID_DRS_DNS_HOST_NAME};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
        })

        host_name = 'invalid'

        m = Message(Dn(self.ldb_user, dn))
        m['dNSHostName'] = MessageElement(host_name,
                                          FLAG_MOD_REPLACE,
                                          'dNSHostName')
        try:
            self.ldb_user.modify(m)
        except LdbError:
            self.fail()

    def test_modify_dns_host_name_invalid_non_computer(self):
        '''Test modifying dNSHostName to an invalid value on a non-computer'''

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        # Grant Validated Write.
        mod = (f'(OA;CI;SW;{security.GUID_DRS_DNS_HOST_NAME};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'user',
            'sAMAccountName': f'{account_name}',
        })

        host_name = 'invalid'

        m = Message(Dn(self.ldb_user, dn))
        m['dNSHostName'] = MessageElement(host_name,
                                          FLAG_MOD_REPLACE,
                                          'dNSHostName')
        try:
            self.ldb_user.modify(m)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_INSUFFICIENT_ACCESS_RIGHTS, num)
        else:
            self.fail()

    def test_modify_dns_host_name_no_value(self):
        '''Test modifying dNSHostName with validated write with no value'''

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        # Grant Validated Write.
        mod = (f'(OA;CI;SW;{security.GUID_DRS_DNS_HOST_NAME};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
        })

        m = Message(Dn(self.ldb_user, dn))
        m['dNSHostName'] = MessageElement([],
                                          FLAG_MOD_REPLACE,
                                          'dNSHostName')
        try:
            self.ldb_user.modify(m)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_OPERATIONS_ERROR, num)
        else:
            # Windows accepts this.
            pass

    def test_modify_dns_host_name_empty_string(self):
        '''Test modifying dNSHostName with validated write of an empty string'''

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        # Grant Validated Write.
        mod = (f'(OA;CI;SW;{security.GUID_DRS_DNS_HOST_NAME};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
        })

        m = Message(Dn(self.ldb_user, dn))
        m['dNSHostName'] = MessageElement('\0',
                                          FLAG_MOD_REPLACE,
                                          'dNSHostName')
        try:
            self.ldb_user.modify(m)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_CONSTRAINT_VIOLATION, num)
        else:
            self.fail()

    def test_modify_dns_host_name_dollar(self):
        '''Test modifying dNSHostName with validated write of a value including a dollar'''

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        # Grant Validated Write.
        mod = (f'(OA;CI;SW;{security.GUID_DRS_DNS_HOST_NAME};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
        })

        host_name = f'{account_name}$.{self.ldb_user.domain_dns_name()}'

        m = Message(Dn(self.ldb_user, dn))
        m['dNSHostName'] = MessageElement(host_name,
                                          FLAG_MOD_REPLACE,
                                          'dNSHostName')
        try:
            self.ldb_user.modify(m)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_CONSTRAINT_VIOLATION, num)
        else:
            self.fail()

    def test_modify_dns_host_name_account_no_dollar(self):
        '''Test modifying dNSHostName with validated write with no dollar in sAMAccountName'''

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        # Grant Validated Write.
        mod = (f'(OA;CI;SW;{security.GUID_DRS_DNS_HOST_NAME};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}',
        })

        host_name = f'{account_name}.{self.ldb_user.domain_dns_name()}'

        m = Message(Dn(self.ldb_user, dn))
        m['dNSHostName'] = MessageElement(host_name,
                                          FLAG_MOD_REPLACE,
                                          'dNSHostName')
        try:
            self.ldb_user.modify(m)
        except LdbError:
            self.fail()

    def test_modify_dns_host_name_no_suffix(self):
        '''Test modifying dNSHostName with validated write of a value missing the suffix'''

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        # Grant Validated Write.
        mod = (f'(OA;CI;SW;{security.GUID_DRS_DNS_HOST_NAME};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
        })

        host_name = f'{account_name}'

        m = Message(Dn(self.ldb_user, dn))
        m['dNSHostName'] = MessageElement(host_name,
                                          FLAG_MOD_REPLACE,
                                          'dNSHostName')
        try:
            self.ldb_user.modify(m)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_CONSTRAINT_VIOLATION, num)
        else:
            self.fail()

    def test_modify_dns_host_name_wrong_prefix(self):
        '''Test modifying dNSHostName with validated write of a value with the wrong prefix'''

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        # Grant Validated Write.
        mod = (f'(OA;CI;SW;{security.GUID_DRS_DNS_HOST_NAME};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
        })

        host_name = f'invalid.{self.ldb_user.domain_dns_name()}'

        m = Message(Dn(self.ldb_user, dn))
        m['dNSHostName'] = MessageElement(host_name,
                                          FLAG_MOD_REPLACE,
                                          'dNSHostName')
        try:
            self.ldb_user.modify(m)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_CONSTRAINT_VIOLATION, num)
        else:
            self.fail()

    def test_modify_dns_host_name_wrong_suffix(self):
        '''Test modifying dNSHostName with validated write of a value with the wrong suffix'''

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        # Grant Validated Write.
        mod = (f'(OA;CI;SW;{security.GUID_DRS_DNS_HOST_NAME};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
        })

        host_name = f'{account_name}.invalid.example.com'

        m = Message(Dn(self.ldb_user, dn))
        m['dNSHostName'] = MessageElement(host_name,
                                          FLAG_MOD_REPLACE,
                                          'dNSHostName')
        try:
            self.ldb_user.modify(m)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_CONSTRAINT_VIOLATION, num)
        else:
            self.fail()

    def test_modify_dns_host_name_case(self):
        '''Test modifying dNSHostName with validated write of a value with irregular case'''

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        # Grant Validated Write.
        mod = (f'(OA;CI;SW;{security.GUID_DRS_DNS_HOST_NAME};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
        })

        host_name = f'{account_name}.{self.ldb_user.domain_dns_name()}'
        host_name = host_name.capitalize()

        m = Message(Dn(self.ldb_user, dn))
        m['dNSHostName'] = MessageElement(host_name,
                                          FLAG_MOD_REPLACE,
                                          'dNSHostName')
        try:
            self.ldb_user.modify(m)
        except LdbError:
            self.fail()

    def test_modify_dns_host_name_allowed_suffixes(self):
        '''Test modifying dNSHostName with validated write and an allowed suffix'''

        allowed_suffix = 'suffix.that.is.allowed'

        # Add the allowed suffix.

        res = self.ldb_admin.search(self.base_dn,
                                    scope=SCOPE_BASE,
                                    attrs=['msDS-AllowedDNSSuffixes'])
        self.assertEqual(1, len(res))
        old_allowed_suffixes = res[0].get('msDS-AllowedDNSSuffixes')

        def modify_allowed_suffixes(suffixes):
            if suffixes is None:
                suffixes = []
                flag = FLAG_MOD_DELETE
            else:
                flag = FLAG_MOD_REPLACE

            m = Message(Dn(self.ldb_admin, self.base_dn))
            m['msDS-AllowedDNSSuffixes'] = MessageElement(
                suffixes,
                flag,
                'msDS-AllowedDNSSuffixes')
            self.ldb_admin.modify(m)

        self.addCleanup(modify_allowed_suffixes, old_allowed_suffixes)

        if old_allowed_suffixes is None:
            allowed_suffixes = []
        else:
            allowed_suffixes = list(old_allowed_suffixes)

        if (allowed_suffix not in allowed_suffixes and
            allowed_suffix.encode('utf-8') not in allowed_suffixes):
                allowed_suffixes.append(allowed_suffix)

        modify_allowed_suffixes(allowed_suffixes)

        # Create the account and run the test.

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        # Grant Validated Write.
        mod = (f'(OA;CI;SW;{security.GUID_DRS_DNS_HOST_NAME};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
        })

        host_name = f'{account_name}.{allowed_suffix}'

        m = Message(Dn(self.ldb_user, dn))
        m['dNSHostName'] = MessageElement(host_name,
                                          FLAG_MOD_REPLACE,
                                          'dNSHostName')
        try:
            self.ldb_user.modify(m)
        except LdbError:
            self.fail()

    def test_modify_dns_host_name_spn(self):
        '''Test modifying dNSHostName and SPN with validated write'''

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        # Grant Validated Write.
        mod = (f'(OA;CI;SW;{security.GUID_DRS_DNS_HOST_NAME};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        mod = (f'(OA;CI;SW;{security.GUID_DRS_VALIDATE_SPN};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
        })

        host_name = f'{account_name}.{self.ldb_user.domain_dns_name()}'
        spn = f'host/{host_name}'

        m = Message(Dn(self.ldb_user, dn))
        m['0'] = MessageElement(host_name,
                                FLAG_MOD_REPLACE,
                                'dNSHostName')
        m['1'] = MessageElement(spn,
                                FLAG_MOD_ADD,
                                'servicePrincipalName')
        try:
            self.ldb_user.modify(m)
        except LdbError:
            self.fail()

    def test_modify_spn_matching_dns_host_name_invalid(self):
        '''Test modifying SPN with validated write, matching a valid dNSHostName '''

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        # Grant Write Property.
        mod = (f'(OA;CI;WP;{security.GUID_DRS_DNS_HOST_NAME};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        # Grant Validated Write.
        mod = (f'(OA;CI;SW;{security.GUID_DRS_VALIDATE_SPN};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
        })

        invalid_host_name = 'invalid'

        host_name = f'{account_name}.{self.ldb_user.domain_dns_name()}'
        spn = f'host/{host_name}'

        m = Message(Dn(self.ldb_user, dn))
        m['0'] = MessageElement(invalid_host_name,
                                FLAG_MOD_REPLACE,
                                'dNSHostName')
        m['1'] = MessageElement(spn,
                                FLAG_MOD_ADD,
                                'servicePrincipalName')
        m['2'] = MessageElement(host_name,
                                FLAG_MOD_REPLACE,
                                'dNSHostName')
        try:
            self.ldb_user.modify(m)
        except LdbError:
            self.fail()

    def test_modify_spn_matching_dns_host_name_original(self):
        '''Test modifying SPN with validated write, matching the original dNSHostName '''

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        # Grant Validated Write.
        mod = (f'(OA;CI;SW;{security.GUID_DRS_DNS_HOST_NAME};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        mod = (f'(OA;CI;SW;{security.GUID_DRS_VALIDATE_SPN};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)

        original_host_name = 'invalid_host_name'
        original_spn = 'host/{original_host_name}'

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
            'dNSHostName': original_host_name,
        })

        host_name = f'{account_name}.{self.ldb_user.domain_dns_name()}'

        m = Message(Dn(self.ldb_user, dn))
        m['0'] = MessageElement(original_spn,
                                FLAG_MOD_ADD,
                                'servicePrincipalName')
        m['1'] = MessageElement(host_name,
                                FLAG_MOD_REPLACE,
                                'dNSHostName')
        try:
            self.ldb_user.modify(m)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_CONSTRAINT_VIOLATION, num)
        else:
            self.fail()

    def test_modify_dns_host_name_spn_matching_account_name_original(self):
        '''Test modifying dNSHostName and SPN with validated write, matching the original sAMAccountName'''

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        sam_account_name = '3e0abfd0-126a-11d0-a060-00aa006c33ed'

        # Grant Write Property.
        mod = (f'(OA;CI;WP;{sam_account_name};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        # Grant Validated Write.
        mod = (f'(OA;CI;SW;{security.GUID_DRS_DNS_HOST_NAME};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        mod = (f'(OA;CI;SW;{security.GUID_DRS_VALIDATE_SPN};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
        })

        new_account_name = 'test_mod_hostname2'
        host_name = f'{account_name}.{self.ldb_user.domain_dns_name()}'
        spn = f'host/{host_name}'

        m = Message(Dn(self.ldb_user, dn))
        m['0'] = MessageElement(host_name,
                                FLAG_MOD_REPLACE,
                                'dNSHostName')
        m['1'] = MessageElement(spn,
                                FLAG_MOD_ADD,
                                'servicePrincipalName')
        m['2'] = MessageElement(f'{new_account_name}$',
                                FLAG_MOD_REPLACE,
                                'sAMAccountName')
        try:
            self.ldb_user.modify(m)
        except LdbError as err:
            num, estr = err.args
            self.assertEqual(ERR_CONSTRAINT_VIOLATION, num)
        else:
            self.fail()

    def test_modify_dns_host_name_spn_matching_account_name_new(self):
        '''Test modifying dNSHostName and SPN with validated write, matching the new sAMAccountName'''

        ou_dn = f'OU=test_modify_ou1,{self.base_dn}'

        account_name = 'test_mod_hostname'
        dn = f'CN={account_name},{ou_dn}'

        self.ldb_admin.create_ou(ou_dn)

        sam_account_name = '3e0abfd0-126a-11d0-a060-00aa006c33ed'

        # Grant Write Property.
        mod = (f'(OA;CI;WP;{sam_account_name};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        # Grant Validated Write.
        mod = (f'(OA;CI;SW;{security.GUID_DRS_DNS_HOST_NAME};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        mod = (f'(OA;CI;SW;{security.GUID_DRS_VALIDATE_SPN};;'
               f'{self.user_sid})')
        self.sd_utils.dacl_add_ace(ou_dn, mod)

        # Create the account.
        self.ldb_admin.add({
            'dn': dn,
            'objectClass': 'computer',
            'sAMAccountName': f'{account_name}$',
        })

        new_account_name = 'test_mod_hostname2'
        new_host_name = f'{new_account_name}.{self.ldb_user.domain_dns_name()}'
        new_spn = f'host/{new_host_name}'

        m = Message(Dn(self.ldb_user, dn))
        m['0'] = MessageElement(new_spn,
                                FLAG_MOD_ADD,
                                'servicePrincipalName')
        m['1'] = MessageElement(new_host_name,
                                FLAG_MOD_REPLACE,
                                'dNSHostName')
        m['2'] = MessageElement(f'{new_account_name}$',
                                FLAG_MOD_REPLACE,
                                'sAMAccountName')
        try:
            self.ldb_user.modify(m)
        except LdbError:
            self.fail()

# enable these when we have search implemented


class AclSearchTests(AclTests):

    def setUp(self):
        super(AclSearchTests, self).setUp()

        # permit password changes during this test
        PasswordCommon.allow_password_changes(self, self.ldb_admin)

        self.u1 = "search_u1"
        self.u2 = "search_u2"
        self.u3 = "search_u3"
        self.group1 = "group1"
        self.ldb_admin.newuser(self.u1, self.user_pass)
        self.ldb_admin.newuser(self.u2, self.user_pass)
        self.ldb_admin.newuser(self.u3, self.user_pass)
        self.ldb_admin.newgroup(self.group1, grouptype=samba.dsdb.GTYPE_SECURITY_GLOBAL_GROUP)
        self.ldb_admin.add_remove_group_members(self.group1, [self.u2],
                                                add_members_operation=True)
        self.ldb_user = self.get_ldb_connection(self.u1, self.user_pass)
        self.ldb_user2 = self.get_ldb_connection(self.u2, self.user_pass)
        self.ldb_user3 = self.get_ldb_connection(self.u3, self.user_pass)
        self.full_list = [Dn(self.ldb_admin, "OU=ou2,OU=ou1," + self.base_dn),
                          Dn(self.ldb_admin, "OU=ou1," + self.base_dn),
                          Dn(self.ldb_admin, "OU=ou3,OU=ou2,OU=ou1," + self.base_dn),
                          Dn(self.ldb_admin, "OU=ou4,OU=ou2,OU=ou1," + self.base_dn),
                          Dn(self.ldb_admin, "OU=ou5,OU=ou3,OU=ou2,OU=ou1," + self.base_dn),
                          Dn(self.ldb_admin, "OU=ou6,OU=ou4,OU=ou2,OU=ou1," + self.base_dn)]
        self.user_sid = self.sd_utils.get_object_sid(self.get_user_dn(self.u1))
        self.group_sid = self.sd_utils.get_object_sid(self.get_user_dn(self.group1))

    def create_clean_ou(self, object_dn):
        """ Base repeating setup for unittests to follow """
        res = self.ldb_admin.search(base=self.base_dn, scope=SCOPE_SUBTREE,
                                    expression="distinguishedName=%s" % object_dn)
        # Make sure top testing OU has been deleted before starting the test
        self.assertEqual(len(res), 0)
        self.ldb_admin.create_ou(object_dn)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        # Make sure there are inheritable ACEs initially
        self.assertTrue("CI" in desc_sddl or "OI" in desc_sddl)
        # Find and remove all inherit ACEs
        res = re.findall(r"\(.*?\)", desc_sddl)
        res = [x for x in res if ("CI" in x) or ("OI" in x)]
        for x in res:
            desc_sddl = desc_sddl.replace(x, "")
        # Add flag 'protected' in both DACL and SACL so no inherit ACEs
        # can propagate from above
        # remove SACL, we are not interested
        desc_sddl = desc_sddl.replace(":AI", ":AIP")
        self.sd_utils.modify_sd_on_dn(object_dn, desc_sddl)
        # Verify all inheritable ACEs are gone
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        self.assertNotIn("CI", desc_sddl)
        self.assertNotIn("OI", desc_sddl)

    def tearDown(self):
        super(AclSearchTests, self).tearDown()
        delete_force(self.ldb_admin, "OU=test_search_ou2,OU=test_search_ou1," + self.base_dn)
        delete_force(self.ldb_admin, "OU=test_search_ou1," + self.base_dn)
        delete_force(self.ldb_admin, "OU=ou6,OU=ou4,OU=ou2,OU=ou1," + self.base_dn)
        delete_force(self.ldb_admin, "OU=ou5,OU=ou3,OU=ou2,OU=ou1," + self.base_dn)
        delete_force(self.ldb_admin, "OU=ou4,OU=ou2,OU=ou1," + self.base_dn)
        delete_force(self.ldb_admin, "OU=ou3,OU=ou2,OU=ou1," + self.base_dn)
        delete_force(self.ldb_admin, "OU=ou2,OU=ou1," + self.base_dn)
        delete_force(self.ldb_admin, "OU=ou1," + self.base_dn)
        delete_force(self.ldb_admin, self.get_user_dn("search_u1"))
        delete_force(self.ldb_admin, self.get_user_dn("search_u2"))
        delete_force(self.ldb_admin, self.get_user_dn("search_u3"))
        delete_force(self.ldb_admin, self.get_user_dn("group1"))

        del self.ldb_user
        del self.ldb_user2
        del self.ldb_user3

    def test_search_anonymous1(self):
        """Verify access of rootDSE with the correct request"""
        anonymous = SamDB(url=ldaphost, credentials=self.creds_tmp, lp=lp)
        res = anonymous.search("", expression="(objectClass=*)", scope=SCOPE_BASE)
        self.assertEqual(len(res), 1)
        # verify some of the attributes
        # don't care about values
        self.assertIn("ldapServiceName", res[0])
        self.assertIn("namingContexts", res[0])
        self.assertIn("isSynchronized", res[0])
        self.assertIn("dsServiceName", res[0])
        self.assertIn("supportedSASLMechanisms", res[0])
        self.assertIn("isGlobalCatalogReady", res[0])
        self.assertIn("domainControllerFunctionality", res[0])
        self.assertIn("serverName", res[0])

    def test_search_anonymous2(self):
        """Make sure we cannot access anything else"""
        anonymous = SamDB(url=ldaphost, credentials=self.creds_tmp, lp=lp)
        try:
            anonymous.search("", expression="(objectClass=*)", scope=SCOPE_SUBTREE)
        except LdbError as e15:
            (num, _) = e15.args
            self.assertEqual(num, ERR_OPERATIONS_ERROR)
        else:
            self.fail()
        try:
            anonymous.search(self.base_dn, expression="(objectClass=*)", scope=SCOPE_SUBTREE)
        except LdbError as e16:
            (num, _) = e16.args
            self.assertEqual(num, ERR_OPERATIONS_ERROR)
        else:
            self.fail()
        try:
            anonymous.search(anonymous.get_config_basedn(), expression="(objectClass=*)",
                             scope=SCOPE_SUBTREE)
        except LdbError as e17:
            (num, _) = e17.args
            self.assertEqual(num, ERR_OPERATIONS_ERROR)
        else:
            self.fail()

    def test_search_anonymous3(self):
        """Set dsHeuristics and repeat"""
        self.ldb_admin.set_dsheuristics("0000002")
        self.ldb_admin.create_ou("OU=test_search_ou1," + self.base_dn)
        mod = "(A;CI;LC;;;AN)"
        self.sd_utils.dacl_add_ace("OU=test_search_ou1," + self.base_dn, mod)
        self.ldb_admin.create_ou("OU=test_search_ou2,OU=test_search_ou1," + self.base_dn)
        anonymous = SamDB(url=ldaphost, credentials=self.creds_tmp, lp=lp)
        res = anonymous.search("OU=test_search_ou2,OU=test_search_ou1," + self.base_dn,
                               expression="(objectClass=*)", scope=SCOPE_SUBTREE)
        self.assertEqual(len(res), 1)
        self.assertIn("dn", res[0])
        self.assertEqual(res[0]["dn"], Dn(self.ldb_admin,
                                          "OU=test_search_ou2,OU=test_search_ou1," + self.base_dn))
        res = anonymous.search(anonymous.get_config_basedn(), expression="(objectClass=*)",
                               scope=SCOPE_SUBTREE)
        self.assertEqual(len(res), 1)
        self.assertIn("dn", res[0])
        self.assertEqual(res[0]["dn"], Dn(self.ldb_admin, self.configuration_dn))

    def test_search1(self):
        """Make sure users can see us if given LC to user and group"""
        self.create_clean_ou("OU=ou1," + self.base_dn)
        mod = "(A;;LC;;;%s)(A;;LC;;;%s)" % (str(self.user_sid), str(self.group_sid))
        self.sd_utils.dacl_add_ace("OU=ou1," + self.base_dn, mod)
        tmp_desc = security.descriptor.from_sddl("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)" + mod,
                                                 self.domain_sid)
        self.ldb_admin.create_ou("OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)
        self.ldb_admin.create_ou("OU=ou3,OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)
        self.ldb_admin.create_ou("OU=ou4,OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)
        self.ldb_admin.create_ou("OU=ou5,OU=ou3,OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)
        self.ldb_admin.create_ou("OU=ou6,OU=ou4,OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)

        # regular users must see only ou1 and ou2
        res = self.ldb_user3.search("OU=ou1," + self.base_dn, expression="(objectClass=*)",
                                    scope=SCOPE_SUBTREE)
        self.assertEqual(len(res), 2)
        ok_list = [Dn(self.ldb_admin, "OU=ou2,OU=ou1," + self.base_dn),
                   Dn(self.ldb_admin, "OU=ou1," + self.base_dn)]

        res_list = [x["dn"] for x in res if x["dn"] in ok_list]
        self.assertEqual(sorted(res_list), sorted(ok_list))

        # these users should see all ous
        res = self.ldb_user.search("OU=ou1," + self.base_dn, expression="(objectClass=*)",
                                   scope=SCOPE_SUBTREE)
        self.assertEqual(len(res), 6)
        res_list = [x["dn"] for x in res if x["dn"] in self.full_list]
        self.assertEqual(sorted(res_list), sorted(self.full_list))

        res = self.ldb_user2.search("OU=ou1," + self.base_dn, expression="(objectClass=*)",
                                    scope=SCOPE_SUBTREE)
        self.assertEqual(len(res), 6)
        res_list = [x["dn"] for x in res if x["dn"] in self.full_list]
        self.assertEqual(sorted(res_list), sorted(self.full_list))

    def test_search2(self):
        """Make sure users can't see us if access is explicitly denied"""
        self.create_clean_ou("OU=ou1," + self.base_dn)
        self.ldb_admin.create_ou("OU=ou2,OU=ou1," + self.base_dn)
        self.ldb_admin.create_ou("OU=ou3,OU=ou2,OU=ou1," + self.base_dn)
        self.ldb_admin.create_ou("OU=ou4,OU=ou2,OU=ou1," + self.base_dn)
        self.ldb_admin.create_ou("OU=ou5,OU=ou3,OU=ou2,OU=ou1," + self.base_dn)
        self.ldb_admin.create_ou("OU=ou6,OU=ou4,OU=ou2,OU=ou1," + self.base_dn)
        mod = "(D;;LC;;;%s)(D;;LC;;;%s)" % (str(self.user_sid), str(self.group_sid))
        self.sd_utils.dacl_add_ace("OU=ou2,OU=ou1," + self.base_dn, mod)
        res = self.ldb_user3.search("OU=ou1," + self.base_dn, expression="(objectClass=*)",
                                    scope=SCOPE_SUBTREE)
        # this user should see all ous
        res_list = [x["dn"] for x in res if x["dn"] in self.full_list]
        self.assertEqual(sorted(res_list), sorted(self.full_list))

        # these users should see ou1, 2, 5 and 6 but not 3 and 4
        res = self.ldb_user.search("OU=ou1," + self.base_dn, expression="(objectClass=*)",
                                   scope=SCOPE_SUBTREE)
        ok_list = [Dn(self.ldb_admin, "OU=ou2,OU=ou1," + self.base_dn),
                   Dn(self.ldb_admin, "OU=ou1," + self.base_dn),
                   Dn(self.ldb_admin, "OU=ou5,OU=ou3,OU=ou2,OU=ou1," + self.base_dn),
                   Dn(self.ldb_admin, "OU=ou6,OU=ou4,OU=ou2,OU=ou1," + self.base_dn)]
        res_list = [x["dn"] for x in res if x["dn"] in ok_list]
        self.assertEqual(sorted(res_list), sorted(ok_list))

        res = self.ldb_user2.search("OU=ou1," + self.base_dn, expression="(objectClass=*)",
                                    scope=SCOPE_SUBTREE)
        self.assertEqual(len(res), 4)
        res_list = [x["dn"] for x in res if x["dn"] in ok_list]
        self.assertEqual(sorted(res_list), sorted(ok_list))

    def test_search3(self):
        """Make sure users can't see ous if access is explicitly denied - 2"""
        self.create_clean_ou("OU=ou1," + self.base_dn)
        mod = "(A;CI;LC;;;%s)(A;CI;LC;;;%s)" % (str(self.user_sid), str(self.group_sid))
        self.sd_utils.dacl_add_ace("OU=ou1," + self.base_dn, mod)
        tmp_desc = security.descriptor.from_sddl("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)" + mod,
                                                 self.domain_sid)
        self.ldb_admin.create_ou("OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)
        self.ldb_admin.create_ou("OU=ou3,OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)
        self.ldb_admin.create_ou("OU=ou4,OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)
        self.ldb_admin.create_ou("OU=ou5,OU=ou3,OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)
        self.ldb_admin.create_ou("OU=ou6,OU=ou4,OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)

        print("Testing correct behavior on nonaccessible search base")
        try:
            self.ldb_user3.search("OU=ou3,OU=ou2,OU=ou1," + self.base_dn, expression="(objectClass=*)",
                                  scope=SCOPE_BASE)
        except LdbError as e18:
            (num, _) = e18.args
            self.assertEqual(num, ERR_NO_SUCH_OBJECT)
        else:
            self.fail()

        mod = "(D;;LC;;;%s)(D;;LC;;;%s)" % (str(self.user_sid), str(self.group_sid))
        self.sd_utils.dacl_add_ace("OU=ou2,OU=ou1," + self.base_dn, mod)

        ok_list = [Dn(self.ldb_admin, "OU=ou2,OU=ou1," + self.base_dn),
                   Dn(self.ldb_admin, "OU=ou1," + self.base_dn)]

        res = self.ldb_user3.search("OU=ou1," + self.base_dn, expression="(objectClass=*)",
                                    scope=SCOPE_SUBTREE)
        res_list = [x["dn"] for x in res if x["dn"] in ok_list]
        self.assertEqual(sorted(res_list), sorted(ok_list))

        ok_list = [Dn(self.ldb_admin, "OU=ou2,OU=ou1," + self.base_dn),
                   Dn(self.ldb_admin, "OU=ou1," + self.base_dn),
                   Dn(self.ldb_admin, "OU=ou5,OU=ou3,OU=ou2,OU=ou1," + self.base_dn),
                   Dn(self.ldb_admin, "OU=ou6,OU=ou4,OU=ou2,OU=ou1," + self.base_dn)]

        # should not see ou3 and ou4, but should see ou5 and ou6
        res = self.ldb_user.search("OU=ou1," + self.base_dn, expression="(objectClass=*)",
                                   scope=SCOPE_SUBTREE)
        self.assertEqual(len(res), 4)
        res_list = [x["dn"] for x in res if x["dn"] in ok_list]
        self.assertEqual(sorted(res_list), sorted(ok_list))

        res = self.ldb_user2.search("OU=ou1," + self.base_dn, expression="(objectClass=*)",
                                    scope=SCOPE_SUBTREE)
        self.assertEqual(len(res), 4)
        res_list = [x["dn"] for x in res if x["dn"] in ok_list]
        self.assertEqual(sorted(res_list), sorted(ok_list))

    def test_search4(self):
        """There is no difference in visibility if the user is also creator"""
        self.create_clean_ou("OU=ou1," + self.base_dn)
        mod = "(A;CI;CCWD;;;%s)" % (str(self.user_sid))
        self.sd_utils.dacl_add_ace("OU=ou1," + self.base_dn, mod)
        tmp_desc = security.descriptor.from_sddl("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)" + mod,
                                                 self.domain_sid)
        self.ldb_user.create_ou("OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)
        self.ldb_user.create_ou("OU=ou3,OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)
        self.ldb_user.create_ou("OU=ou4,OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)
        self.ldb_user.create_ou("OU=ou5,OU=ou3,OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)
        self.ldb_user.create_ou("OU=ou6,OU=ou4,OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)

        ok_list = [Dn(self.ldb_admin, "OU=ou2,OU=ou1," + self.base_dn),
                   Dn(self.ldb_admin, "OU=ou1," + self.base_dn)]
        res = self.ldb_user3.search("OU=ou1," + self.base_dn, expression="(objectClass=*)",
                                    scope=SCOPE_SUBTREE)
        self.assertEqual(len(res), 2)
        res_list = [x["dn"] for x in res if x["dn"] in ok_list]
        self.assertEqual(sorted(res_list), sorted(ok_list))

        res = self.ldb_user.search("OU=ou1," + self.base_dn, expression="(objectClass=*)",
                                   scope=SCOPE_SUBTREE)
        self.assertEqual(len(res), 2)
        res_list = [x["dn"] for x in res if x["dn"] in ok_list]
        self.assertEqual(sorted(res_list), sorted(ok_list))

    def test_search5(self):
        """Make sure users can see only attributes they are allowed to see"""
        self.create_clean_ou("OU=ou1," + self.base_dn)
        mod = "(A;CI;LC;;;%s)" % (str(self.user_sid))
        self.sd_utils.dacl_add_ace("OU=ou1," + self.base_dn, mod)
        tmp_desc = security.descriptor.from_sddl("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)" + mod,
                                                 self.domain_sid)
        self.ldb_admin.create_ou("OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)
        # assert user can only see dn
        res = self.ldb_user.search("OU=ou2,OU=ou1," + self.base_dn, expression="(objectClass=*)",
                                   scope=SCOPE_SUBTREE)
        ok_list = ['dn']
        self.assertEqual(len(res), 1)
        res_list = list(res[0].keys())
        self.assertEqual(res_list, ok_list)

        res = self.ldb_user.search("OU=ou2,OU=ou1," + self.base_dn, expression="(objectClass=*)",
                                   scope=SCOPE_BASE, attrs=["ou"])

        self.assertEqual(len(res), 1)
        res_list = list(res[0].keys())
        self.assertEqual(res_list, ok_list)

        # give read property on ou and assert user can only see dn and ou
        mod = "(OA;;RP;bf9679f0-0de6-11d0-a285-00aa003049e2;;%s)" % (str(self.user_sid))
        self.sd_utils.dacl_add_ace("OU=ou1," + self.base_dn, mod)
        self.sd_utils.dacl_add_ace("OU=ou2,OU=ou1," + self.base_dn, mod)
        res = self.ldb_user.search("OU=ou2,OU=ou1," + self.base_dn, expression="(objectClass=*)",
                                   scope=SCOPE_SUBTREE)
        ok_list = ['dn', 'ou']
        self.assertEqual(len(res), 1)
        res_list = list(res[0].keys())
        self.assertEqual(sorted(res_list), sorted(ok_list))

        # give read property on Public Information and assert user can see ou and other members
        mod = "(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;%s)" % (str(self.user_sid))
        self.sd_utils.dacl_add_ace("OU=ou1," + self.base_dn, mod)
        self.sd_utils.dacl_add_ace("OU=ou2,OU=ou1," + self.base_dn, mod)
        res = self.ldb_user.search("OU=ou2,OU=ou1," + self.base_dn, expression="(objectClass=*)",
                                   scope=SCOPE_SUBTREE)

        ok_list = ['dn', 'objectClass', 'ou', 'distinguishedName', 'name', 'objectGUID', 'objectCategory']
        res_list = list(res[0].keys())
        self.assertEqual(sorted(res_list), sorted(ok_list))

    def test_search6(self):
        """If an attribute that cannot be read is used in a filter, it is as if the attribute does not exist"""
        self.create_clean_ou("OU=ou1," + self.base_dn)
        mod = "(A;CI;LCCCWD;;;%s)" % (str(self.user_sid))
        self.sd_utils.dacl_add_ace("OU=ou1," + self.base_dn, mod)
        tmp_desc = security.descriptor.from_sddl("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)" + mod,
                                                 self.domain_sid)
        self.ldb_admin.create_ou("OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)
        self.ldb_user.create_ou("OU=ou3,OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)

        res = self.ldb_user.search("OU=ou1," + self.base_dn, expression="(ou=ou3)",
                                   scope=SCOPE_SUBTREE)
        # nothing should be returned as ou is not accessible
        self.assertEqual(len(res), 0)

        # give read property on ou and assert user can only see dn and ou
        mod = "(OA;;RP;bf9679f0-0de6-11d0-a285-00aa003049e2;;%s)" % (str(self.user_sid))
        self.sd_utils.dacl_add_ace("OU=ou3,OU=ou2,OU=ou1," + self.base_dn, mod)
        res = self.ldb_user.search("OU=ou1," + self.base_dn, expression="(ou=ou3)",
                                   scope=SCOPE_SUBTREE)
        self.assertEqual(len(res), 1)
        ok_list = ['dn', 'ou']
        res_list = list(res[0].keys())
        self.assertEqual(sorted(res_list), sorted(ok_list))

        # give read property on Public Information and assert user can see ou and other members
        mod = "(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;%s)" % (str(self.user_sid))
        self.sd_utils.dacl_add_ace("OU=ou2,OU=ou1," + self.base_dn, mod)
        res = self.ldb_user.search("OU=ou1," + self.base_dn, expression="(ou=ou2)",
                                   scope=SCOPE_SUBTREE)
        self.assertEqual(len(res), 1)
        ok_list = ['dn', 'objectClass', 'ou', 'distinguishedName', 'name', 'objectGUID', 'objectCategory']
        res_list = list(res[0].keys())
        self.assertEqual(sorted(res_list), sorted(ok_list))

    def assert_search_on_attr(self, dn, samdb, attr, expected_list):

        expected_num = len(expected_list)
        res = samdb.search(dn, expression="(%s=*)" % attr, scope=SCOPE_SUBTREE)
        self.assertEqual(len(res), expected_num)

        res_list = [ x["dn"] for x in res if x["dn"] in expected_list ]
        self.assertEqual(sorted(res_list), sorted(expected_list))

    def test_search7(self):
        """Checks object search visibility when users don't have full rights"""
        self.create_clean_ou("OU=ou1," + self.base_dn)
        mod = "(A;;LC;;;%s)(A;;LC;;;%s)" % (str(self.user_sid),
                                            str(self.group_sid))
        self.sd_utils.dacl_add_ace("OU=ou1," + self.base_dn, mod)
        tmp_desc = security.descriptor.from_sddl("D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)" + mod,
                                                 self.domain_sid)
        self.ldb_admin.create_ou("OU=ou2,OU=ou1," + self.base_dn, sd=tmp_desc)
        self.ldb_admin.create_ou("OU=ou3,OU=ou2,OU=ou1," + self.base_dn,
                                 sd=tmp_desc)
        self.ldb_admin.create_ou("OU=ou4,OU=ou2,OU=ou1," + self.base_dn,
                                 sd=tmp_desc)
        self.ldb_admin.create_ou("OU=ou5,OU=ou3,OU=ou2,OU=ou1," + self.base_dn,
                                 sd=tmp_desc)
        self.ldb_admin.create_ou("OU=ou6,OU=ou4,OU=ou2,OU=ou1," + self.base_dn,
                                 sd=tmp_desc)

        ou2_dn = Dn(self.ldb_admin,  "OU=ou2,OU=ou1," + self.base_dn)
        ou1_dn = Dn(self.ldb_admin,  "OU=ou1," + self.base_dn)

        # even though unprivileged users can't read these attributes for OU2,
        # the object should still be visible in searches, because they have
        # 'List Contents' rights still. This isn't really disclosive because
        # ALL objects have these attributes
        visible_attrs = ["objectClass", "distinguishedName", "name",
                         "objectGUID"]
        two_objects = [ou2_dn, ou1_dn]

        for attr in visible_attrs:
            # a regular user should just see the 2 objects
            self.assert_search_on_attr(str(ou1_dn), self.ldb_user3, attr,
                                       expected_list=two_objects)

            # whereas the following users have LC rights for all the objects,
            # so they should see them all
            self.assert_search_on_attr(str(ou1_dn), self.ldb_user, attr,
                                       expected_list=self.full_list)
            self.assert_search_on_attr(str(ou1_dn), self.ldb_user2, attr,
                                       expected_list=self.full_list)

        # however when searching on the following attributes, objects will not
        # be visible unless the user has Read Property rights
        hidden_attrs = ["objectCategory", "instanceType", "ou", "uSNChanged",
                        "uSNCreated", "whenCreated"]
        one_object = [ou1_dn]

        for attr in hidden_attrs:
            self.assert_search_on_attr(str(ou1_dn), self.ldb_user3, attr,
                                       expected_list=one_object)
            self.assert_search_on_attr(str(ou1_dn), self.ldb_user, attr,
                                       expected_list=one_object)
            self.assert_search_on_attr(str(ou1_dn), self.ldb_user2, attr,
                                       expected_list=one_object)

            # admin has RP rights so can still see all the objects
            self.assert_search_on_attr(str(ou1_dn), self.ldb_admin, attr,
                                       expected_list=self.full_list)


# tests on ldap delete operations


class AclDeleteTests(AclTests):

    def setUp(self):
        super(AclDeleteTests, self).setUp()
        self.regular_user = "acl_delete_user1"
        # Create regular user
        self.ldb_admin.newuser(self.regular_user, self.user_pass)
        self.ldb_user = self.get_ldb_connection(self.regular_user, self.user_pass)

    def tearDown(self):
        super(AclDeleteTests, self).tearDown()
        delete_force(self.ldb_admin, self.get_user_dn("test_delete_user1"))
        delete_force(self.ldb_admin, self.get_user_dn(self.regular_user))
        delete_force(self.ldb_admin, self.get_user_dn("test_anonymous"))

        del self.ldb_user

    def test_delete_u1(self):
        """User is prohibited by default to delete another User object"""
        # Create user that we try to delete
        self.ldb_admin.newuser("test_delete_user1", self.user_pass)
        # Here delete User object should ALWAYS through exception
        try:
            self.ldb_user.delete(self.get_user_dn("test_delete_user1"))
        except LdbError as e19:
            (num, _) = e19.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()

    def test_delete_u2(self):
        """User's group has RIGHT_DELETE to another User object"""
        user_dn = self.get_user_dn("test_delete_user1")
        # Create user that we try to delete
        self.ldb_admin.newuser("test_delete_user1", self.user_pass)
        mod = "(A;;SD;;;AU)"
        self.sd_utils.dacl_add_ace(user_dn, mod)
        # Try to delete User object
        self.ldb_user.delete(user_dn)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % user_dn)
        self.assertEqual(len(res), 0)

    def test_delete_u3(self):
        """User identified by SID has RIGHT_DELETE to another User object"""
        user_dn = self.get_user_dn("test_delete_user1")
        # Create user that we try to delete
        self.ldb_admin.newuser("test_delete_user1", self.user_pass)
        mod = "(A;;SD;;;%s)" % self.sd_utils.get_object_sid(self.get_user_dn(self.regular_user))
        self.sd_utils.dacl_add_ace(user_dn, mod)
        # Try to delete User object
        self.ldb_user.delete(user_dn)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % user_dn)
        self.assertEqual(len(res), 0)

    def test_delete_anonymous(self):
        """Test add operation with anonymous user"""
        anonymous = SamDB(url=ldaphost, credentials=self.creds_tmp, lp=lp)
        self.ldb_admin.newuser("test_anonymous", "samba123@")

        try:
            anonymous.delete(self.get_user_dn("test_anonymous"))
        except LdbError as e20:
            (num, _) = e20.args
            self.assertEqual(num, ERR_OPERATIONS_ERROR)
        else:
            self.fail()

# tests on ldap rename operations


class AclRenameTests(AclTests):

    def setUp(self):
        super(AclRenameTests, self).setUp()
        self.regular_user = "acl_rename_user1"
        self.ou1 = "OU=test_rename_ou1"
        self.ou2 = "OU=test_rename_ou2"
        self.ou3 = "OU=test_rename_ou3,%s" % self.ou2
        self.testuser1 = "test_rename_user1"
        self.testuser2 = "test_rename_user2"
        self.testuser3 = "test_rename_user3"
        self.testuser4 = "test_rename_user4"
        self.testuser5 = "test_rename_user5"
        # Create regular user
        self.ldb_admin.newuser(self.regular_user, self.user_pass)
        self.ldb_user = self.get_ldb_connection(self.regular_user, self.user_pass)

    def tearDown(self):
        super(AclRenameTests, self).tearDown()
        # Rename OU3
        delete_force(self.ldb_admin, "CN=%s,%s,%s" % (self.testuser1, self.ou3, self.base_dn))
        delete_force(self.ldb_admin, "CN=%s,%s,%s" % (self.testuser2, self.ou3, self.base_dn))
        delete_force(self.ldb_admin, "CN=%s,%s,%s" % (self.testuser5, self.ou3, self.base_dn))
        delete_force(self.ldb_admin, "%s,%s" % (self.ou3, self.base_dn))
        # Rename OU2
        delete_force(self.ldb_admin, "CN=%s,%s,%s" % (self.testuser1, self.ou2, self.base_dn))
        delete_force(self.ldb_admin, "CN=%s,%s,%s" % (self.testuser2, self.ou2, self.base_dn))
        delete_force(self.ldb_admin, "CN=%s,%s,%s" % (self.testuser5, self.ou2, self.base_dn))
        delete_force(self.ldb_admin, "%s,%s" % (self.ou2, self.base_dn))
        # Rename OU1
        delete_force(self.ldb_admin, "CN=%s,%s,%s" % (self.testuser1, self.ou1, self.base_dn))
        delete_force(self.ldb_admin, "CN=%s,%s,%s" % (self.testuser2, self.ou1, self.base_dn))
        delete_force(self.ldb_admin, "CN=%s,%s,%s" % (self.testuser5, self.ou1, self.base_dn))
        delete_force(self.ldb_admin, "OU=test_rename_ou3,%s,%s" % (self.ou1, self.base_dn))
        delete_force(self.ldb_admin, "%s,%s" % (self.ou1, self.base_dn))
        delete_force(self.ldb_admin, self.get_user_dn(self.regular_user))

        del self.ldb_user

    def test_rename_u1(self):
        """Regular user fails to rename 'User object' within single OU"""
        # Create OU structure
        self.ldb_admin.create_ou("OU=test_rename_ou1," + self.base_dn)
        self.ldb_admin.newuser(self.testuser1, self.user_pass, userou=self.ou1)
        try:
            self.ldb_user.rename("CN=%s,%s,%s" % (self.testuser1, self.ou1, self.base_dn),
                                 "CN=%s,%s,%s" % (self.testuser5, self.ou1, self.base_dn))
        except LdbError as e21:
            (num, _) = e21.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()

    def test_rename_u2(self):
        """Grant WRITE_PROPERTY to AU so regular user can rename 'User object' within single OU"""
        ou_dn = "OU=test_rename_ou1," + self.base_dn
        user_dn = "CN=test_rename_user1," + ou_dn
        rename_user_dn = "CN=test_rename_user5," + ou_dn
        # Create OU structure
        self.ldb_admin.create_ou(ou_dn)
        self.ldb_admin.newuser(self.testuser1, self.user_pass, userou=self.ou1)
        mod = "(A;;WP;;;AU)"
        self.sd_utils.dacl_add_ace(user_dn, mod)
        # Rename 'User object' having WP to AU
        self.ldb_user.rename(user_dn, rename_user_dn)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % user_dn)
        self.assertEqual(len(res), 0)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % rename_user_dn)
        self.assertNotEqual(len(res), 0)

    def test_rename_u3(self):
        """Test rename with rights granted to 'User object' SID"""
        ou_dn = "OU=test_rename_ou1," + self.base_dn
        user_dn = "CN=test_rename_user1," + ou_dn
        rename_user_dn = "CN=test_rename_user5," + ou_dn
        # Create OU structure
        self.ldb_admin.create_ou(ou_dn)
        self.ldb_admin.newuser(self.testuser1, self.user_pass, userou=self.ou1)
        sid = self.sd_utils.get_object_sid(self.get_user_dn(self.regular_user))
        mod = "(A;;WP;;;%s)" % str(sid)
        self.sd_utils.dacl_add_ace(user_dn, mod)
        # Rename 'User object' having WP to AU
        self.ldb_user.rename(user_dn, rename_user_dn)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % user_dn)
        self.assertEqual(len(res), 0)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % rename_user_dn)
        self.assertNotEqual(len(res), 0)

    def test_rename_u4(self):
        """Rename 'User object' cross OU with WP, SD and CC right granted on reg. user to AU"""
        ou1_dn = "OU=test_rename_ou1," + self.base_dn
        ou2_dn = "OU=test_rename_ou2," + self.base_dn
        user_dn = "CN=test_rename_user2," + ou1_dn
        rename_user_dn = "CN=test_rename_user5," + ou2_dn
        # Create OU structure
        self.ldb_admin.create_ou(ou1_dn)
        self.ldb_admin.create_ou(ou2_dn)
        self.ldb_admin.newuser(self.testuser2, self.user_pass, userou=self.ou1)
        mod = "(A;;WPSD;;;AU)"
        self.sd_utils.dacl_add_ace(user_dn, mod)
        mod = "(A;;CC;;;AU)"
        self.sd_utils.dacl_add_ace(ou2_dn, mod)
        # Rename 'User object' having SD and CC to AU
        self.ldb_user.rename(user_dn, rename_user_dn)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % user_dn)
        self.assertEqual(len(res), 0)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % rename_user_dn)
        self.assertNotEqual(len(res), 0)

    def test_rename_u5(self):
        """Test rename with rights granted to 'User object' SID"""
        ou1_dn = "OU=test_rename_ou1," + self.base_dn
        ou2_dn = "OU=test_rename_ou2," + self.base_dn
        user_dn = "CN=test_rename_user2," + ou1_dn
        rename_user_dn = "CN=test_rename_user5," + ou2_dn
        # Create OU structure
        self.ldb_admin.create_ou(ou1_dn)
        self.ldb_admin.create_ou(ou2_dn)
        self.ldb_admin.newuser(self.testuser2, self.user_pass, userou=self.ou1)
        sid = self.sd_utils.get_object_sid(self.get_user_dn(self.regular_user))
        mod = "(A;;WPSD;;;%s)" % str(sid)
        self.sd_utils.dacl_add_ace(user_dn, mod)
        mod = "(A;;CC;;;%s)" % str(sid)
        self.sd_utils.dacl_add_ace(ou2_dn, mod)
        # Rename 'User object' having SD and CC to AU
        self.ldb_user.rename(user_dn, rename_user_dn)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % user_dn)
        self.assertEqual(len(res), 0)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % rename_user_dn)
        self.assertNotEqual(len(res), 0)

    def test_rename_u6(self):
        """Rename 'User object' cross OU with WP, DC and CC right granted on OU & user to AU"""
        ou1_dn = "OU=test_rename_ou1," + self.base_dn
        ou2_dn = "OU=test_rename_ou2," + self.base_dn
        user_dn = "CN=test_rename_user2," + ou1_dn
        rename_user_dn = "CN=test_rename_user2," + ou2_dn
        # Create OU structure
        self.ldb_admin.create_ou(ou1_dn)
        self.ldb_admin.create_ou(ou2_dn)
        #mod = "(A;CI;DCWP;;;AU)"
        mod = "(A;;DC;;;AU)"
        self.sd_utils.dacl_add_ace(ou1_dn, mod)
        mod = "(A;;CC;;;AU)"
        self.sd_utils.dacl_add_ace(ou2_dn, mod)
        self.ldb_admin.newuser(self.testuser2, self.user_pass, userou=self.ou1)
        mod = "(A;;WP;;;AU)"
        self.sd_utils.dacl_add_ace(user_dn, mod)
        # Rename 'User object' having SD and CC to AU
        self.ldb_user.rename(user_dn, rename_user_dn)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % user_dn)
        self.assertEqual(len(res), 0)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % rename_user_dn)
        self.assertNotEqual(len(res), 0)

    def test_rename_u7(self):
        """Rename 'User object' cross OU (second level) with WP, DC and CC right granted on OU to AU"""
        ou1_dn = "OU=test_rename_ou1," + self.base_dn
        ou2_dn = "OU=test_rename_ou2," + self.base_dn
        ou3_dn = "OU=test_rename_ou3," + ou2_dn
        user_dn = "CN=test_rename_user2," + ou1_dn
        rename_user_dn = "CN=test_rename_user5," + ou3_dn
        # Create OU structure
        self.ldb_admin.create_ou(ou1_dn)
        self.ldb_admin.create_ou(ou2_dn)
        self.ldb_admin.create_ou(ou3_dn)
        mod = "(A;CI;WPDC;;;AU)"
        self.sd_utils.dacl_add_ace(ou1_dn, mod)
        mod = "(A;;CC;;;AU)"
        self.sd_utils.dacl_add_ace(ou3_dn, mod)
        self.ldb_admin.newuser(self.testuser2, self.user_pass, userou=self.ou1)
        # Rename 'User object' having SD and CC to AU
        self.ldb_user.rename(user_dn, rename_user_dn)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % user_dn)
        self.assertEqual(len(res), 0)
        res = self.ldb_admin.search(self.base_dn,
                                    expression="(distinguishedName=%s)" % rename_user_dn)
        self.assertNotEqual(len(res), 0)

    def test_rename_u8(self):
        """Test rename on an object with and without modify access on the RDN attribute"""
        ou1_dn = "OU=test_rename_ou1," + self.base_dn
        ou2_dn = "OU=test_rename_ou2," + ou1_dn
        ou3_dn = "OU=test_rename_ou3," + ou1_dn
        # Create OU structure
        self.ldb_admin.create_ou(ou1_dn)
        self.ldb_admin.create_ou(ou2_dn)
        sid = self.sd_utils.get_object_sid(self.get_user_dn(self.regular_user))
        mod = "(OA;;WP;bf967a0e-0de6-11d0-a285-00aa003049e2;;%s)" % str(sid)
        self.sd_utils.dacl_add_ace(ou2_dn, mod)
        mod = "(OD;;WP;bf9679f0-0de6-11d0-a285-00aa003049e2;;%s)" % str(sid)
        self.sd_utils.dacl_add_ace(ou2_dn, mod)
        try:
            self.ldb_user.rename(ou2_dn, ou3_dn)
        except LdbError as e22:
            (num, _) = e22.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            # This rename operation should always throw ERR_INSUFFICIENT_ACCESS_RIGHTS
            self.fail()
        sid = self.sd_utils.get_object_sid(self.get_user_dn(self.regular_user))
        mod = "(A;;WP;bf9679f0-0de6-11d0-a285-00aa003049e2;;%s)" % str(sid)
        self.sd_utils.dacl_add_ace(ou2_dn, mod)
        self.ldb_user.rename(ou2_dn, ou3_dn)
        res = self.ldb_admin.search(self.base_dn, expression="(distinguishedName=%s)" % ou2_dn)
        self.assertEqual(len(res), 0)
        res = self.ldb_admin.search(self.base_dn, expression="(distinguishedName=%s)" % ou3_dn)
        self.assertNotEqual(len(res), 0)

    def test_rename_u9(self):
        """Rename 'User object' cross OU, with explicit deny on sd and dc"""
        ou1_dn = "OU=test_rename_ou1," + self.base_dn
        ou2_dn = "OU=test_rename_ou2," + self.base_dn
        user_dn = "CN=test_rename_user2," + ou1_dn
        rename_user_dn = "CN=test_rename_user5," + ou2_dn
        # Create OU structure
        self.ldb_admin.create_ou(ou1_dn)
        self.ldb_admin.create_ou(ou2_dn)
        self.ldb_admin.newuser(self.testuser2, self.user_pass, userou=self.ou1)
        mod = "(D;;SD;;;DA)"
        self.sd_utils.dacl_add_ace(user_dn, mod)
        mod = "(D;;DC;;;DA)"
        self.sd_utils.dacl_add_ace(ou1_dn, mod)
        # Rename 'User object' having SD and CC to AU
        try:
            self.ldb_admin.rename(user_dn, rename_user_dn)
        except LdbError as e23:
            (num, _) = e23.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()
        # add an allow ace so we can delete this ou
        mod = "(A;;DC;;;DA)"
        self.sd_utils.dacl_add_ace(ou1_dn, mod)


# tests on Control Access Rights
class AclCARTests(AclTests):

    def setUp(self):
        super(AclCARTests, self).setUp()

        # Get the old "dSHeuristics" if it was set
        dsheuristics = self.ldb_admin.get_dsheuristics()
        # Reset the "dSHeuristics" as they were before
        self.addCleanup(self.ldb_admin.set_dsheuristics, dsheuristics)
        # Set the "dSHeuristics" to activate the correct "userPassword" behaviour
        self.ldb_admin.set_dsheuristics("000000001")
        # Get the old "minPwdAge"
        minPwdAge = self.ldb_admin.get_minPwdAge()
        # Reset the "minPwdAge" as it was before
        self.addCleanup(self.ldb_admin.set_minPwdAge, minPwdAge)
        # Set it temporarily to "0"
        self.ldb_admin.set_minPwdAge("0")

        self.user_with_wp = "acl_car_user1"
        self.user_with_pc = "acl_car_user2"
        self.ldb_admin.newuser(self.user_with_wp, self.user_pass)
        self.ldb_admin.newuser(self.user_with_pc, self.user_pass)
        self.ldb_user = self.get_ldb_connection(self.user_with_wp, self.user_pass)
        self.ldb_user2 = self.get_ldb_connection(self.user_with_pc, self.user_pass)

    def tearDown(self):
        super(AclCARTests, self).tearDown()
        delete_force(self.ldb_admin, self.get_user_dn(self.user_with_wp))
        delete_force(self.ldb_admin, self.get_user_dn(self.user_with_pc))

        del self.ldb_user
        del self.ldb_user2

    def test_change_password1(self):
        """Try a password change operation without any CARs given"""
        # users have change password by default - remove for negative testing
        desc = self.sd_utils.read_sd_on_dn(self.get_user_dn(self.user_with_wp))
        sddl = desc.as_sddl(self.domain_sid)
        sddl = sddl.replace("(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)", "")
        sddl = sddl.replace("(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)", "")
        self.sd_utils.modify_sd_on_dn(self.get_user_dn(self.user_with_wp), sddl)
        try:
            self.ldb_user.modify_ldif("""
dn: """ + self.get_user_dn(self.user_with_wp) + """
changetype: modify
delete: unicodePwd
unicodePwd:: """ + base64.b64encode("\"samba123@\"".encode('utf-16-le')).decode('utf8') + """
add: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS2\"".encode('utf-16-le')).decode('utf8') + """
""")
        except LdbError as e24:
            (num, _) = e24.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            # for some reason we get constraint violation instead of insufficient access error
            self.fail()

    def test_change_password2(self):
        """Make sure WP has no influence"""
        desc = self.sd_utils.read_sd_on_dn(self.get_user_dn(self.user_with_wp))
        sddl = desc.as_sddl(self.domain_sid)
        sddl = sddl.replace("(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)", "")
        sddl = sddl.replace("(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)", "")
        self.sd_utils.modify_sd_on_dn(self.get_user_dn(self.user_with_wp), sddl)
        mod = "(A;;WP;;;PS)"
        self.sd_utils.dacl_add_ace(self.get_user_dn(self.user_with_wp), mod)
        try:
            self.ldb_user.modify_ldif("""
dn: """ + self.get_user_dn(self.user_with_wp) + """
changetype: modify
delete: unicodePwd
unicodePwd:: """ + base64.b64encode("\"samba123@\"".encode('utf-16-le')).decode('utf8') + """
add: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS2\"".encode('utf-16-le')).decode('utf8') + """
""")
        except LdbError as e25:
            (num, _) = e25.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            # for some reason we get constraint violation instead of insufficient access error
            self.fail()

    def test_change_password3(self):
        """Make sure WP has no influence"""
        mod = "(D;;WP;;;PS)"
        self.sd_utils.dacl_add_ace(self.get_user_dn(self.user_with_wp), mod)
        self.ldb_user.modify_ldif("""
dn: """ + self.get_user_dn(self.user_with_wp) + """
changetype: modify
delete: unicodePwd
unicodePwd:: """ + base64.b64encode("\"samba123@\"".encode('utf-16-le')).decode('utf8') + """
add: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS2\"".encode('utf-16-le')).decode('utf8') + """
""")

    def test_change_password5(self):
        """Make sure rights have no influence on dBCSPwd"""
        desc = self.sd_utils.read_sd_on_dn(self.get_user_dn(self.user_with_wp))
        sddl = desc.as_sddl(self.domain_sid)
        sddl = sddl.replace("(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)", "")
        sddl = sddl.replace("(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)", "")
        self.sd_utils.modify_sd_on_dn(self.get_user_dn(self.user_with_wp), sddl)
        mod = "(D;;WP;;;PS)"
        self.sd_utils.dacl_add_ace(self.get_user_dn(self.user_with_wp), mod)
        try:
            self.ldb_user.modify_ldif("""
dn: """ + self.get_user_dn(self.user_with_wp) + """
changetype: modify
delete: dBCSPwd
dBCSPwd: XXXXXXXXXXXXXXXX
add: dBCSPwd
dBCSPwd: YYYYYYYYYYYYYYYY
""")
        except LdbError as e26:
            (num, _) = e26.args
            self.assertEqual(num, ERR_UNWILLING_TO_PERFORM)
        else:
            self.fail()

    def test_change_password6(self):
        """Test uneven delete/adds"""
        try:
            self.ldb_user.modify_ldif("""
dn: """ + self.get_user_dn(self.user_with_wp) + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
delete: userPassword
userPassword: thatsAcomplPASS1
add: userPassword
userPassword: thatsAcomplPASS2
""")
        except LdbError as e27:
            (num, _) = e27.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()
        mod = "(OA;;CR;00299570-246d-11d0-a768-00aa006e0529;;PS)"
        self.sd_utils.dacl_add_ace(self.get_user_dn(self.user_with_wp), mod)
        try:
            self.ldb_user.modify_ldif("""
dn: """ + self.get_user_dn(self.user_with_wp) + """
changetype: modify
delete: userPassword
userPassword: thatsAcomplPASS1
delete: userPassword
userPassword: thatsAcomplPASS1
add: userPassword
userPassword: thatsAcomplPASS2
""")
            # This fails on Windows 2000 domain level with constraint violation
        except LdbError as e28:
            (num, _) = e28.args
            self.assertIn(num, (ERR_CONSTRAINT_VIOLATION,
                                ERR_UNWILLING_TO_PERFORM))
        else:
            self.fail()

    def test_change_password7(self):
        """Try a password change operation without any CARs given"""
        # users have change password by default - remove for negative testing
        desc = self.sd_utils.read_sd_on_dn(self.get_user_dn(self.user_with_wp))
        sddl = desc.as_sddl(self.domain_sid)
        self.sd_utils.modify_sd_on_dn(self.get_user_dn(self.user_with_wp), sddl)
        # first change our own password
        self.ldb_user2.modify_ldif("""
dn: """ + self.get_user_dn(self.user_with_pc) + """
changetype: modify
delete: unicodePwd
unicodePwd:: """ + base64.b64encode("\"samba123@\"".encode('utf-16-le')).decode('utf8') + """
add: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS1\"".encode('utf-16-le')).decode('utf8') + """
""")
        # then someone else's
        self.ldb_user2.modify_ldif("""
dn: """ + self.get_user_dn(self.user_with_wp) + """
changetype: modify
delete: unicodePwd
unicodePwd:: """ + base64.b64encode("\"samba123@\"".encode('utf-16-le')).decode('utf8') + """
add: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS2\"".encode('utf-16-le')).decode('utf8') + """
""")

    def test_reset_password1(self):
        """Try a user password reset operation (unicodePwd) before and after granting CAR"""
        try:
            self.ldb_user.modify_ldif("""
dn: """ + self.get_user_dn(self.user_with_wp) + """
changetype: modify
replace: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS1\"".encode('utf-16-le')).decode('utf8') + """
""")
        except LdbError as e29:
            (num, _) = e29.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()
        mod = "(OA;;CR;00299570-246d-11d0-a768-00aa006e0529;;PS)"
        self.sd_utils.dacl_add_ace(self.get_user_dn(self.user_with_wp), mod)
        self.ldb_user.modify_ldif("""
dn: """ + self.get_user_dn(self.user_with_wp) + """
changetype: modify
replace: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS1\"".encode('utf-16-le')).decode('utf8') + """
""")

    def test_reset_password2(self):
        """Try a user password reset operation (userPassword) before and after granting CAR"""
        try:
            self.ldb_user.modify_ldif("""
dn: """ + self.get_user_dn(self.user_with_wp) + """
changetype: modify
replace: userPassword
userPassword: thatsAcomplPASS1
""")
        except LdbError as e30:
            (num, _) = e30.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()
        mod = "(OA;;CR;00299570-246d-11d0-a768-00aa006e0529;;PS)"
        self.sd_utils.dacl_add_ace(self.get_user_dn(self.user_with_wp), mod)
        try:
            self.ldb_user.modify_ldif("""
dn: """ + self.get_user_dn(self.user_with_wp) + """
changetype: modify
replace: userPassword
userPassword: thatsAcomplPASS1
""")
            # This fails on Windows 2000 domain level with constraint violation
        except LdbError as e31:
            (num, _) = e31.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            pass # Not self.fail() as we normally want success.

    def test_reset_password3(self):
        """Grant WP and see what happens (unicodePwd)"""
        mod = "(A;;WP;;;PS)"
        self.sd_utils.dacl_add_ace(self.get_user_dn(self.user_with_wp), mod)
        try:
            self.ldb_user.modify_ldif("""
dn: """ + self.get_user_dn(self.user_with_wp) + """
changetype: modify
replace: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS1\"".encode('utf-16-le')).decode('utf8') + """
""")
        except LdbError as e32:
            (num, _) = e32.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()

    def test_reset_password4(self):
        """Grant WP and see what happens (userPassword)"""
        mod = "(A;;WP;;;PS)"
        self.sd_utils.dacl_add_ace(self.get_user_dn(self.user_with_wp), mod)
        try:
            self.ldb_user.modify_ldif("""
dn: """ + self.get_user_dn(self.user_with_wp) + """
changetype: modify
replace: userPassword
userPassword: thatsAcomplPASS1
""")
        except LdbError as e33:
            (num, _) = e33.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()

    def test_reset_password5(self):
        """Explicitly deny WP but grant CAR (unicodePwd)"""
        mod = "(D;;WP;;;PS)(OA;;CR;00299570-246d-11d0-a768-00aa006e0529;;PS)"
        self.sd_utils.dacl_add_ace(self.get_user_dn(self.user_with_wp), mod)
        self.ldb_user.modify_ldif("""
dn: """ + self.get_user_dn(self.user_with_wp) + """
changetype: modify
replace: unicodePwd
unicodePwd:: """ + base64.b64encode("\"thatsAcomplPASS1\"".encode('utf-16-le')).decode('utf8') + """
""")

    def test_reset_password6(self):
        """Explicitly deny WP but grant CAR (userPassword)"""
        mod = "(D;;WP;;;PS)(OA;;CR;00299570-246d-11d0-a768-00aa006e0529;;PS)"
        self.sd_utils.dacl_add_ace(self.get_user_dn(self.user_with_wp), mod)
        try:
            self.ldb_user.modify_ldif("""
dn: """ + self.get_user_dn(self.user_with_wp) + """
changetype: modify
replace: userPassword
userPassword: thatsAcomplPASS1
""")
            # This fails on Windows 2000 domain level with constraint violation
        except LdbError as e34:
            (num, _) = e34.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            pass # Not self.fail() as we normally want success


class AclExtendedTests(AclTests):

    def setUp(self):
        super(AclExtendedTests, self).setUp()
        # regular user, will be the creator
        self.u1 = "ext_u1"
        # regular user
        self.u2 = "ext_u2"
        # admin user
        self.u3 = "ext_u3"
        self.ldb_admin.newuser(self.u1, self.user_pass)
        self.ldb_admin.newuser(self.u2, self.user_pass)
        self.ldb_admin.newuser(self.u3, self.user_pass)
        self.ldb_admin.add_remove_group_members("Domain Admins", [self.u3],
                                                add_members_operation=True)
        self.ldb_user1 = self.get_ldb_connection(self.u1, self.user_pass)
        self.ldb_user2 = self.get_ldb_connection(self.u2, self.user_pass)
        self.ldb_user3 = self.get_ldb_connection(self.u3, self.user_pass)
        self.user_sid1 = self.sd_utils.get_object_sid(self.get_user_dn(self.u1))
        self.user_sid2 = self.sd_utils.get_object_sid(self.get_user_dn(self.u2))

    def tearDown(self):
        super(AclExtendedTests, self).tearDown()
        delete_force(self.ldb_admin, self.get_user_dn(self.u1))
        delete_force(self.ldb_admin, self.get_user_dn(self.u2))
        delete_force(self.ldb_admin, self.get_user_dn(self.u3))
        delete_force(self.ldb_admin, "CN=ext_group1,OU=ext_ou1," + self.base_dn)
        delete_force(self.ldb_admin, "ou=ext_ou1," + self.base_dn)

        del self.ldb_user1
        del self.ldb_user2
        del self.ldb_user3

    def test_ntSecurityDescriptor(self):
        # create empty ou
        self.ldb_admin.create_ou("ou=ext_ou1," + self.base_dn)
        # give u1 Create children access
        mod = "(A;;CC;;;%s)" % str(self.user_sid1)
        self.sd_utils.dacl_add_ace("OU=ext_ou1," + self.base_dn, mod)
        mod = "(A;;LC;;;%s)" % str(self.user_sid2)
        self.sd_utils.dacl_add_ace("OU=ext_ou1," + self.base_dn, mod)
        # create a group under that, grant RP to u2
        self.ldb_user1.newgroup("ext_group1", groupou="OU=ext_ou1",
                                grouptype=samba.dsdb.GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP)
        mod = "(A;;RP;;;%s)" % str(self.user_sid2)
        self.sd_utils.dacl_add_ace("CN=ext_group1,OU=ext_ou1," + self.base_dn, mod)
        # u2 must not read the descriptor
        res = self.ldb_user2.search("CN=ext_group1,OU=ext_ou1," + self.base_dn,
                                    SCOPE_BASE, None, ["nTSecurityDescriptor"])
        self.assertNotEqual(len(res), 0)
        self.assertNotIn("nTSecurityDescriptor", res[0].keys())
        # grant RC to u2 - still no access
        mod = "(A;;RC;;;%s)" % str(self.user_sid2)
        self.sd_utils.dacl_add_ace("CN=ext_group1,OU=ext_ou1," + self.base_dn, mod)
        res = self.ldb_user2.search("CN=ext_group1,OU=ext_ou1," + self.base_dn,
                                    SCOPE_BASE, None, ["nTSecurityDescriptor"])
        self.assertNotEqual(len(res), 0)
        self.assertNotIn("nTSecurityDescriptor", res[0].keys())
        # u3 is member of administrators group, should be able to read sd
        res = self.ldb_user3.search("CN=ext_group1,OU=ext_ou1," + self.base_dn,
                                    SCOPE_BASE, None, ["nTSecurityDescriptor"])
        self.assertEqual(len(res), 1)
        self.assertIn("nTSecurityDescriptor", res[0].keys())


class AclUndeleteTests(AclTests):

    def setUp(self):
        super(AclUndeleteTests, self).setUp()
        self.regular_user = "undeleter1"
        self.ou1 = "OU=undeleted_ou,"
        self.testuser1 = "to_be_undeleted1"
        self.testuser2 = "to_be_undeleted2"
        self.testuser3 = "to_be_undeleted3"
        self.testuser4 = "to_be_undeleted4"
        self.testuser5 = "to_be_undeleted5"
        self.testuser6 = "to_be_undeleted6"

        self.new_dn_ou = "CN=" + self.testuser4 + "," + self.ou1 + self.base_dn

        # Create regular user
        self.testuser1_dn = self.get_user_dn(self.testuser1)
        self.testuser2_dn = self.get_user_dn(self.testuser2)
        self.testuser3_dn = self.get_user_dn(self.testuser3)
        self.testuser4_dn = self.get_user_dn(self.testuser4)
        self.testuser5_dn = self.get_user_dn(self.testuser5)
        self.deleted_dn1 = self.create_delete_user(self.testuser1)
        self.deleted_dn2 = self.create_delete_user(self.testuser2)
        self.deleted_dn3 = self.create_delete_user(self.testuser3)
        self.deleted_dn4 = self.create_delete_user(self.testuser4)
        self.deleted_dn5 = self.create_delete_user(self.testuser5)

        self.ldb_admin.create_ou(self.ou1 + self.base_dn)

        self.ldb_admin.newuser(self.regular_user, self.user_pass)
        self.ldb_admin.add_remove_group_members("Domain Admins", [self.regular_user],
                                                add_members_operation=True)
        self.ldb_user = self.get_ldb_connection(self.regular_user, self.user_pass)
        self.sid = self.sd_utils.get_object_sid(self.get_user_dn(self.regular_user))

    def tearDown(self):
        super(AclUndeleteTests, self).tearDown()
        delete_force(self.ldb_admin, self.get_user_dn(self.regular_user))
        delete_force(self.ldb_admin, self.get_user_dn(self.testuser1))
        delete_force(self.ldb_admin, self.get_user_dn(self.testuser2))
        delete_force(self.ldb_admin, self.get_user_dn(self.testuser3))
        delete_force(self.ldb_admin, self.get_user_dn(self.testuser4))
        delete_force(self.ldb_admin, self.get_user_dn(self.testuser5))
        delete_force(self.ldb_admin, self.new_dn_ou)
        delete_force(self.ldb_admin, self.ou1 + self.base_dn)

        del self.ldb_user

    def GUID_string(self, guid):
        return get_string(ldb.schema_format_value("objectGUID", guid))

    def create_delete_user(self, new_user):
        self.ldb_admin.newuser(new_user, self.user_pass)

        res = self.ldb_admin.search(expression="(objectClass=*)",
                                    base=self.get_user_dn(new_user),
                                    scope=SCOPE_BASE,
                                    controls=["show_deleted:1"])
        guid = res[0]["objectGUID"][0]
        self.ldb_admin.delete(self.get_user_dn(new_user))
        res = self.ldb_admin.search(base="<GUID=%s>" % self.GUID_string(guid),
                                    scope=SCOPE_BASE, controls=["show_deleted:1"])
        self.assertEqual(len(res), 1)
        return str(res[0].dn)

    def undelete_deleted(self, olddn, newdn):
        msg = Message()
        msg.dn = Dn(self.ldb_user, olddn)
        msg["isDeleted"] = MessageElement([], FLAG_MOD_DELETE, "isDeleted")
        msg["distinguishedName"] = MessageElement([newdn], FLAG_MOD_REPLACE, "distinguishedName")
        self.ldb_user.modify(msg, ["show_recycled:1"])

    def undelete_deleted_with_mod(self, olddn, newdn):
        msg = Message()
        msg.dn = Dn(ldb, olddn)
        msg["isDeleted"] = MessageElement([], FLAG_MOD_DELETE, "isDeleted")
        msg["distinguishedName"] = MessageElement([newdn], FLAG_MOD_REPLACE, "distinguishedName")
        msg["url"] = MessageElement(["www.samba.org"], FLAG_MOD_REPLACE, "url")
        self.ldb_user.modify(msg, ["show_deleted:1"])

    def test_undelete(self):
        # it appears the user has to have LC on the old parent to be able to move the object
        # otherwise we get no such object. Since only System can modify the SD on deleted object
        # we cannot grant this permission via LDAP, and this leaves us with "negative" tests at the moment

        # deny write property on rdn, should fail
        mod = "(OD;;WP;bf967a0e-0de6-11d0-a285-00aa003049e2;;%s)" % str(self.sid)
        self.sd_utils.dacl_add_ace(self.deleted_dn1, mod)
        try:
            self.undelete_deleted(self.deleted_dn1, self.testuser1_dn)
            self.fail()
        except LdbError as e35:
            (num, _) = e35.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)

        # seems that permissions on isDeleted and distinguishedName are irrelevant
        mod = "(OD;;WP;bf96798f-0de6-11d0-a285-00aa003049e2;;%s)" % str(self.sid)
        self.sd_utils.dacl_add_ace(self.deleted_dn2, mod)
        mod = "(OD;;WP;bf9679e4-0de6-11d0-a285-00aa003049e2;;%s)" % str(self.sid)
        self.sd_utils.dacl_add_ace(self.deleted_dn2, mod)
        self.undelete_deleted(self.deleted_dn2, self.testuser2_dn)

        # attempt undelete with simultaneous addition of url, WP to which is denied
        mod = "(OD;;WP;9a9a0221-4a5b-11d1-a9c3-0000f80367c1;;%s)" % str(self.sid)
        self.sd_utils.dacl_add_ace(self.deleted_dn3, mod)
        try:
            self.undelete_deleted_with_mod(self.deleted_dn3, self.testuser3_dn)
            self.fail()
        except LdbError as e36:
            (num, _) = e36.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)

        # undelete in an ou, in which we have no right to create children
        mod = "(D;;CC;;;%s)" % str(self.sid)
        self.sd_utils.dacl_add_ace(self.ou1 + self.base_dn, mod)
        try:
            self.undelete_deleted(self.deleted_dn4, self.new_dn_ou)
            self.fail()
        except LdbError as e37:
            (num, _) = e37.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)

        # delete is not required
        mod = "(D;;SD;;;%s)" % str(self.sid)
        self.sd_utils.dacl_add_ace(self.deleted_dn5, mod)
        self.undelete_deleted(self.deleted_dn5, self.testuser5_dn)

        # deny Reanimate-Tombstone, should fail
        mod = "(OD;;CR;45ec5156-db7e-47bb-b53f-dbeb2d03c40f;;%s)" % str(self.sid)
        self.sd_utils.dacl_add_ace(self.base_dn, mod)
        try:
            self.undelete_deleted(self.deleted_dn4, self.testuser4_dn)
            self.fail()
        except LdbError as e38:
            (num, _) = e38.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        self.sd_utils.dacl_delete_aces(self.base_dn, mod)


class AclSPNTests(AclTests):

    def setUp(self):
        super(AclSPNTests, self).setUp()
        self.dcname = "TESTSRV8"
        self.rodcname = "TESTRODC8"
        self.computername = "testcomp8"
        self.test_user = "spn_test_user8"
        self.computerdn = "CN=%s,CN=computers,%s" % (self.computername, self.base_dn)
        self.user_object = "user_with_spn"
        self.user_object_dn = "CN=%s,CN=Users,%s" % (self.user_object, self.base_dn)
        self.dc_dn = "CN=%s,OU=Domain Controllers,%s" % (self.dcname, self.base_dn)
        self.site = "Default-First-Site-Name"
        self.rodcctx = DCJoinContext(server=host, creds=creds, lp=lp,
                                     site=self.site, netbios_name=self.rodcname,
                                     targetdir=None, domain=None)
        self.dcctx = DCJoinContext(server=host, creds=creds, lp=lp,
                                   site=self.site, netbios_name=self.dcname,
                                   targetdir=None, domain=None)
        self.ldb_admin.newuser(self.test_user, self.user_pass)
        self.ldb_user1 = self.get_ldb_connection(self.test_user, self.user_pass)
        self.user_sid1 = self.sd_utils.get_object_sid(self.get_user_dn(self.test_user))
        self.create_computer(self.computername, self.dcctx.dnsdomain)
        self.create_rodc(self.rodcctx)
        self.create_dc(self.dcctx)

    def tearDown(self):
        super(AclSPNTests, self).tearDown()
        self.rodcctx.cleanup_old_join()
        self.dcctx.cleanup_old_join()
        delete_force(self.ldb_admin, "cn=%s,cn=computers,%s" % (self.computername, self.base_dn))
        delete_force(self.ldb_admin, self.get_user_dn(self.test_user))
        delete_force(self.ldb_admin, self.user_object_dn)

        del self.ldb_user1

    def replace_spn(self, _ldb, dn, spn):
        print("Setting spn %s on %s" % (spn, dn))
        res = self.ldb_admin.search(dn, expression="(objectClass=*)",
                                    scope=SCOPE_BASE, attrs=["servicePrincipalName"])
        if "servicePrincipalName" in res[0].keys():
            flag = FLAG_MOD_REPLACE
        else:
            flag = FLAG_MOD_ADD

        msg = Message()
        msg.dn = Dn(self.ldb_admin, dn)
        msg["servicePrincipalName"] = MessageElement(spn, flag,
                                                     "servicePrincipalName")
        _ldb.modify(msg)

    def create_computer(self, computername, domainname):
        dn = "CN=%s,CN=computers,%s" % (computername, self.base_dn)
        samaccountname = computername + "$"
        dnshostname = "%s.%s" % (computername, domainname)
        self.ldb_admin.add({
            "dn": dn,
            "objectclass": "computer",
            "sAMAccountName": samaccountname,
            "userAccountControl": str(samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT),
            "dNSHostName": dnshostname})

    # same as for join_RODC, but do not set any SPNs
    def create_rodc(self, ctx):
        ctx.nc_list = [ctx.base_dn, ctx.config_dn, ctx.schema_dn]
        ctx.full_nc_list = [ctx.base_dn, ctx.config_dn, ctx.schema_dn]
        ctx.krbtgt_dn = "CN=krbtgt_%s,CN=Users,%s" % (ctx.myname, ctx.base_dn)

        ctx.never_reveal_sid = ["<SID=%s-%s>" % (ctx.domsid, security.DOMAIN_RID_RODC_DENY),
                                "<SID=%s>" % security.SID_BUILTIN_ADMINISTRATORS,
                                "<SID=%s>" % security.SID_BUILTIN_SERVER_OPERATORS,
                                "<SID=%s>" % security.SID_BUILTIN_BACKUP_OPERATORS,
                                "<SID=%s>" % security.SID_BUILTIN_ACCOUNT_OPERATORS]
        ctx.reveal_sid = "<SID=%s-%s>" % (ctx.domsid, security.DOMAIN_RID_RODC_ALLOW)

        mysid = ctx.get_mysid()
        admin_dn = "<SID=%s>" % mysid
        ctx.managedby = admin_dn

        ctx.userAccountControl = (samba.dsdb.UF_WORKSTATION_TRUST_ACCOUNT |
                                  samba.dsdb.UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION |
                                  samba.dsdb.UF_PARTIAL_SECRETS_ACCOUNT)

        ctx.connection_dn = "CN=RODC Connection (FRS),%s" % ctx.ntds_dn
        ctx.secure_channel_type = misc.SEC_CHAN_RODC
        ctx.RODC = True
        ctx.replica_flags = (drsuapi.DRSUAPI_DRS_INIT_SYNC |
                             drsuapi.DRSUAPI_DRS_PER_SYNC |
                             drsuapi.DRSUAPI_DRS_GET_ANC |
                             drsuapi.DRSUAPI_DRS_NEVER_SYNCED |
                             drsuapi.DRSUAPI_DRS_SPECIAL_SECRET_PROCESSING)

        ctx.join_add_objects()

    def create_dc(self, ctx):
        ctx.nc_list = [ctx.base_dn, ctx.config_dn, ctx.schema_dn]
        ctx.full_nc_list = [ctx.base_dn, ctx.config_dn, ctx.schema_dn]
        ctx.userAccountControl = samba.dsdb.UF_SERVER_TRUST_ACCOUNT | samba.dsdb.UF_TRUSTED_FOR_DELEGATION
        ctx.secure_channel_type = misc.SEC_CHAN_BDC
        ctx.replica_flags = (drsuapi.DRSUAPI_DRS_WRIT_REP |
                             drsuapi.DRSUAPI_DRS_INIT_SYNC |
                             drsuapi.DRSUAPI_DRS_PER_SYNC |
                             drsuapi.DRSUAPI_DRS_FULL_SYNC_IN_PROGRESS |
                             drsuapi.DRSUAPI_DRS_NEVER_SYNCED)

        ctx.join_add_objects()

    def dc_spn_test(self, ctx):
        netbiosdomain = self.dcctx.get_domain_name()
        try:
            self.replace_spn(self.ldb_user1, ctx.acct_dn, "HOST/%s/%s" % (ctx.myname, netbiosdomain))
        except LdbError as e39:
            (num, _) = e39.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()

        mod = "(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;%s)" % str(self.user_sid1)
        self.sd_utils.dacl_add_ace(ctx.acct_dn, mod)
        self.replace_spn(self.ldb_user1, ctx.acct_dn, "HOST/%s/%s" % (ctx.myname, netbiosdomain))
        self.replace_spn(self.ldb_user1, ctx.acct_dn, "HOST/%s" % (ctx.myname))
        self.replace_spn(self.ldb_user1, ctx.acct_dn, "HOST/%s.%s/%s" %
                         (ctx.myname, ctx.dnsdomain, netbiosdomain))
        self.replace_spn(self.ldb_user1, ctx.acct_dn, "HOST/%s/%s" % (ctx.myname, ctx.dnsdomain))
        self.replace_spn(self.ldb_user1, ctx.acct_dn, "HOST/%s.%s/%s" %
                         (ctx.myname, ctx.dnsdomain, ctx.dnsdomain))
        self.replace_spn(self.ldb_user1, ctx.acct_dn, "GC/%s.%s/%s" %
                         (ctx.myname, ctx.dnsdomain, ctx.dnsforest))
        self.replace_spn(self.ldb_user1, ctx.acct_dn, "ldap/%s/%s" % (ctx.myname, netbiosdomain))
        self.replace_spn(self.ldb_user1, ctx.acct_dn, "ldap/%s.%s/%s" %
                         (ctx.myname, ctx.dnsdomain, netbiosdomain))
        self.replace_spn(self.ldb_user1, ctx.acct_dn, "ldap/%s" % (ctx.myname))
        self.replace_spn(self.ldb_user1, ctx.acct_dn, "ldap/%s/%s" % (ctx.myname, ctx.dnsdomain))
        self.replace_spn(self.ldb_user1, ctx.acct_dn, "ldap/%s.%s/%s" %
                         (ctx.myname, ctx.dnsdomain, ctx.dnsdomain))
        self.replace_spn(self.ldb_user1, ctx.acct_dn, "DNS/%s/%s" % (ctx.myname, ctx.dnsdomain))
        self.replace_spn(self.ldb_user1, ctx.acct_dn, "RestrictedKrbHost/%s/%s" %
                         (ctx.myname, ctx.dnsdomain))
        self.replace_spn(self.ldb_user1, ctx.acct_dn, "RestrictedKrbHost/%s" %
                         (ctx.myname))
        self.replace_spn(self.ldb_user1, ctx.acct_dn, "Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/%s/%s" %
                         (ctx.myname, ctx.dnsdomain))
        self.replace_spn(self.ldb_user1, ctx.acct_dn, "NtFrs-88f5d2bd-b646-11d2-a6d3-00c04fc9b232/%s/%s" %
                         (ctx.myname, ctx.dnsdomain))
        self.replace_spn(self.ldb_user1, ctx.acct_dn, "ldap/%s._msdcs.%s" %
                         (ctx.ntds_guid, ctx.dnsdomain))

        # the following spns do not match the restrictions and should fail
        try:
            self.replace_spn(self.ldb_user1, ctx.acct_dn, "ldap/%s.%s/ForestDnsZones.%s" %
                             (ctx.myname, ctx.dnsdomain, ctx.dnsdomain))
        except LdbError as e40:
            (num, _) = e40.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            self.fail()
        try:
            self.replace_spn(self.ldb_user1, ctx.acct_dn, "ldap/%s.%s/DomainDnsZones.%s" %
                             (ctx.myname, ctx.dnsdomain, ctx.dnsdomain))
        except LdbError as e41:
            (num, _) = e41.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            self.fail()
        try:
            self.replace_spn(self.ldb_user1, ctx.acct_dn, "nosuchservice/%s/%s" % ("abcd", "abcd"))
        except LdbError as e42:
            (num, _) = e42.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            self.fail()
        try:
            self.replace_spn(self.ldb_user1, ctx.acct_dn, "GC/%s.%s/%s" %
                             (ctx.myname, ctx.dnsdomain, netbiosdomain))
        except LdbError as e43:
            (num, _) = e43.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            self.fail()
        try:
            self.replace_spn(self.ldb_user1, ctx.acct_dn, "E3514235-4B06-11D1-AB04-00C04FC2DCD2/%s/%s" %
                             (ctx.ntds_guid, ctx.dnsdomain))
        except LdbError as e44:
            (num, _) = e44.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            self.fail()

    def test_computer_spn(self):
        # with WP, any value can be set
        netbiosdomain = self.dcctx.get_domain_name()
        self.replace_spn(self.ldb_admin, self.computerdn, "HOST/%s/%s" %
                         (self.computername, netbiosdomain))
        self.replace_spn(self.ldb_admin, self.computerdn, "HOST/%s" % (self.computername))
        self.replace_spn(self.ldb_admin, self.computerdn, "HOST/%s.%s/%s" %
                         (self.computername, self.dcctx.dnsdomain, netbiosdomain))
        self.replace_spn(self.ldb_admin, self.computerdn, "HOST/%s/%s" %
                         (self.computername, self.dcctx.dnsdomain))
        self.replace_spn(self.ldb_admin, self.computerdn, "HOST/%s.%s/%s" %
                         (self.computername, self.dcctx.dnsdomain, self.dcctx.dnsdomain))
        self.replace_spn(self.ldb_admin, self.computerdn, "GC/%s.%s/%s" %
                         (self.computername, self.dcctx.dnsdomain, self.dcctx.dnsforest))
        self.replace_spn(self.ldb_admin, self.computerdn, "ldap/%s/%s" % (self.computername, netbiosdomain))
        self.replace_spn(self.ldb_admin, self.computerdn, "ldap/%s.%s/ForestDnsZones.%s" %
                         (self.computername, self.dcctx.dnsdomain, self.dcctx.dnsdomain))
        self.replace_spn(self.ldb_admin, self.computerdn, "ldap/%s.%s/DomainDnsZones.%s" %
                         (self.computername, self.dcctx.dnsdomain, self.dcctx.dnsdomain))
        self.replace_spn(self.ldb_admin, self.computerdn, "ldap/%s.%s/%s" %
                         (self.computername, self.dcctx.dnsdomain, netbiosdomain))
        self.replace_spn(self.ldb_admin, self.computerdn, "ldap/%s" % (self.computername))
        self.replace_spn(self.ldb_admin, self.computerdn, "ldap/%s/%s" %
                         (self.computername, self.dcctx.dnsdomain))
        self.replace_spn(self.ldb_admin, self.computerdn, "ldap/%s.%s/%s" %
                         (self.computername, self.dcctx.dnsdomain, self.dcctx.dnsdomain))
        self.replace_spn(self.ldb_admin, self.computerdn, "DNS/%s/%s" %
                         (self.computername, self.dcctx.dnsdomain))
        self.replace_spn(self.ldb_admin, self.computerdn, "RestrictedKrbHost/%s/%s" %
                         (self.computername, self.dcctx.dnsdomain))
        self.replace_spn(self.ldb_admin, self.computerdn, "RestrictedKrbHost/%s" %
                         (self.computername))
        self.replace_spn(self.ldb_admin, self.computerdn, "Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/%s/%s" %
                         (self.computername, self.dcctx.dnsdomain))
        self.replace_spn(self.ldb_admin, self.computerdn, "NtFrs-88f5d2bd-b646-11d2-a6d3-00c04fc9b232/%s/%s" %
                         (self.computername, self.dcctx.dnsdomain))
        self.replace_spn(self.ldb_admin, self.computerdn, "nosuchservice/%s/%s" % ("abcd", "abcd"))

        # user has neither WP nor Validated-SPN, access denied expected
        try:
            self.replace_spn(self.ldb_user1, self.computerdn, "HOST/%s/%s" % (self.computername, netbiosdomain))
        except LdbError as e45:
            (num, _) = e45.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()

        mod = "(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;%s)" % str(self.user_sid1)
        self.sd_utils.dacl_add_ace(self.computerdn, mod)
        # grant Validated-SPN and check which values are accepted
        # see 3.1.1.5.3.1.1.4 servicePrincipalName for reference

        # for regular computer objects we shouldalways get constraint violation

        # This does not pass against Windows, although it should according to docs
        self.replace_spn(self.ldb_user1, self.computerdn, "HOST/%s" % (self.computername))
        self.replace_spn(self.ldb_user1, self.computerdn, "HOST/%s.%s" %
                         (self.computername, self.dcctx.dnsdomain))

        try:
            self.replace_spn(self.ldb_user1, self.computerdn, "HOST/%s/%s" % (self.computername, netbiosdomain))
        except LdbError as e46:
            (num, _) = e46.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            self.fail()
        try:
            self.replace_spn(self.ldb_user1, self.computerdn, "HOST/%s.%s/%s" %
                             (self.computername, self.dcctx.dnsdomain, netbiosdomain))
        except LdbError as e47:
            (num, _) = e47.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            self.fail()
        try:
            self.replace_spn(self.ldb_user1, self.computerdn, "HOST/%s/%s" %
                             (self.computername, self.dcctx.dnsdomain))
        except LdbError as e48:
            (num, _) = e48.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            self.fail()
        try:
            self.replace_spn(self.ldb_user1, self.computerdn, "HOST/%s.%s/%s" %
                             (self.computername, self.dcctx.dnsdomain, self.dcctx.dnsdomain))
        except LdbError as e49:
            (num, _) = e49.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            self.fail()
        try:
            self.replace_spn(self.ldb_user1, self.computerdn, "GC/%s.%s/%s" %
                             (self.computername, self.dcctx.dnsdomain, self.dcctx.dnsforest))
        except LdbError as e50:
            (num, _) = e50.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            self.fail()
        try:
            self.replace_spn(self.ldb_user1, self.computerdn, "ldap/%s/%s" % (self.computername, netbiosdomain))
        except LdbError as e51:
            (num, _) = e51.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            self.fail()
        try:
            self.replace_spn(self.ldb_user1, self.computerdn, "ldap/%s.%s/ForestDnsZones.%s" %
                             (self.computername, self.dcctx.dnsdomain, self.dcctx.dnsdomain))
        except LdbError as e52:
            (num, _) = e52.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            self.fail()

    def test_spn_rwdc(self):
        self.dc_spn_test(self.dcctx)

    def test_spn_rodc(self):
        self.dc_spn_test(self.rodcctx)

    def test_user_spn(self):
        #grant SW to a regular user and try to set the spn on a user object
        #should get  ERR_INSUFFICIENT_ACCESS_RIGHTS, since Validate-SPN only applies to computer
        self.ldb_admin.newuser(self.user_object, self.user_pass)
        mod = "(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;%s)" % str(self.user_sid1)
        self.sd_utils.dacl_add_ace(self.user_object_dn, mod)
        try:
            self.replace_spn(self.ldb_user1, self.user_object_dn, "nosuchservice/%s/%s" % ("abcd", "abcd"))
        except LdbError as e60:
            (num, _) = e60.args
            self.assertEqual(num, ERR_INSUFFICIENT_ACCESS_RIGHTS)
        else:
            self.fail()

    def test_delete_add_spn(self):
        # Grant Validated-SPN property.
        mod = f'(OA;;SW;{security.GUID_DRS_VALIDATE_SPN};;{self.user_sid1})'
        self.sd_utils.dacl_add_ace(self.computerdn, mod)

        spn_base = f'HOST/{self.computername}'

        allowed_spn = f'{spn_base}.{self.dcctx.dnsdomain}'
        not_allowed_spn = f'{spn_base}/{self.dcctx.get_domain_name()}'

        # Ensure we are able to add an allowed SPN.
        msg = Message(Dn(self.ldb_user1, self.computerdn))
        msg['servicePrincipalName'] = MessageElement(allowed_spn,
                                                     FLAG_MOD_ADD,
                                                     'servicePrincipalName')
        self.ldb_user1.modify(msg)

        # Ensure we are not able to add a disallowed SPN.
        msg = Message(Dn(self.ldb_user1, self.computerdn))
        msg['servicePrincipalName'] = MessageElement(not_allowed_spn,
                                                     FLAG_MOD_ADD,
                                                     'servicePrincipalName')
        try:
            self.ldb_user1.modify(msg)
        except LdbError as e:
            num, _ = e.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            self.fail(f'able to add disallowed SPN {not_allowed_spn}')

        # Ensure that deleting an existing SPN followed by adding a disallowed
        # SPN fails.
        msg = Message(Dn(self.ldb_user1, self.computerdn))
        msg['0'] = MessageElement([],
                                  FLAG_MOD_DELETE,
                                  'servicePrincipalName')
        msg['1'] = MessageElement(not_allowed_spn,
                                  FLAG_MOD_ADD,
                                  'servicePrincipalName')
        try:
            self.ldb_user1.modify(msg)
        except LdbError as e:
            num, _ = e.args
            self.assertEqual(num, ERR_CONSTRAINT_VIOLATION)
        else:
            self.fail(f'able to add disallowed SPN {not_allowed_spn}')

    def test_delete_disallowed_spn(self):
        # Grant Validated-SPN property.
        mod = f'(OA;;SW;{security.GUID_DRS_VALIDATE_SPN};;{self.user_sid1})'
        self.sd_utils.dacl_add_ace(self.computerdn, mod)

        spn_base = f'HOST/{self.computername}'

        not_allowed_spn = f'{spn_base}/{self.dcctx.get_domain_name()}'

        # Add a disallowed SPN as admin.
        msg = Message(Dn(self.ldb_admin, self.computerdn))
        msg['servicePrincipalName'] = MessageElement(not_allowed_spn,
                                                     FLAG_MOD_ADD,
                                                     'servicePrincipalName')
        self.ldb_admin.modify(msg)

        # Ensure we are able to delete a disallowed SPN.
        msg = Message(Dn(self.ldb_user1, self.computerdn))
        msg['servicePrincipalName'] = MessageElement(not_allowed_spn,
                                                     FLAG_MOD_DELETE,
                                                     'servicePrincipalName')
        try:
            self.ldb_user1.modify(msg)
        except LdbError:
            self.fail(f'unable to delete disallowed SPN {not_allowed_spn}')


# tests SEC_ADS_LIST vs. SEC_ADS_LIST_OBJECT
@DynamicTestCase
class AclVisibiltyTests(AclTests):

    envs = {
        "No": False,
        "Do": True,
    }
    modes = {
        "Allow": False,
        "Deny": True,
    }
    perms = {
        "nn": 0,
        "Cn": security.SEC_ADS_LIST,
        "nO": security.SEC_ADS_LIST_OBJECT,
        "CO": security.SEC_ADS_LIST | security.SEC_ADS_LIST_OBJECT,
    }

    @classmethod
    def setUpDynamicTestCases(cls):
        for le in cls.envs.keys():
            for lm in cls.modes.keys():
                for l1 in cls.perms.keys():
                    for l2 in cls.perms.keys():
                        for l3 in cls.perms.keys():
                            tname = "%s_%s_%s_%s_%s" % (le, lm, l1, l2, l3)
                            ve = cls.envs[le]
                            vm = cls.modes[lm]
                            v1 = cls.perms[l1]
                            v2 = cls.perms[l2]
                            v3 = cls.perms[l3]
                            targs = (tname, ve, vm, v1, v2, v3)
                            cls.generate_dynamic_test("test_visibility",
                                                      tname, *targs)
        return

    def setUp(self):
        super(AclVisibiltyTests, self).setUp()

        # Get the old "dSHeuristics" if it was set
        self.dsheuristics = self.ldb_admin.get_dsheuristics()
        # Reset the "dSHeuristics" as they were before
        self.addCleanup(self.ldb_admin.set_dsheuristics, self.dsheuristics)

        # Domain Admins and SYSTEM get full access
        self.sddl_dacl = "D:PAI(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
        self.set_dacl_control = ["sd_flags:1:%d" % security.SECINFO_DACL]

        self.level_idxs = [ 1, 2, 3, 4 ]
        self.oul1 = "OU=acl_visibility_oul1"
        self.oul1_dn_str = "%s,%s" % (self.oul1, self.base_dn)
        self.oul2 = "OU=oul2,%s" % self.oul1
        self.oul2_dn_str = "%s,%s" % (self.oul2, self.base_dn)
        self.oul3 = "OU=oul3,%s" % self.oul2
        self.oul3_dn_str = "%s,%s" % (self.oul3, self.base_dn)
        self.user_name = "acl_visibility_user"
        self.user_dn_str = "CN=%s,%s" % (self.user_name, self.oul3_dn_str)
        delete_force(self.ldb_admin, self.user_dn_str)
        delete_force(self.ldb_admin, self.oul3_dn_str)
        delete_force(self.ldb_admin, self.oul2_dn_str)
        delete_force(self.ldb_admin, self.oul1_dn_str)
        self.ldb_admin.create_ou(self.oul1_dn_str)
        self.sd_utils.modify_sd_on_dn(self.oul1_dn_str,
                                      self.sddl_dacl,
                                      controls=self.set_dacl_control)
        self.ldb_admin.create_ou(self.oul2_dn_str)
        self.sd_utils.modify_sd_on_dn(self.oul2_dn_str,
                                      self.sddl_dacl,
                                      controls=self.set_dacl_control)
        self.ldb_admin.create_ou(self.oul3_dn_str)
        self.sd_utils.modify_sd_on_dn(self.oul3_dn_str,
                                      self.sddl_dacl,
                                      controls=self.set_dacl_control)

        self.ldb_admin.newuser(self.user_name, self.user_pass, userou=self.oul3)
        self.user_sid = self.sd_utils.get_object_sid(self.user_dn_str)
        self.ldb_user = self.get_ldb_connection(self.user_name, self.user_pass)

    def tearDown(self):
        super(AclVisibiltyTests, self).tearDown()
        delete_force(self.ldb_admin, self.user_dn_str)
        delete_force(self.ldb_admin, self.oul3_dn_str)
        delete_force(self.ldb_admin, self.oul2_dn_str)
        delete_force(self.ldb_admin, self.oul1_dn_str)

        del self.ldb_user

    def _test_visibility_with_args(self,
                                   tname,
                                   fDoListObject,
                                   modeDeny,
                                   l1_allow,
                                   l2_allow,
                                   l3_allow):
        l1_deny = 0
        l2_deny = 0
        l3_deny = 0
        if modeDeny:
            l1_deny = ~l1_allow
            l2_deny = ~l2_allow
            l3_deny = ~l3_allow
        print("Testing: fDoListObject=%s, modeDeny=%s, l1_allow=0x%02x, l2_allow=0x%02x, l3_allow=0x%02x)" % (
              fDoListObject, modeDeny, l1_allow, l2_allow, l3_allow))
        if fDoListObject:
            self.ldb_admin.set_dsheuristics("001")
        else:
            self.ldb_admin.set_dsheuristics("000")

        def _generate_dacl(allow, deny):
            dacl = self.sddl_dacl
            drights = ""
            if deny & security.SEC_ADS_LIST:
                drights += "LC"
            if deny & security.SEC_ADS_LIST_OBJECT:
                drights += "LO"
            if len(drights) > 0:
                dacl += "(D;;%s;;;%s)" % (drights, self.user_sid)
            arights = ""
            if allow & security.SEC_ADS_LIST:
                arights += "LC"
            if allow & security.SEC_ADS_LIST_OBJECT:
                arights += "LO"
            if len(arights) > 0:
                dacl += "(A;;%s;;;%s)" % (arights, self.user_sid)
            print("dacl: %s" % dacl)
            return dacl

        l1_dacl = _generate_dacl(l1_allow, l1_deny)
        l2_dacl = _generate_dacl(l2_allow, l2_deny)
        l3_dacl = _generate_dacl(l3_allow, l3_deny)
        self.sd_utils.modify_sd_on_dn(self.oul1_dn_str,
                                      l1_dacl,
                                      controls=self.set_dacl_control)
        self.sd_utils.modify_sd_on_dn(self.oul2_dn_str,
                                      l2_dacl,
                                      controls=self.set_dacl_control)
        self.sd_utils.modify_sd_on_dn(self.oul3_dn_str,
                                      l3_dacl,
                                      controls=self.set_dacl_control)

        def _generate_levels(_l1_allow,
                             _l1_deny,
                             _l2_allow,
                             _l2_deny,
                             _l3_allow,
                             _l3_deny):
            _l0_allow = security.SEC_ADS_LIST | security.SEC_ADS_LIST_OBJECT | security.SEC_ADS_READ_PROP
            _l0_deny = 0
            _l4_allow = security.SEC_ADS_LIST | security.SEC_ADS_LIST_OBJECT | security.SEC_ADS_READ_PROP
            _l4_deny = 0
            _levels = [{
                "dn": str(self.base_dn),
                "allow": _l0_allow,
                "deny": _l0_deny,
            },{
                "dn": str(self.oul1_dn_str),
                "allow": _l1_allow,
                "deny": _l1_deny,
            },{
                "dn": str(self.oul2_dn_str),
                "allow": _l2_allow,
                "deny": _l2_deny,
            },{
                "dn": str(self.oul3_dn_str),
                "allow": _l3_allow,
                "deny": _l3_deny,
            },{
                "dn": str(self.user_dn_str),
                "allow": _l4_allow,
                "deny": _l4_deny,
            }]
            return _levels

        def _generate_admin_levels():
            _l1_allow = security.SEC_ADS_LIST | security.SEC_ADS_READ_PROP
            _l1_deny = 0
            _l2_allow = security.SEC_ADS_LIST | security.SEC_ADS_READ_PROP
            _l2_deny = 0
            _l3_allow = security.SEC_ADS_LIST | security.SEC_ADS_READ_PROP
            _l3_deny = 0
            return _generate_levels(_l1_allow, _l1_deny,
                                    _l2_allow, _l2_deny,
                                    _l3_allow, _l3_deny)

        def _generate_user_levels():
            return _generate_levels(l1_allow, l1_deny,
                                    l2_allow, l2_deny,
                                    l3_allow, l3_deny)

        admin_levels = _generate_admin_levels()
        user_levels = _generate_user_levels()

        def _msg_require_name(msg, idx, e):
            self.assertIn("name", msg)
            self.assertEqual(len(msg["name"]), 1)

        def _msg_no_name(msg, idx, e):
            self.assertNotIn("name", msg)

        def _has_right(allow, deny, bit):
            if allow & bit:
                if not (deny & bit):
                    return True
            return False

        def _is_visible(p_allow, p_deny, o_allow, o_deny):
            plc = _has_right(p_allow, p_deny, security.SEC_ADS_LIST)
            if plc:
                return True
            if not fDoListObject:
                return False
            plo = _has_right(p_allow, p_deny, security.SEC_ADS_LIST_OBJECT)
            if not plo:
                return False
            olo = _has_right(o_allow, o_deny, security.SEC_ADS_LIST_OBJECT)
            if not olo:
                return False
            return True

        def _generate_expected(scope, base_level, levels):
            expected = {}

            p = levels[base_level-1]
            o = levels[base_level]
            base_visible = _is_visible(p["allow"], p["deny"],
                                       o["allow"], o["deny"])

            if scope == SCOPE_BASE:
                lmin = base_level
                lmax = base_level
            elif scope == SCOPE_ONELEVEL:
                lmin = base_level+1
                lmax = base_level+1
            else:
                lmin = base_level
                lmax = len(levels)

            next_idx = 0
            for li in self.level_idxs:
                if li < lmin:
                    continue
                if li > lmax:
                    break
                p = levels[li-1]
                o = levels[li]
                visible = _is_visible(p["allow"], p["deny"],
                                      o["allow"], o["deny"])
                if not visible:
                    continue
                read = _has_right(o["allow"], o["deny"], security.SEC_ADS_READ_PROP)
                if read:
                    check_msg_fn = _msg_require_name
                else:
                    check_msg_fn = _msg_no_name
                expected[o["dn"]] = {
                    "idx": next_idx,
                    "check_msg_fn": check_msg_fn,
                }
                next_idx += 1

            if len(expected) == 0 and not base_visible:
                # This means we're expecting NO_SUCH_OBJECT
                return None
            return expected

        def _verify_result_array(results,
                                 description,
                                 expected):
            print("%s Results: %d" % (description, len(results)))
            for msg in results:
                print("%s" % msg)
            self.assertIsNotNone(expected)
            print("%s Expected: %d" % (description, len(expected)))
            for e in expected:
                print("%s" % e)
            self.assertEqual(len(results), len(expected))
            idx = 0
            found = {}
            for msg in results:
                dn_str = str(msg.dn)
                self.assertIn(dn_str, expected)
                self.assertNotIn(dn_str, found)
                found[dn_str] = idx
                e = expected[dn_str]
                if self.strict_checking:
                    self.assertEqual(idx, int(e["idx"]))
                if "check_msg_fn" in e:
                    check_msg_fn = e["check_msg_fn"]
                    check_msg_fn(msg, idx, e)
                idx += 1

            return

        for li in self.level_idxs:
            base_dn = admin_levels[li]["dn"]
            for scope in [SCOPE_BASE, SCOPE_ONELEVEL, SCOPE_SUBTREE]:
                print("\nTesting SCOPE[%d] %s" % (scope, base_dn))
                admin_expected = _generate_expected(scope, li, admin_levels)
                admin_res = self.ldb_admin.search(base_dn, scope=scope, attrs=["name"])
                _verify_result_array(admin_res, "Admin", admin_expected)

                user_expected = _generate_expected(scope, li, user_levels)
                try:
                    user_res = self.ldb_user.search(base_dn, scope=scope, attrs=["name"])
                except LdbError as e:
                    (num, _) = e.args
                    if user_expected is None:
                        self.assertEqual(num, ERR_NO_SUCH_OBJECT)
                        print("User: NO_SUCH_OBJECT")
                        continue
                    self.fail(e)
                _verify_result_array(user_res, "User", user_expected)

# Important unit running information

ldb = SamDB(ldaphost, credentials=creds, session_info=system_session(lp), lp=lp)

TestProgram(module=__name__, opts=subunitopts)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import optparse
import sys
import os
import base64
import re
import random

sys.path.insert(0, "bin/python")
import samba

from samba.tests.subunitrun import SubunitOptions, TestProgram

import samba.getopt as options

# Some error messages that are being tested
from ldb import SCOPE_SUBTREE, SCOPE_BASE, LdbError, ERR_NO_SUCH_OBJECT

# For running the test unit
from samba.ndr import ndr_pack, ndr_unpack
from samba.dcerpc import security

from samba import gensec, sd_utils
from samba.samdb import SamDB
from samba.credentials import Credentials, DONT_USE_KERBEROS
from samba.auth import system_session
from samba.dsdb import DS_DOMAIN_FUNCTION_2008
from samba.dcerpc.security import (
    SECINFO_OWNER, SECINFO_GROUP, SECINFO_DACL, SECINFO_SACL)
import samba.tests
from samba.tests import delete_force

parser = optparse.OptionParser("sec_descriptor.py [options] <host>")
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

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)
creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)

#
# Tests start here
#


class DescriptorTests(samba.tests.TestCase):

    def get_users_domain_dn(self, name):
        return "CN=%s,CN=Users,%s" % (name, self.base_dn)

    def create_schema_class(self, _ldb, desc=None):
        while True:
            class_id = random.randint(0, 65535)
            class_name = "descriptor-test-class%s" % class_id
            class_dn = "CN=%s,%s" % (class_name, self.schema_dn)
            try:
                self.ldb_admin.search(base=class_dn, attrs=["name"])
            except LdbError as e:
                (num, _) = e.args
                self.assertEqual(num, ERR_NO_SUCH_OBJECT)
                break

        ldif = """
dn: """ + class_dn + """
objectClass: classSchema
objectCategory: CN=Class-Schema,""" + self.schema_dn + """
defaultObjectCategory: """ + class_dn + """
governsId: 1.3.6.1.4.1.7165.4.6.2.3.""" + str(class_id) + """
instanceType: 4
objectClassCategory: 1
subClassOf: organizationalPerson
systemFlags: 16
rDNAttID: cn
systemMustContain: cn
systemOnly: FALSE
"""
        if desc:
            assert(isinstance(desc, str) or isinstance(desc, security.descriptor))
            if isinstance(desc, str):
                ldif += "nTSecurityDescriptor: %s" % desc
            elif isinstance(desc, security.descriptor):
                ldif += "nTSecurityDescriptor:: %s" % base64.b64encode(ndr_pack(desc)).decode('utf8')
        _ldb.add_ldif(ldif)
        return class_dn

    def create_configuration_container(self, _ldb, object_dn, desc=None):
        ldif = """
dn: """ + object_dn + """
objectClass: container
objectCategory: CN=Container,""" + self.schema_dn + """
showInAdvancedViewOnly: TRUE
instanceType: 4
"""
        if desc:
            assert(isinstance(desc, str) or isinstance(desc, security.descriptor))
            if isinstance(desc, str):
                ldif += "nTSecurityDescriptor: %s" % desc
            elif isinstance(desc, security.descriptor):
                ldif += "nTSecurityDescriptor:: %s" % base64.b64encode(ndr_pack(desc)).decode('utf8')
        _ldb.add_ldif(ldif)

    def create_configuration_specifier(self, _ldb, object_dn, desc=None):
        ldif = """
dn: """ + object_dn + """
objectClass: displaySpecifier
showInAdvancedViewOnly: TRUE
"""
        if desc:
            assert(isinstance(desc, str) or isinstance(desc, security.descriptor))
            if isinstance(desc, str):
                ldif += "nTSecurityDescriptor: %s" % desc
            elif isinstance(desc, security.descriptor):
                ldif += "nTSecurityDescriptor:: %s" % base64.b64encode(ndr_pack(desc)).decode('utf8')
        _ldb.add_ldif(ldif)

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
        ldb_target = SamDB(url=host, credentials=creds_tmp, lp=lp)
        return ldb_target

    def setUp(self):
        super(DescriptorTests, self).setUp()
        self.ldb_admin = SamDB(host, credentials=creds, session_info=system_session(lp), lp=lp,
                               options=ldb_options)
        self.base_dn = self.ldb_admin.domain_dn()
        self.configuration_dn = self.ldb_admin.get_config_basedn().get_linearized()
        self.schema_dn = self.ldb_admin.get_schema_basedn().get_linearized()
        self.domain_sid = security.dom_sid(self.ldb_admin.get_domain_sid())
        self.sd_utils = sd_utils.SDUtils(self.ldb_admin)
        self.addCleanup(self.delete_admin_connection)
        print("baseDN: %s" % self.base_dn)

    def delete_admin_connection(self):
        del self.sd_utils
        del self.ldb_admin

    ################################################################################################

    # Tests for DOMAIN

    # Default descriptor tests #####################################################################


class OwnerGroupDescriptorTests(DescriptorTests):

    def deleteAll(self):
        delete_force(self.ldb_admin, self.get_users_domain_dn("testuser1"))
        delete_force(self.ldb_admin, self.get_users_domain_dn("testuser2"))
        delete_force(self.ldb_admin, self.get_users_domain_dn("testuser3"))
        delete_force(self.ldb_admin, self.get_users_domain_dn("testuser4"))
        delete_force(self.ldb_admin, self.get_users_domain_dn("testuser5"))
        delete_force(self.ldb_admin, self.get_users_domain_dn("testuser6"))
        delete_force(self.ldb_admin, self.get_users_domain_dn("testuser7"))
        delete_force(self.ldb_admin, self.get_users_domain_dn("testuser8"))
        # DOMAIN
        delete_force(self.ldb_admin, self.get_users_domain_dn("test_domain_group1"))
        delete_force(self.ldb_admin, "CN=test_domain_user1,OU=test_domain_ou1," + self.base_dn)
        delete_force(self.ldb_admin, "OU=test_domain_ou2,OU=test_domain_ou1," + self.base_dn)
        delete_force(self.ldb_admin, "OU=test_domain_ou1," + self.base_dn)
        # SCHEMA
        mod = "(A;CI;WDCC;;;AU)(A;;CC;;;AU)"
        self.sd_utils.dacl_delete_aces(self.schema_dn, mod)
        # CONFIGURATION
        delete_force(self.ldb_admin, "CN=test-specifier1,CN=test-container1,CN=DisplaySpecifiers,"
                     + self.configuration_dn)
        delete_force(self.ldb_admin, "CN=test-container1,CN=DisplaySpecifiers," + self.configuration_dn)

    def setUp(self):
        super(OwnerGroupDescriptorTests, self).setUp()
        self.deleteAll()
        # Create users
        # User 1 - Enterprise Admins
        self.ldb_admin.newuser("testuser1", "samba123@")
        # User 2 - Domain Admins
        self.ldb_admin.newuser("testuser2", "samba123@")
        # User 3 - Schema Admins
        self.ldb_admin.newuser("testuser3", "samba123@")
        # User 4 - regular user
        self.ldb_admin.newuser("testuser4", "samba123@")
        # User 5 - Enterprise Admins and Domain Admins
        self.ldb_admin.newuser("testuser5", "samba123@")
        # User 6 - Enterprise Admins, Domain Admins, Schema Admins
        self.ldb_admin.newuser("testuser6", "samba123@")
        # User 7 - Domain Admins and Schema Admins
        self.ldb_admin.newuser("testuser7", "samba123@")
        # User 5 - Enterprise Admins and Schema Admins
        self.ldb_admin.newuser("testuser8", "samba123@")

        self.ldb_admin.add_remove_group_members("Enterprise Admins",
                                                ["testuser1", "testuser5", "testuser6", "testuser8"],
                                                add_members_operation=True)
        self.ldb_admin.add_remove_group_members("Domain Admins",
                                                ["testuser2", "testuser5", "testuser6", "testuser7"],
                                                add_members_operation=True)
        self.ldb_admin.add_remove_group_members("Schema Admins",
                                                ["testuser3", "testuser6", "testuser7", "testuser8"],
                                                add_members_operation=True)

        self.results = {
            # msDS-Behavior-Version < DS_DOMAIN_FUNCTION_2008
            "ds_behavior_win2003": {
                "100": "O:EAG:DU",
                "101": "O:DAG:DU",
                "102": "O:%sG:DU",
                "103": "O:%sG:DU",
                "104": "O:DAG:DU",
                "105": "O:DAG:DU",
                "106": "O:DAG:DU",
                "107": "O:EAG:DU",
                "108": "O:DAG:DA",
                "109": "O:DAG:DA",
                "110": "O:%sG:DA",
                "111": "O:%sG:DA",
                "112": "O:DAG:DA",
                "113": "O:DAG:DA",
                "114": "O:DAG:DA",
                "115": "O:DAG:DA",
                "130": "O:EAG:DU",
                "131": "O:DAG:DU",
                "132": "O:SAG:DU",
                "133": "O:%sG:DU",
                "134": "O:EAG:DU",
                "135": "O:SAG:DU",
                "136": "O:SAG:DU",
                "137": "O:SAG:DU",
                "138": "O:DAG:DA",
                "139": "O:DAG:DA",
                "140": "O:%sG:DA",
                "141": "O:%sG:DA",
                "142": "O:DAG:DA",
                "143": "O:DAG:DA",
                "144": "O:DAG:DA",
                "145": "O:DAG:DA",
                "160": "O:EAG:DU",
                "161": "O:DAG:DU",
                "162": "O:%sG:DU",
                "163": "O:%sG:DU",
                "164": "O:EAG:DU",
                "165": "O:EAG:DU",
                "166": "O:DAG:DU",
                "167": "O:EAG:DU",
                "168": "O:DAG:DA",
                "169": "O:DAG:DA",
                "170": "O:%sG:DA",
                "171": "O:%sG:DA",
                "172": "O:DAG:DA",
                "173": "O:DAG:DA",
                "174": "O:DAG:DA",
                "175": "O:DAG:DA",
            },
            # msDS-Behavior-Version >= DS_DOMAIN_FUNCTION_2008
            "ds_behavior_win2008": {
                "100": "O:EAG:EA",
                "101": "O:DAG:DA",
                "102": "O:%sG:DU",
                "103": "O:%sG:DU",
                "104": "O:DAG:DA",
                "105": "O:DAG:DA",
                "106": "O:DAG:DA",
                "107": "O:EAG:EA",
                "108": "O:DAG:DA",
                "109": "O:DAG:DA",
                "110": "O:%sG:DA",
                "111": "O:%sG:DA",
                "112": "O:DAG:DA",
                "113": "O:DAG:DA",
                "114": "O:DAG:DA",
                "115": "O:DAG:DA",
                "130": "O:EAG:EA",
                "131": "O:DAG:DA",
                "132": "O:SAG:SA",
                "133": "O:%sG:DU",
                "134": "O:EAG:EA",
                "135": "O:SAG:SA",
                "136": "O:SAG:SA",
                "137": "O:SAG:SA",
                "138": "",
                "139": "",
                "140": "O:%sG:DA",
                "141": "O:%sG:DA",
                "142": "",
                "143": "",
                "144": "",
                "145": "",
                "160": "O:EAG:EA",
                "161": "O:DAG:DA",
                "162": "O:%sG:DU",
                "163": "O:%sG:DU",
                "164": "O:EAG:EA",
                "165": "O:EAG:EA",
                "166": "O:DAG:DA",
                "167": "O:EAG:EA",
                "168": "O:DAG:DA",
                "169": "O:DAG:DA",
                "170": "O:%sG:DA",
                "171": "O:%sG:DA",
                "172": "O:DAG:DA",
                "173": "O:DAG:DA",
                "174": "O:DAG:DA",
                "175": "O:DAG:DA",
            },
        }
        # Discover 'domainControllerFunctionality'
        res = self.ldb_admin.search(base="", scope=SCOPE_BASE,
                                    attrs=['domainControllerFunctionality'])
        res = int(res[0]['domainControllerFunctionality'][0])
        if res < DS_DOMAIN_FUNCTION_2008:
            self.DS_BEHAVIOR = "ds_behavior_win2003"
        else:
            self.DS_BEHAVIOR = "ds_behavior_win2008"

    def tearDown(self):
        super(OwnerGroupDescriptorTests, self).tearDown()
        self.deleteAll()

    def check_user_belongs(self, user_dn, groups=None):
        """ Test whether user is member of the expected group(s) """
        if groups is None:
            groups = []

        if groups != []:
            # User is member of at least one additional group
            res = self.ldb_admin.search(user_dn, attrs=["memberOf"])
            res = [str(x).upper() for x in sorted(list(res[0]["memberOf"]))]
            expected = []
            for x in groups:
                expected.append(self.get_users_domain_dn(x))
            expected = [x.upper() for x in sorted(expected)]
            self.assertEqual(expected, res)
        else:
            # User is not a member of any additional groups but default
            res = self.ldb_admin.search(user_dn, attrs=["*"])
            res = [x.upper() for x in res[0].keys()]
            self.assertNotIn("MEMBEROF", res)

    def check_modify_inheritance(self, _ldb, object_dn, owner_group=""):
        # Modify
        sd_user_utils = sd_utils.SDUtils(_ldb)
        ace = "(D;;CC;;;LG)"  # Deny Create Children to Guest account
        if owner_group != "":
            sd_user_utils.modify_sd_on_dn(object_dn, owner_group + "D:" + ace)
        else:
            sd_user_utils.modify_sd_on_dn(object_dn, "D:" + ace)
        # Make sure the modify operation has been applied
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        self.assertIn(ace, desc_sddl)
        # Make sure we have identical result for both "add" and "modify"
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        print(self._testMethodName)
        test_number = self._testMethodName[5:]
        self.assertEqual(self.results[self.DS_BEHAVIOR][test_number], res)

    def test_100(self):
        """ Enterprise admin group member creates object (default nTSecurityDescriptor) in DOMAIN
        """
        user_name = "testuser1"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        _ldb.newgroup("test_domain_group1", grouptype=4)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_101(self):
        """ Domain admin group member creates object (default nTSecurityDescriptor) in DOMAIN
        """
        user_name = "testuser2"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        _ldb.newgroup("test_domain_group1", grouptype=4)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_102(self):
        """ Schema admin group member with CC right creates object (default nTSecurityDescriptor) in DOMAIN
        """
        user_name = "testuser3"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "OU=test_domain_ou1," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        self.ldb_admin.create_ou(object_dn)
        user_sid = self.sd_utils.get_object_sid(self.get_users_domain_dn(user_name))
        mod = "(A;CI;WPWDCC;;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace(object_dn, mod)
        # Create additional object into the first one
        object_dn = "CN=test_domain_user1," + object_dn
        delete_force(self.ldb_admin, object_dn)
        _ldb.newuser("test_domain_user1", "samba123@",
                     userou="OU=test_domain_ou1", setpassword=False)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)
        # This fails, research why
        #self.check_modify_inheritance(_ldb, object_dn)

    def test_103(self):
        """ Regular user with CC right creates object (default nTSecurityDescriptor) in DOMAIN
        """
        user_name = "testuser4"
        self.check_user_belongs(self.get_users_domain_dn(user_name), [])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "OU=test_domain_ou1," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        self.ldb_admin.create_ou(object_dn)
        user_sid = self.sd_utils.get_object_sid(self.get_users_domain_dn(user_name))
        mod = "(A;CI;WPWDCC;;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace(object_dn, mod)
        # Create additional object into the first one
        object_dn = "CN=test_domain_user1," + object_dn
        delete_force(self.ldb_admin, object_dn)
        _ldb.newuser("test_domain_user1", "samba123@",
                     userou="OU=test_domain_ou1", setpassword=False)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)
        # this fails, research why
        #self.check_modify_inheritance(_ldb, object_dn)

    def test_104(self):
        """ Enterprise & Domain admin group member creates object (default nTSecurityDescriptor) in DOMAIN
        """
        user_name = "testuser5"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        _ldb.newgroup("test_domain_group1", grouptype=4)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_105(self):
        """ Enterprise & Domain & Schema admin group member creates object (default nTSecurityDescriptor) in DOMAIN
        """
        user_name = "testuser6"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        _ldb.newgroup("test_domain_group1", grouptype=4)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_106(self):
        """ Domain & Schema admin group member creates object (default nTSecurityDescriptor) in DOMAIN
        """
        user_name = "testuser7"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        _ldb.newgroup("test_domain_group1", grouptype=4)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_107(self):
        """ Enterprise & Schema admin group member creates object (default nTSecurityDescriptor) in DOMAIN
        """
        user_name = "testuser8"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        _ldb.newgroup("test_domain_group1", grouptype=4)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    # Control descriptor tests #####################################################################

    def test_108(self):
        """ Enterprise admin group member creates object (custom descriptor) in DOMAIN
        """
        user_name = "testuser1"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        tmp_desc = security.descriptor.from_sddl(sddl, self.domain_sid)
        _ldb.newgroup("test_domain_group1", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)

    def test_109(self):
        """ Domain admin group member creates object (custom descriptor) in DOMAIN
        """
        user_name = "testuser2"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        tmp_desc = security.descriptor.from_sddl(sddl, self.domain_sid)
        _ldb.newgroup("test_domain_group1", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)

    def test_110(self):
        """ Schema admin group member with CC right creates object (custom descriptor) in DOMAIN
        """
        user_name = "testuser3"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "OU=test_domain_ou1," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        self.ldb_admin.create_ou(object_dn)
        user_sid = self.sd_utils.get_object_sid(self.get_users_domain_dn(user_name))
        mod = "(A;CI;WOWDCC;;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace(object_dn, mod)
        # Create a custom security descriptor
        # NB! Problematic owner part won't accept DA only <User Sid> !!!
        sddl = "O:%sG:DAD:(A;;RP;;;DU)" % str(user_sid)
        tmp_desc = security.descriptor.from_sddl(sddl, self.domain_sid)
        # Create additional object into the first one
        object_dn = "CN=test_domain_user1," + object_dn
        delete_force(self.ldb_admin, object_dn)
        _ldb.newuser("test_domain_user1", "samba123@",
                     userou="OU=test_domain_ou1", sd=tmp_desc, setpassword=False)
        desc = self.sd_utils.read_sd_on_dn(object_dn)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)

    def test_111(self):
        """ Regular user with CC right creates object (custom descriptor) in DOMAIN
        """
        user_name = "testuser4"
        self.check_user_belongs(self.get_users_domain_dn(user_name), [])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "OU=test_domain_ou1," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        self.ldb_admin.create_ou(object_dn)
        user_sid = self.sd_utils.get_object_sid(self.get_users_domain_dn(user_name))
        mod = "(A;CI;WOWDCC;;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace(object_dn, mod)
        # Create a custom security descriptor
        # NB! Problematic owner part won't accept DA only <User Sid> !!!
        sddl = "O:%sG:DAD:(A;;RP;;;DU)" % str(user_sid)
        tmp_desc = security.descriptor.from_sddl(sddl, self.domain_sid)
        # Create additional object into the first one
        object_dn = "CN=test_domain_user1," + object_dn
        delete_force(self.ldb_admin, object_dn)
        _ldb.newuser("test_domain_user1", "samba123@",
                     userou="OU=test_domain_ou1", sd=tmp_desc, setpassword=False)
        desc = self.sd_utils.read_sd_on_dn(object_dn)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)

    def test_112(self):
        """ Domain & Enterprise admin group member creates object (custom descriptor) in DOMAIN
        """
        user_name = "testuser5"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        tmp_desc = security.descriptor.from_sddl(sddl, self.domain_sid)
        _ldb.newgroup("test_domain_group1", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)

    def test_113(self):
        """ Domain & Enterprise & Schema admin group  member creates object (custom descriptor) in DOMAIN
        """
        user_name = "testuser6"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        tmp_desc = security.descriptor.from_sddl(sddl, self.domain_sid)
        _ldb.newgroup("test_domain_group1", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)

    def test_114(self):
        """ Domain & Schema admin group  member creates object (custom descriptor) in DOMAIN
        """
        user_name = "testuser7"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        tmp_desc = security.descriptor.from_sddl(sddl, self.domain_sid)
        _ldb.newgroup("test_domain_group1", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)

    def test_115(self):
        """ Enterprise & Schema admin group  member creates object (custom descriptor) in DOMAIN
        """
        user_name = "testuser8"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        object_dn = "CN=test_domain_group1,CN=Users," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        tmp_desc = security.descriptor.from_sddl(sddl, self.domain_sid)
        _ldb.newgroup("test_domain_group1", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)

    def test_999(self):
        user_name = "Administrator"
        object_dn = "OU=test_domain_ou1," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        self.ldb_admin.create_ou(object_dn)
        user_sid = self.sd_utils.get_object_sid(self.get_users_domain_dn(user_name))
        mod = "(D;CI;WP;;;S-1-3-0)"
        #mod = ""
        self.sd_utils.dacl_add_ace(object_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        # Create additional object into the first one
        object_dn = "OU=test_domain_ou2," + object_dn
        delete_force(self.ldb_admin, object_dn)
        self.ldb_admin.create_ou(object_dn)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)

    # Tests for SCHEMA

    # Default descriptor tests ##################################################################

    def test_130(self):
        user_name = "testuser1"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        user_sid = self.sd_utils.get_object_sid(self.get_users_domain_dn(user_name))
        mod = "(A;CI;WDCC;;;AU)"
        self.sd_utils.dacl_add_ace(self.schema_dn, mod)
        # Create example Schema class
        try:
            class_dn = self.create_schema_class(_ldb)
        except LdbError as e3:
            self.fail()
        desc_sddl = self.sd_utils.get_sd_as_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, class_dn)

    def test_131(self):
        user_name = "testuser2"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;CI;WDCC;;;AU)"
        self.sd_utils.dacl_add_ace(self.schema_dn, mod)
        # Create example Schema class
        class_dn = self.create_schema_class(_ldb)
        desc_sddl = self.sd_utils.get_sd_as_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, class_dn)

    def test_132(self):
        user_name = "testuser3"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;CI;WDCC;;;AU)"
        self.sd_utils.dacl_add_ace(self.schema_dn, mod)
        # Create example Schema class
        class_dn = self.create_schema_class(_ldb)
        desc_sddl = self.sd_utils.get_sd_as_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        #self.check_modify_inheritance(_ldb, class_dn)

    def test_133(self):
        user_name = "testuser4"
        self.check_user_belongs(self.get_users_domain_dn(user_name), [])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        user_sid = self.sd_utils.get_object_sid(self.get_users_domain_dn(user_name))
        mod = "(A;CI;WDCC;;;AU)"
        self.sd_utils.dacl_add_ace(self.schema_dn, mod)
        # Create example Schema class
        class_dn = self.create_schema_class(_ldb)
        desc_sddl = self.sd_utils.get_sd_as_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)
        #self.check_modify_inheritance(_ldb, class_dn)

    def test_134(self):
        user_name = "testuser5"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;CI;WDCC;;;AU)"
        self.sd_utils.dacl_add_ace(self.schema_dn, mod)
        # Create example Schema class
        class_dn = self.create_schema_class(_ldb)
        desc_sddl = self.sd_utils.get_sd_as_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, class_dn)

    def test_135(self):
        user_name = "testuser6"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;CI;WDCC;;;AU)"
        self.sd_utils.dacl_add_ace(self.schema_dn, mod)
        # Create example Schema class
        class_dn = self.create_schema_class(_ldb)
        desc_sddl = self.sd_utils.get_sd_as_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, class_dn)

    def test_136(self):
        user_name = "testuser7"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;CI;WDCC;;;AU)"
        self.sd_utils.dacl_add_ace(self.schema_dn, mod)
        # Create example Schema class
        class_dn = self.create_schema_class(_ldb)
        desc_sddl = self.sd_utils.get_sd_as_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, class_dn)

    def test_137(self):
        user_name = "testuser8"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;CI;WDCC;;;AU)"
        self.sd_utils.dacl_add_ace(self.schema_dn, mod)
        # Create example Schema class
        class_dn = self.create_schema_class(_ldb)
        desc_sddl = self.sd_utils.get_sd_as_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, class_dn)

    # Custom descriptor tests ##################################################################

    def test_138(self):
        user_name = "testuser1"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;;CC;;;AU)"
        self.sd_utils.dacl_add_ace(self.schema_dn, mod)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        # Create example Schema class
        class_dn = self.create_schema_class(_ldb, desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_139(self):
        user_name = "testuser2"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;;CC;;;AU)"
        self.sd_utils.dacl_add_ace(self.schema_dn, mod)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        # Create example Schema class
        class_dn = self.create_schema_class(_ldb, desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_140(self):
        user_name = "testuser3"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create a custom security descriptor
        # NB! Problematic owner part won't accept DA only <User Sid> !!!
        user_sid = self.sd_utils.get_object_sid(self.get_users_domain_dn(user_name))
        desc_sddl = "O:%sG:DAD:(A;;RP;;;DU)" % str(user_sid)
        # Create example Schema class
        class_dn = self.create_schema_class(_ldb, desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)

    def test_141(self):
        user_name = "testuser4"
        self.check_user_belongs(self.get_users_domain_dn(user_name), [])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;;CC;;;AU)"
        self.sd_utils.dacl_add_ace(self.schema_dn, mod)
        # Create a custom security descriptor
        # NB! Problematic owner part won't accept DA only <User Sid> !!!
        user_sid = self.sd_utils.get_object_sid(self.get_users_domain_dn(user_name))
        desc_sddl = "O:%sG:DAD:(A;;RP;;;DU)" % str(user_sid)
        # Create example Schema class
        class_dn = self.create_schema_class(_ldb, desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)

    def test_142(self):
        user_name = "testuser5"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;;CC;;;AU)"
        self.sd_utils.dacl_add_ace(self.schema_dn, mod)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        # Create example Schema class
        class_dn = self.create_schema_class(_ldb, desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_143(self):
        user_name = "testuser6"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;;CC;;;AU)"
        self.sd_utils.dacl_add_ace(self.schema_dn, mod)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        # Create example Schema class
        class_dn = self.create_schema_class(_ldb, desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_144(self):
        user_name = "testuser7"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;;CC;;;AU)"
        self.sd_utils.dacl_add_ace(self.schema_dn, mod)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        # Create example Schema class
        class_dn = self.create_schema_class(_ldb, desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_145(self):
        user_name = "testuser8"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Change Schema partition descriptor
        mod = "(A;;CC;;;AU)"
        self.sd_utils.dacl_add_ace(self.schema_dn, mod)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        # Create example Schema class
        class_dn = self.create_schema_class(_ldb, desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(class_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    # Tests for CONFIGURATION

    # Default descriptor tests ##################################################################

    def test_160(self):
        user_name = "testuser1"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(_ldb, object_dn, )
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_161(self):
        user_name = "testuser2"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(_ldb, object_dn, )
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_162(self):
        user_name = "testuser3"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        object_dn = "CN=test-container1,CN=DisplaySpecifiers," + self.configuration_dn
        delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(self.ldb_admin, object_dn, )
        user_sid = self.sd_utils.get_object_sid(self.get_users_domain_dn(user_name))
        mod = "(A;CI;WDCC;;;AU)"
        self.sd_utils.dacl_add_ace(object_dn, mod)
        # Create child object with user's credentials
        object_dn = "CN=test-specifier1," + object_dn
        delete_force(self.ldb_admin, object_dn)
        try:
            self.create_configuration_specifier(_ldb, object_dn)
        except LdbError as e3:
            self.fail()
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)
        #self.check_modify_inheritance(_ldb, object_dn)

    def test_163(self):
        user_name = "testuser4"
        self.check_user_belongs(self.get_users_domain_dn(user_name), [])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        object_dn = "CN=test-container1,CN=DisplaySpecifiers," + self.configuration_dn
        delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(self.ldb_admin, object_dn, )
        user_sid = self.sd_utils.get_object_sid(self.get_users_domain_dn(user_name))
        mod = "(A;CI;WDCC;;;AU)"
        self.sd_utils.dacl_add_ace(object_dn, mod)
        # Create child object with user's credentials
        object_dn = "CN=test-specifier1," + object_dn
        delete_force(self.ldb_admin, object_dn)
        self.create_configuration_specifier(_ldb, object_dn)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)
        #self.check_modify_inheritance(_ldb, object_dn)

    def test_164(self):
        user_name = "testuser5"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(_ldb, object_dn, )
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_165(self):
        user_name = "testuser6"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(_ldb, object_dn, )
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_166(self):
        user_name = "testuser7"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(_ldb, object_dn, )
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    def test_167(self):
        user_name = "testuser8"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(_ldb, object_dn, )
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]], res)
        self.check_modify_inheritance(_ldb, object_dn)

    # Custom descriptor tests ##################################################################

    def test_168(self):
        user_name = "testuser1"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        self.create_configuration_container(_ldb, object_dn, desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_169(self):
        user_name = "testuser2"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        self.create_configuration_container(_ldb, object_dn, desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_170(self):
        user_name = "testuser3"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        object_dn = "CN=test-container1,CN=DisplaySpecifiers," + self.configuration_dn
        delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(self.ldb_admin, object_dn, )
        user_sid = self.sd_utils.get_object_sid(self.get_users_domain_dn(user_name))
        mod = "(A;CI;CCWD;;;AU)"
        self.sd_utils.dacl_add_ace(object_dn, mod)
        # Create child object with user's credentials
        object_dn = "CN=test-specifier1," + object_dn
        delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        # NB! Problematic owner part won't accept DA only <User Sid> !!!
        desc_sddl = "O:%sG:DAD:(A;;RP;;;DU)" % str(user_sid)
        try:
            self.create_configuration_specifier(_ldb, object_dn, desc_sddl)
        except LdbError as e3:
            self.fail()
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)

    def test_171(self):
        user_name = "testuser4"
        self.check_user_belongs(self.get_users_domain_dn(user_name), [])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        object_dn = "CN=test-container1,CN=DisplaySpecifiers," + self.configuration_dn
        delete_force(self.ldb_admin, object_dn)
        self.create_configuration_container(self.ldb_admin, object_dn, )
        user_sid = self.sd_utils.get_object_sid(self.get_users_domain_dn(user_name))
        mod = "(A;CI;CCWD;;;AU)"
        self.sd_utils.dacl_add_ace(object_dn, mod)
        # Create child object with user's credentials
        object_dn = "CN=test-specifier1," + object_dn
        delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        # NB! Problematic owner part won't accept DA only <User Sid> !!!
        desc_sddl = "O:%sG:DAD:(A;;RP;;;DU)" % str(user_sid)
        try:
            self.create_configuration_specifier(_ldb, object_dn, desc_sddl)
        except LdbError as e3:
            self.fail()
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual(self.results[self.DS_BEHAVIOR][self._testMethodName[5:]] % str(user_sid), res)

    def test_172(self):
        user_name = "testuser5"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        self.create_configuration_container(_ldb, object_dn, desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_173(self):
        user_name = "testuser6"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        self.create_configuration_container(_ldb, object_dn, desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_174(self):
        user_name = "testuser7"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Domain Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        self.create_configuration_container(_ldb, object_dn, desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    def test_175(self):
        user_name = "testuser8"
        self.check_user_belongs(self.get_users_domain_dn(user_name), ["Enterprise Admins", "Schema Admins"])
        # Open Ldb connection with the tested user
        _ldb = self.get_ldb_connection(user_name, "samba123@")
        # Create example Configuration container
        container_name = "test-container1"
        object_dn = "CN=%s,CN=DisplaySpecifiers,%s" % (container_name, self.configuration_dn)
        delete_force(self.ldb_admin, object_dn)
        # Create a custom security descriptor
        desc_sddl = "O:DAG:DAD:(A;;RP;;;DU)"
        self.create_configuration_container(_ldb, object_dn, desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(object_dn)
        res = re.search("(O:.*G:.*?)D:", desc_sddl).group(1)
        self.assertEqual("O:DAG:DA", res)

    ########################################################################################
    # Inheritance tests for DACL


class DaclDescriptorTests(DescriptorTests):

    def deleteAll(self):
        delete_force(self.ldb_admin, "CN=test_inherit_group,OU=test_inherit_ou," + self.base_dn)
        delete_force(self.ldb_admin, "OU=test_inherit_ou5,OU=test_inherit_ou1,OU=test_inherit_ou_p," + self.base_dn)
        delete_force(self.ldb_admin, "OU=test_inherit_ou6,OU=test_inherit_ou2,OU=test_inherit_ou_p," + self.base_dn)
        delete_force(self.ldb_admin, "OU=test_inherit_ou1,OU=test_inherit_ou_p," + self.base_dn)
        delete_force(self.ldb_admin, "OU=test_inherit_ou2,OU=test_inherit_ou_p," + self.base_dn)
        delete_force(self.ldb_admin, "OU=test_inherit_ou3,OU=test_inherit_ou_p," + self.base_dn)
        delete_force(self.ldb_admin, "OU=test_inherit_ou4,OU=test_inherit_ou_p," + self.base_dn)
        delete_force(self.ldb_admin, "OU=test_inherit_ou_p," + self.base_dn)
        delete_force(self.ldb_admin, "OU=test_inherit_ou," + self.base_dn)

    def setUp(self):
        super(DaclDescriptorTests, self).setUp()
        self.deleteAll()

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

    def test_200(self):
        """ OU with protected flag and child group. See if the group has inherit ACEs.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Create group child object
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4)
        # Make sure created group object contains NO inherit ACEs
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertNotIn("ID", desc_sddl)

    def test_201(self):
        """ OU with protected flag and no inherit ACEs, child group with custom descriptor.
            Verify group has custom and default ACEs only.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Create group child object using custom security descriptor
        sddl = "O:AUG:AUD:AI(D;;WP;;;DU)"
        tmp_desc = security.descriptor.from_sddl(sddl, self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        # Make sure created group descriptor has NO additional ACEs
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertEqual(desc_sddl, sddl)
        sddl = "O:AUG:AUD:AI(D;;CC;;;LG)"
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, sddl)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertEqual(desc_sddl, sddl)

    def test_202(self):
        """ OU with protected flag and add couple non-inheritable ACEs, child group.
            See if the group has any of the added ACEs.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom non-inheritable ACEs
        mod = "(D;;WP;;;DU)(A;;RP;;;DU)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        # Verify all inheritable ACEs are gone
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4)
        # Make sure created group object contains NO inherit ACEs
        # also make sure the added above non-inheritable ACEs are absent too
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertNotIn("ID", desc_sddl)
        for x in re.findall(r"\(.*?\)", mod):
            self.assertNotIn(x, desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertNotIn("ID", desc_sddl)
        for x in re.findall(r"\(.*?\)", mod):
            self.assertNotIn(x, desc_sddl)

    def test_203(self):
        """ OU with protected flag and add 'CI' ACE, child group.
            See if the group has the added inherited ACE.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'CI' ACE
        mod = "(D;CI;WP;;;DU)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        # Make sure created group object contains only the above inherited ACE
        # that we've added manually
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        mod = mod.replace(";CI;", ";CIID;")
        self.assertIn(mod, desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertIn(mod, desc_sddl)

    def test_204(self):
        """ OU with protected flag and add 'OI' ACE, child group.
            See if the group has the added inherited ACE.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'CI' ACE
        mod = "(D;OI;WP;;;DU)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        # Make sure created group object contains only the above inherited ACE
        # that we've added manually
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        mod = mod.replace(";OI;", ";OIIOID;")  # change it how it's gonna look like
        self.assertIn(mod, desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertIn(mod, desc_sddl)

    def test_205(self):
        """ OU with protected flag and add 'OA' for GUID & 'CI' ACE, child group.
            See if the group has the added inherited ACE.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'OA' for 'name' attribute & 'CI' ACE
        mod = "(OA;CI;WP;bf967a0e-0de6-11d0-a285-00aa003049e2;;DU)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        # Make sure created group object contains only the above inherited ACE
        # that we've added manually
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        mod = mod.replace(";CI;", ";CIID;")  # change it how it's gonna look like
        self.assertIn(mod, desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertIn(mod, desc_sddl)

    def test_206(self):
        """ OU with protected flag and add 'OA' for GUID & 'OI' ACE, child group.
            See if the group has the added inherited ACE.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'OA' for 'name' attribute & 'OI' ACE
        mod = "(OA;OI;WP;bf967a0e-0de6-11d0-a285-00aa003049e2;;DU)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        # Make sure created group object contains only the above inherited ACE
        # that we've added manually
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        mod = mod.replace(";OI;", ";OIIOID;")  # change it how it's gonna look like
        self.assertIn(mod, desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertIn(mod, desc_sddl)

    def test_207(self):
        """ OU with protected flag and add 'OA' for OU specific GUID & 'CI' ACE, child group.
            See if the group has the added inherited ACE.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'OA' for 'st' attribute (OU specific) & 'CI' ACE
        mod = "(OA;CI;WP;bf967a39-0de6-11d0-a285-00aa003049e2;;DU)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        # Make sure created group object contains only the above inherited ACE
        # that we've added manually
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        mod = mod.replace(";CI;", ";CIID;")  # change it how it's gonna look like
        self.assertIn(mod, desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertIn(mod, desc_sddl)

    def test_208(self):
        """ OU with protected flag and add 'OA' for OU specific GUID & 'OI' ACE, child group.
            See if the group has the added inherited ACE.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'OA' for 'st' attribute (OU specific) & 'OI' ACE
        mod = "(OA;OI;WP;bf967a39-0de6-11d0-a285-00aa003049e2;;DU)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        # Make sure created group object contains only the above inherited ACE
        # that we've added manually
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        mod = mod.replace(";OI;", ";OIIOID;")  # change it how it's gonna look like
        self.assertIn(mod, desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:(OA;OI;WP;bf967a39-0de6-11d0-a285-00aa003049e2;;DU)" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertIn(mod, desc_sddl)

    def test_209(self):
        """ OU with protected flag and add 'CI' ACE with 'CO' SID, child group.
            See if the group has the added inherited ACE.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'CI' ACE
        mod = "(D;CI;WP;;;CO)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        # Make sure created group object contains only the above inherited ACE(s)
        # that we've added manually
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn("(D;ID;WP;;;AU)", desc_sddl)
        self.assertIn("(D;CIIOID;WP;;;CO)", desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertIn("(D;ID;WP;;;DA)", desc_sddl)
        self.assertIn("(D;CIIOID;WP;;;CO)", desc_sddl)

    def test_210(self):
        """ OU with protected flag, provide ACEs with ID flag raised. Should be ignored.
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        self.create_clean_ou(ou_dn)
        # Add some custom  ACE
        mod = "D:(D;CIIO;WP;;;CO)(A;ID;WP;;;AU)"
        tmp_desc = security.descriptor.from_sddl(mod, self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        # Make sure created group object does not contain the ID ace
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertNotIn("(A;ID;WP;;;AU)", desc_sddl)

    def test_211(self):
        """ Provide ACE with CO SID, should be expanded and replaced
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'CI' ACE
        mod = "D:(D;CI;WP;;;CO)"
        tmp_desc = security.descriptor.from_sddl(mod, self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn("(D;;WP;;;DA)", desc_sddl)
        self.assertIn("(D;CIIO;WP;;;CO)", desc_sddl)

    def test_212(self):
        """ Provide ACE with IO flag, should be ignored
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'CI' ACE
        mod = "D:(D;CIIO;WP;;;CO)"
        tmp_desc = security.descriptor.from_sddl(mod, self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        # Make sure created group object contains only the above inherited ACE(s)
        # that we've added manually
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn("(D;CIIO;WP;;;CO)", desc_sddl)
        self.assertNotIn("(D;;WP;;;DA)", desc_sddl)
        self.assertNotIn("(D;CIIO;WP;;;CO)(D;CIIO;WP;;;CO)", desc_sddl)

    def test_213(self):
        """ Provide ACE with IO flag, should be ignored
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "D:(D;IO;WP;;;DA)"
        tmp_desc = security.descriptor.from_sddl(mod, self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        # Make sure created group object contains only the above inherited ACE(s)
        # that we've added manually
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertNotIn("(D;IO;WP;;;DA)", desc_sddl)

    def test_214(self):
        """ Test behavior of ACEs containing generic rights
        """
        ou_dn = "OU=test_inherit_ou_p," + self.base_dn
        ou_dn1 = "OU=test_inherit_ou1," + ou_dn
        ou_dn2 = "OU=test_inherit_ou2," + ou_dn
        ou_dn3 = "OU=test_inherit_ou3," + ou_dn
        ou_dn4 = "OU=test_inherit_ou4," + ou_dn
        ou_dn5 = "OU=test_inherit_ou5," + ou_dn1
        ou_dn6 = "OU=test_inherit_ou6," + ou_dn2
        # Create inheritable-free OU
        mod = "D:P(A;CI;WPRPLCCCDCWDRCSD;;;DA)"
        tmp_desc = security.descriptor.from_sddl(mod, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, sd=tmp_desc)
        mod = "D:(A;CI;GA;;;DU)"
        tmp_desc = security.descriptor.from_sddl(mod, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn1, sd=tmp_desc)
        mod = "D:(A;CIIO;GA;;;DU)"
        tmp_desc = security.descriptor.from_sddl(mod, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn2, sd=tmp_desc)
        mod = "D:(A;;GA;;;DU)"
        tmp_desc = security.descriptor.from_sddl(mod, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn3, sd=tmp_desc)
        mod = "D:(A;IO;GA;;;DU)"
        tmp_desc = security.descriptor.from_sddl(mod, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn4, sd=tmp_desc)

        self.ldb_admin.create_ou(ou_dn5)
        self.ldb_admin.create_ou(ou_dn6)

        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn1)
        self.assertIn("(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DU)", desc_sddl)
        self.assertIn("(A;CIIO;GA;;;DU)", desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn2)
        self.assertNotIn("(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DU)", desc_sddl)
        self.assertIn("(A;CIIO;GA;;;DU)", desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn3)
        self.assertIn("(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DU)", desc_sddl)
        self.assertNotIn("(A;CIIO;GA;;;DU)", desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn4)
        self.assertNotIn("(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DU)", desc_sddl)
        self.assertNotIn("(A;CIIO;GA;;;DU)", desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn5)
        self.assertIn("(A;ID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DU)", desc_sddl)
        self.assertIn("(A;CIIOID;GA;;;DU)", desc_sddl)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn6)
        self.assertIn("(A;ID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DU)", desc_sddl)
        self.assertIn("(A;CIIOID;GA;;;DU)", desc_sddl)

    def test_215(self):
        """ Make sure IO flag is removed in child objects
        """
        ou_dn = "OU=test_inherit_ou_p," + self.base_dn
        ou_dn1 = "OU=test_inherit_ou1," + ou_dn
        ou_dn5 = "OU=test_inherit_ou5," + ou_dn1
        # Create inheritable-free OU
        mod = "D:P(A;CI;WPRPLCCCDCWDRCSD;;;DA)"
        tmp_desc = security.descriptor.from_sddl(mod, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, sd=tmp_desc)
        mod = "D:(A;CIIO;WP;;;DU)"
        tmp_desc = security.descriptor.from_sddl(mod, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn1, sd=tmp_desc)
        self.ldb_admin.create_ou(ou_dn5)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn5)
        self.assertIn("(A;CIID;WP;;;DU)", desc_sddl)
        self.assertNotIn("(A;CIIOID;WP;;;DU)", desc_sddl)

    def test_216(self):
        """ Make sure ID ACES provided by user are ignored
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        mod = "D:P(A;;WPRPLCCCDCWDRCSD;;;DA)"
        tmp_desc = security.descriptor.from_sddl(mod, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, sd=tmp_desc)
        # Add some custom  ACE
        mod = "D:(D;ID;WP;;;AU)"
        tmp_desc = security.descriptor.from_sddl(mod, self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        # Make sure created group object does not contain the ID ace
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertNotIn("(A;ID;WP;;;AU)", desc_sddl)
        self.assertNotIn("(A;;WP;;;AU)", desc_sddl)

    def test_217(self):
        """ Make sure ID ACES provided by user are not ignored if P flag is set
        """
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        mod = "D:P(A;;WPRPLCCCDCWDRCSD;;;DA)"
        tmp_desc = security.descriptor.from_sddl(mod, self.domain_sid)
        self.ldb_admin.create_ou(ou_dn, sd=tmp_desc)
        # Add some custom  ACE
        mod = "D:P(A;ID;WP;;;AU)"
        tmp_desc = security.descriptor.from_sddl(mod, self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        # Make sure created group object does not contain the ID ace
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertNotIn("(A;ID;WP;;;AU)", desc_sddl)
        self.assertIn("(A;;WP;;;AU)", desc_sddl)

    def test_ci_and_io_on_attribute(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "(OA;CIOI;WP;bf967a0e-0de6-11d0-a285-00aa003049e2;;DU)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        mod = mod.replace(";CIOI;", ";OICIID;")  # change it how it's gonna look like
        self.assertIn(mod, desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertIn(mod, desc_sddl)

    def test_ci_and_np_on_attribute(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "(OA;CINP;WP;bf967a0e-0de6-11d0-a285-00aa003049e2;;DU)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        mod = mod.replace(";CINP;", ";ID;")  # change it how it's gonna look like
        self.assertIn(mod, desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertIn(mod, desc_sddl)

    def test_oi_and_np_on_attribute(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "(OA;OINP;WP;bf967a0e-0de6-11d0-a285-00aa003049e2;;DU)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        mod = mod.replace(";OINP;", ";ID;")  # change it how it's gonna look like
        self.assertNotIn(mod, desc_sddl)
        self.assertNotIn("bf967a0e-0de6-11d0-a285-00aa003049e2", desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertNotIn(mod, desc_sddl)
        self.assertNotIn("bf967a0e-0de6-11d0-a285-00aa003049e2", desc_sddl)

    def test_ci_ga_no_attr_objectclass_same(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "(OA;CI;GA;;bf967a9c-0de6-11d0-a285-00aa003049e2;DA)"
        modob = "(A;ID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DA)"
        modid = "(OA;CIIOID;GA;;bf967a9c-0de6-11d0-a285-00aa003049e2;DA)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(modob, desc_sddl)
        self.assertIn(modid, desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertIn(modob, desc_sddl)
        self.assertIn(modid, desc_sddl)

    def test_ci_ga_no_attr_objectclass_different(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "(OA;CI;GA;;aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;DA)"
        modno = "(A;ID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DA)"
        modid = "(OA;CIIOID;GA;;aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;DA)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertNotIn(modno, desc_sddl)
        self.assertIn(modid, desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertNotIn(modno, desc_sddl)
        self.assertIn(modid, desc_sddl)

    def test_ci_ga_name_attr_objectclass_same(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "(OA;CI;GA;bf967a0e-0de6-11d0-a285-00aa003049e2;bf967a9c-0de6-11d0-a285-00aa003049e2;DA)"
        modob = "(OA;ID;CCDCLCSWRPWPDTLOCRSDRCWDWO;bf967a0e-0de6-11d0-a285-00aa003049e2;;DA)"
        modid = "(OA;CIIOID;GA;bf967a0e-0de6-11d0-a285-00aa003049e2;bf967a9c-0de6-11d0-a285-00aa003049e2;DA)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(modob, desc_sddl)
        self.assertIn(modid, desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertIn(modob, desc_sddl)
        self.assertIn(modid, desc_sddl)

    def test_ci_ga_name_attr_objectclass_different(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "(OA;CI;GA;bf967a0e-0de6-11d0-a285-00aa003049e2;aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;DA)"
        modno = "(OA;ID;CCDCLCSWRPWPDTLOCRSDRCWDWO;bf967a0e-0de6-11d0-a285-00aa003049e2;;DA)"
        modid = "(OA;CIIOID;GA;bf967a0e-0de6-11d0-a285-00aa003049e2;aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;DA)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertNotIn(modno, desc_sddl)
        self.assertIn(modid, desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertNotIn(modno, desc_sddl)
        self.assertIn(modid, desc_sddl)

    def test_ci_lc_no_attr_objectclass_same(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "(OA;CI;LC;;bf967a9c-0de6-11d0-a285-00aa003049e2;DA)"
        modno = "(A;ID;LC;;;DA)"
        modid = "(OA;CIID;LC;;bf967a9c-0de6-11d0-a285-00aa003049e2;DA)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertNotIn(modno, desc_sddl)
        self.assertIn(modid, desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertNotIn(modno, desc_sddl)
        self.assertIn(modid, desc_sddl)

    def test_ci_lc_no_attr_objectclass_different(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "(OA;CI;LC;;aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;DA)"
        modno = "(A;ID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DA)"
        modid = "(OA;CIIOID;LC;;aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;DA)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertNotIn(modno, desc_sddl)
        self.assertIn(modid, desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertNotIn(modno, desc_sddl)
        self.assertIn(modid, desc_sddl)

    def test_ci_lc_name_attr_objectclass_same(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "(OA;CI;LC;bf967a0e-0de6-11d0-a285-00aa003049e2;bf967a9c-0de6-11d0-a285-00aa003049e2;DA)"
        modob = "(OA;ID;LC;bf967a0e-0de6-11d0-a285-00aa003049e2;;DA)"
        modid = "(OA;CIID;LC;bf967a0e-0de6-11d0-a285-00aa003049e2;bf967a9c-0de6-11d0-a285-00aa003049e2;DA)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertNotIn(modob, desc_sddl)
        self.assertIn(modid, desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertNotIn(modob, desc_sddl)
        self.assertIn(modid, desc_sddl)

    def test_ci_lc_name_attr_objectclass_different(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "(OA;CI;LC;bf967a0e-0de6-11d0-a285-00aa003049e2;aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;DA)"
        modno = "(OA;ID;LC;bf967a0e-0de6-11d0-a285-00aa003049e2;;DA)"
        modid = "(OA;CIIOID;LC;bf967a0e-0de6-11d0-a285-00aa003049e2;aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;DA)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertNotIn(modno, desc_sddl)
        self.assertIn(modid, desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertNotIn(modno, desc_sddl)
        self.assertIn(modid, desc_sddl)

    def test_ci_np_ga_no_attr_objectclass_same(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        # Add some custom 'OA' for 'name' attribute & 'CI'+'OI' ACE
        mod = "(OA;CINP;GA;;bf967a9c-0de6-11d0-a285-00aa003049e2;DA)"
        modob = "(A;ID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DA)"
        modid = "(OA;CIIOID;GA;;bf967a9c-0de6-11d0-a285-00aa003049e2;DA)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(modob, desc_sddl)
        self.assertNotIn(modid, desc_sddl)
        self.assertNotIn("bf967a9c-0de6-11d0-a285-00aa003049e2", desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertNotIn(modid, desc_sddl)
        self.assertNotIn("bf967a9c-0de6-11d0-a285-00aa003049e2", desc_sddl)

    def test_ci_np_ga_no_attr_objectclass_different(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "(OA;CINP;GA;;aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;DA)"
        modno = "(A;ID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;DA)"
        modid = "(OA;CIIOID;GA;;aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;DA)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertNotIn(modno, desc_sddl)
        self.assertNotIn(modid, desc_sddl)
        self.assertNotIn("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertNotIn(modno, desc_sddl)
        self.assertNotIn(modid, desc_sddl)
        self.assertNotIn("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", desc_sddl)

    def test_ci_np_ga_name_attr_objectclass_same(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "(OA;CINP;GA;bf967a0e-0de6-11d0-a285-00aa003049e2;bf967a9c-0de6-11d0-a285-00aa003049e2;DA)"
        modob = "(OA;ID;CCDCLCSWRPWPDTLOCRSDRCWDWO;bf967a0e-0de6-11d0-a285-00aa003049e2;;DA)"
        modid = "(OA;CIIOID;GA;bf967a0e-0de6-11d0-a285-00aa003049e2;bf967a9c-0de6-11d0-a285-00aa003049e2;DA)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(modob, desc_sddl)
        self.assertNotIn(modid, desc_sddl)
        self.assertNotIn("bf967a9c-0de6-11d0-a285-00aa003049e2", desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertIn(modob, desc_sddl)
        self.assertNotIn(modid, desc_sddl)
        self.assertNotIn("bf967a9c-0de6-11d0-a285-00aa003049e2", desc_sddl)

    def test_ci_np_ga_name_attr_objectclass_different(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "(OA;CINP;GA;bf967a0e-0de6-11d0-a285-00aa003049e2;aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;DA)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertNotIn("bf967a0e-0de6-11d0-a285-00aa003049e2", desc_sddl)
        self.assertNotIn("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertNotIn("bf967a0e-0de6-11d0-a285-00aa003049e2", desc_sddl)
        self.assertNotIn("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", desc_sddl)

    def test_ci_np_lc_no_attr_objectclass_same(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "(OA;CINP;LC;;bf967a9c-0de6-11d0-a285-00aa003049e2;DA)"
        modno = "(A;ID;LC;;;DA)"
        modid = "(OA;CIID;LC;;bf967a9c-0de6-11d0-a285-00aa003049e2;DA)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(modno, desc_sddl)
        self.assertNotIn(modid, desc_sddl)
        self.assertNotIn("bf967a9c-0de6-11d0-a285-00aa003049e2", desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertIn(modno, desc_sddl)
        self.assertNotIn(modid, desc_sddl)
        self.assertNotIn("bf967a9c-0de6-11d0-a285-00aa003049e2", desc_sddl)

    def test_ci_np_lc_no_attr_objectclass_different(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "(OA;CINP;LC;;aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;DA)"
        modno = "(A;ID;LC;;;DA)"
        modid = "(OA;CIIOID;LC;;aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;DA)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertNotIn(modno, desc_sddl)
        self.assertNotIn(modid, desc_sddl)
        self.assertNotIn("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertNotIn(modno, desc_sddl)
        self.assertNotIn(modid, desc_sddl)
        self.assertNotIn("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", desc_sddl)

    def test_ci_np_lc_name_attr_objectclass_same(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "(OA;CINP;LC;bf967a0e-0de6-11d0-a285-00aa003049e2;bf967a9c-0de6-11d0-a285-00aa003049e2;DA)"
        modob = "(OA;ID;LC;bf967a0e-0de6-11d0-a285-00aa003049e2;;DA)"
        modid = "(OA;CIID;LC;bf967a0e-0de6-11d0-a285-00aa003049e2;bf967a9c-0de6-11d0-a285-00aa003049e2;DA)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(modob, desc_sddl)
        self.assertNotIn(modid, desc_sddl)
        self.assertNotIn("bf967a9c-0de6-11d0-a285-00aa003049e2", desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertIn(modob, desc_sddl)
        self.assertNotIn(modid, desc_sddl)
        self.assertNotIn("bf967a9c-0de6-11d0-a285-00aa003049e2", desc_sddl)

    def test_ci_np_lc_name_attr_objectclass_different(self):
        ou_dn = "OU=test_inherit_ou," + self.base_dn
        group_dn = "CN=test_inherit_group," + ou_dn
        # Create inheritable-free OU
        self.create_clean_ou(ou_dn)
        mod = "(OA;CINP;LC;bf967a0e-0de6-11d0-a285-00aa003049e2;aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;DA)"
        modno = "(OA;ID;LC;bf967a0e-0de6-11d0-a285-00aa003049e2;;DA)"
        modid = "(OA;CIIOID;LC;bf967a0e-0de6-11d0-a285-00aa003049e2;aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee;DA)"
        moded = "(D;;CC;;;LG)"
        self.sd_utils.dacl_add_ace(ou_dn, mod)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # Create group child object
        tmp_desc = security.descriptor.from_sddl("O:AUG:AUD:AI(A;;CC;;;AU)", self.domain_sid)
        self.ldb_admin.newgroup("test_inherit_group", groupou="OU=test_inherit_ou", grouptype=4, sd=tmp_desc)
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertNotIn(modno, desc_sddl)
        self.assertNotIn(modid, desc_sddl)
        self.assertNotIn("bf967a0e-0de6-11d0-a285-00aa003049e2", desc_sddl)
        self.assertNotIn("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", desc_sddl)
        try:
            self.sd_utils.modify_sd_on_dn(group_dn, "D:" + moded)
        except LdbError as e:
            self.fail(str(e))
        desc_sddl = self.sd_utils.get_sd_as_sddl(group_dn)
        self.assertIn(moded, desc_sddl)
        self.assertNotIn(modno, desc_sddl)
        self.assertNotIn(modid, desc_sddl)
        self.assertNotIn("bf967a0e-0de6-11d0-a285-00aa003049e2", desc_sddl)
        self.assertNotIn("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", desc_sddl)

    ########################################################################################


class SdFlagsDescriptorTests(DescriptorTests):
    def deleteAll(self):
        delete_force(self.ldb_admin, "OU=test_sdflags_ou," + self.base_dn)

    def setUp(self):
        super(SdFlagsDescriptorTests, self).setUp()
        self.test_descr = "O:AUG:AUD:(D;;CC;;;LG)S:(OU;;WP;;;AU)"
        self.deleteAll()

    def test_301(self):
        """ Modify a descriptor with OWNER_SECURITY_INFORMATION set.
            See that only the owner has been changed.
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.ldb_admin.create_ou(ou_dn)
        self.sd_utils.modify_sd_on_dn(ou_dn, self.test_descr, controls=["sd_flags:1:%d" % (SECINFO_OWNER)])
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # make sure we have modified the owner
        self.assertIn("O:AU", desc_sddl)
        # make sure nothing else has been modified
        self.assertNotIn("G:AU", desc_sddl)
        self.assertNotIn("D:(D;;CC;;;LG)", desc_sddl)
        self.assertNotIn("(OU;;WP;;;AU)", desc_sddl)

    def test_302(self):
        """ Modify a descriptor with GROUP_SECURITY_INFORMATION set.
            See that only the owner has been changed.
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.ldb_admin.create_ou(ou_dn)
        self.sd_utils.modify_sd_on_dn(ou_dn, self.test_descr, controls=["sd_flags:1:%d" % (SECINFO_GROUP)])
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # make sure we have modified the group
        self.assertIn("G:AU", desc_sddl)
        # make sure nothing else has been modified
        self.assertNotIn("O:AU", desc_sddl)
        self.assertNotIn("D:(D;;CC;;;LG)", desc_sddl)
        self.assertNotIn("(OU;;WP;;;AU)", desc_sddl)

    def test_303(self):
        """ Modify a descriptor with SACL_SECURITY_INFORMATION set.
            See that only the owner has been changed.
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.ldb_admin.create_ou(ou_dn)
        self.sd_utils.modify_sd_on_dn(ou_dn, self.test_descr, controls=["sd_flags:1:%d" % (SECINFO_DACL)])
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # make sure we have modified the DACL
        self.assertIn("(D;;CC;;;LG)", desc_sddl)
        # make sure nothing else has been modified
        self.assertNotIn("O:AU", desc_sddl)
        self.assertNotIn("G:AU", desc_sddl)
        self.assertNotIn("(OU;;WP;;;AU)", desc_sddl)

    def test_304(self):
        """ Modify a descriptor with SACL_SECURITY_INFORMATION set.
            See that only the owner has been changed.
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.ldb_admin.create_ou(ou_dn)
        self.sd_utils.modify_sd_on_dn(ou_dn, self.test_descr, controls=["sd_flags:1:%d" % (SECINFO_SACL)])
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # make sure we have modified the DACL
        self.assertIn("(OU;;WP;;;AU)", desc_sddl)
        # make sure nothing else has been modified
        self.assertNotIn("O:AU", desc_sddl)
        self.assertNotIn("G:AU", desc_sddl)
        self.assertNotIn("(D;;CC;;;LG)", desc_sddl)

    def test_305(self):
        """ Modify a descriptor with 0x0 set.
            Contrary to logic this is interpreted as no control,
            which is the same as 0xF
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.ldb_admin.create_ou(ou_dn)
        self.sd_utils.modify_sd_on_dn(ou_dn, self.test_descr, controls=["sd_flags:1:0"])
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # make sure we have modified the DACL
        self.assertIn("(OU;;WP;;;AU)", desc_sddl)
        # make sure nothing else has been modified
        self.assertIn("O:AU", desc_sddl)
        self.assertIn("G:AU", desc_sddl)
        self.assertIn("(D;;CC;;;LG)", desc_sddl)

    def test_306(self):
        """ Modify a descriptor with 0xF set.
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.ldb_admin.create_ou(ou_dn)
        self.sd_utils.modify_sd_on_dn(ou_dn, self.test_descr, controls=["sd_flags:1:15"])
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn)
        # make sure we have modified the DACL
        self.assertIn("(OU;;WP;;;AU)", desc_sddl)
        # make sure nothing else has been modified
        self.assertIn("O:AU", desc_sddl)
        self.assertIn("G:AU", desc_sddl)
        self.assertIn("(D;;CC;;;LG)", desc_sddl)

    def test_307(self):
        """ Read a descriptor with OWNER_SECURITY_INFORMATION
            Only the owner part should be returned.
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.ldb_admin.create_ou(ou_dn)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn, controls=["sd_flags:1:%d" % (SECINFO_OWNER)])
        # make sure we have read the owner
        self.assertIn("O:", desc_sddl)
        # make sure we have read nothing else
        self.assertNotIn("G:", desc_sddl)
        self.assertNotIn("D:", desc_sddl)
        self.assertNotIn("S:", desc_sddl)

    def test_308(self):
        """ Read a descriptor with GROUP_SECURITY_INFORMATION
            Only the group part should be returned.
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.ldb_admin.create_ou(ou_dn)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn, controls=["sd_flags:1:%d" % (SECINFO_GROUP)])
        # make sure we have read the owner
        self.assertIn("G:", desc_sddl)
        # make sure we have read nothing else
        self.assertNotIn("O:", desc_sddl)
        self.assertNotIn("D:", desc_sddl)
        self.assertNotIn("S:", desc_sddl)

    def test_309(self):
        """ Read a descriptor with SACL_SECURITY_INFORMATION
            Only the sacl part should be returned.
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.ldb_admin.create_ou(ou_dn)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn, controls=["sd_flags:1:%d" % (SECINFO_SACL)])
        # make sure we have read the owner
        self.assertIn("S:", desc_sddl)
        # make sure we have read nothing else
        self.assertNotIn("O:", desc_sddl)
        self.assertNotIn("D:", desc_sddl)
        self.assertNotIn("G:", desc_sddl)

    def test_310(self):
        """ Read a descriptor with DACL_SECURITY_INFORMATION
            Only the dacl part should be returned.
        """
        ou_dn = "OU=test_sdflags_ou," + self.base_dn
        self.ldb_admin.create_ou(ou_dn)
        desc_sddl = self.sd_utils.get_sd_as_sddl(ou_dn, controls=["sd_flags:1:%d" % (SECINFO_DACL)])
        # make sure we have read the owner
        self.assertIn("D:", desc_sddl)
        # make sure we have read nothing else
        self.assertNotIn("O:", desc_sddl)
        self.assertNotIn("S:", desc_sddl)
        self.assertNotIn("G:", desc_sddl)

    def test_311(self):
        sd_flags = (SECINFO_OWNER |
                    SECINFO_GROUP |
                    SECINFO_DACL |
                    SECINFO_SACL)

        res = self.ldb_admin.search(self.base_dn, SCOPE_BASE, None,
                                    [], controls=None)
        self.assertNotIn("nTSecurityDescriptor", res[0])

        res = self.ldb_admin.search(self.base_dn, SCOPE_BASE, None,
                                    ["name"], controls=None)
        self.assertNotIn("nTSecurityDescriptor", res[0])

        res = self.ldb_admin.search(self.base_dn, SCOPE_BASE, None,
                                    ["name"], controls=["sd_flags:1:%d" % (sd_flags)])
        self.assertNotIn("nTSecurityDescriptor", res[0])

        res = self.ldb_admin.search(self.base_dn, SCOPE_BASE, None,
                                    controls=["sd_flags:1:%d" % (sd_flags)])
        self.assertIn("nTSecurityDescriptor", res[0])
        tmp = res[0]["nTSecurityDescriptor"][0]
        sd = ndr_unpack(security.descriptor, tmp)
        sddl = sd.as_sddl(self.sd_utils.domain_sid)
        self.assertIn("O:", sddl)
        self.assertIn("G:", sddl)
        self.assertIn("D:", sddl)
        self.assertIn("S:", sddl)

        res = self.ldb_admin.search(self.base_dn, SCOPE_BASE, None,
                                    ["*"], controls=["sd_flags:1:%d" % (sd_flags)])
        self.assertIn("nTSecurityDescriptor", res[0])
        tmp = res[0]["nTSecurityDescriptor"][0]
        sd = ndr_unpack(security.descriptor, tmp)
        sddl = sd.as_sddl(self.sd_utils.domain_sid)
        self.assertIn("O:", sddl)
        self.assertIn("G:", sddl)
        self.assertIn("D:", sddl)
        self.assertIn("S:", sddl)

        res = self.ldb_admin.search(self.base_dn, SCOPE_BASE, None,
                                    ["nTSecurityDescriptor", "*"], controls=["sd_flags:1:%d" % (sd_flags)])
        self.assertIn("nTSecurityDescriptor", res[0])
        tmp = res[0]["nTSecurityDescriptor"][0]
        sd = ndr_unpack(security.descriptor, tmp)
        sddl = sd.as_sddl(self.sd_utils.domain_sid)
        self.assertIn("O:", sddl)
        self.assertIn("G:", sddl)
        self.assertIn("D:", sddl)
        self.assertIn("S:", sddl)

        res = self.ldb_admin.search(self.base_dn, SCOPE_BASE, None,
                                    ["*", "nTSecurityDescriptor"], controls=["sd_flags:1:%d" % (sd_flags)])
        self.assertIn("nTSecurityDescriptor", res[0])
        tmp = res[0]["nTSecurityDescriptor"][0]
        sd = ndr_unpack(security.descriptor, tmp)
        sddl = sd.as_sddl(self.sd_utils.domain_sid)
        self.assertIn("O:", sddl)
        self.assertIn("G:", sddl)
        self.assertIn("D:", sddl)
        self.assertIn("S:", sddl)

        res = self.ldb_admin.search(self.base_dn, SCOPE_BASE, None,
                                    ["nTSecurityDescriptor", "name"], controls=["sd_flags:1:%d" % (sd_flags)])
        self.assertIn("nTSecurityDescriptor", res[0])
        tmp = res[0]["nTSecurityDescriptor"][0]
        sd = ndr_unpack(security.descriptor, tmp)
        sddl = sd.as_sddl(self.sd_utils.domain_sid)
        self.assertIn("O:", sddl)
        self.assertIn("G:", sddl)
        self.assertIn("D:", sddl)
        self.assertIn("S:", sddl)

        res = self.ldb_admin.search(self.base_dn, SCOPE_BASE, None,
                                    ["name", "nTSecurityDescriptor"], controls=["sd_flags:1:%d" % (sd_flags)])
        self.assertIn("nTSecurityDescriptor", res[0])
        tmp = res[0]["nTSecurityDescriptor"][0]
        sd = ndr_unpack(security.descriptor, tmp)
        sddl = sd.as_sddl(self.sd_utils.domain_sid)
        self.assertIn("O:", sddl)
        self.assertIn("G:", sddl)
        self.assertIn("D:", sddl)
        self.assertIn("S:", sddl)

        res = self.ldb_admin.search(self.base_dn, SCOPE_BASE, None,
                                    ["nTSecurityDescriptor"], controls=None)
        self.assertIn("nTSecurityDescriptor", res[0])
        tmp = res[0]["nTSecurityDescriptor"][0]
        sd = ndr_unpack(security.descriptor, tmp)
        sddl = sd.as_sddl(self.sd_utils.domain_sid)
        self.assertIn("O:", sddl)
        self.assertIn("G:", sddl)
        self.assertIn("D:", sddl)
        self.assertIn("S:", sddl)

        res = self.ldb_admin.search(self.base_dn, SCOPE_BASE, None,
                                    ["name", "nTSecurityDescriptor"], controls=None)
        self.assertIn("nTSecurityDescriptor", res[0])
        tmp = res[0]["nTSecurityDescriptor"][0]
        sd = ndr_unpack(security.descriptor, tmp)
        sddl = sd.as_sddl(self.sd_utils.domain_sid)
        self.assertIn("O:", sddl)
        self.assertIn("G:", sddl)
        self.assertIn("D:", sddl)
        self.assertIn("S:", sddl)

        res = self.ldb_admin.search(self.base_dn, SCOPE_BASE, None,
                                    ["nTSecurityDescriptor", "name"], controls=None)
        self.assertIn("nTSecurityDescriptor", res[0])
        tmp = res[0]["nTSecurityDescriptor"][0]
        sd = ndr_unpack(security.descriptor, tmp)
        sddl = sd.as_sddl(self.sd_utils.domain_sid)
        self.assertIn("O:", sddl)
        self.assertIn("G:", sddl)
        self.assertIn("D:", sddl)
        self.assertIn("S:", sddl)

    def test_312(self):
        """This search is done by the windows dc join..."""

        res = self.ldb_admin.search(self.base_dn, SCOPE_BASE, None, ["1.1"],
                                    controls=["extended_dn:1:0", "sd_flags:1:0", "search_options:1:1"])
        self.assertNotIn("nTSecurityDescriptor", res[0])


class RightsAttributesTests(DescriptorTests):

    def deleteAll(self):
        delete_force(self.ldb_admin, self.get_users_domain_dn("testuser_attr"))
        delete_force(self.ldb_admin, self.get_users_domain_dn("testuser_attr2"))
        delete_force(self.ldb_admin, "OU=test_domain_ou1," + self.base_dn)

    def setUp(self):
        super(RightsAttributesTests, self).setUp()
        self.deleteAll()
        # Create users
        # User 1
        self.ldb_admin.newuser("testuser_attr", "samba123@")
        # User 2, Domain Admins
        self.ldb_admin.newuser("testuser_attr2", "samba123@")
        self.ldb_admin.add_remove_group_members("Domain Admins",
                                                ["testuser_attr2"],
                                                add_members_operation=True)

    def test_sDRightsEffective(self):
        object_dn = "OU=test_domain_ou1," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        self.ldb_admin.create_ou(object_dn)
        print(self.get_users_domain_dn("testuser_attr"))
        user_sid = self.sd_utils.get_object_sid(self.get_users_domain_dn("testuser_attr"))
        # give testuser1 read access so attributes can be retrieved
        mod = "(A;CI;RP;;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace(object_dn, mod)
        _ldb = self.get_ldb_connection("testuser_attr", "samba123@")
        res = _ldb.search(base=object_dn, expression="", scope=SCOPE_BASE,
                          attrs=["sDRightsEffective"])
        # user should have no rights at all
        self.assertEqual(len(res), 1)
        self.assertEqual(str(res[0]["sDRightsEffective"][0]), "0")
        # give the user Write DACL and see what happens
        mod = "(A;CI;WD;;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace(object_dn, mod)
        res = _ldb.search(base=object_dn, expression="", scope=SCOPE_BASE,
                          attrs=["sDRightsEffective"])
        # user should have DACL_SECURITY_INFORMATION
        self.assertEqual(len(res), 1)
        self.assertEqual(str(res[0]["sDRightsEffective"][0]), ("%d") % SECINFO_DACL)
        # give the user Write Owners and see what happens
        mod = "(A;CI;WO;;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace(object_dn, mod)
        res = _ldb.search(base=object_dn, expression="", scope=SCOPE_BASE,
                          attrs=["sDRightsEffective"])
        # user should have DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION
        self.assertEqual(len(res), 1)
        self.assertEqual(str(res[0]["sDRightsEffective"][0]), ("%d") % (SECINFO_DACL | SECINFO_GROUP | SECINFO_OWNER))
        # no way to grant security privilege bu adding ACE's so we use a member of Domain Admins
        _ldb = self.get_ldb_connection("testuser_attr2", "samba123@")
        res = _ldb.search(base=object_dn, expression="", scope=SCOPE_BASE,
                          attrs=["sDRightsEffective"])
        # user should have DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION
        self.assertEqual(len(res), 1)
        self.assertEqual(str(res[0]["sDRightsEffective"][0]),
                          ("%d") % (SECINFO_DACL | SECINFO_GROUP | SECINFO_OWNER | SECINFO_SACL))

    def test_allowedChildClassesEffective(self):
        object_dn = "OU=test_domain_ou1," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        self.ldb_admin.create_ou(object_dn)
        user_sid = self.sd_utils.get_object_sid(self.get_users_domain_dn("testuser_attr"))
        # give testuser1 read access so attributes can be retrieved
        mod = "(A;CI;RP;;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace(object_dn, mod)
        _ldb = self.get_ldb_connection("testuser_attr", "samba123@")
        res = _ldb.search(base=object_dn, expression="", scope=SCOPE_BASE,
                          attrs=["allowedChildClassesEffective"])
        # there should be no allowed child classes
        self.assertEqual(len(res), 1)
        self.assertNotIn("allowedChildClassesEffective", res[0].keys())
        # give the user the right to create children of type user
        mod = "(OA;CI;CC;bf967aba-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace(object_dn, mod)
        res = _ldb.search(base=object_dn, expression="", scope=SCOPE_BASE,
                          attrs=["allowedChildClassesEffective"])
        # allowedChildClassesEffective should only have one value, user
        self.assertEqual(len(res), 1)
        self.assertEqual(len(res[0]["allowedChildClassesEffective"]), 1)
        self.assertEqual(str(res[0]["allowedChildClassesEffective"][0]), "user")

    def test_allowedAttributesEffective(self):
        object_dn = "OU=test_domain_ou1," + self.base_dn
        delete_force(self.ldb_admin, object_dn)
        self.ldb_admin.create_ou(object_dn)
        user_sid = self.sd_utils.get_object_sid(self.get_users_domain_dn("testuser_attr"))
        # give testuser1 read access so attributes can be retrieved
        mod = "(A;CI;RP;;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace(object_dn, mod)
        _ldb = self.get_ldb_connection("testuser_attr", "samba123@")
        res = _ldb.search(base=object_dn, expression="", scope=SCOPE_BASE,
                          attrs=["allowedAttributesEffective"])
        # there should be no allowed attributes
        self.assertEqual(len(res), 1)
        self.assertNotIn("allowedAttributesEffective", res[0].keys())
        # give the user the right to write displayName and managedBy
        mod2 = "(OA;CI;WP;bf967953-0de6-11d0-a285-00aa003049e2;;%s)" % str(user_sid)
        mod = "(OA;CI;WP;0296c120-40da-11d1-a9c0-0000f80367c1;;%s)" % str(user_sid)
        # also rights to modify an read only attribute, fromEntry
        mod3 = "(OA;CI;WP;9a7ad949-ca53-11d1-bbd0-0080c76670c0;;%s)" % str(user_sid)
        self.sd_utils.dacl_add_ace(object_dn, mod + mod2 + mod3)
        res = _ldb.search(base=object_dn, expression="", scope=SCOPE_BASE,
                          attrs=["allowedAttributesEffective"])
        # value should only contain user and managedBy
        self.assertEqual(len(res), 1)
        self.assertEqual(len(res[0]["allowedAttributesEffective"]), 2)
        self.assertIn(b"displayName", res[0]["allowedAttributesEffective"])
        self.assertIn(b"managedBy", res[0]["allowedAttributesEffective"])


class SdAutoInheritTests(DescriptorTests):
    def deleteAll(self):
        delete_force(self.ldb_admin, self.sub_dn)
        delete_force(self.ldb_admin, self.ou_dn)

    def setUp(self):
        super(SdAutoInheritTests, self).setUp()
        self.ou_dn = "OU=test_SdAutoInherit_ou," + self.base_dn
        self.sub_dn = "OU=test_sub," + self.ou_dn
        self.deleteAll()

    def test_301(self):
        """ Modify a descriptor with OWNER_SECURITY_INFORMATION set.
            See that only the owner has been changed.
        """
        attrs = ["nTSecurityDescriptor", "replPropertyMetaData", "uSNChanged"]
        controls = ["sd_flags:1:%d" % (SECINFO_DACL)]
        ace = "(A;CI;CC;;;NU)"
        sub_ace = "(A;CIID;CC;;;NU)"
        sd_sddl = "O:BAG:BAD:P(A;CI;0x000f01ff;;;AU)"
        sd = security.descriptor.from_sddl(sd_sddl, self.domain_sid)

        self.ldb_admin.create_ou(self.ou_dn, sd=sd)
        self.ldb_admin.create_ou(self.sub_dn)

        ou_res0 = self.sd_utils.ldb.search(self.ou_dn, SCOPE_BASE,
                                           None, attrs, controls=controls)
        sub_res0 = self.sd_utils.ldb.search(self.sub_dn, SCOPE_BASE,
                                            None, attrs, controls=controls)

        ou_sd0 = ndr_unpack(security.descriptor, ou_res0[0]["nTSecurityDescriptor"][0])
        sub_sd0 = ndr_unpack(security.descriptor, sub_res0[0]["nTSecurityDescriptor"][0])

        ou_sddl0 = ou_sd0.as_sddl(self.domain_sid)
        sub_sddl0 = sub_sd0.as_sddl(self.domain_sid)

        self.assertNotIn(ace, ou_sddl0)
        self.assertNotIn(ace, sub_sddl0)

        ou_sddl1 = (ou_sddl0[:ou_sddl0.index("(")] + ace +
                    ou_sddl0[ou_sddl0.index("("):])

        sub_sddl1 = (sub_sddl0[:sub_sddl0.index("(")] + ace +
                     sub_sddl0[sub_sddl0.index("("):])

        self.sd_utils.modify_sd_on_dn(self.ou_dn, ou_sddl1, controls=controls)

        self.sd_utils.modify_sd_on_dn(self.sub_dn, sub_sddl1, controls=controls)

        sub_res2 = self.sd_utils.ldb.search(self.sub_dn, SCOPE_BASE,
                                            None, attrs, controls=controls)
        ou_res2 = self.sd_utils.ldb.search(self.ou_dn, SCOPE_BASE,
                                           None, attrs, controls=controls)

        ou_sd2 = ndr_unpack(security.descriptor, ou_res2[0]["nTSecurityDescriptor"][0])
        sub_sd2 = ndr_unpack(security.descriptor, sub_res2[0]["nTSecurityDescriptor"][0])

        ou_sddl2 = ou_sd2.as_sddl(self.domain_sid)
        sub_sddl2 = sub_sd2.as_sddl(self.domain_sid)

        self.assertNotEqual(ou_sddl2, ou_sddl0)
        self.assertNotEqual(sub_sddl2, sub_sddl0)

        if ace not in ou_sddl2:
            print("ou0: %s" % ou_sddl0)
            print("ou2: %s" % ou_sddl2)

        if sub_ace not in sub_sddl2:
            print("sub0: %s" % sub_sddl0)
            print("sub2: %s" % sub_sddl2)

        self.assertIn(ace, ou_sddl2)
        self.assertIn(sub_ace, sub_sddl2)

        ou_usn0 = int(ou_res0[0]["uSNChanged"][0])
        ou_usn2 = int(ou_res2[0]["uSNChanged"][0])
        self.assertGreater(ou_usn2, ou_usn0)

        sub_usn0 = int(sub_res0[0]["uSNChanged"][0])
        sub_usn2 = int(sub_res2[0]["uSNChanged"][0])
        self.assertGreater(sub_usn2, sub_usn0)


if "://" not in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host

# use 'paged_search' module when connecting remotely
if host.lower().startswith("ldap://"):
    ldb_options = ["modules:paged_searches"]

TestProgram(module=__name__, opts=subunitopts)

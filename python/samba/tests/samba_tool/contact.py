# Unix SMB/CIFS implementation.
#
# Tests for samba-tool contact management commands
#
# Copyright (C) Bjoern Baumbach <bbaumbach@samba.org> 2019
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

import os
import ldb
from samba.tests.samba_tool.base import SambaToolCmdTest

class ContactCmdTestCase(SambaToolCmdTest):
    """Tests for samba-tool contact subcommands"""
    contacts = []
    samdb = None

    def setUp(self):
        super(ContactCmdTestCase, self).setUp()
        self.creds = "-U%s%%%s" % (os.environ["DC_USERNAME"],
                                   os.environ["DC_PASSWORD"])
        self.samdb = self.getSamDB("-H",
                                   "ldap://%s" % os.environ["DC_SERVER"],
                                   self.creds)
        contact = None
        self.contacts = []

        contact = self._randomContact({"expectedname": "contact1",
                                       "name": "contact1"})
        self.contacts.append(contact)

        # No 'name' is given here, so the name will be made from givenname.
        contact = self._randomContact({"expectedname": "contact2",
                                       "givenName": "contact2"})
        self.contacts.append(contact)

        contact = self._randomContact({"expectedname": "contact3",
                                       "name": "contact3",
                                       "displayName": "contact3displayname",
                                       "givenName": "not_contact3",
                                       "initials": "I",
                                       "sn": "not_contact3",
                                       "mobile": "12345"})
        self.contacts.append(contact)

        # No 'name' is given here, so the name will be made from the the
        # sn, initials and givenName attributes.
        contact = self._randomContact({"expectedname": "James T. Kirk",
                                       "sn": "Kirk",
                                       "initials": "T",
                                       "givenName": "James"})
        self.contacts.append(contact)

        # setup the 4 contacts and ensure they are correct
        for contact in self.contacts:
            (result, out, err) = self._create_contact(contact)

            self.assertCmdSuccess(result, out, err)
            self.assertNotIn(
                "ERROR", err, "There shouldn't be any error message")
            self.assertIn("Contact '%s' added successfully" %
                          contact["expectedname"], out)

            found = self._find_contact(contact["expectedname"])

            self.assertIsNotNone(found)

            contactname = contact["expectedname"]
            self.assertEqual("%s" % found.get("name"), contactname)
            self.assertEqual("%s" % found.get("description"),
                              contact["description"])

    def tearDown(self):
        super(ContactCmdTestCase, self).tearDown()
        # clean up all the left over contacts, just in case
        for contact in self.contacts:
            if self._find_contact(contact["expectedname"]):
                (result, out, err) = self.runsubcmd(
                    "contact", "delete", "%s" % contact["expectedname"])
                self.assertCmdSuccess(result, out, err,
                                      "Failed to delete contact '%s'" %
                                      contact["expectedname"])

    def test_newcontact(self):
        """This tests the "contact create" and "contact delete" commands"""
        # try to create all the contacts again, this should fail
        for contact in self.contacts:
            (result, out, err) = self._create_contact(contact)
            self.assertCmdFail(result, "Succeeded to create existing contact")
            self.assertIn("already exists", err)

        # try to delete all the contacts we just added
        for contact in self.contacts:
            (result, out, err) = self.runsubcmd("contact", "delete", "%s" %
                                                contact["expectedname"])
            self.assertCmdSuccess(result, out, err,
                                  "Failed to delete contact '%s'" %
                                  contact["expectedname"])
            found = self._find_contact(contact["expectedname"])
            self.assertIsNone(found,
                              "Deleted contact '%s' still exists" %
                              contact["expectedname"])

        # test creating contacts in an specified OU
        parentou = self._randomOU({"name": "testOU"})
        (result, out, err) = self._create_ou(parentou)
        self.assertCmdSuccess(result, out, err)

        for contact in self.contacts:
            (result, out, err) = self._create_contact(contact, ou="OU=testOU")

            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "There shouldn't be any error message")
            self.assertIn("Contact '%s' added successfully" %
                          contact["expectedname"], out)

            found = self._find_contact(contact["expectedname"])

            contactname = contact["expectedname"]
            self.assertEqual("%s" % found.get("name"), contactname)
            self.assertEqual("%s" % found.get("description"),
                              contact["description"])

        # try to delete all the contacts we just added, by DN
        for contact in self.contacts:
            expecteddn = ldb.Dn(self.samdb,
                                "CN=%s,OU=%s,%s" %
                                (contact["expectedname"],
                                 parentou["name"],
                                 self.samdb.domain_dn()))
            (result, out, err) = self.runsubcmd("contact", "delete", "%s" %
                                                expecteddn)
            self.assertCmdSuccess(result, out, err,
                                  "Failed to delete contact '%s'" %
                                  contact["expectedname"])
            found = self._find_contact(contact["expectedname"])
            self.assertIsNone(found,
                              "Deleted contact '%s' still exists" %
                              contact["expectedname"])

        (result, out, err) = self.runsubcmd("ou", "delete",
                                            "OU=%s" % parentou["name"])
        self.assertCmdSuccess(result, out, err,
                              "Failed to delete ou '%s'" % parentou["name"])

        # creating contacts, again for further tests
        for contact in self.contacts:
            (result, out, err) = self._create_contact(contact)

            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "There shouldn't be any error message")
            self.assertIn("Contact '%s' added successfully" %
                          contact["expectedname"], out)

            found = self._find_contact(contact["expectedname"])

            contactname = contact["expectedname"]
            self.assertEqual("%s" % found.get("name"), contactname)
            self.assertEqual("%s" % found.get("description"),
                              contact["description"])

    def test_list(self):
        (result, out, err) = self.runsubcmd("contact", "list")
        self.assertCmdSuccess(result, out, err, "Error running list")

        search_filter = "(objectClass=contact)"
        contactlist = self.samdb.search(base=self.samdb.domain_dn(),
                                         scope=ldb.SCOPE_SUBTREE,
                                         expression=search_filter,
                                         attrs=["name"])

        self.assertTrue(len(contactlist) > 0, "no contacts found in samdb")

        for contactobj in contactlist:
            name = contactobj.get("name", idx=0)
            self.assertMatch(out, str(name),
                             "contact '%s' not found" % name)

    def test_list_full_dn(self):
        (result, out, err) = self.runsubcmd("contact", "list", "--full-dn")
        self.assertCmdSuccess(result, out, err, "Error running list")

        search_filter = "(objectClass=contact)"
        contactlist = self.samdb.search(base=self.samdb.domain_dn(),
                                         scope=ldb.SCOPE_SUBTREE,
                                         expression=search_filter,
                                         attrs=["dn"])

        self.assertTrue(len(contactlist) > 0, "no contacts found in samdb")

        for contactobj in contactlist:
            self.assertMatch(out, str(contactobj.dn),
                             "contact '%s' not found" % str(contactobj.dn))

    def test_list_base_dn(self):
        base_dn = str(self.samdb.domain_dn())
        (result, out, err) = self.runsubcmd("contact", "list",
                                            "-b", base_dn)
        self.assertCmdSuccess(result, out, err, "Error running list")

        search_filter = "(objectClass=contact)"
        contactlist = self.samdb.search(base=base_dn,
                                         scope=ldb.SCOPE_SUBTREE,
                                         expression=search_filter,
                                         attrs=["name"])

        self.assertTrue(len(contactlist) > 0, "no contacts found in samdb")

        for contactobj in contactlist:
            name = contactobj.get("name", idx=0)
            self.assertMatch(out, str(name),
                             "contact '%s' not found" % name)

    def test_move(self):
        parentou = self._randomOU({"name": "parentOU"})
        (result, out, err) = self._create_ou(parentou)
        self.assertCmdSuccess(result, out, err)

        for contact in self.contacts:
            olddn = self._find_contact(contact["expectedname"]).get("dn")

            (result, out, err) = self.runsubcmd("contact", "move",
                                                "%s" % contact["expectedname"],
                                                "OU=%s" % parentou["name"])
            self.assertCmdSuccess(result, out, err,
                                  "Failed to move contact '%s'" %
                                  contact["expectedname"])
            self.assertEqual(err, "", "There shouldn't be any error message")
            self.assertIn('Moved contact "%s"' % contact["expectedname"], out)

            found = self._find_contact(contact["expectedname"])
            self.assertNotEqual(found.get("dn"), olddn,
                                ("Moved contact '%s' still exists with the "
                                 "same dn" % contact["expectedname"]))
            contactname = contact["expectedname"]
            newexpecteddn = ldb.Dn(self.samdb,
                                   "CN=%s,OU=%s,%s" %
                                   (contactname,
                                    parentou["name"],
                                    self.samdb.domain_dn()))
            self.assertEqual(found.get("dn"), newexpecteddn,
                              "Moved contact '%s' does not exist" %
                              contact["expectedname"])

            (result, out, err) = self.runsubcmd("contact", "move",
                                                "%s" % contact["expectedname"],
                                                "%s" % olddn.parent())
            self.assertCmdSuccess(result, out, err,
                                  "Failed to move contact '%s'" %
                                  contact["expectedname"])

        (result, out, err) = self.runsubcmd("ou", "delete",
                                            "OU=%s" % parentou["name"])
        self.assertCmdSuccess(result, out, err,
                              "Failed to delete ou '%s'" % parentou["name"])

    def test_rename_givenname_initials_surname(self):
        """rename and remove given name, initials and surname for all contacts"""
        for contact in self.contacts:
            name = contact["name"] if "name" in contact else contact["expectedname"]

            new_givenname = "new_given_name_of_" + name
            new_initials = "A"
            new_surname = "new_surname_of_" + name
            new_cn = "new_cn_of_" + name
            expected_cn = "%s %s. %s" % (new_givenname, new_initials, new_surname)

            # rename given name, initials and surname
            (result, out, err) = self.runsubcmd("contact", "rename", name,
                                                "--reset-cn",
                                                "--surname=%s" % new_surname,
                                                "--initials=%s" % new_initials,
                                                "--given-name=%s" % new_givenname)
            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "Shouldn't be any error messages")
            self.assertIn('successfully', out)

            found = self._find_contact(expected_cn)
            self.assertEqual("%s" % found.get("givenName"), new_givenname)
            self.assertEqual("%s" % found.get("initials"), new_initials)
            self.assertEqual("%s" % found.get("sn"), new_surname)
            self.assertEqual("%s" % found.get("name"), expected_cn)
            self.assertEqual("%s" % found.get("cn"), expected_cn)

            # remove given name, initials and surname
            # (must forece new cn, because en empty new CN throws an error)
            (result, out, err) = self.runsubcmd("contact", "rename", expected_cn,
                                                "--force-new-cn=%s" % expected_cn,
                                                "--surname=",
                                                "--initials=",
                                                "--given-name=")
            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "Shouldn't be any error messages")
            self.assertIn('successfully', out)

            found = self._find_contact(expected_cn)
            self.assertEqual(found.get("givenName"), None)
            self.assertEqual(found.get("initials"), None)
            self.assertEqual(found.get("sn"), None)

            # reset changes (initials are already removed)
            old_surname = contact["sn"] if "sn" in contact else ""
            old_initials = contact["initials"] if "initials" in contact else ""
            old_givenname = contact["givenName"] if "givenName" in contact else ""
            old_cn = contact["cn"] if "cn" in contact else name
            (result, out, err) = self.runsubcmd("contact", "rename", expected_cn,
                                                "--force-new-cn=%s"  % old_cn,
                                                "--surname=%s" % old_surname,
                                                "--initials=%s" % old_initials,
                                                "--given-name=%s" % old_givenname)
            self.assertCmdSuccess(result, out, err)

    def test_rename_cn(self):
        """rename and try to remove the cn of all contacts"""
        for contact in self.contacts:
            name = contact["name"] if "name" in contact else contact["expectedname"]
            new_cn = "new_cn_of_" + name

            # rename cn
            (result, out, err) = self.runsubcmd("contact", "rename", name,
                                                "--force-new-cn=%s" % new_cn)
            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "Shouldn't be any error messages")
            self.assertIn('successfully', out)

            found = self._find_contact(new_cn)
            self.assertEqual("%s" % found.get("cn"), new_cn)

            # trying to remove cn (throws an error)
            (result, out, err) = self.runsubcmd("contact", "rename", new_cn,
                                                "--force-new-cn=")
            self.assertCmdFail(result)
            self.assertIn('Failed to rename contact', err)
            self.assertIn("delete protected attribute", err)

            # reset changes (cn must be the name)
            (result, out, err) = self.runsubcmd("contact", "rename", new_cn,
                                                "--force-new-cn=%s" % name)
            self.assertCmdSuccess(result, out, err)


    def test_rename_mailaddress_displayname(self):
        """rename and remove the mail and the displayname attribute of all contacts"""
        for contact in self.contacts:
            name = contact["name"] if "name" in contact else contact["expectedname"]
            new_mail = "new_mailaddress_of_" + name
            new_displayname = "new displayname of " + name

            # change mail and displayname
            (result, out, err) = self.runsubcmd("contact", "rename", name,
                                                "--mail-address=%s"
                                                  % new_mail,
                                                "--display-name=%s"
                                                  % new_displayname)
            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "Shouldn't be any error messages")
            self.assertIn('successfully', out)

            found = self._find_contact(name)
            self.assertEqual("%s" % found.get("mail"), new_mail)
            self.assertEqual("%s" % found.get("displayName"), new_displayname)

            # remove mail and displayname
            (result, out, err) = self.runsubcmd("contact", "rename", name,
                                                "--mail-address=",
                                                "--display-name=")
            self.assertCmdSuccess(result, out, err)
            self.assertEqual(err, "", "Shouldn't be any error messages")
            self.assertIn('successfully', out)

            found = self._find_contact(name)
            self.assertEqual(found.get("mail"), None)
            self.assertEqual(found.get("displayName"), None)

            # reset changes
            old_mail = contact["givenName"] if "givenName" in contact else ""
            old_displayname = contact["cn"] if "cn" in contact else ""
            (result, out, err) = self.runsubcmd("contact", "rename", name,
                                                "--mail-address=%s" % old_mail,
                                                "--display-name=%s" % old_displayname)
            self.assertCmdSuccess(result, out, err)

    def _randomContact(self, base={}):
        """Create a contact with random attribute values, you can specify base
        attributes"""

        # No name attributes are given here, because the object name will
        # be made from the sn, givenName and initials attributes, if no name
        # is given.
        contact = {
            "description": self.randomName(count=100),
        }
        contact.update(base)
        return contact

    def _randomOU(self, base={}):
        """Create an ou with random attribute values, you can specify base
        attributes."""

        ou = {
            "name": self.randomName(),
            "description": self.randomName(count=100),
        }
        ou.update(base)
        return ou

    def _create_contact(self, contact, ou=None):
        args = ""

        if "name" in contact:
            args += '{0}'.format(contact['name'])

        args += ' {0}'.format(self.creds)

        if ou is not None:
            args += ' --ou={0}'.format(ou)

        if "description" in contact:
            args += ' --description={0}'.format(contact["description"])
        if "sn" in contact:
            args += ' --surname={0}'.format(contact["sn"])
        if "initials" in contact:
            args += ' --initials={0}'.format(contact["initials"])
        if "givenName" in contact:
            args += ' --given-name={0}'.format(contact["givenName"])
        if "displayName" in contact:
            args += ' --display-name={0}'.format(contact["displayName"])
        if "mobile" in contact:
            args += ' --mobile-number={0}'.format(contact["mobile"])

        args = args.split()

        return self.runsubcmd('contact', 'create', *args)

    def _create_ou(self, ou):
        return self.runsubcmd("ou",
                              "create",
                              "OU=%s" % ou["name"],
                              "--description=%s" % ou["description"])

    def _find_contact(self, name):
        contactname = name
        search_filter = ("(&(objectClass=contact)(name=%s))" %
                         ldb.binary_encode(contactname))
        contactlist = self.samdb.search(base=self.samdb.domain_dn(),
                                        scope=ldb.SCOPE_SUBTREE,
                                        expression=search_filter,
                                        attrs=[])
        if contactlist:
            return contactlist[0]
        else:
            return None

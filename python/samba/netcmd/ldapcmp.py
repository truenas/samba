# Unix SMB/CIFS implementation.
# A command to compare differences of objects and attributes between
# two LDAP servers both running at the same time. It generally compares
# one of the three pratitions DOMAIN, CONFIGURATION or SCHEMA. Users
# that have to be provided sheould be able to read objects in any of the
# above partitions.

# Copyright (C) Zahari Zahariev <zahari.zahariev@postpath.com> 2009, 2010
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
import re
import sys

import samba
import samba.getopt as options
from samba import Ldb
from samba.ndr import ndr_unpack
from samba.dcerpc import security
from ldb import SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE, ERR_NO_SUCH_OBJECT, LdbError
from samba.netcmd import (
    Command,
    CommandError,
    Option,
)

RE_RANGED_RESULT = re.compile(r"^([^;]+);range=(\d+)-(\d+|\*)$")


class LDAPBase(object):

    def __init__(self, host, creds, lp,
                 two=False, quiet=False, descriptor=False, sort_aces=False, verbose=False,
                 view="section", base="", scope="SUB",
                 outf=sys.stdout, errf=sys.stderr, skip_missing_dn=True):
        ldb_options = []
        samdb_url = host
        if "://" not in host:
            if os.path.isfile(host):
                samdb_url = "tdb://%s" % host
            else:
                samdb_url = "ldap://%s" % host
        # use 'paged_search' module when connecting remotely
        if samdb_url.lower().startswith("ldap://"):
            ldb_options = ["modules:paged_searches"]
        self.outf = outf
        self.errf = errf
        self.ldb = Ldb(url=samdb_url,
                       credentials=creds,
                       lp=lp,
                       options=ldb_options)
        self.search_base = base
        self.search_scope = scope
        self.two_domains = two
        self.quiet = quiet
        self.descriptor = descriptor
        self.sort_aces = sort_aces
        self.view = view
        self.verbose = verbose
        self.host = host
        self.skip_missing_dn = skip_missing_dn
        self.base_dn = str(self.ldb.get_default_basedn())
        self.root_dn = str(self.ldb.get_root_basedn())
        self.config_dn = str(self.ldb.get_config_basedn())
        self.schema_dn = str(self.ldb.get_schema_basedn())
        self.domain_netbios = self.find_netbios()
        self.server_names = self.find_servers()
        self.domain_name = re.sub("[Dd][Cc]=", "", self.base_dn).replace(",", ".")
        self.domain_sid = self.find_domain_sid()
        self.get_sid_map()
        #
        # Log some domain controller specific place-holers that are being used
        # when compare content of two DCs. Uncomment for DEBUG purposes.
        if self.two_domains and not self.quiet:
            self.outf.write("\n* Place-holders for %s:\n" % self.host)
            self.outf.write(4 * " " + "${DOMAIN_DN}      => %s\n" %
                            self.base_dn)
            self.outf.write(4 * " " + "${DOMAIN_NETBIOS} => %s\n" %
                            self.domain_netbios)
            self.outf.write(4 * " " + "${SERVER_NAME}     => %s\n" %
                            self.server_names)
            self.outf.write(4 * " " + "${DOMAIN_NAME}    => %s\n" %
                            self.domain_name)

    def find_domain_sid(self):
        res = self.ldb.search(base=self.base_dn, expression="(objectClass=*)", scope=SCOPE_BASE)
        return ndr_unpack(security.dom_sid, res[0]["objectSid"][0])

    def find_servers(self):
        """
        """
        res = self.ldb.search(base="OU=Domain Controllers,%s" % self.base_dn,
                              scope=SCOPE_SUBTREE, expression="(objectClass=computer)", attrs=["cn"])
        assert len(res) > 0
        return [str(x["cn"][0]) for x in res]

    def find_netbios(self):
        try:
            res = self.ldb.search(base="CN=Partitions,%s" % self.config_dn,
                                  scope=SCOPE_SUBTREE, attrs=["nETBIOSName"])
        except LdbError as e:
            enum, estr = e
            if estr in ["Operation unavailable without authentication"]:
                raise CommandError(estr, e)

        if len(res) == 0:
            raise CommandError("Could not find netbios name")

        for x in res:
            if "nETBIOSName" in x:
                return x["nETBIOSName"][0].decode()

    def object_exists(self, object_dn):
        res = None
        try:
            res = self.ldb.search(base=object_dn, scope=SCOPE_BASE)
        except LdbError as e2:
            (enum, estr) = e2.args
            if enum == ERR_NO_SUCH_OBJECT:
                return False
            raise
        return len(res) == 1

    def delete_force(self, object_dn):
        try:
            self.ldb.delete(object_dn)
        except Ldb.LdbError as e:
            assert "No such object" in str(e)

    def get_attribute_name(self, key):
        """ Returns the real attribute name
            It resolved ranged results e.g. member;range=0-1499
        """

        m = RE_RANGED_RESULT.match(key)
        if m is None:
            return key

        return m.group(1)

    def get_attribute_values(self, object_dn, key, vals):
        """ Returns list with all attribute values
            It resolved ranged results e.g. member;range=0-1499
        """

        m = RE_RANGED_RESULT.match(key)
        if m is None:
            # no range, just return the values
            return vals

        attr = m.group(1)
        hi = int(m.group(3))

        # get additional values in a loop
        # until we get a response with '*' at the end
        while True:

            n = "%s;range=%d-*" % (attr, hi + 1)
            res = self.ldb.search(base=object_dn, scope=SCOPE_BASE, attrs=[n])
            assert len(res) == 1
            res = dict(res[0])
            del res["dn"]

            fm = None
            fvals = None

            for key in res:
                m = RE_RANGED_RESULT.match(key)

                if m is None:
                    continue

                if m.group(1) != attr:
                    continue

                fm = m
                fvals = list(res[key])
                break

            if fm is None:
                break

            vals.extend(fvals)
            if fm.group(3) == "*":
                # if we got "*" we're done
                break

            assert int(fm.group(2)) == hi + 1
            hi = int(fm.group(3))

        return vals

    def get_attributes(self, object_dn):
        """ Returns dict with all default visible attributes
        """
        res = self.ldb.search(base=object_dn, scope=SCOPE_BASE, attrs=["*"])
        assert len(res) == 1
        res = dict(res[0])
        # 'Dn' element is not iterable and we have it as 'distinguishedName'
        del res["dn"]

        attributes = {}
        for key, vals in res.items():
            name = self.get_attribute_name(key)
            # sort vals and return a list, help to compare
            vals = sorted(vals)
            attributes[name] = self.get_attribute_values(object_dn, key, vals)

        return attributes

    def get_descriptor_sddl(self, object_dn):
        res = self.ldb.search(base=object_dn, scope=SCOPE_BASE, attrs=["nTSecurityDescriptor"])
        desc = res[0]["nTSecurityDescriptor"][0]
        desc = ndr_unpack(security.descriptor, desc)
        return desc.as_sddl(self.domain_sid)

    def guid_as_string(self, guid_blob):
        """ Translate binary representation of schemaIDGUID to standard string representation.
            @gid_blob: binary schemaIDGUID
        """
        blob = "%s" % guid_blob
        stops = [4, 2, 2, 2, 6]
        index = 0
        res = ""
        x = 0
        while x < len(stops):
            tmp = ""
            y = 0
            while y < stops[x]:
                c = hex(ord(blob[index])).replace("0x", "")
                c = [None, "0" + c, c][len(c)]
                if 2 * index < len(blob):
                    tmp = c + tmp
                else:
                    tmp += c
                index += 1
                y += 1
            res += tmp + " "
            x += 1
        assert index == len(blob)
        return res.strip().replace(" ", "-")

    def get_sid_map(self):
        """ Build dictionary that maps GUID to 'name' attribute found in Schema or Extended-Rights.
        """
        self.sid_map = {}
        res = self.ldb.search(base=self.base_dn,
                              expression="(objectSid=*)", scope=SCOPE_SUBTREE, attrs=["objectSid", "sAMAccountName"])
        for item in res:
            try:
                self.sid_map["%s" % ndr_unpack(security.dom_sid, item["objectSid"][0])] = str(item["sAMAccountName"][0])
            except KeyError:
                pass


class Descriptor(object):
    def __init__(self, connection, dn, outf=sys.stdout, errf=sys.stderr):
        self.outf = outf
        self.errf = errf
        self.con = connection
        self.dn = dn
        self.sddl = self.con.get_descriptor_sddl(self.dn)
        self.dacl_list = self.extract_dacl()
        if self.con.sort_aces:
            self.dacl_list.sort()

    def extract_dacl(self):
        """ Extracts the DACL as a list of ACE string (with the brakets).
        """
        try:
            if "S:" in self.sddl:
                res = re.search(r"D:(.*?)(\(.*?\))S:", self.sddl).group(2)
            else:
                res = re.search(r"D:(.*?)(\(.*\))", self.sddl).group(2)
        except AttributeError:
            return []
        return re.findall(r"(\(.*?\))", res)

    def fix_sid(self, ace):
        res = "%s" % ace
        sids = re.findall("S-[-0-9]+", res)
        # If there are not SIDs to replace return the same ACE
        if len(sids) == 0:
            return res
        for sid in sids:
            try:
                name = self.con.sid_map[sid]
                res = res.replace(sid, name)
            except KeyError:
                # Do not bother if the SID is not found in baseDN
                pass
        return res

    def diff_1(self, other):
        res = ""
        if len(self.dacl_list) != len(other.dacl_list):
            res += 4 * " " + "Difference in ACE count:\n"
            res += 8 * " " + "=> %s\n" % len(self.dacl_list)
            res += 8 * " " + "=> %s\n" % len(other.dacl_list)
        #
        i = 0
        flag = True
        while True:
            self_ace = None
            other_ace = None
            try:
                self_ace = "%s" % self.dacl_list[i]
            except IndexError:
                self_ace = ""
            #
            try:
                other_ace = "%s" % other.dacl_list[i]
            except IndexError:
                other_ace = ""
            if len(self_ace) + len(other_ace) == 0:
                break
            self_ace_fixed = "%s" % self.fix_sid(self_ace)
            other_ace_fixed = "%s" % other.fix_sid(other_ace)
            if self_ace_fixed != other_ace_fixed:
                res += "%60s * %s\n" % (self_ace_fixed, other_ace_fixed)
                flag = False
            else:
                res += "%60s | %s\n" % (self_ace_fixed, other_ace_fixed)
            i += 1
        return (flag, res)

    def diff_2(self, other):
        res = ""
        if len(self.dacl_list) != len(other.dacl_list):
            res += 4 * " " + "Difference in ACE count:\n"
            res += 8 * " " + "=> %s\n" % len(self.dacl_list)
            res += 8 * " " + "=> %s\n" % len(other.dacl_list)
        #
        common_aces = []
        self_aces = []
        other_aces = []
        self_dacl_list_fixed = [self.fix_sid(ace) for ace in self.dacl_list]
        other_dacl_list_fixed = [other.fix_sid(ace) for ace in other.dacl_list]
        for ace in self_dacl_list_fixed:
            try:
                other_dacl_list_fixed.index(ace)
            except ValueError:
                self_aces.append(ace)
            else:
                common_aces.append(ace)
        self_aces = sorted(self_aces)
        if len(self_aces) > 0:
            res += 4 * " " + "ACEs found only in %s:\n" % self.con.host
            for ace in self_aces:
                res += 8 * " " + ace + "\n"
        #
        for ace in other_dacl_list_fixed:
            try:
                self_dacl_list_fixed.index(ace)
            except ValueError:
                other_aces.append(ace)
            else:
                common_aces.append(ace)
        other_aces = sorted(other_aces)
        if len(other_aces) > 0:
            res += 4 * " " + "ACEs found only in %s:\n" % other.con.host
            for ace in other_aces:
                res += 8 * " " + ace + "\n"
        #
        common_aces = sorted(list(set(common_aces)))
        if self.con.verbose:
            res += 4 * " " + "ACEs found in both:\n"
            for ace in common_aces:
                res += 8 * " " + ace + "\n"
        return (self_aces == [] and other_aces == [], res)


class LDAPObject(object):
    def __init__(self, connection, dn, summary, filter_list,
                 outf=sys.stdout, errf=sys.stderr):
        self.outf = outf
        self.errf = errf
        self.con = connection
        self.two_domains = self.con.two_domains
        self.quiet = self.con.quiet
        self.verbose = self.con.verbose
        self.summary = summary
        self.dn = dn.replace("${DOMAIN_DN}", self.con.base_dn)
        self.dn = self.dn.replace("CN=${DOMAIN_NETBIOS}", "CN=%s" % self.con.domain_netbios)
        for x in self.con.server_names:
            self.dn = self.dn.replace("CN=${SERVER_NAME}", "CN=%s" % x)
        self.attributes = self.con.get_attributes(self.dn)
        # One domain - two domain controllers
        #
        # Some attributes are defined as FLAG_ATTR_NOT_REPLICATED
        #
        # The following list was generated by
        # egrep '^systemFlags: |^ldapDisplayName: |^linkID: ' \
        #       source4/setup/ad-schema/MS-AD_Schema_2K8_R2_Attributes.txt | \
        #       grep -B1 FLAG_ATTR_NOT_REPLICATED | \
        #       grep ldapDisplayName | \
        #       cut -d ' ' -f2
        self.non_replicated_attributes = [
                "badPasswordTime",
                "badPwdCount",
                "dSCorePropagationData",
                "lastLogoff",
                "lastLogon",
                "logonCount",
                "modifiedCount",
                "msDS-Cached-Membership",
                "msDS-Cached-Membership-Time-Stamp",
                "msDS-EnabledFeatureBL",
                "msDS-ExecuteScriptPassword",
                "msDS-NcType",
                "msDS-ReplicationEpoch",
                "msDS-RetiredReplNCSignatures",
                "msDS-USNLastSyncSuccess",
                # "distinguishedName", # This is implicitly replicated
                # "objectGUID", # This is implicitly replicated
                "partialAttributeDeletionList",
                "partialAttributeSet",
                "pekList",
                "prefixMap",
                "replPropertyMetaData",
                "replUpToDateVector",
                "repsFrom",
                "repsTo",
                "rIDNextRID",
                "rIDPreviousAllocationPool",
                "schemaUpdate",
                "serverState",
                "subRefs",
                "uSNChanged",
                "uSNCreated",
                "uSNLastObjRem",
                "whenChanged",  # This is implicitly replicated, but may diverge on updates of non-replicated attributes
        ]
        self.ignore_attributes = self.non_replicated_attributes
        self.ignore_attributes += ["msExchServer1HighestUSN"]
        if filter_list:
            self.ignore_attributes += filter_list

        self.dn_attributes = []
        self.domain_attributes = []
        self.servername_attributes = []
        self.netbios_attributes = []
        self.other_attributes = []
        # Two domains - two domain controllers

        if self.two_domains:
            self.ignore_attributes += [
                "objectCategory", "objectGUID", "objectSid", "whenCreated",
                "whenChanged", "pwdLastSet", "uSNCreated", "creationTime",
                "modifiedCount", "priorSetTime", "rIDManagerReference",
                "gPLink", "ipsecNFAReference", "fRSPrimaryMember",
                "fSMORoleOwner", "masteredBy", "ipsecOwnersReference",
                "wellKnownObjects", "otherWellKnownObjects", "badPwdCount",
                "ipsecISAKMPReference", "ipsecFilterReference",
                "msDs-masteredBy", "lastSetTime",
                "ipsecNegotiationPolicyReference", "subRefs", "gPCFileSysPath",
                "accountExpires", "invocationId", "operatingSystemVersion",
                "oEMInformation", "schemaInfo",
                # After Exchange preps
                "targetAddress", "msExchMailboxGuid", "siteFolderGUID"]
            #
            # Attributes that contain the unique DN tail part e.g. 'DC=samba,DC=org'
            self.dn_attributes = [
                "distinguishedName", "defaultObjectCategory", "member", "memberOf", "siteList", "nCName",
                "homeMDB", "homeMTA", "interSiteTopologyGenerator", "serverReference",
                "msDS-HasInstantiatedNCs", "hasMasterNCs", "msDS-hasMasterNCs", "msDS-HasDomainNCs", "dMDLocation",
                "msDS-IsDomainFor", "rIDSetReferences", "serverReferenceBL",
                # After Exchange preps
                "msExchHomeRoutingGroup", "msExchResponsibleMTAServer", "siteFolderServer", "msExchRoutingMasterDN",
                "msExchRoutingGroupMembersBL", "homeMDBBL", "msExchHomePublicMDB", "msExchOwningServer", "templateRoots",
                "addressBookRoots", "msExchPolicyRoots", "globalAddressList", "msExchOwningPFTree",
                "msExchResponsibleMTAServerBL", "msExchOwningPFTreeBL",
                # After 2012 R2 functional preparation
                "msDS-MembersOfResourcePropertyListBL",
                "msDS-ValueTypeReference",
                "msDS-MembersOfResourcePropertyList",
                "msDS-ValueTypeReferenceBL",
                "msDS-ClaimTypeAppliesToClass",
            ]
            self.dn_attributes = [x.upper() for x in self.dn_attributes]
            #
            # Attributes that contain the Domain name e.g. 'samba.org'
            self.domain_attributes = [
                "proxyAddresses", "mail", "userPrincipalName", "msExchSmtpFullyQualifiedDomainName",
                "dnsHostName", "networkAddress", "dnsRoot", "servicePrincipalName", ]
            self.domain_attributes = [x.upper() for x in self.domain_attributes]
            #
            # May contain DOMAIN_NETBIOS and SERVER_NAME
            self.servername_attributes = ["distinguishedName", "name", "CN", "sAMAccountName", "dNSHostName",
                                          "servicePrincipalName", "rIDSetReferences", "serverReference", "serverReferenceBL",
                                          "msDS-IsDomainFor", "interSiteTopologyGenerator", ]
            self.servername_attributes = [x.upper() for x in self.servername_attributes]
            #
            self.netbios_attributes = ["servicePrincipalName", "CN", "distinguishedName", "nETBIOSName", "name", ]
            self.netbios_attributes = [x.upper() for x in self.netbios_attributes]
            #
            self.other_attributes = ["name", "DC", ]
            self.other_attributes = [x.upper() for x in self.other_attributes]
        #
        self.ignore_attributes = set([x.upper() for x in self.ignore_attributes])

    def log(self, msg):
        """
        Log on the screen if there is no --quiet option set
        """
        if not self.quiet:
            self.outf.write(msg +"\n")

    def fix_dn(self, s):
        res = "%s" % s
        if not self.two_domains:
            return res
        if res.upper().endswith(self.con.base_dn.upper()):
            res = res[:len(res) - len(self.con.base_dn)] + "${DOMAIN_DN}"
        return res

    def fix_domain_name(self, s):
        res = "%s" % s
        if not self.two_domains:
            return res
        res = res.replace(self.con.domain_name.lower(), self.con.domain_name.upper())
        res = res.replace(self.con.domain_name.upper(), "${DOMAIN_NAME}")
        return res

    def fix_domain_netbios(self, s):
        res = "%s" % s
        if not self.two_domains:
            return res
        res = res.replace(self.con.domain_netbios.lower(), self.con.domain_netbios.upper())
        res = res.replace(self.con.domain_netbios.upper(), "${DOMAIN_NETBIOS}")
        return res

    def fix_server_name(self, s):
        res = "%s" % s
        if not self.two_domains or len(self.con.server_names) > 1:
            return res
        for x in self.con.server_names:
            res = res.upper().replace(x, "${SERVER_NAME}")
        return res

    def __eq__(self, other):
        if self.con.descriptor:
            return self.cmp_desc(other)
        return self.cmp_attrs(other)

    def cmp_desc(self, other):
        d1 = Descriptor(self.con, self.dn, outf=self.outf, errf=self.errf)
        d2 = Descriptor(other.con, other.dn, outf=self.outf, errf=self.errf)
        if self.con.view == "section":
            res = d1.diff_2(d2)
        elif self.con.view == "collision":
            res = d1.diff_1(d2)
        else:
            raise ValueError(f"Unknown --view option value: {self.con.view}")
        #
        self.screen_output = res[1]
        other.screen_output = res[1]
        #
        return res[0]

    def cmp_attrs(self, other):
        res = ""
        self.df_value_attrs = []

        self_attrs = set([attr.upper() for attr in self.attributes])
        other_attrs = set([attr.upper() for attr in other.attributes])

        self_unique_attrs = self_attrs - other_attrs - other.ignore_attributes
        if self_unique_attrs:
            res += 4 * " " + "Attributes found only in %s:" % self.con.host
            for x in self_unique_attrs:
                res += 8 * " " + x + "\n"

        other_unique_attrs = other_attrs - self_attrs - self.ignore_attributes
        if other_unique_attrs:
            res += 4 * " " + "Attributes found only in %s:" % other.con.host
            for x in other_unique_attrs:
                res += 8 * " " + x + "\n"

        missing_attrs = self_unique_attrs & other_unique_attrs
        title = 4 * " " + "Difference in attribute values:"
        for x in self.attributes:
            if x.upper() in self.ignore_attributes or x.upper() in missing_attrs:
                continue
            ours = self.attributes[x]
            theirs = other.attributes.get(x)

            if isinstance(ours, list) and isinstance(theirs, list):
                ours = sorted(ours)
                theirs = sorted(theirs)

            if ours != theirs:
                p = None
                q = None
                m = None
                n = None
                # First check if the difference can be fixed but shunting the first part
                # of the DomainHostName e.g. 'mysamba4.test.local' => 'mysamba4'
                if x.upper() in self.other_attributes:
                    p = [self.con.domain_name.split(".")[0] == j for j in ours]
                    q = [other.con.domain_name.split(".")[0] == j for j in theirs]
                    if p == q:
                        continue
                # Attribute values that are list that contain DN based values that may differ
                elif x.upper() in self.dn_attributes:
                    m = ours
                    n = theirs
                    p = [self.fix_dn(j) for j in m]
                    q = [other.fix_dn(j) for j in n]
                    if p == q:
                        continue
                # Attributes that contain the Domain name in them
                if x.upper() in self.domain_attributes:
                    m = p
                    n = q
                    if not p and not q:
                        m = ours
                        n = theirs
                    p = [self.fix_domain_name(j) for j in m]
                    q = [other.fix_domain_name(j) for j in n]
                    if p == q:
                        continue
                #
                if x.upper() in self.servername_attributes:
                    # Attributes with SERVER_NAME
                    m = p
                    n = q
                    if not p and not q:
                        m = ours
                        n = theirs
                    p = [self.fix_server_name(j) for j in m]
                    q = [other.fix_server_name(j) for j in n]
                    if p == q:
                        continue
                #
                if x.upper() in self.netbios_attributes:
                    # Attributes with NETBIOS Domain name
                    m = p
                    n = q
                    if not p and not q:
                        m = ours
                        n = theirs
                    p = [self.fix_domain_netbios(j) for j in m]
                    q = [other.fix_domain_netbios(j) for j in n]
                    if p == q:
                        continue
                #
                if title:
                    res += title + "\n"
                    title = None
                if p and q:
                    res += 8 * " " + x + " => \n%s\n%s" % (p, q) + "\n"
                else:
                    res += 8 * " " + x + " => \n%s\n%s" % (ours, theirs) + "\n"
                self.df_value_attrs.append(x)
        #
        if missing_attrs:
            assert self_unique_attrs != other_unique_attrs
        self.summary["unique_attrs"] += list(self_unique_attrs)
        self.summary["df_value_attrs"] += self.df_value_attrs
        other.summary["unique_attrs"] += list(other_unique_attrs)
        other.summary["df_value_attrs"] += self.df_value_attrs  # they are the same
        #
        self.screen_output = res
        other.screen_output = res
        #
        return res == ""


class LDAPBundle(object):

    def __init__(self, connection, context, dn_list=None, filter_list=None,
                 outf=sys.stdout, errf=sys.stderr):
        self.outf = outf
        self.errf = errf
        self.con = connection
        self.two_domains = self.con.two_domains
        self.quiet = self.con.quiet
        self.verbose = self.con.verbose
        self.search_base = self.con.search_base
        self.search_scope = self.con.search_scope
        self.skip_missing_dn = self.con.skip_missing_dn
        self.summary = {}
        self.summary["unique_attrs"] = []
        self.summary["df_value_attrs"] = []
        self.summary["known_ignored_dn"] = []
        self.summary["abnormal_ignored_dn"] = []
        self.filter_list = filter_list
        if dn_list:
            self.dn_list = dn_list
        elif context.upper() in ["DOMAIN", "CONFIGURATION", "SCHEMA", "DNSDOMAIN", "DNSFOREST"]:
            self.context = context.upper()
            self.dn_list = self.get_dn_list(context)
        else:
            raise Exception("Unknown initialization data for LDAPBundle().")
        counter = 0
        while counter < len(self.dn_list) and self.two_domains:
            # Use alias reference
            tmp = self.dn_list[counter]
            tmp = tmp[:len(tmp) - len(self.con.base_dn)] + "${DOMAIN_DN}"
            tmp = tmp.replace("CN=%s" % self.con.domain_netbios, "CN=${DOMAIN_NETBIOS}")
            if len(self.con.server_names) == 1:
                for x in self.con.server_names:
                    tmp = tmp.replace("CN=%s" % x, "CN=${SERVER_NAME}")
            self.dn_list[counter] = tmp
            counter += 1
        self.dn_list = list(set(self.dn_list))
        self.dn_list = sorted(self.dn_list)
        self.size = len(self.dn_list)

    def log(self, msg):
        """
        Log on the screen if there is no --quiet option set
        """
        if not self.quiet:
            self.outf.write(msg + "\n")

    def update_size(self):
        self.size = len(self.dn_list)
        self.dn_list = sorted(self.dn_list)

    def diff(self, other):
        res = True
        if self.size != other.size:
            self.log("\n* DN lists have different size: %s != %s" % (self.size, other.size))
            if not self.skip_missing_dn:
                res = False

        self_dns = set([q.upper() for q in self.dn_list])
        other_dns = set([q.upper() for q in other.dn_list])

        #
        # This is the case where we want to explicitly compare two objects with different DNs.
        # It does not matter if they are in the same DC, in two DC in one domain or in two
        # different domains.
        if self.search_scope != SCOPE_BASE and not self.skip_missing_dn:

            self_only = self_dns - other_dns  # missing in other
            if self_only:
                res = False
                self.log("\n* DNs found only in %s:" % self.con.host)
                for x in sorted(self_only):
                    self.log(4 * " " + x)

            other_only = other_dns - self_dns  # missing in self
            if other_only:
                res = False
                self.log("\n* DNs found only in %s:" % other.con.host)
                for x in sorted(other_only):
                    self.log(4 * " " + x)

        common_dns = self_dns & other_dns
        self.log("\n* Objects to be compared: %d" % len(common_dns))

        for dn in common_dns:

            try:
                object1 = LDAPObject(connection=self.con,
                                     dn=dn,
                                     summary=self.summary,
                                     filter_list=self.filter_list,
                                     outf=self.outf, errf=self.errf)
            except LdbError as e:
                self.log("LdbError for dn %s: %s" % (dn, e))
                continue

            try:
                object2 = LDAPObject(connection=other.con,
                                     dn=dn,
                                     summary=other.summary,
                                     filter_list=self.filter_list,
                                     outf=self.outf, errf=self.errf)
            except LdbError as e:
                self.log("LdbError for dn %s: %s" % (dn, e))
                continue

            if object1 == object2:
                if self.con.verbose:
                    self.log("\nComparing:")
                    self.log("'%s' [%s]" % (object1.dn, object1.con.host))
                    self.log("'%s' [%s]" % (object2.dn, object2.con.host))
                    self.log(4 * " " + "OK")
            else:
                self.log("\nComparing:")
                self.log("'%s' [%s]" % (object1.dn, object1.con.host))
                self.log("'%s' [%s]" % (object2.dn, object2.con.host))
                self.log(object1.screen_output)
                self.log(4 * " " + "FAILED")
                res = False
            self.summary = object1.summary
            other.summary = object2.summary

        return res

    def get_dn_list(self, context):
        """ Query LDAP server about the DNs of certain naming self.con.ext Domain (or Default), Configuration, Schema.
            Parse all DNs and filter those that are 'strange' or abnormal.
        """
        if context.upper() == "DOMAIN":
            search_base = self.con.base_dn
        elif context.upper() == "CONFIGURATION":
            search_base = self.con.config_dn
        elif context.upper() == "SCHEMA":
            search_base = self.con.schema_dn
        elif context.upper() == "DNSDOMAIN":
            search_base = "DC=DomainDnsZones,%s" % self.con.base_dn
        elif context.upper() == "DNSFOREST":
            search_base = "DC=ForestDnsZones,%s" % self.con.root_dn

        dn_list = []
        if not self.search_base:
            self.search_base = search_base
        self.search_scope = self.search_scope.upper()
        if self.search_scope == "SUB":
            self.search_scope = SCOPE_SUBTREE
        elif self.search_scope == "BASE":
            self.search_scope = SCOPE_BASE
        elif self.search_scope == "ONE":
            self.search_scope = SCOPE_ONELEVEL
        else:
            raise ValueError("Wrong 'scope' given. Choose from: SUB, ONE, BASE")
        try:
            res = self.con.ldb.search(base=self.search_base, scope=self.search_scope, attrs=["dn"])
        except LdbError as e3:
            (enum, estr) = e3.args
            self.outf.write("Failed search of base=%s\n" % self.search_base)
            raise
        for x in res:
            dn_list.append(x["dn"].get_linearized())
        return dn_list

    def print_summary(self):
        self.summary["unique_attrs"] = list(set(self.summary["unique_attrs"]))
        self.summary["df_value_attrs"] = list(set(self.summary["df_value_attrs"]))
        #
        if self.summary["unique_attrs"]:
            self.log("\nAttributes found only in %s:" % self.con.host)
            self.log("".join([str("\n" + 4 * " " + x) for x in self.summary["unique_attrs"]]))
        #
        if self.summary["df_value_attrs"]:
            self.log("\nAttributes with different values:")
            self.log("".join([str("\n" + 4 * " " + x) for x in self.summary["df_value_attrs"]]))
            self.summary["df_value_attrs"] = []


class cmd_ldapcmp(Command):
    """Compare two ldap databases."""
    synopsis = "%prog <URL1> <URL2> (domain|configuration|schema|dnsdomain|dnsforest) [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptionsDouble,
    }

    takes_args = ["URL1", "URL2", "context1?", "context2?", "context3?", "context4?", "context5?"]

    takes_options = [
        Option("-w", "--two", dest="two", action="store_true", default=False,
               help="Hosts are in two different domains"),
        Option("-q", "--quiet", dest="quiet", action="store_true", default=False,
               help="Do not print anything but relay on just exit code"),
        Option("-v", "--verbose", dest="verbose", action="store_true", default=False,
               help="Print all DN pairs that have been compared"),
        Option("--sd", dest="descriptor", action="store_true", default=False,
               help="Compare nTSecurityDescriptor attibutes only"),
        Option("--sort-aces", dest="sort_aces", action="store_true", default=False,
               help="Sort ACEs before comparison of nTSecurityDescriptor attribute"),
        Option("--view", dest="view", default="section", choices=["section", "collision"],
               help="Display mode for nTSecurityDescriptor results. Possible values: section or collision."),
        Option("--base", dest="base", default="",
               help="Pass search base that will build DN list for the first DC."),
        Option("--base2", dest="base2", default="",
               help="Pass search base that will build DN list for the second DC. Used when --two or when compare two different DNs."),
        Option("--scope", dest="scope", default="SUB", choices=["SUB", "ONE", "BASE"],
               help="Pass search scope that builds DN list. Options: SUB, ONE, BASE"),
        Option("--filter", dest="filter", default="",
               help="List of comma separated attributes to ignore in the comparision"),
        Option("--skip-missing-dn", dest="skip_missing_dn", action="store_true", default=False,
               help="Skip report and failure due to missing DNs in one server or another"),
    ]

    def run(self, URL1, URL2,
            context1=None, context2=None, context3=None, context4=None, context5=None,
            two=False, quiet=False, verbose=False, descriptor=False, sort_aces=False,
            view="section", base="", base2="", scope="SUB", filter="",
            credopts=None, sambaopts=None, versionopts=None, skip_missing_dn=False):

        lp = sambaopts.get_loadparm()

        using_ldap = URL1.startswith("ldap") or URL2.startswith("ldap")

        if using_ldap:
            creds = credopts.get_credentials(lp, fallback_machine=True)
        else:
            creds = None
        creds2 = credopts.get_credentials2(lp, guess=False)
        if creds2.is_anonymous():
            creds2 = creds
        else:
            creds2.set_domain("")
            creds2.set_workstation("")
        if using_ldap and not creds.authentication_requested():
            raise CommandError("You must supply at least one username/password pair")

        # make a list of contexts to compare in
        contexts = []
        if context1 is None:
            if base and base2:
                # If search bases are specified context is defaulted to
                # DOMAIN so the given search bases can be verified.
                contexts = ["DOMAIN"]
            else:
                # if no argument given, we compare all contexts
                contexts = ["DOMAIN", "CONFIGURATION", "SCHEMA", "DNSDOMAIN", "DNSFOREST"]
        else:
            for c in [context1, context2, context3, context4, context5]:
                if c is None:
                    continue
                if not c.upper() in ["DOMAIN", "CONFIGURATION", "SCHEMA", "DNSDOMAIN", "DNSFOREST"]:
                    raise CommandError("Incorrect argument: %s" % c)
                contexts.append(c.upper())

        if verbose and quiet:
            raise CommandError("You cannot set --verbose and --quiet together")
        if (not base and base2) or (base and not base2):
            raise CommandError("You need to specify both --base and --base2 at the same time")

        con1 = LDAPBase(URL1, creds, lp,
                        two=two, quiet=quiet, descriptor=descriptor, sort_aces=sort_aces,
                        verbose=verbose, view=view, base=base, scope=scope,
                        outf=self.outf, errf=self.errf, skip_missing_dn=skip_missing_dn)
        assert len(con1.base_dn) > 0

        con2 = LDAPBase(URL2, creds2, lp,
                        two=two, quiet=quiet, descriptor=descriptor, sort_aces=sort_aces,
                        verbose=verbose, view=view, base=base2, scope=scope,
                        outf=self.outf, errf=self.errf, skip_missing_dn=skip_missing_dn)
        assert len(con2.base_dn) > 0

        filter_list = filter.split(",")

        status = 0
        for context in contexts:
            if not quiet:
                self.outf.write("\n* Comparing [%s] context...\n" % context)

            b1 = LDAPBundle(con1, context=context, filter_list=filter_list,
                            outf=self.outf, errf=self.errf)
            b2 = LDAPBundle(con2, context=context, filter_list=filter_list,
                            outf=self.outf, errf=self.errf)

            if b1.diff(b2):
                if not quiet:
                    self.outf.write("\n* Result for [%s]: SUCCESS\n" %
                                    context)
            else:
                if not quiet:
                    self.outf.write("\n* Result for [%s]: FAILURE\n" % context)
                    if not descriptor:
                        assert len(b1.summary["df_value_attrs"]) == len(b2.summary["df_value_attrs"])
                        b2.summary["df_value_attrs"] = []
                        self.outf.write("\nSUMMARY\n")
                        self.outf.write("---------\n")
                        b1.print_summary()
                        b2.print_summary()
                # mark exit status as FAILURE if a least one comparison failed
                status = -1
        if status != 0:
            raise CommandError("Compare failed: %d" % status)

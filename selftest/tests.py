#!/usr/bin/python
# This script generates a list of testsuites that should be run as part of
# the Samba test suite.

# The output of this script is parsed by selftest.pl, which then decides
# which of the tests to actually run. It will, for example, skip all tests
# listed in selftest/skip or only run a subset during "make quicktest".

# The idea is that this script outputs all of the tests of Samba, not
# just those that are known to pass, and list those that should be skipped
# or are known to fail in selftest/skip or selftest/knownfail. This makes it
# very easy to see what functionality is still missing in Samba and makes
# it possible to run the testsuite against other servers, such as
# Windows that have a different set of features.

# The syntax for a testsuite is "-- TEST --" on a single line, followed
# by the name of the test, the environment it needs and the command to run, all
# three separated by newlines. All other lines in the output are considered
# comments.

import os, tempfile
from selftesthelpers import bindir, srcdir, python
from selftesthelpers import planpythontestsuite, samba4srcdir
from selftesthelpers import plantestsuite, bbdir
from selftesthelpers import configuration, valgrindify
from selftesthelpers import skiptestsuite

try:
    config_h = os.environ["CONFIG_H"]
except KeyError:
    samba4bindir = bindir()
    config_h = os.path.join(samba4bindir, "default/include/config.h")

# check available features
config_hash = dict()
f = open(config_h, 'r')
try:
    lines = f.readlines()
    config_hash = dict((x[0], ' '.join(x[1:]))
                       for x in map(lambda line: line.strip().split(' ')[1:],
                                    list(filter(lambda line: (line[0:7] == '#define') and (len(line.split(' ')) > 2), lines))))
finally:
    f.close()

have_man_pages_support = ("XSLTPROC_MANPAGES" in config_hash)
with_pam = ("WITH_PAM" in config_hash)
with_elasticsearch_backend = ("HAVE_SPOTLIGHT_BACKEND_ES" in config_hash)
pam_wrapper_so_path = config_hash.get("LIBPAM_WRAPPER_SO_PATH")
pam_set_items_so_path = config_hash.get("PAM_SET_ITEMS_SO_PATH")
have_heimdal_support = "SAMBA4_USES_HEIMDAL" in config_hash
using_system_gssapi = "USING_SYSTEM_GSSAPI" in config_hash

planpythontestsuite("none", "samba.tests.source")
planpythontestsuite("none", "samba.tests.source_chars")

if have_man_pages_support:
    planpythontestsuite("none", "samba.tests.docs")

try:
    import testscenarios
except ImportError:
    skiptestsuite("subunit", "testscenarios not available")
else:
    planpythontestsuite("none", "subunit.tests.test_suite")
planpythontestsuite("none", "samba.tests.blackbox.ndrdump")
planpythontestsuite("none", "samba.tests.blackbox.check_output")
planpythontestsuite("none", "api", name="ldb.python", extra_path=['lib/ldb/tests/python'])
planpythontestsuite("none", "samba.tests.credentials")
planpythontestsuite("none", "samba.tests.registry")
planpythontestsuite("ad_dc_ntvfs:local", "samba.tests.auth")
planpythontestsuite("none", "samba.tests.get_opt")
planpythontestsuite("none", "samba.tests.cred_opt")
planpythontestsuite("none", "samba.tests.security")
planpythontestsuite("none", "samba.tests.dcerpc.misc")
planpythontestsuite("none", "samba.tests.dcerpc.integer")
planpythontestsuite("none", "samba.tests.param")
planpythontestsuite("none", "samba.tests.upgrade")
planpythontestsuite("none", "samba.tests.core")
planpythontestsuite("none", "samba.tests.common")
planpythontestsuite("none", "samba.tests.provision")
planpythontestsuite("none", "samba.tests.password_quality")
planpythontestsuite("none", "samba.tests.strings")
planpythontestsuite("none", "samba.tests.netcmd")
planpythontestsuite("none", "samba.tests.dcerpc.rpc_talloc")
planpythontestsuite("none", "samba.tests.dcerpc.array")
planpythontestsuite("none", "samba.tests.dcerpc.string_tests")
planpythontestsuite("none", "samba.tests.hostconfig")
planpythontestsuite("ad_dc_ntvfs:local", "samba.tests.messaging")
planpythontestsuite("none", "samba.tests.s3param")
planpythontestsuite("none", "samba.tests.s3passdb")
planpythontestsuite("none", "samba.tests.s3registry")
planpythontestsuite("none", "samba.tests.s3windb")
planpythontestsuite("none", "samba.tests.s3idmapdb")
planpythontestsuite("none", "samba.tests.samba3sam")
planpythontestsuite("none", "samba.tests.dsdb_api")
planpythontestsuite("none", "samba.tests.smbconf")
planpythontestsuite("none", "samba.tests.logfiles")
planpythontestsuite(
    "none", "wafsamba.tests.test_suite",
    extra_path=[os.path.join(samba4srcdir, "..", "buildtools"),
                os.path.join(samba4srcdir, "..", "third_party", "waf")])
planpythontestsuite("fileserver", "samba.tests.smbd_fuzztest")
planpythontestsuite("nt4_dc_smb1", "samba.tests.dcerpc.binding")
planpythontestsuite('ad_dc:local', "samba.tests.dcerpc.samr_change_password")
planpythontestsuite('ad_dc_fips:local',
                    "samba.tests.dcerpc.samr_change_password",
                    environ={'GNUTLS_FORCE_FIPS_MODE': '1',
                             'OPENSSL_FORCE_FIPS_MODE': '1'})


def cmdline(script, *args):
    """
    Prefix PYTHON env var and append --configurefile option to abs script path.

    script.sh arg1 arg2
    -->
    PYTHON=python /path/to/bbdir/script.sh arg1 arg2 \
    --configurefile $SMB_CONF_FILE
    """
    return [
        "PYTHON=%s" % python,
        os.path.join(bbdir, script),
    ] + list(args) + [configuration]


plantestsuite(
    "samba4.blackbox.demote-saveddb", "none",
    cmdline('demote-saveddb.sh', '$PREFIX_ABS/demote'))

plantestsuite(
    "samba4.blackbox.dbcheck.alpha13", "none",
    cmdline('dbcheck-oldrelease.sh', '$PREFIX_ABS/provision',
            'alpha13'))

# same test as above but skip member link checks
plantestsuite(
    "samba4.blackbox.dbcheck.alpha13.quick", "none",
    cmdline('dbcheck-oldrelease.sh', '$PREFIX_ABS/provision',
            'alpha13', '--quick-membership-checks'))

plantestsuite(
    "samba4.blackbox.dbcheck.release-4-0-0", "none",
    cmdline('dbcheck-oldrelease.sh', '$PREFIX_ABS/provision',
            'release-4-0-0'))

# same test as above but skip member link checks
plantestsuite(
    "samba4.blackbox.dbcheck.release-4-0-0.quick", "none",
    cmdline('dbcheck-oldrelease.sh', '$PREFIX_ABS/provision',
            'release-4-0-0', '--quick-membership-checks'))

plantestsuite(
    "samba4.blackbox.dbcheck.release-4-1-0rc3", "none",
    cmdline('dbcheck-oldrelease.sh', '$PREFIX_ABS/provision',
            'release-4-1-0rc3'))

# same test as above but skip member link checks
plantestsuite(
    "samba4.blackbox.dbcheck.release-4-1-0rc3.quick", "none",
    cmdline('dbcheck-oldrelease.sh', '$PREFIX_ABS/provision',
            'release-4-1-0rc3', '--quick-membership-checks'))

plantestsuite(
    "samba4.blackbox.dbcheck.release-4-1-6-partial-object", "none",
    cmdline('dbcheck-oldrelease.sh', '$PREFIX_ABS/provision',
            'release-4-1-6-partial-object'))

# same test as above but skip member link checks
plantestsuite(
    "samba4.blackbox.dbcheck.release-4-1-6-partial-object.quick", "none",
    cmdline('dbcheck-oldrelease.sh', '$PREFIX_ABS/provision',
            'release-4-1-6-partial-object', '--quick-membership-checks'))

plantestsuite(
    "samba4.blackbox.dbcheck.release-4-5-0-pre1", "none",
    cmdline('dbcheck-oldrelease.sh', '$PREFIX_ABS/provision',
            'release-4-5-0-pre1'))

# same test as above but skip member link checks
plantestsuite(
    "samba4.blackbox.dbcheck.release-4-5-0-pre1.quick", "none",
    cmdline('dbcheck-oldrelease.sh', '$PREFIX_ABS/provision',
            'release-4-5-0-pre1', '--quick-membership-checks'))

plantestsuite(
    "samba4.blackbox.upgradeprovision.alpha13", "none",
    cmdline('upgradeprovision-oldrelease.sh', '$PREFIX_ABS/provision',
            'alpha13'))

plantestsuite(
    "samba4.blackbox.upgradeprovision.release-4-0-0", "none",
    cmdline('upgradeprovision-oldrelease.sh', '$PREFIX_ABS/provision',
            'release-4-0-0'))

plantestsuite(
    "samba4.blackbox.tombstones-expunge.release-4-5-0-pre1", "none",
    cmdline('tombstones-expunge.sh', '$PREFIX_ABS/provision',
            'release-4-5-0-pre1'))

plantestsuite(
    "samba4.blackbox.dbcheck-links.release-4-5-0-pre1", "none",
    cmdline('dbcheck-links.sh', '$PREFIX_ABS/provision',
            'release-4-5-0-pre1'))

plantestsuite(
    "samba4.blackbox.runtime-links.release-4-5-0-pre1", "none",
    cmdline('runtime-links.sh', '$PREFIX_ABS/provision',
            'release-4-5-0-pre1'))

plantestsuite(
    "samba4.blackbox.schemaupgrade", "none",
    cmdline('schemaupgrade.sh', '$PREFIX_ABS/provision'))

plantestsuite(
    "samba4.blackbox.functionalprep", "none",
    cmdline('functionalprep.sh', '$PREFIX_ABS/provision'))

plantestsuite(
    "samba4.blackbox.test_special_group", "none",
    cmdline('test_special_group.sh', '$PREFIX_ABS/provision'))

planpythontestsuite("none", "samba.tests.upgradeprovision")
planpythontestsuite("none", "samba.tests.xattr")
planpythontestsuite("none", "samba.tests.ntacls")
planpythontestsuite("none", "samba.tests.policy")
planpythontestsuite("none", "samba.tests.kcc.graph")
planpythontestsuite("none", "samba.tests.kcc.graph_utils")
planpythontestsuite("none", "samba.tests.kcc.ldif_import_export")
planpythontestsuite("none", "samba.tests.graph")
plantestsuite("wafsamba.duplicate_symbols", "none", [os.path.join(srcdir(), "buildtools/wafsamba/test_duplicate_symbol.sh")])
planpythontestsuite("none", "samba.tests.glue")
planpythontestsuite("none", "samba.tests.tdb_util")
planpythontestsuite("none", "samba.tests.samdb")
planpythontestsuite("none", "samba.tests.samdb_api")
planpythontestsuite("none", "samba.tests.ndr")

if with_pam:
    env = "ad_member"
    options = [
        {
            "description": "krb5",
            "pam_options": "krb5_auth krb5_ccache_type=FILE:%s/krb5cc_pam_test_%%u" % (tempfile.gettempdir()),
        },
        {
            "description": "default",
            "pam_options": "",
        },
    ]
    for o in options:
        description = o["description"]
        pam_options = "'%s'" % o["pam_options"]

        plantestsuite("samba.tests.pam_winbind(local+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "$SERVER", "$USERNAME", "$PASSWORD",
                       pam_options])
        plantestsuite("samba.tests.pam_winbind(domain1+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "$DOMAIN", "$DC_USERNAME", "$DC_PASSWORD",
                       pam_options])
        plantestsuite("samba.tests.pam_winbind(domain2+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "$REALM", "$DC_USERNAME", "$DC_PASSWORD",
                       pam_options])
        plantestsuite("samba.tests.pam_winbind(domain3+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "''", "${DC_USERNAME}@${DOMAIN}", "$DC_PASSWORD",
                       pam_options])
        plantestsuite("samba.tests.pam_winbind(domain4+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "''", "${DC_USERNAME}@${REALM}", "$DC_PASSWORD",
                       pam_options])
        plantestsuite("samba.tests.pam_winbind(domain5+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "$REALM", "${DC_USERNAME}@${DOMAIN}", "$DC_PASSWORD",
                       pam_options])
        plantestsuite("samba.tests.pam_winbind(domain6+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "$DOMAIN", "${DC_USERNAME}@${REALM}", "$DC_PASSWORD",
                       pam_options])
        plantestsuite("samba.tests.pam_winbind(trust_f_both1+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "$TRUST_F_BOTH_DOMAIN",
                       "$TRUST_F_BOTH_USERNAME",
                       "$TRUST_F_BOTH_PASSWORD",
                       pam_options])
        plantestsuite("samba.tests.pam_winbind(trust_f_both2+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "$TRUST_F_BOTH_REALM",
                       "$TRUST_F_BOTH_USERNAME",
                       "$TRUST_F_BOTH_PASSWORD",
                       pam_options])
        plantestsuite("samba.tests.pam_winbind(trust_f_both3+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "''",
                       "${TRUST_F_BOTH_USERNAME}@${TRUST_F_BOTH_DOMAIN}",
                       "$TRUST_F_BOTH_PASSWORD",
                       pam_options])
        plantestsuite("samba.tests.pam_winbind(trust_f_both4+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "''",
                       "${TRUST_F_BOTH_USERNAME}@${TRUST_F_BOTH_REALM}",
                       "$TRUST_F_BOTH_PASSWORD",
                       pam_options])
        plantestsuite("samba.tests.pam_winbind(trust_f_both5+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "${TRUST_F_BOTH_REALM}",
                       "${TRUST_F_BOTH_USERNAME}@${TRUST_F_BOTH_DOMAIN}",
                       "$TRUST_F_BOTH_PASSWORD",
                       pam_options])
        plantestsuite("samba.tests.pam_winbind(trust_f_both6+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "${TRUST_F_BOTH_DOMAIN}",
                       "${TRUST_F_BOTH_USERNAME}@${TRUST_F_BOTH_REALM}",
                       "$TRUST_F_BOTH_PASSWORD",
                       pam_options])
        plantestsuite("samba.tests.pam_winbind(trust_e_both1+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "$TRUST_E_BOTH_DOMAIN",
                       "$TRUST_E_BOTH_USERNAME",
                       "$TRUST_E_BOTH_PASSWORD",
                       pam_options])
        plantestsuite("samba.tests.pam_winbind(trust_e_both2+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "$TRUST_E_BOTH_REALM",
                       "$TRUST_E_BOTH_USERNAME",
                       "$TRUST_E_BOTH_PASSWORD",
                       pam_options])
        plantestsuite("samba.tests.pam_winbind(trust_e_both3+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "''",
                       "${TRUST_E_BOTH_USERNAME}@${TRUST_E_BOTH_DOMAIN}",
                       "$TRUST_E_BOTH_PASSWORD",
                       pam_options])
        plantestsuite("samba.tests.pam_winbind(trust_e_both4+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "''",
                       "${TRUST_E_BOTH_USERNAME}@${TRUST_E_BOTH_REALM}",
                       "$TRUST_E_BOTH_PASSWORD",
                       pam_options])
        plantestsuite("samba.tests.pam_winbind(trust_e_both5+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "${TRUST_E_BOTH_REALM}",
                       "${TRUST_E_BOTH_USERNAME}@${TRUST_E_BOTH_DOMAIN}",
                       "$TRUST_E_BOTH_PASSWORD",
                       pam_options])
        plantestsuite("samba.tests.pam_winbind(trust_e_both6+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "${TRUST_E_BOTH_DOMAIN}",
                       "${TRUST_E_BOTH_USERNAME}@${TRUST_E_BOTH_REALM}",
                       "$TRUST_E_BOTH_PASSWORD",
                       pam_options])

        for authtok_options in ["", "use_authtok", "try_authtok"]:
            _pam_options = "'%s %s'" % (o["pam_options"], authtok_options)
            _description = "%s %s" % (description, authtok_options)
            plantestsuite("samba.tests.pam_winbind_chauthtok(domain+%s)" % _description, env,
                          [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind_chauthtok.sh"),
                           valgrindify(python), pam_wrapper_so_path, pam_set_items_so_path,
                           "$DOMAIN", "TestPamOptionsUser", "oldp@ssword0", "newp@ssword0",
                           _pam_options, 'yes',
                           "$DC_SERVER", "$DC_USERNAME", "$DC_PASSWORD"])

        plantestsuite("samba.tests.pam_winbind_warn_pwd_expire(domain+%s)" % description, env,
                      [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind_warn_pwd_expire.sh"),
                       valgrindify(python), pam_wrapper_so_path,
                       "$DOMAIN", "alice", "Secret007",
                       pam_options])

    description = "krb5"
    pam_options = "'krb5_auth krb5_ccache_type=FILE:%s/krb5cc_pam_test_setcred_%%u'" % (tempfile.gettempdir())
    plantestsuite("samba.tests.pam_winbind_setcred(domain+%s)" % description, "ad_dc:local",
                  [os.path.join(srcdir(), "python/samba/tests/test_pam_winbind_setcred.sh"),
                   valgrindify(python), pam_wrapper_so_path,
                   "${DOMAIN}", "${DC_USERNAME}", "${DC_PASSWORD}",
                   pam_options])


plantestsuite("samba.unittests.krb5samba", "none",
              [os.path.join(bindir(), "default/testsuite/unittests/test_krb5samba")])
plantestsuite("samba.unittests.lib_util_modules", "none",
              [os.path.join(bindir(), "default/testsuite/unittests/test_lib_util_modules")])
plantestsuite("samba.unittests.background_send",
              "none",
              [os.path.join(
                  bindir(),
                  "default/testsuite/unittests/test_background_send"),
               "$SMB_CONF_PATH"])

plantestsuite("samba.unittests.smb1cli_session", "none",
              [os.path.join(bindir(), "default/libcli/smb/test_smb1cli_session")])
plantestsuite("samba.unittests.smb_util_translate", "none",
              [os.path.join(bindir(), "default/libcli/smb/test_util_translate")])

plantestsuite("samba.unittests.talloc_keep_secret", "none",
              [os.path.join(bindir(), "default/lib/util/test_talloc_keep_secret")])

plantestsuite("samba.unittests.tldap", "none",
              [os.path.join(bindir(), "default/source3/test_tldap")])
plantestsuite("samba.unittests.rfc1738", "none",
              [os.path.join(bindir(), "default/lib/util/test_rfc1738")])
plantestsuite("samba.unittests.kerberos", "none",
              [os.path.join(bindir(), "test_kerberos")])
plantestsuite("samba.unittests.ms_fnmatch", "none",
              [os.path.join(bindir(), "default/lib/util/test_ms_fnmatch")])
plantestsuite("samba.unittests.byteorder", "none",
              [os.path.join(bindir(), "default/lib/util/test_byteorder")])
plantestsuite("samba.unittests.bytearray", "none",
              [os.path.join(bindir(), "default/lib/util/test_bytearray")])
plantestsuite("samba.unittests.byteorder_verify", "none",
              [os.path.join(bindir(), "default/lib/util/test_byteorder_verify")])
plantestsuite("samba.unittests.util_paths", "none",
              [os.path.join(bindir(), "default/lib/util/test_util_paths")])
plantestsuite("samba.unittests.util", "none",
              [os.path.join(bindir(), "default/lib/util/test_util")])
plantestsuite("samba.unittests.memcache", "none",
              [os.path.join(bindir(), "default/lib/util/test_memcache")])
plantestsuite("samba.unittests.sys_rw", "none",
              [os.path.join(bindir(), "default/lib/util/test_sys_rw")])
plantestsuite("samba.unittests.ntlm_check", "none",
              [os.path.join(bindir(), "default/libcli/auth/test_ntlm_check")])
plantestsuite("samba.unittests.gnutls", "none",
              [os.path.join(bindir(), "default/libcli/auth/test_gnutls")])
plantestsuite("samba.unittests.rc4_passwd_buffer", "none",
              [os.path.join(bindir(), "default/libcli/auth/test_rc4_passwd_buffer")])
plantestsuite("samba.unittests.schannel", "none",
              [os.path.join(bindir(), "default/libcli/auth/test_schannel")])
plantestsuite("samba.unittests.test_registry_regfio", "none",
              [os.path.join(bindir(), "default/source3/test_registry_regfio")])
plantestsuite("samba.unittests.test_oLschema2ldif", "none",
              [os.path.join(bindir(), "default/source4/utils/oLschema2ldif/test_oLschema2ldif")])
plantestsuite("samba.unittests.auth.sam", "none",
              [os.path.join(bindir(), "test_auth_sam")])
if have_heimdal_support and not using_system_gssapi:
    plantestsuite("samba.unittests.auth.heimdal_gensec_unwrap_des", "none",
                  [valgrindify(os.path.join(bindir(), "test_heimdal_gensec_unwrap_des"))])
if with_elasticsearch_backend:
    plantestsuite("samba.unittests.mdsparser_es", "none",
                  [os.path.join(bindir(), "default/source3/test_mdsparser_es")] + [configuration])
    plantestsuite("samba.unittests.mdsparser_es_failures", "none",
                  [os.path.join(bindir(), "default/source3/test_mdsparser_es"),
                  " --option=elasticsearch:testmappingfailures=yes",
                  " --option=elasticsearch:ignoreunknownattribute=yes",
                  " --option=elasticsearch:ignoreunknowntype=yes"] +
                  [configuration])
plantestsuite("samba.unittests.credentials", "none",
              [os.path.join(bindir(), "default/auth/credentials/test_creds")])
plantestsuite("samba.unittests.tsocket_bsd_addr", "none",
              [os.path.join(bindir(), "default/lib/tsocket/test_tsocket_bsd_addr")])
plantestsuite("samba.unittests.tsocket_tstream", "none",
              [os.path.join(bindir(), "default/lib/tsocket/test_tstream")],
              environ={'SOCKET_WRAPPER_DIR': ''})
plantestsuite("samba.unittests.adouble", "none",
              [os.path.join(bindir(), "test_adouble")])
plantestsuite("samba.unittests.gnutls_aead_aes_256_cbc_hmac_sha512", "none",
              [os.path.join(bindir(), "test_gnutls_aead_aes_256_cbc_hmac_sha512")])
plantestsuite("samba.unittests.encode_decode", "none",
              [os.path.join(bindir(), "test_encode_decode")])

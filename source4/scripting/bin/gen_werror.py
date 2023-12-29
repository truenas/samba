#!/usr/bin/env python3

#
# Unix SMB/CIFS implementation.
#
# WERROR error definition generation
#
# Copyright (C) Catalyst.Net Ltd. 2017
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

import sys, os.path, io, string
from gen_error_common import parseErrorDescriptions, ErrorDef

def generateHeaderFile(out_file, errors):
    out_file.write("/*\n")
    out_file.write(" * Descriptions for errors generated from\n")
    out_file.write(" * [MS-ERREF] https://msdn.microsoft.com/en-us/library/cc231199.aspx\n")
    out_file.write(" */\n\n")
    out_file.write("#ifndef _WERR_GEN_H\n")
    out_file.write("#define _WERR_GEN_H\n")
    for err in errors:
        line = "#define %s W_ERROR(%s)\n" % (err.err_define, hex(err.err_code))
        out_file.write(line)
    out_file.write("\n#endif /* _WERR_GEN_H */\n")

def generateSourceFile(out_file, errors):
    out_file.write("/*\n")
    out_file.write(" * Names for errors generated from\n")
    out_file.write(" * [MS-ERREF] https://msdn.microsoft.com/en-us/library/cc231199.aspx\n")
    out_file.write(" */\n")

    for err in errors:
        if (err.err_define == 'WERR_NERR_SUCCESS'):
            continue
        out_file.write(f'\t case {hex(err.err_code)}:\n')
        out_file.write(f'\t\treturn \"{err.err_define}\";\n')
        out_file.write(f'\t\tbreak;\n')

def generateFriendlySourceFile(out_file, errors):
    out_file.write("/*\n")
    out_file.write(" * Names for errors generated from\n")
    out_file.write(" * [MS-ERREF] https://msdn.microsoft.com/en-us/library/cc231199.aspx\n")
    out_file.write(" */\n")

    for err in errors:
        if (err.err_define == 'WERR_NERR_SUCCESS'):
            continue
        out_file.write(f'\tcase {hex(err.err_code)}:\n')
        out_file.write(f'\t\treturn \"{err.err_string}\";\n')
        out_file.write('\t\tbreak;\n')

def generatePythonFile(out_file, errors):
    out_file.write("/*\n")
    out_file.write(" * Errors generated from\n")
    out_file.write(" * [MS-ERREF] https://msdn.microsoft.com/en-us/library/cc231199.aspx\n")
    out_file.write(" */\n")
    out_file.write("#include \"lib/replace/system/python.h\"\n")
    out_file.write("#include \"python/py3compat.h\"\n")
    out_file.write("#include \"includes.h\"\n\n")
    # This is needed to avoid a missing prototype error from the C
    # compiler. There is never a prototype for this function, it is a
    # module loaded by python with dlopen() and found with dlsym().
    out_file.write("static struct PyModuleDef moduledef = {\n")
    out_file.write("\tPyModuleDef_HEAD_INIT,\n")
    out_file.write("\t.m_name = \"werror\",\n")
    out_file.write("\t.m_doc = \"WERROR defines\",\n")
    out_file.write("\t.m_size = -1,\n")
    out_file.write("};\n\n")
    out_file.write("MODULE_INIT_FUNC(werror)\n")
    out_file.write("{\n")
    out_file.write("\tPyObject *m;\n\n")
    out_file.write("\tm = PyModule_Create(&moduledef);\n")
    out_file.write("\tif (m == NULL)\n")
    out_file.write("\t\treturn NULL;\n\n")
    for err in errors:
        line = """\tPyModule_AddObject(m, \"%s\",
                  \t\tPyLong_FromUnsignedLongLong(W_ERROR_V(%s)));\n""" % (err.err_define, err.err_define)
        out_file.write(line)
    out_file.write("\n")
    out_file.write("\treturn m;\n")
    out_file.write("}\n")

def transformErrorName( error_name ):
    if error_name.startswith("WERR_"):
        error_name = error_name.replace("WERR_", "", 1)
    elif error_name.startswith("ERROR_"):
        error_name = error_name.replace("ERROR_", "", 1)
    return "WERR_" + error_name.upper()

# Script to generate files werror_gen.h, doserr_gen.c and
# py_werror.c.
#
# These files contain generated definitions for WERRs and
# their descriptions/names.
#
# This script takes four inputs:
# [1]: The name of the text file which is the content of an HTML table
#      (e.g. the one found at https://msdn.microsoft.com/en-us/library/cc231199.aspx)
#      copied and pasted.
# [2]: [[output werror_gen.h]]
# [3]: [[output doserr_gen.c]]
# [4]: [[output py_werror.c]]
def main():
    if len(sys.argv) == 6:
        input_file_name = sys.argv[1]
        gen_headerfile_name = sys.argv[2]
        gen_sourcefile_name = sys.argv[3]
        gen_friendlysource_name = sys.argv[4]
        gen_pythonfile_name = sys.argv[5]
    else:
        print("usage: %s winerrorfile headerfile sourcefile pythonfile" % sys.argv[0])
        sys.exit()

    input_file = io.open(input_file_name, "rt", encoding='utf8')
    errors = parseErrorDescriptions(input_file, True, transformErrorName)
    input_file.close()

    print("writing new header file: %s" % gen_headerfile_name)
    out_file = io.open(gen_headerfile_name, "wt", encoding='utf8')
    generateHeaderFile(out_file, errors)
    out_file.close()
    print("writing new source file: %s" % gen_sourcefile_name)
    out_file = io.open(gen_sourcefile_name, "wt", encoding='utf8')
    generateSourceFile(out_file, errors)
    out_file.close()
    print("writing new source file: %s" % gen_friendlysource_name)
    out_file = io.open(gen_friendlysource_name, "wt", encoding='utf8')
    generateFriendlySourceFile(out_file, errors)
    out_file.close()
    print("writing new python file: %s" % gen_pythonfile_name)
    out_file = io.open(gen_pythonfile_name, "wt", encoding='utf8')
    generatePythonFile(out_file, errors)
    out_file.close()

if __name__ == '__main__':

    main()

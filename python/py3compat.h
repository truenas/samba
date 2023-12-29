/*
   Unix SMB/CIFS implementation.
   Python 3 compatibility macros
   Copyright (C) Petr Viktorin <pviktori@redhat.com> 2015

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

#ifndef _SAMBA_PY3COMPAT_H_
#define _SAMBA_PY3COMPAT_H_
#include "lib/replace/system/python.h"

/* Quick docs:
 * Syntax for module initialization is as in Python 3, except the entrypoint
 * function definition and declaration:
 *     PyMODINIT_FUNC PyInit_modulename(void);
 *     PyMODINIT_FUNC PyInit_modulename(void)
 *     {
 *         ...
 *     }
 * is replaced by:
 *     MODULE_INIT_FUNC(modulename)
 *     {
 *         ...
 *     }
 *
 * In the entrypoint, create a module using PyModule_Create and PyModuleDef,
 * and return it. See Python 3 documentation for details.
 */

#define MODULE_INIT_FUNC(name) \
    PyMODINIT_FUNC PyInit_ ## name(void); \
    PyMODINIT_FUNC PyInit_ ## name(void)

/* PyArg_ParseTuple/Py_BuildValue argument */

#define PYARG_BYTES_LEN "y#"
#define PYARG_STR_UNI "es"

#endif

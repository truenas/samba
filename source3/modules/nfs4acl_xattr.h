/*
 * Copyright (C) Ralph Boehme 2017
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef __NFS4ACL_XATTR_H__
#define __NFS4ACL_XATTR_H__

#define NFS4ACL_XDR_MAX_ACES 8192

enum nfs4acl_encoding {
	NFS4ACL_ENCODING_NDR,
	NFS4ACL_ENCODING_XDR,
	NFS4ACL_ENCODING_NFS
};

struct nfs4acl_config {
	unsigned nfs_version;
	enum nfs4acl_encoding encoding;
	char *xattr_name;
	struct smbacl4_vfs_params nfs4_params;
	enum default_acl_style default_acl_style;
	bool nfs4_id_numeric;
	bool validate_mode;
	bool map_modify;
};

#endif /* __NFS4ACL_XATTR_H__ */

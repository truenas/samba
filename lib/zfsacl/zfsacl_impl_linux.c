
#include <arpa/inet.h>
#include <sys/xattr.h>
#include <assert.h>
#include "replace.h"
#include "zfsacl.h"
#define ACL4_MAX_ENTRIES 64
#define ACL4_XATTR "system.nfs4_acl_xdr"
#define ACL4_METADATA (sizeof(uint) * 2)

/* Non-ACL metadata */
#define ACL_GET_SZ(aclp) ((size_t) * (aclp))

/* NFSv4 ACL metadata */
#define ACL4_GET_FL(aclp) (aclp)
#define ACL4_GET_CNT(aclp) (ACL4_GET_FL(aclp) + 1)

/* NFSv4 ACL ENTRY */
#define ACE4_SZ (sizeof(uint) * 5)
#define ACL4_METADATA (sizeof(uint) * 2)
#define ACL4SZ_FROM_ACECNT(cnt) (ACL4_METADATA + (cnt * ACE4_SZ))
#define ACL4_GETENTRY(aclp, idx) ((char *)aclp + ACL4SZ_FROM_ACECNT(idx))
#define ACLBUF_TO_ACES(aclp) (

struct zfsacl {
	size_t aclbuf_size;
	zfsacl_brand_t brand;
	uint *aclbuf;
};

struct zfsace4 { uint netlong[5]; };
#define ACL4BUF_TO_ACES(aclp) ((struct zfsace4 *)(aclp + 2))

static bool acl_check_brand(zfsacl_t _acl, zfsacl_brand_t expected)
{
	if (_acl->brand != expected) {
#if devel
		smb_panic("Incorrect ACL brand");
#endif
		errno = ENOSYS;
		return false;
	}
	return true;
}

zfsacl_t zfsacl_init(int _acecnt, zfsacl_brand_t _brand)
{
	size_t naclsz;
	zfsacl_t out = NULL;
	if (_brand != ZFSACL_BRAND_NFSV4) {
		errno = EINVAL;
		return NULL;
	}

	out = calloc(1, sizeof(struct zfsacl));
	if (out == NULL) {
		return NULL;
	}

	naclsz = ACL4SZ_FROM_ACECNT(_acecnt);
	out->aclbuf = calloc(naclsz, sizeof(char));
	if (out->aclbuf == NULL) {
		free(out);
		return NULL;
	}
	out->brand = _brand;
	out->aclbuf_size = naclsz;
	return out;
}

void zfsacl_free(zfsacl_t *_pacl)
{
	zfsacl_t to_free = *_pacl;
	free(to_free->aclbuf);
	free(to_free);
	*_pacl = NULL;
}

bool zfsacl_get_brand(zfsacl_t _acl, zfsacl_brand_t *_brandp)
{
	*_brandp = _acl->brand;
	return true;
}

bool zfsacl_get_aclflags(zfsacl_t _acl, zfsacl_aclflags_t *_paclflags)
{
	zfsacl_aclflags_t flags;

	if (!acl_check_brand(_acl, ZFSACL_BRAND_NFSV4)) {
		return false;
	}

	flags = ntohl(*ACL4_GET_FL(_acl->aclbuf));
	*_paclflags = flags;
	return true;
}

bool zfsacl_set_aclflags(zfsacl_t _acl, zfsacl_aclflags_t _aclflags)
{
	zfsacl_aclflags_t *flags;

	if (!acl_check_brand(_acl, ZFSACL_BRAND_NFSV4)) {
		return false;
	}

	if (ZFSACL_FLAGS_INVALID(_aclflags)) {
#if devel
		smb_panic("Invalid aclflags");
#endif
		errno = EINVAL;
		return false;
	}

	flags = ACL4_GET_FL(_acl->aclbuf);
	*flags = htonl(_aclflags);

	return true;
}

bool zfsacl_get_acecnt(zfsacl_t _acl, uint *pcnt)
{
	uint acecnt;
	if (!acl_check_brand(_acl, ZFSACL_BRAND_NFSV4)) {
		return false;
	}

	acecnt = ntohl(*ACL4_GET_CNT(_acl->aclbuf));
	*pcnt = acecnt;
	return true;
}


static bool validate_entry_idx(zfsacl_t _acl, int _idx)
{
	uint acecnt;
	bool ok;

	ok = zfsacl_get_acecnt(_acl, &acecnt);
	if (!ok) {
		return false;
	}

	if ((_idx + 1) > acecnt) {
		errno = E2BIG;
		return false;
	}

	return true;
}

/* out will be set to new required size if realloc required */
static bool acl_get_new_size(zfsacl_t _acl, uint new_count, size_t *out)
{
	size_t current_sz, required_sz;

	if (new_count > ACL4_MAX_ENTRIES) {
		errno = E2BIG;
		return false;
	}
	current_sz = _acl->aclbuf_size;
	required_sz = ACL4SZ_FROM_ACECNT(new_count);

	if (current_sz >= required_sz) {
		*out = 0;
	} else {
		*out = required_sz;
	}

	return true;
}

bool zfsacl_create_aclentry(zfsacl_t _acl, int _idx, zfsacl_entry_t *_pentry)
{
	uint acecnt;
	uint *pacecnt;
	zfsacl_entry_t entry;
	size_t new_size, new_offset, acl_size;
	bool ok;
	struct zfsace4 *z = ACL4BUF_TO_ACES(_acl->aclbuf);

	ok = zfsacl_get_acecnt(_acl, &acecnt);
	if (!ok) {
		return false;
	}

	if ((_idx != ZFSACL_APPEND_ENTRY) && (_idx + 1 > acecnt)) {
		errno = ERANGE;
		return false;
	}

	ok = acl_get_new_size(_acl, acecnt + 1, &new_size);
	if (!ok) {
		return false;
	}

	acl_size = _acl->aclbuf_size;

	if (new_size != 0) {
		size_t *paclsize = NULL;
		zfsacl_t _tmp = realloc(_acl->aclbuf, new_size);
		if (_tmp == NULL) {
			errno = ENOMEM;
			return false;
		}
		_acl->aclbuf_size = new_size;
		assert(new_size == (acl_size + ACE4_SZ));
		memset(_acl->aclbuf + (new_size - ACE4_SZ), 0, ACE4_SZ);
	}

	if (_idx == ZFSACL_APPEND_ENTRY) {
		*_pentry = &z[acecnt];
		goto done;
	}

	new_offset = ACL4SZ_FROM_ACECNT(_idx);

	/*
	 * shift back one ace from offset
	 * to make room for new entry
	 */
	entry = &z[_idx];
	memmove(entry + 1, entry, acl_size - new_offset - ACE4_SZ);

	/* zero-out new ACE */
	memset(entry, 0, ACE4_SZ);
	*_pentry = entry;

done:
	pacecnt = ACL4_GET_CNT(_acl->aclbuf);
	*pacecnt = htonl(acecnt + 1);
	return true;
}

#if devel
void dump_entry(struct zfsace4 *z)
{
	fprintf(stderr,
		"0x%08X  %p "
		"0x%08X  %p "
		"0x%08X  %p "
		"0x%08X  %p "
		"0x%08X  %p \n",
		z->netlong[0],
		&z->netlong[0],
		z->netlong[1],
		&z->netlong[1],
		z->netlong[2],
		&z->netlong[2],
		z->netlong[3],
		&z->netlong[3],
		z->netlong[4],
		&z->netlong[4]);
}
#endif

bool zfsacl_get_aclentry(zfsacl_t _acl, int _idx, zfsacl_entry_t *_pentry)
{
	zfsacl_entry_t entry;

	if (!validate_entry_idx(_acl, _idx)) {
		return false;
	}

	entry = ACL4_GETENTRY(_acl->aclbuf, _idx);
	*_pentry = entry;
#if devel
	dump_entry(entry);
#endif
	return true;
}

bool zfsacl_delete_aclentry(zfsacl_t _acl, int _idx)
{
	uint acecnt;
	uint *aclacecnt = NULL;
	bool ok;
	struct zfsace4 *z = ACL4BUF_TO_ACES(_acl->aclbuf);
	size_t orig_sz, after_offset;

	if (!validate_entry_idx(_acl, _idx)) {
		return false;
	}

	ok = zfsacl_get_acecnt(_acl, &acecnt);
	if (!ok) {
		return false;
	}

        if (acecnt == 1) {
		/* ACL without entries is not permitted */
		errno = ERANGE;
		return false;
	}

	if (_idx + 1 == acecnt) {
		memset(&z[_idx], 0, ACE4_SZ);
	} else {
		orig_sz = _acl->aclbuf_size;
		after_offset = orig_sz - ACL4SZ_FROM_ACECNT(_idx) - ACE4_SZ;
		memmove(&z[_idx], &z[_idx + 1], after_offset);
	}

	aclacecnt = ACL4_GET_CNT(_acl->aclbuf);
	*aclacecnt = htonl(acecnt -1);
	return true;
}

#define ZFSACE_TYPE_OFFSET	0
#define ZFSACE_FLAGSET_OFFSET	1
#define ZFSACE_WHOTYPE_OFFSET	2
#define ZFSACE_PERMSET_OFFSET	3
#define ZFSACE_WHOID_OFFSET	4
#define ZFSACE_SPECIAL_ID	0x00000001
#define HAS_SPECIAL_ID(who) ((who == ZFSACE_SPECIAL_ID) ? true : false)

bool zfsace_get_permset(zfsacl_entry_t _entry, zfsace_permset_t *_pperm)
{
	uint *entry = (uint *)_entry;
	zfsace_permset_t perm;

	perm = ntohl(*(entry + ZFSACE_PERMSET_OFFSET));
	*_pperm = perm;
	return true;
}

bool zfsace_get_flagset(zfsacl_entry_t _entry, zfsace_flagset_t *_pflags)
{
	uint *entry = (uint *)_entry;
	zfsace_flagset_t flags;

	flags = ntohl(*(entry + ZFSACE_FLAGSET_OFFSET));
	*_pflags = flags;
	return true;
}

bool zfsace_get_who(zfsacl_entry_t _entry, zfsace_who_t *pwho, zfsace_id_t *_paeid)
{
	struct zfsace4 *entry = (struct zfsace4 *)_entry;
	zfsace_who_t whotype;
	zfsace_id_t whoid;
	zfsace_flagset_t flags;
	bool is_special;

	is_special = HAS_SPECIAL_ID(ntohl(entry->netlong[ZFSACE_WHOTYPE_OFFSET]));

	if (is_special) {
		whotype =  ntohl(entry->netlong[ZFSACE_WHOID_OFFSET]);
		whoid = ZFSACL_UNDEFINED_ID;
	} else {
		flags = ntohl(entry->netlong[ZFSACE_FLAGSET_OFFSET]);
		if (ZFSACE_IS_GROUP(flags)) {
			whotype = ZFSACL_GROUP;
		} else {
			whotype = ZFSACL_USER;
		}
		whoid =  ntohl(entry->netlong[ZFSACE_WHOID_OFFSET]);
	}

	*pwho = whotype;
	*_paeid = whoid;
	return true;
}

bool zfsace_get_entry_type(zfsacl_entry_t _entry, zfsace_entry_type_t *_tp)
{
	uint *entry = (uint *)_entry;
	zfsace_entry_type_t entry_type;

	entry_type = ntohl(*(entry + ZFSACE_TYPE_OFFSET));
	*_tp = entry_type;
	return true;
}

bool zfsace_set_permset(zfsacl_entry_t _entry, zfsace_permset_t _perm)
{
	uint *pperm = (uint *)_entry + ZFSACE_PERMSET_OFFSET;

	if (ZFSACE_ACCESS_MASK_INVALID(_perm)) {
		errno = EINVAL;
		return false;
	}

	*pperm = htonl(_perm);
	return true;
}

bool zfsace_set_flagset(zfsacl_entry_t _entry, zfsace_flagset_t _flags) {
	uint *pflags = (uint *)_entry + ZFSACE_FLAGSET_OFFSET;

	if (ZFSACE_FLAG_INVALID(_flags)) {
		errno = EINVAL;
		return false;
	}

	*pflags = htonl(_flags);
	return true;
}

bool zfsace_set_who(zfsacl_entry_t _entry, zfsace_who_t _whotype, zfsace_id_t _whoid)
{
	struct zfsace4 *entry = (struct zfsace4 *)_entry;
	uint *pspecial = &entry->netlong[ZFSACE_WHOTYPE_OFFSET];
	uint *pwhoid = &entry->netlong[ZFSACE_WHOID_OFFSET];
	uint special_flag, whoid;
	zfsace_flagset_t flags;

	flags = ntohl(entry->netlong[ZFSACE_FLAGSET_OFFSET]);

	switch (_whotype) {
	case ZFSACL_USER_OBJ:
	case ZFSACL_EVERYONE:
		whoid = _whotype;
		special_flag = ZFSACE_SPECIAL_ID;
		if (ZFSACE_IS_GROUP(flags)) {
			zfsace_set_flagset(_entry, flags & ~ZFSACE_IDENTIFIER_GROUP);
		}
		break;
	case ZFSACL_GROUP_OBJ:
		whoid = _whotype;
		special_flag = ZFSACE_SPECIAL_ID;
		if (!ZFSACE_IS_GROUP(flags)) {
			zfsace_set_flagset(_entry, flags | ZFSACE_IDENTIFIER_GROUP);
		}
		break;
	case ZFSACL_USER:
		if (_whoid == ZFSACL_UNDEFINED_ID) {
			errno = EINVAL;
			return false;
		}
		whoid = _whoid;
		special_flag = 0;
		if (ZFSACE_IS_GROUP(flags)) {
			zfsace_set_flagset(_entry, flags & ~ZFSACE_IDENTIFIER_GROUP);
		}
		break;
	case ZFSACL_GROUP:
		if (_whoid == ZFSACL_UNDEFINED_ID) {
			errno = EINVAL;
			return false;
		}
		whoid = _whoid;
		special_flag = 0;
		if (!ZFSACE_IS_GROUP(flags)) {
			zfsace_set_flagset(_entry, flags | ZFSACE_IDENTIFIER_GROUP);
		}
		break;
	default:
		errno = EINVAL;
		return false;
	}

	*pspecial = htonl(special_flag);
	*pwhoid = htonl(whoid);
	return true;
}

bool zfsace_set_entry_type(zfsacl_entry_t _entry, zfsace_entry_type_t _tp)
{
	uint *ptype = (uint *)_entry + ZFSACE_TYPE_OFFSET;

	if (ZFSACE_TYPE_INVALID(_tp)) {
		errno = EINVAL;
		return false;
	}

	*ptype = htonl(_tp);
	return true;
}

#if devel
void dump_xattr(uint *buf, size_t len)
{
        size_t i;

        fprintf(stderr, "off: 0, 0x%08x, ptr: %p | ", ntohl(buf[0]), &buf[0]);
        fprintf(stderr, "off: 1, 0x%08x, ptr: %p | ", ntohl(buf[1]), &buf[0]);

        for (i = 2; i < (len / sizeof(uint)); i++) {
                if (((i -2) % 5) == 0) {
                        fprintf(stderr, "\n");
                }
                fprintf(stderr, "off: %d, 0x%08x, ptr: %p\n",
                        i, ntohl(buf[i]), &buf[i]);
        }
}
#endif

zfsacl_t zfsacl_get_fd(int fd, zfsacl_brand_t _brand)
{
	zfsacl_t out = NULL;
	size_t acl_sz;
	ssize_t res;

	if (_brand != ZFSACL_BRAND_NFSV4) {
		errno = EINVAL;
		return NULL;
	}

	out = zfsacl_init(ACL4_MAX_ENTRIES, _brand);
	if (out == NULL) {
		return NULL;
	}

	res = fgetxattr(fd, ACL4_XATTR, out->aclbuf, out->aclbuf_size);
	if (res == -1) {
		zfsacl_free(&out);
		return NULL;
	}
#if devel
	dump_xattr(out->aclbuf, out->aclbuf_size);
#endif

	return out;
}

zfsacl_t zfsacl_get_file(const char *_path_p, zfsacl_brand_t _brand)
{
	zfsacl_t out = NULL;
	size_t acl_sz;
	ssize_t res;

	if (_brand != ZFSACL_BRAND_NFSV4) {
		errno = EINVAL;
		return NULL;
	}

	out = zfsacl_init(ACL4_MAX_ENTRIES, _brand);
	if (out == NULL) {
		return NULL;
	}

	res = getxattr(_path_p, ACL4_XATTR, out->aclbuf, out->aclbuf_size);
	if (res == -1) {
		zfsacl_free(&out);
		return NULL;
	}
#if devel
	dump_xattr(out->aclbuf, out->aclbuf_size);
#endif

	return out;
}

zfsacl_t zfsacl_get_link(const char *_path_p, zfsacl_brand_t _brand)
{
	zfsacl_t out = NULL;
	size_t acl_sz;
	ssize_t res;

	if (_brand != ZFSACL_BRAND_NFSV4) {
		errno = EINVAL;
		return NULL;
	}

	out = zfsacl_init(ACL4_MAX_ENTRIES, _brand);
	if (out == NULL) {
		return NULL;
	}

	res = lgetxattr(_path_p, ACL4_XATTR, out->aclbuf, out->aclbuf_size);
	if (res == -1) {
		zfsacl_free(&out);
		return NULL;
	}

#if devel
	dump_xattr(out->aclbuf, out->aclbuf_size);
#endif
	return out;
}

static bool xatbuf_from_acl(zfsacl_t acl, char **pbuf, size_t *bufsz)
{
	uint acecnt;
	size_t calculated_acl_sz;
	char *buf = NULL;
	bool ok;

	ok = zfsacl_get_acecnt(acl, &acecnt);
	if (!ok) {
		return false;
	}

	if (acecnt == 0) {
		errno = ENODATA;
	}
        else if (acecnt > ACL4_MAX_ENTRIES) {
		errno = ERANGE;
		return false;
	}

	calculated_acl_sz = ACL4SZ_FROM_ACECNT(acecnt);
	assert(calculated_acl_sz <= acl->aclbuf_size);

	*pbuf = (char *)acl->aclbuf;

	*bufsz = calculated_acl_sz;
	return true;
}

bool zfsacl_set_fd(int _fd, zfsacl_t _acl)
{
	int err;
	bool ok;
	char *buf = NULL;
	size_t bufsz = 0;

	ok = xatbuf_from_acl(_acl, &buf, &bufsz);
	if (!ok) {
		return false;
	}

	err = fsetxattr(_fd, ACL4_XATTR, buf, bufsz, 0);
	if (err) {
		return false;
	}
	return true;
}

bool zfsacl_set_file(const char *_path_p, zfsacl_t _acl)
{
	int err;
	bool ok;
	char *buf = NULL;
	size_t bufsz = 0;

	ok = xatbuf_from_acl(_acl, &buf, &bufsz);
	if (!ok) {
		return false;
	}

	err = setxattr(_path_p, ACL4_XATTR, buf, bufsz, 0);
	if (err) {
		return false;
	}
	return true;
}

bool zfsacl_set_link(const char *_path_p, zfsacl_t _acl)
{
	int err;
	bool ok;
	char *buf = NULL;
	size_t bufsz = 0;

	ok = xatbuf_from_acl(_acl, &buf, &bufsz);
	if (!ok) {
		return false;
	}

	err = lsetxattr(_path_p, ACL4_XATTR, buf, bufsz, 0);
	if (err) {
		return false;
	}
	return true;
}

bool zfsacl_to_native(zfsacl_t _acl, struct native_acl *pnative)
{
	char *to_copy = NULL;
	char *out_buf = NULL;
	size_t bufsz;
	bool ok;

	if (pnative == NULL) {
		errno = ENOMEM;
		return false;
	}

	ok = xatbuf_from_acl(_acl, &to_copy, &bufsz);
	if (!ok) {
		return false;
	}

	out_buf = calloc(bufsz, sizeof(char));
	if (out_buf == NULL) {
		errno = ENOMEM;
		return false;
	}
	memcpy(out_buf, to_copy, bufsz);
	pnative->data = out_buf;
	pnative->datalen = bufsz;
	pnative->brand = _acl->brand;
	return true;
}

bool zfsacl_is_trivial(zfsacl_t _acl, bool *trivialp)
{
	errno = EOPNOTSUPP;
	return false;
}

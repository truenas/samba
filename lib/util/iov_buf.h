/*
 * Unix SMB/CIFS implementation.
 * Samba system utilities
 * Copyright (C) Volker Lendecke 2014
 * Copyright (C) Stefan Metzmacher 2020,2026 (iov_valgrind_mem_defined,
 *                                            adapted from upstream !4453)
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LIB_IOV_BUF_H__
#define __LIB_IOV_BUF_H__

#include "replace.h"
#include <talloc.h>
#include "system/filesys.h"

static inline
ssize_t iov_buf(const struct iovec *iov, int iovcnt,
		uint8_t *buf, size_t buflen)
{
	size_t needed = 0;
	uint8_t *p = buf;
	int i;

	for (i=0; i<iovcnt; i++) {
		size_t thislen = iov[i].iov_len;
		size_t tmp;

		tmp = needed + thislen;

		if (tmp < needed) {
			/* wrap */
			return -1;
		}
		needed = tmp;

		if ((p != NULL) && needed <= buflen && thislen > 0) {
			memcpy(p, iov[i].iov_base, thislen);
			p += thislen;
		}
	}

	return needed;
}

static inline
ssize_t iov_buflen(const struct iovec *iov, int iovcnt)
{
	return iov_buf(iov, iovcnt, NULL, 0);
}

static inline
bool iov_advance(struct iovec **iov, int *iovcnt, size_t n)
{
	struct iovec *v = *iov;
	int cnt = *iovcnt;

	while (n > 0) {
		if (cnt == 0) {
			return false;
		}
		if (n < v->iov_len) {
			v->iov_base = (char *)v->iov_base + n;
			v->iov_len -= n;
			break;
		}
		n -= v->iov_len;
		v += 1;
		cnt -= 1;
	}

	/*
	 * Skip 0-length iovec's
	 *
	 * There might be empty buffers at the end of iov. Next time we do a
	 * readv/writev based on this iov would give 0 transferred bytes, also
	 * known as EPIPE. So we need to be careful discarding them.
	 */

	while ((cnt > 0) && (v->iov_len == 0)) {
		v += 1;
		cnt -= 1;
	}

	*iov = v;
	*iovcnt = cnt;
	return true;
}

uint8_t *iov_concat(TALLOC_CTX *mem_ctx, const struct iovec *iov, int count);

#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#elif defined(HAVE_VALGRIND_H)
#include <valgrind.h>
#endif

/*
 * Mark the first n bytes spanned by iov[0..iovcnt) as defined for
 * valgrind. No-op in non-valgrind builds.
 *
 * Used after kernel-side fills (e.g. io_uring RECVMSG / READ /
 * RDMA-offloaded SMB2 read) that valgrind's syscall instrumentation
 * cannot see: the bytes ARE valid, but the talloc-allocated buffer
 * appears as uninit to memcheck. Calling this with (iov, iovcnt, n)
 * matching the kernel-reported byte count silences the false positive
 * without paying memset cost in production.
 */
static inline
void iov_valgrind_mem_defined(struct iovec *iov, int iovcnt, size_t n)
{
#ifdef VALGRIND_MAKE_MEM_DEFINED
	int i;

	for (i = 0; i < iovcnt && n > 0; i++) {
		if (iov[i].iov_len == 0) {
			continue;
		}

		if (n < iov[i].iov_len) {
			VALGRIND_MAKE_MEM_DEFINED(iov[i].iov_base, n);
			return;
		}

		VALGRIND_MAKE_MEM_DEFINED(iov[i].iov_base, iov[i].iov_len);
		n -= iov[i].iov_len;
	}
#else
	(void)iov;
	(void)iovcnt;
	(void)n;
#endif
}

#endif

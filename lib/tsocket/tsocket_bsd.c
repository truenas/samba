/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2009

     ** NOTE! The following LGPL license applies to the tsocket
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/filesys.h"
#include "system/network.h"
#include "system/select.h"
#include "tsocket.h"
#include "tsocket_internal.h"
#include "lib/util/select.h"
#include "lib/util/iov_buf.h"
#include "lib/util/blocking.h"
#include "lib/util/util_net.h"
#include "lib/util/samba_util.h"

static int tsocket_bsd_error_from_errno(int ret,
					int sys_errno,
					bool *retry)
{
	*retry = false;

	if (ret >= 0) {
		return 0;
	}

	if (ret != -1) {
		return EIO;
	}

	if (sys_errno == 0) {
		return EIO;
	}

	if (sys_errno == EINTR) {
		*retry = true;
		return sys_errno;
	}

	if (sys_errno == EINPROGRESS) {
		*retry = true;
		return sys_errno;
	}

	if (sys_errno == EAGAIN) {
		*retry = true;
		return sys_errno;
	}

	/* ENOMEM is retryable on Solaris/illumos, and possibly other systems. */
	if (sys_errno == ENOMEM) {
		*retry = true;
		return sys_errno;
	}

#ifdef EWOULDBLOCK
	if (sys_errno == EWOULDBLOCK) {
		*retry = true;
		return sys_errno;
	}
#endif

	return sys_errno;
}

static int tsocket_bsd_common_prepare_fd(int fd, bool high_fd)
{
	int i;
	int sys_errno = 0;
	int fds[3];
	int num_fds = 0;

	int result;
	bool ok;

	if (fd == -1) {
		return -1;
	}

	/* first make a fd >= 3 */
	if (high_fd) {
		while (fd < 3) {
			fds[num_fds++] = fd;
			fd = dup(fd);
			if (fd == -1) {
				sys_errno = errno;
				break;
			}
		}
		for (i=0; i<num_fds; i++) {
			close(fds[i]);
		}
		if (fd == -1) {
			errno = sys_errno;
			return fd;
		}
	}

	result = set_blocking(fd, false);
	if (result == -1) {
		goto fail;
	}

	ok = smb_set_close_on_exec(fd);
	if (!ok) {
		goto fail;
	}

	return fd;

 fail:
	if (fd != -1) {
		sys_errno = errno;
		close(fd);
		errno = sys_errno;
	}
	return -1;
}

#ifdef HAVE_LINUX_RTNETLINK_H
/**
 * Get the amount of pending bytes from a netlink socket
 *
 * For some reason netlink sockets don't support querying the amount of pending
 * data via ioctl with FIONREAD, which is what we use in tsocket_bsd_pending()
 * below.
 *
 * We know we are on Linux as we're using netlink, which means we have a working
 * MSG_TRUNC flag to recvmsg() as well, so we use that together with MSG_PEEK.
 **/
static ssize_t tsocket_bsd_netlink_pending(int fd)
{
	struct iovec iov;
	struct msghdr msg;
	char buf[1];

	iov = (struct iovec) {
		.iov_base = buf,
		.iov_len = sizeof(buf)
	};

	msg = (struct msghdr) {
		.msg_iov = &iov,
		.msg_iovlen = 1
	};

	return recvmsg(fd, &msg, MSG_PEEK | MSG_TRUNC);
}
#else
static ssize_t tsocket_bsd_netlink_pending(int fd)
{
	errno = ENOSYS;
	return -1;
}
#endif

static int tsocket_bsd_poll_error(int fd)
{
	struct pollfd pfd = {
		.fd = fd,
#ifdef POLLRDHUP
		.events = POLLRDHUP, /* POLLERR and POLLHUP are not needed */
#endif
	};
	int ret;

	errno = 0;
	ret = sys_poll_intr(&pfd, 1, 0);
	if (ret == 0) {
		return 0;
	}
	if (ret != 1) {
		return POLLNVAL;
	}

	if (pfd.revents & POLLERR) {
		return POLLERR;
	}
	if (pfd.revents & POLLHUP) {
		return POLLHUP;
	}
#ifdef POLLRDHUP
	if (pfd.revents & POLLRDHUP) {
		return POLLRDHUP;
	}
#endif

	/* should never be reached! */
	return POLLNVAL;
}

static int tsocket_bsd_sock_error(int fd)
{
	int ret, error = 0;
	socklen_t len = sizeof(error);

	/*
	 * if no data is available check if the socket is in error state. For
	 * dgram sockets it's the way to return ICMP error messages of
	 * connected sockets to the caller.
	 */
	ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
	if (ret == -1) {
		return ret;
	}
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

static int tsocket_bsd_error(int fd)
{
	int ret;
	int poll_error = 0;

	poll_error = tsocket_bsd_poll_error(fd);
	if (poll_error == 0) {
		return 0;
	}

#ifdef POLLRDHUP
	if (poll_error == POLLRDHUP) {
		errno = ECONNRESET;
		return -1;
	}
#endif

	if (poll_error == POLLHUP) {
		errno = EPIPE;
		return -1;
	}

	/*
	 * POLLERR and POLLNVAL fallback to
	 * getsockopt(fd, SOL_SOCKET, SO_ERROR)
	 * and force EPIPE as fallback.
	 */

	errno = 0;
	ret = tsocket_bsd_sock_error(fd);
	if (ret == 0) {
		errno = EPIPE;
	}

	if (errno == 0) {
		errno = EPIPE;
	}

	return -1;
}

static ssize_t tsocket_bsd_pending(int fd)
{
	int ret;
	int value = 0;

	ret = ioctl(fd, FIONREAD, &value);
	if (ret == -1) {
		return ret;
	}

	if (ret != 0) {
		/* this should not be reached */
		errno = EIO;
		return -1;
	}

	if (value != 0) {
		return value;
	}

	return tsocket_bsd_error(fd);
}

static const struct tsocket_address_ops tsocket_address_bsd_ops;

int _tsocket_address_bsd_from_sockaddr(TALLOC_CTX *mem_ctx,
				       const struct sockaddr *sa,
				       size_t sa_socklen,
				       struct tsocket_address **_addr,
				       const char *location)
{
	struct tsocket_address *addr;
	struct samba_sockaddr *bsda = NULL;

	if (sa_socklen < sizeof(sa->sa_family)) {
		errno = EINVAL;
		return -1;
	}

	switch (sa->sa_family) {
	case AF_UNIX:
		if (sa_socklen > sizeof(struct sockaddr_un)) {
			sa_socklen = sizeof(struct sockaddr_un);
		}
		break;
	case AF_INET:
		if (sa_socklen < sizeof(struct sockaddr_in)) {
			errno = EINVAL;
			return -1;
		}
		sa_socklen = sizeof(struct sockaddr_in);
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		if (sa_socklen < sizeof(struct sockaddr_in6)) {
			errno = EINVAL;
			return -1;
		}
		sa_socklen = sizeof(struct sockaddr_in6);
		break;
#endif
	default:
		errno = EAFNOSUPPORT;
		return -1;
	}

	if (sa_socklen > sizeof(struct sockaddr_storage)) {
		errno = EINVAL;
		return -1;
	}

	addr = tsocket_address_create(mem_ctx,
				      &tsocket_address_bsd_ops,
				      &bsda,
				      struct samba_sockaddr,
				      location);
	if (!addr) {
		errno = ENOMEM;
		return -1;
	}

	ZERO_STRUCTP(bsda);

	memcpy(&bsda->u.ss, sa, sa_socklen);

	bsda->sa_socklen = sa_socklen;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	bsda->u.sa.sa_len = bsda->sa_socklen;
#endif

	*_addr = addr;
	return 0;
}

int _tsocket_address_bsd_from_samba_sockaddr(TALLOC_CTX *mem_ctx,
					 const struct samba_sockaddr *xs_addr,
					 struct tsocket_address **t_addr,
					 const char *location)
{
	return _tsocket_address_bsd_from_sockaddr(mem_ctx,
						  &xs_addr->u.sa,
						  xs_addr->sa_socklen,
						  t_addr,
						  location);
}

ssize_t tsocket_address_bsd_sockaddr(const struct tsocket_address *addr,
				     struct sockaddr *sa,
				     size_t sa_socklen)
{
	struct samba_sockaddr *bsda = talloc_get_type(addr->private_data,
					   struct samba_sockaddr);

	if (!bsda) {
		errno = EINVAL;
		return -1;
	}

	if (sa_socklen < bsda->sa_socklen) {
		errno = EINVAL;
		return -1;
	}

	if (sa_socklen > bsda->sa_socklen) {
		memset(sa, 0, sa_socklen);
		sa_socklen = bsda->sa_socklen;
	}

	memcpy(sa, &bsda->u.ss, sa_socklen);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	sa->sa_len = sa_socklen;
#endif
	return sa_socklen;
}

bool tsocket_address_is_inet(const struct tsocket_address *addr, const char *fam)
{
	struct samba_sockaddr *bsda = talloc_get_type(addr->private_data,
					   struct samba_sockaddr);

	if (!bsda) {
		return false;
	}

	switch (bsda->u.sa.sa_family) {
	case AF_INET:
		if (strcasecmp(fam, "ip") == 0) {
			return true;
		}

		if (strcasecmp(fam, "ipv4") == 0) {
			return true;
		}

		return false;
#ifdef HAVE_IPV6
	case AF_INET6:
		if (strcasecmp(fam, "ip") == 0) {
			return true;
		}

		if (strcasecmp(fam, "ipv6") == 0) {
			return true;
		}

		return false;
#endif
	}

	return false;
}

int _tsocket_address_inet_from_strings(TALLOC_CTX *mem_ctx,
				       const char *fam,
				       const char *addr,
				       uint16_t port,
				       struct tsocket_address **_addr,
				       const char *location)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	char port_str[6];
	int ret;

	ZERO_STRUCT(hints);
	/*
	 * we use SOCKET_STREAM here to get just one result
	 * back from getaddrinfo().
	 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

	if (strcasecmp(fam, "ip") == 0) {
		hints.ai_family = AF_UNSPEC;
		if (!addr) {
#ifdef HAVE_IPV6
			addr = "::";
#else
			addr = "0.0.0.0";
#endif
		}
	} else if (strcasecmp(fam, "ipv4") == 0) {
		hints.ai_family = AF_INET;
		if (!addr) {
			addr = "0.0.0.0";
		}
#ifdef HAVE_IPV6
	} else if (strcasecmp(fam, "ipv6") == 0) {
		hints.ai_family = AF_INET6;
		if (!addr) {
			addr = "::";
		}
#endif
	} else {
		errno = EAFNOSUPPORT;
		return -1;
	}

	snprintf(port_str, sizeof(port_str), "%u", port);

	ret = getaddrinfo(addr, port_str, &hints, &result);
	if (ret != 0) {
		switch (ret) {
		case EAI_FAIL:
		case EAI_NONAME:
#ifdef EAI_ADDRFAMILY
		case EAI_ADDRFAMILY:
#endif
			errno = EINVAL;
			break;
		}
		ret = -1;
		goto done;
	}

	if (result->ai_socktype != SOCK_STREAM) {
		errno = EINVAL;
		ret = -1;
		goto done;
	}

	ret = _tsocket_address_bsd_from_sockaddr(mem_ctx,
						  result->ai_addr,
						  result->ai_addrlen,
						  _addr,
						  location);

done:
	if (result) {
		freeaddrinfo(result);
	}
	return ret;
}

int _tsocket_address_inet_from_hostport_strings(TALLOC_CTX *mem_ctx,
						const char *fam,
						const char *host_port_addr,
						uint16_t default_port,
						struct tsocket_address **_addr,
						const char *location)
{
	char *pl_sq = NULL;
	char *pr_sq = NULL;
	char *pl_period = NULL;
	char *port_sep = NULL;
	char *cport = NULL;
	char *buf = NULL;
	uint64_t port = 0;
	int ret;
	char *s_addr = NULL;
	uint16_t s_port = default_port;
	bool conv_ret;
	bool is_ipv6_by_squares = false;

	if (host_port_addr == NULL) {
		/* got straight to next function if host_port_addr is NULL */
		goto get_addr;
	}
	buf = talloc_strdup(mem_ctx, host_port_addr);
	if (buf == NULL) {
		errno = ENOMEM;
		return -1;
	}
	pl_period = strchr_m(buf, '.');
	port_sep = strrchr_m(buf, ':');
	pl_sq = strchr_m(buf, '[');
	pr_sq = strrchr_m(buf, ']');
	/* See if its IPv4 or IPv6 */
	/* Only parse IPv6 with squares with/without port, and IPv4 with port */
	/* Everything else, let tsocket_address_inet_from string() */
	/* find parsing errors */
#ifdef HAVE_IPV6
	is_ipv6_by_squares = (pl_sq != NULL && pr_sq != NULL && pr_sq > pl_sq);
#endif
	if (is_ipv6_by_squares) {
		/* IPv6 possibly with port - squares detected */
		port_sep = pr_sq + 1;
		if (*port_sep == '\0') {
			s_addr = pl_sq + 1;
			*pr_sq = 0;
			s_port = default_port;
			goto get_addr;
		}
		if (*port_sep != ':') {
			errno = EINVAL;
			return -1;
		}
		cport = port_sep + 1;
		conv_ret = conv_str_u64(cport, &port);
		if (!conv_ret) {
			errno = EINVAL;
			return -1;
		}
		if (port > 65535) {
			errno = EINVAL;
			return -1;
		}
		s_port = (uint16_t)port;
		*port_sep = 0;
		*pr_sq = 0;
		s_addr = pl_sq + 1;
		*pl_sq = 0;
		goto get_addr;
	} else if (pl_period != NULL && port_sep != NULL) {
		/* IPv4 with port - more than one period in string */
		cport = port_sep + 1;
		conv_ret = conv_str_u64(cport, &port);
		if (!conv_ret) {
			errno = EINVAL;
			return -1;
		}
		if (port > 65535) {
			errno = EINVAL;
			return -1;
		}
		s_port = (uint16_t)port;
		*port_sep = 0;
		s_addr = buf;
		goto get_addr;
	} else {
		/* Everything else, let tsocket_address_inet_from string() */
		/* find parsing errors */
		s_addr = buf;
		s_port = default_port;
		goto get_addr;
	}
get_addr:
	ret = _tsocket_address_inet_from_strings(
	    mem_ctx, fam, s_addr, s_port, _addr, location);

	return ret;
}

char *tsocket_address_inet_addr_string(const struct tsocket_address *addr,
				       TALLOC_CTX *mem_ctx)
{
	struct samba_sockaddr *bsda = talloc_get_type(addr->private_data,
					   struct samba_sockaddr);
	char addr_str[INET6_ADDRSTRLEN+1];
	const char *str;

	if (!bsda) {
		errno = EINVAL;
		return NULL;
	}

	switch (bsda->u.sa.sa_family) {
	case AF_INET:
		str = inet_ntop(bsda->u.in.sin_family,
				&bsda->u.in.sin_addr,
				addr_str, sizeof(addr_str));
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		str = inet_ntop(bsda->u.in6.sin6_family,
				&bsda->u.in6.sin6_addr,
				addr_str, sizeof(addr_str));
		break;
#endif
	default:
		errno = EINVAL;
		return NULL;
	}

	if (!str) {
		return NULL;
	}

	return talloc_strdup(mem_ctx, str);
}

uint16_t tsocket_address_inet_port(const struct tsocket_address *addr)
{
	struct samba_sockaddr *bsda = talloc_get_type(addr->private_data,
					   struct samba_sockaddr);
	uint16_t port = 0;

	if (!bsda) {
		errno = EINVAL;
		return 0;
	}

	switch (bsda->u.sa.sa_family) {
	case AF_INET:
		port = ntohs(bsda->u.in.sin_port);
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		port = ntohs(bsda->u.in6.sin6_port);
		break;
#endif
	default:
		errno = EINVAL;
		return 0;
	}

	return port;
}

int tsocket_address_inet_set_port(struct tsocket_address *addr,
				  uint16_t port)
{
	struct samba_sockaddr *bsda = talloc_get_type(addr->private_data,
					   struct samba_sockaddr);

	if (!bsda) {
		errno = EINVAL;
		return -1;
	}

	switch (bsda->u.sa.sa_family) {
	case AF_INET:
		bsda->u.in.sin_port = htons(port);
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		bsda->u.in6.sin6_port = htons(port);
		break;
#endif
	default:
		errno = EINVAL;
		return -1;
	}

	return 0;
}

bool tsocket_address_is_unix(const struct tsocket_address *addr)
{
	struct samba_sockaddr *bsda = talloc_get_type(addr->private_data,
					   struct samba_sockaddr);

	if (!bsda) {
		return false;
	}

	switch (bsda->u.sa.sa_family) {
	case AF_UNIX:
		return true;
	}

	return false;
}

int _tsocket_address_unix_from_path(TALLOC_CTX *mem_ctx,
				    const char *path,
				    struct tsocket_address **_addr,
				    const char *location)
{
	struct sockaddr_un un;
	void *p = &un;
	int ret;

	if (!path) {
		path = "";
	}

	if (strlen(path) > sizeof(un.sun_path)-1) {
		errno = ENAMETOOLONG;
		return -1;
	}

	ZERO_STRUCT(un);
	un.sun_family = AF_UNIX;
	strncpy(un.sun_path, path, sizeof(un.sun_path)-1);

	ret = _tsocket_address_bsd_from_sockaddr(mem_ctx,
						 (struct sockaddr *)p,
						 sizeof(un),
						 _addr,
						 location);

	return ret;
}

char *tsocket_address_unix_path(const struct tsocket_address *addr,
				TALLOC_CTX *mem_ctx)
{
	struct samba_sockaddr *bsda = talloc_get_type(addr->private_data,
					   struct samba_sockaddr);
	const char *str;

	if (!bsda) {
		errno = EINVAL;
		return NULL;
	}

	switch (bsda->u.sa.sa_family) {
	case AF_UNIX:
		str = bsda->u.un.sun_path;
		break;
	default:
		errno = EINVAL;
		return NULL;
	}

	return talloc_strdup(mem_ctx, str);
}

static char *tsocket_address_bsd_string(const struct tsocket_address *addr,
					TALLOC_CTX *mem_ctx)
{
	struct samba_sockaddr *bsda = talloc_get_type(addr->private_data,
					   struct samba_sockaddr);
	char *str;
	char *addr_str;
	const char *prefix = NULL;
	uint16_t port;

	switch (bsda->u.sa.sa_family) {
	case AF_UNIX:
		return talloc_asprintf(mem_ctx, "unix:%s",
				       bsda->u.un.sun_path);
	case AF_INET:
		prefix = "ipv4";
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		prefix = "ipv6";
		break;
#endif
	default:
		errno = EINVAL;
		return NULL;
	}

	addr_str = tsocket_address_inet_addr_string(addr, mem_ctx);
	if (!addr_str) {
		return NULL;
	}

	port = tsocket_address_inet_port(addr);

	str = talloc_asprintf(mem_ctx, "%s:%s:%u",
			      prefix, addr_str, port);
	talloc_free(addr_str);

	return str;
}

static struct tsocket_address *tsocket_address_bsd_copy(const struct tsocket_address *addr,
							 TALLOC_CTX *mem_ctx,
							 const char *location)
{
	struct samba_sockaddr *bsda = talloc_get_type(addr->private_data,
					   struct samba_sockaddr);
	struct tsocket_address *copy;
	int ret;

	ret = _tsocket_address_bsd_from_sockaddr(mem_ctx,
						 &bsda->u.sa,
						 bsda->sa_socklen,
						 &copy,
						 location);
	if (ret != 0) {
		return NULL;
	}

	return copy;
}

static const struct tsocket_address_ops tsocket_address_bsd_ops = {
	.name		= "bsd",
	.string		= tsocket_address_bsd_string,
	.copy		= tsocket_address_bsd_copy,
};

struct tdgram_bsd {
	int fd;

	void *event_ptr;
	struct tevent_fd *fde;
	bool optimize_recvfrom;
	bool netlink;

	void *readable_private;
	void (*readable_handler)(void *private_data);
	void *writeable_private;
	void (*writeable_handler)(void *private_data);
};

bool tdgram_bsd_optimize_recvfrom(struct tdgram_context *dgram,
				  bool on)
{
	struct tdgram_bsd *bsds =
		talloc_get_type(_tdgram_context_data(dgram),
		struct tdgram_bsd);
	bool old;

	if (bsds == NULL) {
		/* not a bsd socket */
		return false;
	}

	old = bsds->optimize_recvfrom;
	bsds->optimize_recvfrom = on;

	return old;
}

static void tdgram_bsd_fde_handler(struct tevent_context *ev,
				   struct tevent_fd *fde,
				   uint16_t flags,
				   void *private_data)
{
	struct tdgram_bsd *bsds = talloc_get_type_abort(private_data,
				  struct tdgram_bsd);

	if (flags & TEVENT_FD_WRITE) {
		bsds->writeable_handler(bsds->writeable_private);
		return;
	}
	if (flags & TEVENT_FD_READ) {
		if (!bsds->readable_handler) {
			TEVENT_FD_NOT_READABLE(bsds->fde);
			return;
		}
		bsds->readable_handler(bsds->readable_private);
		return;
	}
}

static int tdgram_bsd_set_readable_handler(struct tdgram_bsd *bsds,
					   struct tevent_context *ev,
					   void (*handler)(void *private_data),
					   void *private_data)
{
	if (ev == NULL) {
		if (handler) {
			errno = EINVAL;
			return -1;
		}
		if (!bsds->readable_handler) {
			return 0;
		}
		bsds->readable_handler = NULL;
		bsds->readable_private = NULL;

		return 0;
	}

	/* read and write must use the same tevent_context */
	if (bsds->event_ptr != ev) {
		if (bsds->readable_handler || bsds->writeable_handler) {
			errno = EINVAL;
			return -1;
		}
		bsds->event_ptr = NULL;
		TALLOC_FREE(bsds->fde);
	}

	if (tevent_fd_get_flags(bsds->fde) == 0) {
		TALLOC_FREE(bsds->fde);

		bsds->fde = tevent_add_fd(ev, bsds,
					  bsds->fd, TEVENT_FD_READ,
					  tdgram_bsd_fde_handler,
					  bsds);
		if (!bsds->fde) {
			errno = ENOMEM;
			return -1;
		}

		/* cache the event context we're running on */
		bsds->event_ptr = ev;
	} else if (!bsds->readable_handler) {
		TEVENT_FD_READABLE(bsds->fde);
	}

	bsds->readable_handler = handler;
	bsds->readable_private = private_data;

	return 0;
}

static int tdgram_bsd_set_writeable_handler(struct tdgram_bsd *bsds,
					    struct tevent_context *ev,
					    void (*handler)(void *private_data),
					    void *private_data)
{
	if (ev == NULL) {
		if (handler) {
			errno = EINVAL;
			return -1;
		}
		if (!bsds->writeable_handler) {
			return 0;
		}
		bsds->writeable_handler = NULL;
		bsds->writeable_private = NULL;
		TEVENT_FD_NOT_WRITEABLE(bsds->fde);

		return 0;
	}

	/* read and write must use the same tevent_context */
	if (bsds->event_ptr != ev) {
		if (bsds->readable_handler || bsds->writeable_handler) {
			errno = EINVAL;
			return -1;
		}
		bsds->event_ptr = NULL;
		TALLOC_FREE(bsds->fde);
	}

	if (tevent_fd_get_flags(bsds->fde) == 0) {
		TALLOC_FREE(bsds->fde);

		bsds->fde = tevent_add_fd(ev, bsds,
					  bsds->fd, TEVENT_FD_WRITE,
					  tdgram_bsd_fde_handler,
					  bsds);
		if (!bsds->fde) {
			errno = ENOMEM;
			return -1;
		}

		/* cache the event context we're running on */
		bsds->event_ptr = ev;
	} else if (!bsds->writeable_handler) {
		TEVENT_FD_WRITEABLE(bsds->fde);
	}

	bsds->writeable_handler = handler;
	bsds->writeable_private = private_data;

	return 0;
}

struct tdgram_bsd_recvfrom_state {
	struct tdgram_context *dgram;
	bool first_try;
	uint8_t *buf;
	size_t len;
	struct tsocket_address *src;
};

static int tdgram_bsd_recvfrom_destructor(struct tdgram_bsd_recvfrom_state *state)
{
	struct tdgram_bsd *bsds = tdgram_context_data(state->dgram,
				  struct tdgram_bsd);

	tdgram_bsd_set_readable_handler(bsds, NULL, NULL, NULL);

	return 0;
}

static void tdgram_bsd_recvfrom_handler(void *private_data);

static struct tevent_req *tdgram_bsd_recvfrom_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct tdgram_context *dgram)
{
	struct tevent_req *req;
	struct tdgram_bsd_recvfrom_state *state;
	struct tdgram_bsd *bsds = tdgram_context_data(dgram, struct tdgram_bsd);
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct tdgram_bsd_recvfrom_state);
	if (!req) {
		return NULL;
	}

	state->dgram	= dgram;
	state->first_try= true;
	state->buf	= NULL;
	state->len	= 0;
	state->src	= NULL;

	talloc_set_destructor(state, tdgram_bsd_recvfrom_destructor);

	if (bsds->fd == -1) {
		tevent_req_error(req, ENOTCONN);
		goto post;
	}


	/*
	 * this is a fast path, not waiting for the
	 * socket to become explicit readable gains
	 * about 10%-20% performance in benchmark tests.
	 */
	if (bsds->optimize_recvfrom) {
		/*
		 * We only do the optimization on
		 * recvfrom if the caller asked for it.
		 *
		 * This is needed because in most cases
		 * we prefer to flush send buffers before
		 * receiving incoming requests.
		 */
		tdgram_bsd_recvfrom_handler(req);
		if (!tevent_req_is_in_progress(req)) {
			goto post;
		}
	}

	ret = tdgram_bsd_set_readable_handler(bsds, ev,
					      tdgram_bsd_recvfrom_handler,
					      req);
	if (ret == -1) {
		tevent_req_error(req, errno);
		goto post;
	}

	return req;

 post:
	tevent_req_post(req, ev);
	return req;
}

static void tdgram_bsd_recvfrom_handler(void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(private_data,
				 struct tevent_req);
	struct tdgram_bsd_recvfrom_state *state = tevent_req_data(req,
					struct tdgram_bsd_recvfrom_state);
	struct tdgram_context *dgram = state->dgram;
	struct tdgram_bsd *bsds = tdgram_context_data(dgram, struct tdgram_bsd);
	struct samba_sockaddr *bsda = NULL;
	ssize_t ret;
	int err;
	bool retry;

	if (bsds->netlink) {
		ret = tsocket_bsd_netlink_pending(bsds->fd);
	} else {
		ret = tsocket_bsd_pending(bsds->fd);
	}

	if (state->first_try && ret == 0) {
		state->first_try = false;
		/* retry later */
		return;
	}
	state->first_try = false;

	err = tsocket_bsd_error_from_errno(ret, errno, &retry);
	if (retry) {
		/* retry later */
		return;
	}
	if (tevent_req_error(req, err)) {
		return;
	}

	/* note that 'ret' can be 0 here */
	state->buf = talloc_array(state, uint8_t, ret);
	if (tevent_req_nomem(state->buf, req)) {
		return;
	}
	state->len = ret;

	state->src = tsocket_address_create(state,
					    &tsocket_address_bsd_ops,
					    &bsda,
					    struct samba_sockaddr,
					    __location__ "bsd_recvfrom");
	if (tevent_req_nomem(state->src, req)) {
		return;
	}

	ZERO_STRUCTP(bsda);
	bsda->sa_socklen = sizeof(bsda->u.ss);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	bsda->u.sa.sa_len = bsda->sa_socklen;
#endif

	ret = recvfrom(bsds->fd, state->buf, state->len, 0,
		       &bsda->u.sa, &bsda->sa_socklen);
	err = tsocket_bsd_error_from_errno(ret, errno, &retry);
	if (retry) {
		/* retry later */
		return;
	}
	if (tevent_req_error(req, err)) {
		return;
	}

	/*
	 * Some systems (FreeBSD, see bug #7115) return too much
	 * bytes in tsocket_bsd_pending()/ioctl(fd, FIONREAD, ...),
	 * the return value includes some IP/UDP header bytes,
	 * while recvfrom() just returns the payload.
	 */
	state->buf = talloc_realloc(state, state->buf, uint8_t, ret);
	if (tevent_req_nomem(state->buf, req)) {
		return;
	}
	state->len = ret;

	tevent_req_done(req);
}

static ssize_t tdgram_bsd_recvfrom_recv(struct tevent_req *req,
					int *perrno,
					TALLOC_CTX *mem_ctx,
					uint8_t **buf,
					struct tsocket_address **src)
{
	struct tdgram_bsd_recvfrom_state *state = tevent_req_data(req,
					struct tdgram_bsd_recvfrom_state);
	ssize_t ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		*buf = talloc_move(mem_ctx, &state->buf);
		ret = state->len;
		if (src) {
			*src = talloc_move(mem_ctx, &state->src);
		}
	}

	tevent_req_received(req);
	return ret;
}

struct tdgram_bsd_sendto_state {
	struct tdgram_context *dgram;

	const uint8_t *buf;
	size_t len;
	const struct tsocket_address *dst;

	ssize_t ret;
};

static int tdgram_bsd_sendto_destructor(struct tdgram_bsd_sendto_state *state)
{
	struct tdgram_bsd *bsds = tdgram_context_data(state->dgram,
				  struct tdgram_bsd);

	tdgram_bsd_set_writeable_handler(bsds, NULL, NULL, NULL);

	return 0;
}

static void tdgram_bsd_sendto_handler(void *private_data);

static struct tevent_req *tdgram_bsd_sendto_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct tdgram_context *dgram,
						 const uint8_t *buf,
						 size_t len,
						 const struct tsocket_address *dst)
{
	struct tevent_req *req;
	struct tdgram_bsd_sendto_state *state;
	struct tdgram_bsd *bsds = tdgram_context_data(dgram, struct tdgram_bsd);
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct tdgram_bsd_sendto_state);
	if (!req) {
		return NULL;
	}

	state->dgram	= dgram;
	state->buf	= buf;
	state->len	= len;
	state->dst	= dst;
	state->ret	= -1;

	talloc_set_destructor(state, tdgram_bsd_sendto_destructor);

	if (bsds->fd == -1) {
		tevent_req_error(req, ENOTCONN);
		goto post;
	}

	/*
	 * this is a fast path, not waiting for the
	 * socket to become explicit writeable gains
	 * about 10%-20% performance in benchmark tests.
	 */
	tdgram_bsd_sendto_handler(req);
	if (!tevent_req_is_in_progress(req)) {
		goto post;
	}

	ret = tdgram_bsd_set_writeable_handler(bsds, ev,
					       tdgram_bsd_sendto_handler,
					       req);
	if (ret == -1) {
		tevent_req_error(req, errno);
		goto post;
	}

	return req;

 post:
	tevent_req_post(req, ev);
	return req;
}

static void tdgram_bsd_sendto_handler(void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(private_data,
				 struct tevent_req);
	struct tdgram_bsd_sendto_state *state = tevent_req_data(req,
					struct tdgram_bsd_sendto_state);
	struct tdgram_context *dgram = state->dgram;
	struct tdgram_bsd *bsds = tdgram_context_data(dgram, struct tdgram_bsd);
	struct sockaddr *sa = NULL;
	socklen_t sa_socklen = 0;
	ssize_t ret;
	int err;
	bool retry;

	if (state->dst) {
		struct samba_sockaddr *bsda =
			talloc_get_type(state->dst->private_data,
			struct samba_sockaddr);

		sa = &bsda->u.sa;
		sa_socklen = bsda->sa_socklen;
	}

	ret = sendto(bsds->fd, state->buf, state->len, 0, sa, sa_socklen);
	err = tsocket_bsd_error_from_errno(ret, errno, &retry);
	if (retry) {
		/* retry later */
		return;
	}

	if (err == EMSGSIZE) {
		/* round up in 1K increments */
		int bufsize = ((state->len + 1023) & (~1023));

		ret = setsockopt(bsds->fd, SOL_SOCKET, SO_SNDBUF, &bufsize,
				 sizeof(bufsize));
		if (ret == 0) {
			/*
			 * We do the retry here, rather then via the
			 * handler, as we only want to retry once for
			 * this condition, so if there is a mismatch
			 * between what setsockopt() accepts and what can
			 * actually be sent, we do not end up in a
			 * loop.
			 */

			ret = sendto(bsds->fd, state->buf, state->len,
				     0, sa, sa_socklen);
			err = tsocket_bsd_error_from_errno(ret, errno, &retry);
			if (retry) { /* retry later */
				return;
			}
		}
	}

	if (tevent_req_error(req, err)) {
		return;
	}

	state->ret = ret;

	tevent_req_done(req);
}

static ssize_t tdgram_bsd_sendto_recv(struct tevent_req *req, int *perrno)
{
	struct tdgram_bsd_sendto_state *state = tevent_req_data(req,
					struct tdgram_bsd_sendto_state);
	ssize_t ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}

	tevent_req_received(req);
	return ret;
}

struct tdgram_bsd_disconnect_state {
	uint8_t __dummy;
};

static struct tevent_req *tdgram_bsd_disconnect_send(TALLOC_CTX *mem_ctx,
						     struct tevent_context *ev,
						     struct tdgram_context *dgram)
{
	struct tdgram_bsd *bsds = tdgram_context_data(dgram, struct tdgram_bsd);
	struct tevent_req *req;
	struct tdgram_bsd_disconnect_state *state;
	int ret;
	int err;
	bool dummy;

	req = tevent_req_create(mem_ctx, &state,
				struct tdgram_bsd_disconnect_state);
	if (req == NULL) {
		return NULL;
	}

	if (bsds->fd == -1) {
		tevent_req_error(req, ENOTCONN);
		goto post;
	}

	TALLOC_FREE(bsds->fde);
	ret = close(bsds->fd);
	bsds->fd = -1;
	err = tsocket_bsd_error_from_errno(ret, errno, &dummy);
	if (tevent_req_error(req, err)) {
		goto post;
	}

	tevent_req_done(req);
post:
	tevent_req_post(req, ev);
	return req;
}

static int tdgram_bsd_disconnect_recv(struct tevent_req *req,
				      int *perrno)
{
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);

	tevent_req_received(req);
	return ret;
}

static const struct tdgram_context_ops tdgram_bsd_ops = {
	.name			= "bsd",

	.recvfrom_send		= tdgram_bsd_recvfrom_send,
	.recvfrom_recv		= tdgram_bsd_recvfrom_recv,

	.sendto_send		= tdgram_bsd_sendto_send,
	.sendto_recv		= tdgram_bsd_sendto_recv,

	.disconnect_send	= tdgram_bsd_disconnect_send,
	.disconnect_recv	= tdgram_bsd_disconnect_recv,
};

static int tdgram_bsd_destructor(struct tdgram_bsd *bsds)
{
	TALLOC_FREE(bsds->fde);
	if (bsds->fd != -1) {
		close(bsds->fd);
		bsds->fd = -1;
	}
	return 0;
}

static int tdgram_bsd_dgram_socket(const struct tsocket_address *local,
				   const struct tsocket_address *remote,
				   bool broadcast,
				   TALLOC_CTX *mem_ctx,
				   struct tdgram_context **_dgram,
				   const char *location)
{
	struct samba_sockaddr *lbsda =
		talloc_get_type_abort(local->private_data,
		struct samba_sockaddr);
	struct samba_sockaddr *rbsda = NULL;
	struct tdgram_context *dgram;
	struct tdgram_bsd *bsds;
	int fd;
	int ret;
	bool do_bind = false;
	bool do_reuseaddr = false;
	bool do_ipv6only = false;
	bool is_inet = false;
	int sa_fam = lbsda->u.sa.sa_family;

	if (remote) {
		rbsda = talloc_get_type_abort(remote->private_data,
			struct samba_sockaddr);
	}

	switch (lbsda->u.sa.sa_family) {
	case AF_UNIX:
		if (broadcast) {
			errno = EINVAL;
			return -1;
		}
		if (lbsda->u.un.sun_path[0] != 0) {
			do_reuseaddr = true;
			do_bind = true;
		}
		break;
	case AF_INET:
		if (lbsda->u.in.sin_port != 0) {
			do_reuseaddr = true;
			do_bind = true;
		}
		if (lbsda->u.in.sin_addr.s_addr != INADDR_ANY) {
			do_bind = true;
		}
		is_inet = true;
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		if (lbsda->u.in6.sin6_port != 0) {
			do_reuseaddr = true;
			do_bind = true;
		}
		if (memcmp(&in6addr_any,
			   &lbsda->u.in6.sin6_addr,
			   sizeof(in6addr_any)) != 0) {
			do_bind = true;
		}
		is_inet = true;
		do_ipv6only = true;
		break;
#endif
	default:
		errno = EINVAL;
		return -1;
	}

	if (!do_bind && is_inet && rbsda) {
		sa_fam = rbsda->u.sa.sa_family;
		switch (sa_fam) {
		case AF_INET:
			do_ipv6only = false;
			break;
#ifdef HAVE_IPV6
		case AF_INET6:
			do_ipv6only = true;
			break;
#endif
		}
	}

	fd = socket(sa_fam, SOCK_DGRAM, 0);
	if (fd < 0) {
		return -1;
	}

	fd = tsocket_bsd_common_prepare_fd(fd, true);
	if (fd < 0) {
		return -1;
	}

	dgram = tdgram_context_create(mem_ctx,
				      &tdgram_bsd_ops,
				      &bsds,
				      struct tdgram_bsd,
				      location);
	if (!dgram) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	ZERO_STRUCTP(bsds);
	bsds->fd = fd;
	talloc_set_destructor(bsds, tdgram_bsd_destructor);

#ifdef HAVE_IPV6
	if (do_ipv6only) {
		int val = 1;

		ret = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
				 (const void *)&val, sizeof(val));
		if (ret == -1) {
			int saved_errno = errno;
			talloc_free(dgram);
			errno = saved_errno;
			return -1;
		}
	}
#endif

	if (broadcast) {
		int val = 1;

		ret = setsockopt(fd, SOL_SOCKET, SO_BROADCAST,
				 (const void *)&val, sizeof(val));
		if (ret == -1) {
			int saved_errno = errno;
			talloc_free(dgram);
			errno = saved_errno;
			return -1;
		}
	}

	if (do_reuseaddr) {
		int val = 1;

		ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
				 (const void *)&val, sizeof(val));
		if (ret == -1) {
			int saved_errno = errno;
			talloc_free(dgram);
			errno = saved_errno;
			return -1;
		}
	}

	if (do_bind) {
		ret = bind(fd, &lbsda->u.sa, lbsda->sa_socklen);
		if (ret == -1) {
			int saved_errno = errno;
			talloc_free(dgram);
			errno = saved_errno;
			return -1;
		}
	}

	if (rbsda) {
		if (rbsda->u.sa.sa_family != sa_fam) {
			talloc_free(dgram);
			errno = EINVAL;
			return -1;
		}

		ret = connect(fd, &rbsda->u.sa, rbsda->sa_socklen);
		if (ret == -1) {
			int saved_errno = errno;
			talloc_free(dgram);
			errno = saved_errno;
			return -1;
		}
	}

	*_dgram = dgram;
	return 0;
}

int _tdgram_bsd_existing_socket(TALLOC_CTX *mem_ctx,
				int fd,
				struct tdgram_context **_dgram,
				const char *location)
{
	struct tdgram_context *dgram;
	struct tdgram_bsd *bsds;
#ifdef HAVE_LINUX_RTNETLINK_H
	int result;
	struct sockaddr sa;
	socklen_t sa_len = sizeof(struct sockaddr);
#endif

	dgram = tdgram_context_create(mem_ctx,
				      &tdgram_bsd_ops,
				      &bsds,
				      struct tdgram_bsd,
				      location);
	if (!dgram) {
		return -1;
	}
	ZERO_STRUCTP(bsds);
	bsds->fd = fd;
	talloc_set_destructor(bsds, tdgram_bsd_destructor);

	*_dgram = dgram;

#ifdef HAVE_LINUX_RTNETLINK_H
	/*
	 * Try to determine the protocol family and remember if it's
	 * AF_NETLINK. We don't care if this fails.
	 */
	result = getsockname(fd, &sa, &sa_len);
	if (result == 0 && sa.sa_family == AF_NETLINK) {
		bsds->netlink = true;
	}
#endif

	return 0;
}

int _tdgram_inet_udp_socket(const struct tsocket_address *local,
			    const struct tsocket_address *remote,
			    TALLOC_CTX *mem_ctx,
			    struct tdgram_context **dgram,
			    const char *location)
{
	struct samba_sockaddr *lbsda =
		talloc_get_type_abort(local->private_data,
		struct samba_sockaddr);
	int ret;

	switch (lbsda->u.sa.sa_family) {
	case AF_INET:
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		break;
#endif
	default:
		errno = EINVAL;
		return -1;
	}

	ret = tdgram_bsd_dgram_socket(local, remote, false,
				      mem_ctx, dgram, location);

	return ret;
}

int _tdgram_inet_udp_broadcast_socket(const struct tsocket_address *local,
				      TALLOC_CTX *mem_ctx,
				      struct tdgram_context **dgram,
				      const char *location)
{
	struct samba_sockaddr *lbsda =
		talloc_get_type_abort(local->private_data,
		struct samba_sockaddr);
	int ret;

	switch (lbsda->u.sa.sa_family) {
	case AF_INET:
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		/* only ipv4 */
		errno = EINVAL;
		return -1;
#endif
	default:
		errno = EINVAL;
		return -1;
	}

	ret = tdgram_bsd_dgram_socket(local, NULL, true,
				      mem_ctx, dgram, location);

	return ret;
}

int _tdgram_unix_socket(const struct tsocket_address *local,
			const struct tsocket_address *remote,
			TALLOC_CTX *mem_ctx,
			struct tdgram_context **dgram,
			const char *location)
{
	struct samba_sockaddr *lbsda =
		talloc_get_type_abort(local->private_data,
		struct samba_sockaddr);
	int ret;

	switch (lbsda->u.sa.sa_family) {
	case AF_UNIX:
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	ret = tdgram_bsd_dgram_socket(local, remote, false,
				      mem_ctx, dgram, location);

	return ret;
}

struct tstream_bsd {
	int fd;
	int error;

	void *event_ptr;
	struct tevent_fd *fde;
	bool optimize_readv;

	void *readable_private;
	void (*readable_handler)(void *private_data);
	void *writeable_private;
	void (*writeable_handler)(void *private_data);

	struct tevent_context *error_ctx;
	struct tevent_timer *error_timer;
};

bool tstream_bsd_optimize_readv(struct tstream_context *stream,
				bool on)
{
	struct tstream_bsd *bsds =
		talloc_get_type(_tstream_context_data(stream),
		struct tstream_bsd);
	bool old;

	if (bsds == NULL) {
		/* not a bsd socket */
		return false;
	}

	old = bsds->optimize_readv;
	bsds->optimize_readv = on;

	return old;
}

static void tstream_bsd_error_timer(struct tevent_context *ev,
				    struct tevent_timer *te,
				    struct timeval current_time,
				    void *private_data)
{
	struct tstream_bsd *bsds =
		talloc_get_type(private_data,
		struct tstream_bsd);

	TALLOC_FREE(bsds->error_timer);

	/*
	 * Turn on TEVENT_FD_READABLE() again
	 * if we have a writeable_handler that
	 * wants to monitor the connection
	 * for errors.
	 */
	if (bsds->writeable_handler != NULL) {
		TEVENT_FD_READABLE(bsds->fde);
	}
}

static void tstream_bsd_fde_handler(struct tevent_context *ev,
				    struct tevent_fd *fde,
				    uint16_t flags,
				    void *private_data)
{
	struct tstream_bsd *bsds = talloc_get_type_abort(private_data,
				   struct tstream_bsd);

	if (flags & TEVENT_FD_WRITE) {
		bsds->writeable_handler(bsds->writeable_private);
		return;
	}
	if (flags & TEVENT_FD_READ) {
		if (!bsds->readable_handler) {
			struct timeval recheck_time;

			/*
			 * In order to avoid cpu-spinning
			 * we no longer want to get TEVENT_FD_READ
			 */
			TEVENT_FD_NOT_READABLE(bsds->fde);

			if (!bsds->writeable_handler) {
				return;
			}

			/*
			 * If we have a writeable handler we
			 * want that to report connection errors
			 * early.
			 *
			 * So we check if the socket is in an
			 * error state.
			 */
			if (bsds->error == 0) {
				int ret = tsocket_bsd_error(bsds->fd);

				if (ret == -1) {
					bsds->error = errno;
				}
			}

			if (bsds->error != 0) {
				/*
				 * Let the writeable handler report the error
				 */
				bsds->writeable_handler(bsds->writeable_private);
				return;
			}

			/*
			 * Here we called TEVENT_FD_NOT_READABLE() without
			 * calling into the writeable handler.
			 *
			 * So we may have to wait for the kernels tcp stack
			 * to report TEVENT_FD_WRITE in order to let
			 * make progress and turn on TEVENT_FD_READABLE()
			 * again.
			 *
			 * As a fallback we use a timer that turns on
			 * TEVENT_FD_READABLE() again after a timeout of
			 * 1 second.
			 */

			if (bsds->error_timer != NULL) {
				return;
			}

			recheck_time = timeval_current_ofs(1, 0);
			bsds->error_timer = tevent_add_timer(bsds->error_ctx,
							     bsds,
							     recheck_time,
							     tstream_bsd_error_timer,
							     bsds);
			if (bsds->error_timer == NULL) {
				bsds->error = ENOMEM;
				/*
				 * Let the writeable handler report the error
				 */
				bsds->writeable_handler(bsds->writeable_private);
				return;
			}
			return;
		}
		bsds->readable_handler(bsds->readable_private);
		return;
	}
}

static int tstream_bsd_set_readable_handler(struct tstream_bsd *bsds,
					    struct tevent_context *ev,
					    void (*handler)(void *private_data),
					    void *private_data)
{
	if (ev == NULL) {
		if (handler) {
			errno = EINVAL;
			return -1;
		}
		if (!bsds->readable_handler) {
			return 0;
		}
		bsds->readable_handler = NULL;
		bsds->readable_private = NULL;

		return 0;
	}

	/* read and write must use the same tevent_context */
	if (bsds->event_ptr != ev) {
		if (bsds->readable_handler || bsds->writeable_handler) {
			errno = EINVAL;
			return -1;
		}
		bsds->event_ptr = NULL;
		TALLOC_FREE(bsds->fde);
	}

	if (tevent_fd_get_flags(bsds->fde) == 0) {
		TALLOC_FREE(bsds->fde);

		bsds->fde = tevent_add_fd(ev, bsds,
					  bsds->fd, TEVENT_FD_READ,
					  tstream_bsd_fde_handler,
					  bsds);
		if (!bsds->fde) {
			errno = ENOMEM;
			return -1;
		}

		/* cache the event context we're running on */
		bsds->event_ptr = ev;
	} else if (!bsds->readable_handler) {
		TEVENT_FD_READABLE(bsds->fde);
	}

	TALLOC_FREE(bsds->error_timer);

	bsds->readable_handler = handler;
	bsds->readable_private = private_data;

	return 0;
}

static int tstream_bsd_set_writeable_handler(struct tstream_bsd *bsds,
					     struct tevent_context *ev,
					     void (*handler)(void *private_data),
					     void *private_data)
{
	if (ev == NULL) {
		if (handler) {
			errno = EINVAL;
			return -1;
		}
		if (!bsds->writeable_handler) {
			return 0;
		}
		bsds->writeable_handler = NULL;
		bsds->writeable_private = NULL;
		TEVENT_FD_NOT_WRITEABLE(bsds->fde);
		TALLOC_FREE(bsds->error_timer);
		bsds->error_ctx = NULL;
		return 0;
	}

	/* read and write must use the same tevent_context */
	if (bsds->event_ptr != ev) {
		if (bsds->readable_handler || bsds->writeable_handler) {
			errno = EINVAL;
			return -1;
		}
		bsds->event_ptr = NULL;
		TALLOC_FREE(bsds->fde);
		TALLOC_FREE(bsds->error_timer);
		bsds->error_ctx = NULL;
	}

	if (tevent_fd_get_flags(bsds->fde) == 0) {
		TALLOC_FREE(bsds->fde);

		bsds->fde = tevent_add_fd(ev, bsds,
					  bsds->fd,
					  TEVENT_FD_READ | TEVENT_FD_WRITE,
					  tstream_bsd_fde_handler,
					  bsds);
		if (!bsds->fde) {
			errno = ENOMEM;
			return -1;
		}

		/* cache the event context we're running on */
		bsds->event_ptr = ev;
	} else if (!bsds->writeable_handler) {
		uint16_t flags = tevent_fd_get_flags(bsds->fde);
		flags |= TEVENT_FD_READ | TEVENT_FD_WRITE;
		tevent_fd_set_flags(bsds->fde, flags);
	}

	bsds->writeable_handler = handler;
	bsds->writeable_private = private_data;
	bsds->error_ctx = ev;

	return 0;
}

static ssize_t tstream_bsd_pending_bytes(struct tstream_context *stream)
{
	struct tstream_bsd *bsds = tstream_context_data(stream,
				   struct tstream_bsd);
	ssize_t ret;

	if (bsds->fd == -1) {
		errno = ENOTCONN;
		return -1;
	}

	if (bsds->error != 0) {
		errno = bsds->error;
		return -1;
	}

	ret = tsocket_bsd_pending(bsds->fd);
	if (ret == -1) {
		/*
		 * remember the error and don't
		 * allow further requests
		 */
		bsds->error = errno;
	}

	return ret;
}

struct tstream_bsd_readv_state {
	struct tstream_context *stream;

	struct iovec *vector;
	size_t count;

	int ret;
};

static int tstream_bsd_readv_destructor(struct tstream_bsd_readv_state *state)
{
	struct tstream_bsd *bsds = tstream_context_data(state->stream,
				   struct tstream_bsd);

	tstream_bsd_set_readable_handler(bsds, NULL, NULL, NULL);

	return 0;
}

static void tstream_bsd_readv_handler(void *private_data);

static struct tevent_req *tstream_bsd_readv_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct tstream_context *stream,
					struct iovec *vector,
					size_t count)
{
	struct tevent_req *req;
	struct tstream_bsd_readv_state *state;
	struct tstream_bsd *bsds = tstream_context_data(stream, struct tstream_bsd);
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_bsd_readv_state);
	if (!req) {
		return NULL;
	}

	state->stream	= stream;
	/* we make a copy of the vector so that we can modify it */
	state->vector	= talloc_array(state, struct iovec, count);
	if (tevent_req_nomem(state->vector, req)) {
		goto post;
	}
	memcpy(state->vector, vector, sizeof(struct iovec)*count);
	state->count	= count;
	state->ret	= 0;

	talloc_set_destructor(state, tstream_bsd_readv_destructor);

	if (bsds->fd == -1) {
		tevent_req_error(req, ENOTCONN);
		goto post;
	}

	/*
	 * this is a fast path, not waiting for the
	 * socket to become explicit readable gains
	 * about 10%-20% performance in benchmark tests.
	 */
	if (bsds->optimize_readv) {
		/*
		 * We only do the optimization on
		 * readv if the caller asked for it.
		 *
		 * This is needed because in most cases
		 * we prefer to flush send buffers before
		 * receiving incoming requests.
		 */
		tstream_bsd_readv_handler(req);
		if (!tevent_req_is_in_progress(req)) {
			goto post;
		}
	}

	ret = tstream_bsd_set_readable_handler(bsds, ev,
					      tstream_bsd_readv_handler,
					      req);
	if (ret == -1) {
		tevent_req_error(req, errno);
		goto post;
	}

	return req;

 post:
	tevent_req_post(req, ev);
	return req;
}

static void tstream_bsd_readv_handler(void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(private_data,
				 struct tevent_req);
	struct tstream_bsd_readv_state *state = tevent_req_data(req,
					struct tstream_bsd_readv_state);
	struct tstream_context *stream = state->stream;
	struct tstream_bsd *bsds = tstream_context_data(stream, struct tstream_bsd);
	int ret;
	int err;
	int _count;
	bool ok, retry;

	if (bsds->error != 0) {
		tevent_req_error(req, bsds->error);
		return;
	}

	ret = readv(bsds->fd, state->vector, state->count);
	if (ret == 0) {
		/* propagate end of file */
		bsds->error = EPIPE;
		tevent_req_error(req, EPIPE);
		return;
	}
	err = tsocket_bsd_error_from_errno(ret, errno, &retry);
	if (retry) {
		/* retry later */
		return;
	}
	if (err != 0) {
		/*
		 * remember the error and don't
		 * allow further requests
		 */
		bsds->error = err;
	}
	if (tevent_req_error(req, err)) {
		return;
	}

	state->ret += ret;

	_count = state->count; /* tstream has size_t count, readv has int */
	ok = iov_advance(&state->vector, &_count, ret);
	state->count = _count;

	if (!ok) {
		tevent_req_error(req, EINVAL);
		return;
	}

	if (state->count > 0) {
		/* we have more to read */
		return;
	}

	tevent_req_done(req);
}

static int tstream_bsd_readv_recv(struct tevent_req *req,
				  int *perrno)
{
	struct tstream_bsd_readv_state *state = tevent_req_data(req,
					struct tstream_bsd_readv_state);
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}

	tevent_req_received(req);
	return ret;
}

struct tstream_bsd_writev_state {
	struct tstream_context *stream;

	struct iovec *vector;
	size_t count;

	int ret;
};

static int tstream_bsd_writev_destructor(struct tstream_bsd_writev_state *state)
{
	struct tstream_bsd *bsds = tstream_context_data(state->stream,
				  struct tstream_bsd);

	tstream_bsd_set_writeable_handler(bsds, NULL, NULL, NULL);

	return 0;
}

static void tstream_bsd_writev_handler(void *private_data);

static struct tevent_req *tstream_bsd_writev_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct tstream_context *stream,
						 const struct iovec *vector,
						 size_t count)
{
	struct tevent_req *req;
	struct tstream_bsd_writev_state *state;
	struct tstream_bsd *bsds = tstream_context_data(stream, struct tstream_bsd);
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_bsd_writev_state);
	if (!req) {
		return NULL;
	}

	state->stream	= stream;
	/* we make a copy of the vector so that we can modify it */
	state->vector	= talloc_array(state, struct iovec, count);
	if (tevent_req_nomem(state->vector, req)) {
		goto post;
	}
	memcpy(state->vector, vector, sizeof(struct iovec)*count);
	state->count	= count;
	state->ret	= 0;

	talloc_set_destructor(state, tstream_bsd_writev_destructor);

	if (bsds->fd == -1) {
		tevent_req_error(req, ENOTCONN);
		goto post;
	}

	/*
	 * this is a fast path, not waiting for the
	 * socket to become explicit writeable gains
	 * about 10%-20% performance in benchmark tests.
	 */
	tstream_bsd_writev_handler(req);
	if (!tevent_req_is_in_progress(req)) {
		goto post;
	}

	ret = tstream_bsd_set_writeable_handler(bsds, ev,
					       tstream_bsd_writev_handler,
					       req);
	if (ret == -1) {
		tevent_req_error(req, errno);
		goto post;
	}

	return req;

 post:
	tevent_req_post(req, ev);
	return req;
}

static void tstream_bsd_writev_handler(void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(private_data,
				 struct tevent_req);
	struct tstream_bsd_writev_state *state = tevent_req_data(req,
					struct tstream_bsd_writev_state);
	struct tstream_context *stream = state->stream;
	struct tstream_bsd *bsds = tstream_context_data(stream, struct tstream_bsd);
	ssize_t ret;
	int err;
	int _count;
	bool ok, retry;

	if (bsds->error != 0) {
		tevent_req_error(req, bsds->error);
		return;
	}

	ret = writev(bsds->fd, state->vector, state->count);
	if (ret == 0) {
		/* propagate end of file */
		bsds->error = EPIPE;
		tevent_req_error(req, EPIPE);
		return;
	}
	err = tsocket_bsd_error_from_errno(ret, errno, &retry);
	if (retry) {
		/*
		 * retry later...
		 *
		 * make sure we also wait readable again
		 * in order to notice errors early
		 */
		TEVENT_FD_READABLE(bsds->fde);
		TALLOC_FREE(bsds->error_timer);
		return;
	}
	if (err != 0) {
		/*
		 * remember the error and don't
		 * allow further requests
		 */
		bsds->error = err;
	}
	if (tevent_req_error(req, err)) {
		return;
	}

	state->ret += ret;

	_count = state->count; /* tstream has size_t count, writev has int */
	ok = iov_advance(&state->vector, &_count, ret);
	state->count = _count;

	if (!ok) {
		tevent_req_error(req, EINVAL);
		return;
	}

	if (state->count > 0) {
		/*
		 * we have more to write
		 *
		 * make sure we also wait readable again
		 * in order to notice errors early
		 */
		TEVENT_FD_READABLE(bsds->fde);
		return;
	}

	tevent_req_done(req);
}

static int tstream_bsd_writev_recv(struct tevent_req *req, int *perrno)
{
	struct tstream_bsd_writev_state *state = tevent_req_data(req,
					struct tstream_bsd_writev_state);
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}

	tevent_req_received(req);
	return ret;
}

struct tstream_bsd_disconnect_state {
	void *__dummy;
};

static struct tevent_req *tstream_bsd_disconnect_send(TALLOC_CTX *mem_ctx,
						     struct tevent_context *ev,
						     struct tstream_context *stream)
{
	struct tstream_bsd *bsds = tstream_context_data(stream, struct tstream_bsd);
	struct tevent_req *req;
	struct tstream_bsd_disconnect_state *state;
	int ret;
	int err;
	bool dummy;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_bsd_disconnect_state);
	if (req == NULL) {
		return NULL;
	}

	if (bsds->fd == -1) {
		tevent_req_error(req, ENOTCONN);
		goto post;
	}

	TALLOC_FREE(bsds->error_timer);
	bsds->error_ctx = NULL;
	TALLOC_FREE(bsds->fde);
	ret = close(bsds->fd);
	bsds->fd = -1;
	err = tsocket_bsd_error_from_errno(ret, errno, &dummy);
	if (tevent_req_error(req, err)) {
		goto post;
	}

	tevent_req_done(req);
post:
	tevent_req_post(req, ev);
	return req;
}

static int tstream_bsd_disconnect_recv(struct tevent_req *req,
				      int *perrno)
{
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);

	tevent_req_received(req);
	return ret;
}

static const struct tstream_context_ops tstream_bsd_ops = {
	.name			= "bsd",

	.pending_bytes		= tstream_bsd_pending_bytes,

	.readv_send		= tstream_bsd_readv_send,
	.readv_recv		= tstream_bsd_readv_recv,

	.writev_send		= tstream_bsd_writev_send,
	.writev_recv		= tstream_bsd_writev_recv,

	.disconnect_send	= tstream_bsd_disconnect_send,
	.disconnect_recv	= tstream_bsd_disconnect_recv,
};

static int tstream_bsd_destructor(struct tstream_bsd *bsds)
{
	TALLOC_FREE(bsds->error_timer);
	bsds->error_ctx = NULL;
	TALLOC_FREE(bsds->fde);
	if (bsds->fd != -1) {
		close(bsds->fd);
		bsds->fd = -1;
	}
	return 0;
}

int _tstream_bsd_existing_socket(TALLOC_CTX *mem_ctx,
				 int fd,
				 struct tstream_context **_stream,
				 const char *location)
{
	struct tstream_context *stream;
	struct tstream_bsd *bsds;

	stream = tstream_context_create(mem_ctx,
					&tstream_bsd_ops,
					&bsds,
					struct tstream_bsd,
					location);
	if (!stream) {
		return -1;
	}
	ZERO_STRUCTP(bsds);
	bsds->fd = fd;
	talloc_set_destructor(bsds, tstream_bsd_destructor);

	*_stream = stream;
	return 0;
}

struct tstream_bsd_connect_state {
	int fd;
	struct tevent_fd *fde;
	struct tstream_conext *stream;
	struct tsocket_address *local;
};

static int tstream_bsd_connect_destructor(struct tstream_bsd_connect_state *state)
{
	TALLOC_FREE(state->fde);
	if (state->fd != -1) {
		close(state->fd);
		state->fd = -1;
	}

	return 0;
}

static void tstream_bsd_connect_fde_handler(struct tevent_context *ev,
					    struct tevent_fd *fde,
					    uint16_t flags,
					    void *private_data);

static struct tevent_req *tstream_bsd_connect_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					int sys_errno,
					const struct tsocket_address *local,
					const struct tsocket_address *remote)
{
	struct tevent_req *req;
	struct tstream_bsd_connect_state *state;
	struct samba_sockaddr *lbsda =
		talloc_get_type_abort(local->private_data,
		struct samba_sockaddr);
	struct samba_sockaddr *lrbsda = NULL;
	struct samba_sockaddr *rbsda =
		talloc_get_type_abort(remote->private_data,
		struct samba_sockaddr);
	int ret;
	bool do_bind = false;
	bool do_reuseaddr = false;
	bool do_ipv6only = false;
	bool is_inet = false;
	int sa_fam = lbsda->u.sa.sa_family;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_bsd_connect_state);
	if (!req) {
		return NULL;
	}
	state->fd = -1;
	state->fde = NULL;

	talloc_set_destructor(state, tstream_bsd_connect_destructor);

	/* give the wrappers a chance to report an error */
	if (sys_errno != 0) {
		tevent_req_error(req, sys_errno);
		goto post;
	}

	switch (lbsda->u.sa.sa_family) {
	case AF_UNIX:
		if (lbsda->u.un.sun_path[0] != 0) {
			do_reuseaddr = true;
			do_bind = true;
		}
		break;
	case AF_INET:
		if (lbsda->u.in.sin_port != 0) {
			do_reuseaddr = true;
			do_bind = true;
		}
		if (lbsda->u.in.sin_addr.s_addr != INADDR_ANY) {
			do_bind = true;
		}
		is_inet = true;
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		if (lbsda->u.in6.sin6_port != 0) {
			do_reuseaddr = true;
			do_bind = true;
		}
		if (memcmp(&in6addr_any,
			   &lbsda->u.in6.sin6_addr,
			   sizeof(in6addr_any)) != 0) {
			do_bind = true;
		}
		is_inet = true;
		do_ipv6only = true;
		break;
#endif
	default:
		tevent_req_error(req, EINVAL);
		goto post;
	}

	if (!do_bind && is_inet) {
		sa_fam = rbsda->u.sa.sa_family;
		switch (sa_fam) {
		case AF_INET:
			do_ipv6only = false;
			break;
#ifdef HAVE_IPV6
		case AF_INET6:
			do_ipv6only = true;
			break;
#endif
		}
	}

	if (is_inet) {
		state->local = tsocket_address_create(state,
						      &tsocket_address_bsd_ops,
						      &lrbsda,
						      struct samba_sockaddr,
						      __location__ "bsd_connect");
		if (tevent_req_nomem(state->local, req)) {
			goto post;
		}

		ZERO_STRUCTP(lrbsda);
		lrbsda->sa_socklen = sizeof(lrbsda->u.ss);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		lrbsda->u.sa.sa_len = lrbsda->sa_socklen;
#endif
	}

	state->fd = socket(sa_fam, SOCK_STREAM, 0);
	if (state->fd == -1) {
		tevent_req_error(req, errno);
		goto post;
	}

	state->fd = tsocket_bsd_common_prepare_fd(state->fd, true);
	if (state->fd == -1) {
		tevent_req_error(req, errno);
		goto post;
	}

#ifdef HAVE_IPV6
	if (do_ipv6only) {
		int val = 1;

		ret = setsockopt(state->fd, IPPROTO_IPV6, IPV6_V6ONLY,
				 (const void *)&val, sizeof(val));
		if (ret == -1) {
			tevent_req_error(req, errno);
			goto post;
		}
	}
#endif

	if (do_reuseaddr) {
		int val = 1;

		ret = setsockopt(state->fd, SOL_SOCKET, SO_REUSEADDR,
				 (const void *)&val, sizeof(val));
		if (ret == -1) {
			tevent_req_error(req, errno);
			goto post;
		}
	}

	if (do_bind) {
		ret = bind(state->fd, &lbsda->u.sa, lbsda->sa_socklen);
		if (ret == -1) {
			tevent_req_error(req, errno);
			goto post;
		}
	}

	if (rbsda->u.sa.sa_family != sa_fam) {
		tevent_req_error(req, EINVAL);
		goto post;
	}

	ret = connect(state->fd, &rbsda->u.sa, rbsda->sa_socklen);
	if (ret == -1) {
		if (errno == EINPROGRESS) {
			goto async;
		}
		tevent_req_error(req, errno);
		goto post;
	}

	if (!state->local) {
		tevent_req_done(req);
		goto post;
	}

	if (lrbsda != NULL) {
		ret = getsockname(state->fd,
				  &lrbsda->u.sa,
				  &lrbsda->sa_socklen);
		if (ret == -1) {
			tevent_req_error(req, errno);
			goto post;
		}
	}

	tevent_req_done(req);
	goto post;

 async:

	/*
	 * Note for historic reasons TEVENT_FD_WRITE is not enough
	 * to get notified for POLLERR or EPOLLHUP even if they
	 * come together with POLLOUT. That means we need to
	 * use TEVENT_FD_READ in addition until we have
	 * TEVENT_FD_ERROR.
	 */
	state->fde = tevent_add_fd(ev, state,
				   state->fd,
				   TEVENT_FD_READ | TEVENT_FD_WRITE,
				   tstream_bsd_connect_fde_handler,
				   req);
	if (tevent_req_nomem(state->fde, req)) {
		goto post;
	}

	return req;

 post:
	tevent_req_post(req, ev);
	return req;
}

static void tstream_bsd_connect_fde_handler(struct tevent_context *ev,
					    struct tevent_fd *fde,
					    uint16_t flags,
					    void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(private_data,
				 struct tevent_req);
	struct tstream_bsd_connect_state *state = tevent_req_data(req,
					struct tstream_bsd_connect_state);
	struct samba_sockaddr *lrbsda = NULL;
	int ret;
	int error=0;
	socklen_t len = sizeof(error);
	int err;
	bool retry;

	ret = getsockopt(state->fd, SOL_SOCKET, SO_ERROR, &error, &len);
	if (ret == 0) {
		if (error != 0) {
			errno = error;
			ret = -1;
		}
	}
	err = tsocket_bsd_error_from_errno(ret, errno, &retry);
	if (retry) {
		/* retry later */
		return;
	}
	if (tevent_req_error(req, err)) {
		return;
	}

	if (!state->local) {
		tevent_req_done(req);
		return;
	}

	lrbsda = talloc_get_type_abort(state->local->private_data,
				       struct samba_sockaddr);

	ret = getsockname(state->fd, &lrbsda->u.sa, &lrbsda->sa_socklen);
	if (ret == -1) {
		tevent_req_error(req, errno);
		return;
	}

	tevent_req_done(req);
}

static int tstream_bsd_connect_recv(struct tevent_req *req,
				    int *perrno,
				    TALLOC_CTX *mem_ctx,
				    struct tstream_context **stream,
				    struct tsocket_address **local,
				    const char *location)
{
	struct tstream_bsd_connect_state *state = tevent_req_data(req,
					struct tstream_bsd_connect_state);
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = _tstream_bsd_existing_socket(mem_ctx,
						   state->fd,
						   stream,
						   location);
		if (ret == -1) {
			*perrno = errno;
			goto done;
		}
		TALLOC_FREE(state->fde);
		state->fd = -1;

		if (local) {
			*local = talloc_move(mem_ctx, &state->local);
		}
	}

done:
	tevent_req_received(req);
	return ret;
}

struct tevent_req * tstream_inet_tcp_connect_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const struct tsocket_address *local,
					const struct tsocket_address *remote)
{
	struct samba_sockaddr *lbsda =
		talloc_get_type_abort(local->private_data,
		struct samba_sockaddr);
	struct tevent_req *req;
	int sys_errno = 0;

	switch (lbsda->u.sa.sa_family) {
	case AF_INET:
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		break;
#endif
	default:
		sys_errno = EINVAL;
		break;
	}

	req = tstream_bsd_connect_send(mem_ctx, ev, sys_errno, local, remote);

	return req;
}

int _tstream_inet_tcp_connect_recv(struct tevent_req *req,
				   int *perrno,
				   TALLOC_CTX *mem_ctx,
				   struct tstream_context **stream,
				   struct tsocket_address **local,
				   const char *location)
{
	return tstream_bsd_connect_recv(req, perrno,
					mem_ctx, stream, local,
					location);
}

struct tevent_req * tstream_unix_connect_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const struct tsocket_address *local,
					const struct tsocket_address *remote)
{
	struct samba_sockaddr *lbsda =
		talloc_get_type_abort(local->private_data,
		struct samba_sockaddr);
	struct tevent_req *req;
	int sys_errno = 0;

	switch (lbsda->u.sa.sa_family) {
	case AF_UNIX:
		break;
	default:
		sys_errno = EINVAL;
		break;
	}

	req = tstream_bsd_connect_send(mem_ctx, ev, sys_errno, local, remote);

	return req;
}

int _tstream_unix_connect_recv(struct tevent_req *req,
				      int *perrno,
				      TALLOC_CTX *mem_ctx,
				      struct tstream_context **stream,
				      const char *location)
{
	return tstream_bsd_connect_recv(req, perrno,
					mem_ctx, stream, NULL,
					location);
}

int _tstream_unix_socketpair(TALLOC_CTX *mem_ctx1,
			     struct tstream_context **_stream1,
			     TALLOC_CTX *mem_ctx2,
			     struct tstream_context **_stream2,
			     const char *location)
{
	int ret;
	int fds[2];
	int fd1;
	int fd2;
	struct tstream_context *stream1 = NULL;
	struct tstream_context *stream2 = NULL;

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	if (ret == -1) {
		return -1;
	}
	fd1 = fds[0];
	fd2 = fds[1];

	fd1 = tsocket_bsd_common_prepare_fd(fd1, true);
	if (fd1 == -1) {
		int sys_errno = errno;
		close(fd2);
		errno = sys_errno;
		return -1;
	}

	fd2 = tsocket_bsd_common_prepare_fd(fd2, true);
	if (fd2 == -1) {
		int sys_errno = errno;
		close(fd1);
		errno = sys_errno;
		return -1;
	}

	ret = _tstream_bsd_existing_socket(mem_ctx1,
					   fd1,
					   &stream1,
					   location);
	if (ret == -1) {
		int sys_errno = errno;
		close(fd1);
		close(fd2);
		errno = sys_errno;
		return -1;
	}

	ret = _tstream_bsd_existing_socket(mem_ctx2,
					   fd2,
					   &stream2,
					   location);
	if (ret == -1) {
		int sys_errno = errno;
		talloc_free(stream1);
		close(fd2);
		errno = sys_errno;
		return -1;
	}

	*_stream1 = stream1;
	*_stream2 = stream2;
	return 0;
}


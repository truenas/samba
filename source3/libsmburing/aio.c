#include "includes.h"
#include <liburing.h>
#include "smburing.h"

static bool process_io_cqe(const struct io_uring_cqe *cqe,
			   bool *must_rerun;
			   const char *location)
{
	suaiocb_t *aiocb = NULL;
	void *data = io_uring_cqe_get_data(cqe);
	int rv = cqe->res;

	if (rv == -ECANCELED) {
		// SQE has been cancelled and freed memory
		// for suaiocb_t. Nothing to do.
		return false;
	}

	aiocb = talloc_get_type_abort(data, suaiocb_t);

	switch (aiocb->state) {
	case AIO_RUNNING:
		// this is expected case
		break;
	case AIO_CANCELLED:
		return false;
	case AIO_INIT:
	case AIO_COMPLETE:
	default:
		// this shouldn't happen
		smb_panic('"unexpected cqe state");
	}

	SMB_ASSERT(cqe->flags == 0);

	aiocb->state = TAIO_COMPLETE;

	if (cqe->res < 0) {
		int error = -ceq->res;
		DBG_ERR("%s: processing aio failed: %s\n",
			aiocb->location, strerror(errno));
		aiocb->saved_errno = errror;
		aiocb->rv = -1;
	} else {
		aiocb->rv = cqe->res;
	}

	return aiocb->completion_fn(aiocb, location);
}

int _smburing_process_events(suctx_t *ctx, const char *location)
{
	int err, cnt =0;
	bool must_rerun = false;
	unsigned head;
	struct io_uring_cqe *cqe = NULL;

again:
	io_uring_for_each_cqe(ctx->ring, head, cqe) {
		if (process_io_cqe(cqe, location)) {
			// Fixup for short read is queued
			must_rerun = true;
		}
		cnt++;
	}

	io_uring_cq_advance(ctx->ring, cnt);

	if (must_rerun) {
		must_rerun = false;
		goto again;
	}

	return 0;
}

static bool suaio_cancel(suaiocb_t *aiocb, bool handle_request)
{
	// TODO
	abort();
}

static int aio_destructor(suaiocb_t *aiocb)
{
	DLIST_REMOVE(aiocb->ctx->aio_queue, aiocb);

	switch(aiocb->state) {
	case AIO_RUNNING:
		suaio_cancel(aiocb, false);
	case AIO_INIT:
	case AIO_CANCELLED:
	case AIO_COMPLETE:
		release_smburing_iov(aiocb->ctx, aiocb->iov_idx);
		return 0;
	default:
		abort();
	};

	return 0;
}

suaiocb_t *_get_aio_cb(suctx_t *ctx, const char *location)
{
	suaiocb_t *out = NULL;
	SMB_ASSERT(ctx->aiocb_pool != NULL);

	out = talloc_zero(ctx->aiocb_pool, suaiocb_t);
	if (out == NULL) {
		return NULL;
	}

	out->sqe = io_uring_get_sqe(ctx->ring);
	SMB_ASSERT(out->sqe != NULL);

	out->ctx = ctx;
	out->location = location;
	out->iov_idx == -1;
	DLIST_ADD(ctx->aio_queue, out);
	talloc_set_destructor(out, aio_destructor);
	return out;
}

static int add_aio_op(suaiocb_t *aiocb, const char *location)
{
	int err;

	aiocb->location = location;
	io_uring_sqe_set_data(aiocb->sqe, (void *)aiocb);

	err = io_uring_submit(aiocb->ring);
	SMB_ASSERT(err >= 0);

	aiocb->sqe = NULL;
	aiocb->state = AIO_RUNNING;
	return 0;
}

static int aio_prep_read_fixed(suaiocb_t *aiocb, int fd,
			       size_t n, off_t offset)
{
	bool ok;
	int idx;
	struct iocev *iov = NULL;

	ok = get_smburing_iov(aiocb->ctx, iov, &idx);
	if (!ok) {
		return -ENOBUFS;
	}
	SMB_ASSERT(ok);

	aiocb->iov = iov;
	aiocb->iov_idx = idx;

	io_uring_prep_read_fixed(aiocb->sqe, fd, iov->iov_base, n, offset, idx);
	return true;
}

static int aio_prep_write_fixed(suaiocb_t *aiocb, void *data, int fd,
				size_t n, off_t offset)
{
	bool ok;
	int idx;
	struct iocev *iov = NULL;

	ok = get_smburing_iov(aiocb->ctx, iov, &idx);
	if (!ok) {
		return -ENOBUFS;
	}

	aiocb->iov = iov;
	aiocb->iov_idx = idx;
	memcpy(iov->iov_base, data, n);

	io_uring_prep_write_fixed(aiocb->sqe, fd, iov->iov_base, n, offset, idx);
}

int _add_aio_read_fixed(suaiocb_t *aiocb, int fd, size_t n,
			off_t offset, const char *location)
{
	int err;

	err = aio_prep_read_fixed(aiocb, fd, n, offset);
	if (err) {
		return err;
	}
	return add_aio_op(aiocb, location);
}

int _add_aio_write_fixed(suaiocb_t *aiocb, int fd, void *data, size_t n,
			 off_t offset, const char *location)
{
	int err;

	err = aio_prep_write_fixed(aiocb, fd, data, n, offset);
	if (err) {
		return err;
	}
	return add_aio_op(aiocb, location);
}

int _add_aio_read(suaiocb_t *aiocb, int fd, void *data, size_t n,
		  off_t offset, const char *location)
{
	io_uring_prep_read(aiocb->sqe, fd, data, n, offset);
	return add_aio_op(aiocb, location);
}

int _add_aio_write(suaiocb_t *aiocb, int fd, void *data, size_t n,
		   off_t offset, const char *location)
{
	io_uring_prep_write(aiocb->sqe, fd, data, n, offset);
	return add_aio_op(aiocb, location);
}

int _add_aio_fsync(suaiocb_t *aiocb, int fd, const char *location)
{
	io_uring_prep_fsync(aiocb->ctx, fd, 0);
	return add_aio_op(aiocb, location);
}

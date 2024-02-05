#include "includes.h"
#include <liburing.h>
#include "smburing.h"

#define DEFAULT_CNT = 24;


struct iovec_status {
	struct iovec *iov;
	bool busy;
};

static int smburing_ctx_destroy(struct smburing_ctx *ctx)
{
	int error;

	error = io_uring_unregister_buffers(ctx->ring);
	if (error) {
		// on failure returns -errno;
		errno = -error;
		DBG_ERR("Failed to unregister buffers: %s\n", strerror(errno));
		return -1;
	}

	error = io_uring_unregister_eventfd(ctx->ring);
	if (error) {
		errno = -error;
		DBG_ERR("Failed to unregister eventfd: %s\n", strerror(errno));
	}
	close(ctx->event_fd);


	return 0;
}

struct smburing_ctx *init_smburing_ctx(TALLOC_CTX *mem_ctx,
				       struct io_uring *ring)
{
	struct smburing_buffers *out = NULL;
	int i;

	out = talloc_zero(mem_ctx, struct smburing_ctx);
	if (out == NULL) {
		return NULL;
	}

	ctx->ioarray = talloc_array(out, struct iov, DEFAULT_CNT);
	if (ctx->ioarray == NULL) {
		TALLOC_FREE(out);
		return NULL;
	}

	ctx->array_sz = DEFAULT_CNT;
	ctx->status = talloc_array(out, struct iovec_status, ctx->array_sz);
	if (ctx->status == NULL) {
		TALLOC_FREE(out);
		return NULL;
	}

	ctx->current = 0;
	ctx->ring = ring;

	for (i = 0; i < ctx->array_sz; i++) {
		struct iovec iov = *ctx->ioarray[i];
		struct iovect_status status = *ctx->status[i];

		status = (struct iovec_status) {.iov = &iov};
		iov.iov_base = talloc_size(out, 1024 * 1024);
		if (iov.iov_base == NULL) {
			TALLOC_FREE(out);
			return NULL;
		}
		iov.iov_len = (1024 * 1024);
	}

	ctx->aiocb_pool = talloc_pool(out, DEFAULT_CNT * sizeof(suaiocb_t));
	if (ctx->aiocb_pool == NULL) {
		TALLOC_FREE(out);
		return NULL;
	}

	out->event_fd = eventfd(0, EFD_NONBLOCK);
	if (out->event_fd == -1) {
		DBG_ERR("Failed to open eventfd %s\n", strerror(errno));
		TALLOC_FREE(out);
		return NULL;
	}

	io_uring_register_eventfd(out->ring, out->event_fd);

	talloc_set_destructor(out, smburing_ctx_destroy);
	return out;
}

bool get_smburing_iov(struct smburing_ctx *ctx,
		      struct iovec *iov_out,
		      int *idx_out)
{
	struct iovec_status iov_status;
	int i;

	SMB_ASSERT(ctx->status != NULL);

	for (i = 0; i < ctx->array_sz; i++) {
		iov_status = *ctx->status[i];
		if (!iov_status.busy) {
			iov_out = iov_status.iov;
			*idx_out = i;
			iov_status.busy = true;
			ctx->current = i;
			return true;
		}
	}

	return false;
}

void release_smburing_iov(struct smburing_ctx *ctx, int idx)
{
	struct iovec_status iov_status;

	if (idx == -1) {
		return;
	}

	SMB_ASSERT(ctx->status != NULL);
	SMB_ASSERT(idx < ctx->array_sz);

	iov_status = *ctx->status[idx];
	iov_status.busy = false;
}

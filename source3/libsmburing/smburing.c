#include "includes.h"
#include <liburing.h>
#include <sys/eventfd.h>
#include "smburing.h"

#define DEFAULT_CNT 24


static int smburing_ctx_destroy(struct smburing_ctx *ctx)
{
	int error;

	error = io_uring_unregister_eventfd(&ctx->ring);
	if (error) {
		DBG_ERR("Failed to unregister eventfd: %s\n", strerror(-error));
	}

	close(ctx->event_fd);

	return 0;
}

struct smburing_ctx *init_smburing_ctx(TALLOC_CTX *mem_ctx, size_t uring_sz)
{
	struct smburing_ctx *ctx = NULL;
	int ret;

	ctx = talloc_zero(mem_ctx, struct smburing_ctx);
	if (ctx == NULL) {
		return NULL;
	}
	ret = io_uring_queue_init(uring_sz, &ctx->ring, 0);
	SMB_ASSERT(ret == 0);

	ctx->aiocb_pool = talloc_pool(ctx, uring_sz * sizeof(suaiocb_t));
	if (ctx->aiocb_pool == NULL) {
		TALLOC_FREE(ctx);
		return NULL;
	}

	ctx->event_fd = eventfd(0, EFD_NONBLOCK);
	if (ctx->event_fd == -1) {
		DBG_ERR("Failed to open eventfd %s\n", strerror(errno));
		TALLOC_FREE(ctx);
		return NULL;
	}

	io_uring_register_eventfd(&ctx->ring, ctx->event_fd);
	talloc_set_destructor(ctx, smburing_ctx_destroy);
	return ctx;
}

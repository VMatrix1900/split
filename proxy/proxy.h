#include <stdlib.h>
struct proxy_ctx_t {
    struct sockaddr_storage dstsock;
    socklen_t dstsocklen;
    int af;
    struct shm_ctx_t *cli_shm_ctx;
    struct shm_ctx_t *serv_shm_ctx;
};

void proxy_ctx_free(struct proxy_ctx_t *ctx)
{
    if (ctx->cli_shm_ctx) {
        free(ctx->cli_shm_ctx);
    }
    if (ctx->serv_shm_ctx) {
        free(ctx->serv_shm_ctx);
    }
    free(ctx);
}

#include <stdlib.h>
struct proxy_ctx_t {
    struct sockaddr_storage dstsock;
    socklen_t dstsocklen;
    int af;
    struct bufferevent *cli_bev;
    struct bufferevent *serv_bev;
    struct event *timer;
    struct shm_ctx_t *channel;
};

void proxy_ctx_free(struct proxy_ctx_t *ctx)
{
    if (!ctx->cli_bev) {
        free(ctx->cli_bev);
    }
    if (!ctx->serv_bev) {
        free(ctx->serv_bev);
    }
    free(ctx);
}

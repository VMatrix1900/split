#include <stdlib.h>
#include "constants.h"
struct pxy_conn {
    struct sockaddr_storage dstsock;
    socklen_t dstsocklen;
    int index;
    struct bufferevent *cli_bev;
    struct bufferevent *serv_bev;
    struct event *timer;
    struct shm_ctx_t *shm_ctx;
};

struct proxy_ctx {
    struct pxy_conn * conns[MAXCONNS];
    struct shm_ctx_t *shm_ctx;
    struct event *timer;
    struct event_base *base;
};

void
proxy_ctx_free(struct pxy_conn *ctx){
    if (!ctx->cli_bev) {
        free(ctx->cli_bev);
    }
    if (!ctx->serv_bev) {
        free(ctx->serv_bev);
    }
    free(ctx);
}

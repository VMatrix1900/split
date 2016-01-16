#include <stdlib.h>
#include "constants.h"

struct pxy_conn {
    int closed;
    struct sockaddr_storage dstsock;
    socklen_t dstsocklen;
    int index;
    struct bufferevent *cli_bev;
    struct bufferevent *serv_bev;
    struct event *timer;
    struct shm_ctx_t *shm_ctx;
    struct proxy_ctx *parent;
};

struct proxy_ctx {
    int counts;
    struct pxy_conn *conns[MAXCONNS];
    struct shm_ctx_t *shm_ctx;
    struct event *timer;
    struct event_base *base;
};

int find_next_slot(struct proxy_ctx *);

struct proxy_ctx *proxy_ctx_new();
void proxy_ctx_free(struct proxy_ctx *);
struct pxy_conn *pxy_conn_new(struct proxy_ctx *);
void pxy_conn_free(struct pxy_conn *);

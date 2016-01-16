#include "proxy_tcp.h"
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <stdio.h>

int find_next_slot(struct proxy_ctx *ctx)
{
    int i;
    for (i = ctx->counts; i < MAXCONNS; i++) {
        ctx->counts = (ctx->counts + 1) % MAXCONNS;
        if (!ctx->conns[i]) {
            return i;
        } else if (ctx->conns[i]->closed) {
            pxy_conn_free(ctx->conns[i]);
            return i;
        }
    }
    // can not find avaliable slot. is full;
    return -1;
}

struct pxy_conn *pxy_conn_new(struct proxy_ctx *ctx)
{
    struct pxy_conn *conn = malloc(sizeof(struct pxy_conn));
    // setup the proxy struct;
    conn->closed = 0;
    conn->cli_bev = NULL;
    conn->serv_bev = NULL;
    conn->shm_ctx = ctx->shm_ctx;
    conn->index = find_next_slot(ctx);
    if (conn->index == -1) {
        printf("pxy conn is full!\n");
        exit(-1);
    }
    conn->timer = ctx->timer;
    conn->parent = ctx;
    ctx->conns[conn->index] = conn;
    return conn;
}

void pxy_conn_free(struct pxy_conn *ctx)
{
    if (ctx->cli_bev) {
        bufferevent_free(ctx->cli_bev);
    }
    if (ctx->serv_bev) {
        bufferevent_free(ctx->serv_bev);
    }
    free(ctx);
}

void proxy_ctx_free(struct proxy_ctx *ctx) {}

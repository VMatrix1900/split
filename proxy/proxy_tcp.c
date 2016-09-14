#include "proxy_tcp.h"
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <stdio.h>
#include <string.h>

int find_next_slot(struct proxy_ctx *ctx)
{
  int i;
  for (i = ctx->counts; i < MAXCONNS; i++) {
    ctx->counts = (ctx->counts + 1) % MAXCONNS;
    if (!ctx->conns[i]) {
      return i;
    } else if (ctx->conns[i]->cli_state == CLOSED || ctx->conns[i]->serv_state == CLOSED) {
      pxy_conn_free(ctx->conns[i]);
      return i;
    }
  }
  // can not find avaliable slot. is full;
  return -1;
}

struct pxy_conn *pxy_conn_new(struct proxy_ctx *ctx)
{
  struct pxy_conn *conn = (struct pxy_conn*)malloc(sizeof(struct pxy_conn));
  // setup the proxy struct;
  conn->serv_state = OPEN;
  conn->cli_state = OPEN;
  conn->cli_bev = NULL;
  conn->serv_bev = NULL;
  conn->index = find_next_slot(ctx);
  if (conn->index == -1) {
    printf("pxy conn is full!\n");
    exit(-1);
  }
  conn->parent = ctx;
  ctx->conns[conn->index] = conn;
  return conn;
}

void pxy_conn_free(struct pxy_conn *ctx)
{
  if (ctx->cli_bev) {
    bufferevent_free(ctx->cli_bev);
    ctx->cli_bev = NULL;
  }
  if (ctx->serv_bev) {
    bufferevent_free(ctx->serv_bev);
    ctx->serv_bev = NULL;
  }
  printf("free %d\n", ctx->index);
}

struct proxy_ctx *proxy_ctx_new()
{
  struct proxy_ctx *proxy = malloc(sizeof(struct proxy_ctx));
  proxy->base = event_base_new();
  proxy->counts = 0;
  memset(proxy->conns, 0, MAXCONNS * sizeof(struct pxy_conns *));
  return proxy;
}

void proxy_ctx_free(struct proxy_ctx *ctx) {}

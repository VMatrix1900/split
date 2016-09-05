#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <string.h>

#include <fcntl.h>
#include <linux/netfilter_ipv4.h>
#include <semaphore.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/stat.h>
#include <assert.h>

#include "message.h"
#include "channel.hpp"
#include "proxy_tcp.h"

Channel TCP_to_SSL("tcp_to_ssl");
Channel SSL_to_TCP("ssl_to_tcp");

struct timeval usec = {0, 1};
struct timeval msec = {0, 600};

void log(std::string txt) { std::clog << txt << std::endl; }

int timecount = 0;
int nat_netfilter_lookup(struct sockaddr *dst_addr, socklen_t *dst_addrlen,
                         evutil_socket_t s, struct sockaddr *src_addr,
                         socklen_t src_addrlen) {
  int rv;

  if (src_addr->sa_family != AF_INET) {
    printf(
        "The netfilter NAT engine only "
        "supports IPv4 state lookups\n");
    return -1;
  }

  rv = getsockopt(s, SOL_IP, SO_ORIGINAL_DST, dst_addr, dst_addrlen);
  if (rv == -1) {
    perror("Error from getsockopt(SO_ORIGINAL_DST):");
  }
  return rv;
}

void cleanconn(evutil_socket_t fd, short what, void *ptr) {
  // globol timer trigger this one ptr is proxy_ctx
  struct proxy_ctx *ctx = (struct proxy_ctx *)ptr;
  event_del(ctx->cleantimer);
  int i;
  for (i = 0; i < MAXCONNS; i++) {
    if (ctx->conns[i] &&
        (ctx->conns[i]->cli_closed || ctx->conns[i]->serv_closed)) {
      pxy_conn_free(ctx->conns[i]);
    }
  }
}

void copydata(evutil_socket_t fd, short what, void *ptr) {
  // globol timer trigger this one ptr is proxy_ctx
  struct proxy_ctx *ctx = (struct proxy_ctx *)ptr;
  bool msg = false;
  struct bufferevent *bev;
  struct pxy_conn *conn;
  evtimer_del(ctx->timer);
  /* timecount ++; */
  /* if (timecount == 1000) { */
  // printf("enter copydata\n");

  /*   timecount = 0; */
  /* } */
  struct TLSPacket pi;
  while (SSL_to_TCP.pull_data(&pi, 35000) > 0) {
    msg = true;
    printf("Get [%d] %d from Genode\n", pi.id, pi.side);
    /* printf("get from genode\n"); */
    conn = ctx->conns[pi.id];
    // send to client side or server side.
    if (pi.side == server && !conn->serv_closed) {
      bev = conn->serv_bev;
    } else if (pi.side == client && !conn->cli_closed) {
      bev = conn->cli_bev;
    } else if (pi.side == close_server) {
      /* printf("[%d]: clean server\n", pi.id); */
      if (conn->serv_bev) {
        bufferevent_free(conn->serv_bev);
        conn->serv_bev = NULL;
      }
      conn->serv_closed = true;
      /* event_add(ctx->cleantimer, &msec); */
      continue;
    } else if (pi.side == close_client) {
      /* printf("[%d]: clean client\n", pi.id); */
      if (conn->cli_bev) {
        bufferevent_free(conn->cli_bev);
        conn->cli_bev = NULL;
      }
      conn->cli_closed = true;
      /* event_add(ctx->cleantimer, &msec); */
      continue;
    } else {
      /* printf("closed connection\n"); */
      continue;
    }
    int written = bufferevent_write(bev, pi.buffer, pi.size);
    if (written != 0) {
      /* printf("bufferevent write wrong\n"); */
    } else {
      /* printf("write correct\n"); */
    }
  }
  int r = evtimer_add(ctx->timer, &usec);
  if (r == -1) {
    /* printf("event add wrong\n"); */
  }
  if (msg && r == 0) {
    /* printf("timer add\n"); */
  }
}

void sendCloseToGenode(int id, enum packet_type side) {
  struct TLSPacket pi;
  pi.id = id;
  pi.side = side;
  pi.size = 10;
  while (TCP_to_SSL.put_data(
             &pi, pi.size + offsetof(struct TLSPacket, buffer)) < 0) {
    ;
  }
  std::string sidetxt = (side == close_client) ? "close_client" : "close_server";
  std::clog << "ID[" << pi.id << "] "
            << "Forward " << sidetxt << " to SSL."
            << "Size[" << pi.size << "]" << std::endl;
}

void readcb(struct bufferevent *bev, void *ptr, enum packet_type side) {
  struct pxy_conn *ctx = (struct pxy_conn *)ptr;

  struct TLSPacket pi;
  pi.id = ctx->index;
  pi.side = side;
  // char *write_pointer = *write;
  /* printf("Before write:%p\n", (void *)*write); */
  pi.size = bufferevent_read(bev, pi.buffer, MAX_MSG_SIZE);
  /* printf("After write:%p\n", (void *)*write); */
  /* char buffer[10000] = {'0'}; */
  /* memcpy(buffer, *write, pi.size); */
  if (pi.size > 0) {
    while (TCP_to_SSL.put_data(
               &pi, pi.size + offsetof(struct TLSPacket, buffer)) < 0) {
      ;
    }
    std::string sidetxt = (side == server) ? "server" : "client";
    std::clog << "ID[" << pi.id << "] "
              << "Forward " << sidetxt << " to SSL."
              << "Size[" << pi.size << "]" << std::endl;
  } else {
  }
}

void cli_readcb(struct bufferevent *bev, void *ptr) {
  log("cli read");
  readcb(bev, ptr, client);
}

void serv_readcb(struct bufferevent *bev, void *ptr) {
  log("serv read");
  readcb(bev, ptr, server);
}

void writecb(struct bufferevent *bev, void *ptr) {
  /*printf("packet sent to network layer\n");*/
}

void eventcb(struct bufferevent *bev, short events, void *ptr) {
  struct pxy_conn *ctx = (struct pxy_conn *)ptr;
  if (events & BEV_EVENT_CONNECTED) {
    printf("client socket %d: connected\n", ctx->index);
  } else if (events & BEV_EVENT_ERROR) {
    /* An error occured while connecting. */
    /* ctx->closed = 1; */
  } else if (events & BEV_EVENT_EOF) {
    if (bev == ctx->cli_bev) {
      bufferevent_free(ctx->cli_bev);
      ctx->cli_bev = NULL;
      ctx->cli_closed = true;
      sendCloseToGenode(ctx->index, close_client);
      /* event_add(ctx->parent->cleantimer, &msec); */
    } else {
      bufferevent_free(ctx->serv_bev);
      ctx->serv_bev = NULL;
      ctx->serv_closed = true;
      sendCloseToGenode(ctx->index, close_server);
      /* event_add(ctx->parent->cleantimer, &msec); */
    }
    printf("%s socket %d is closed\n",
           (bev == ctx->cli_bev) ? "client" : "server", ctx->index);
  }
}

void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd,
                    struct sockaddr *peeraddr, int peeraddrlen, void *ptr) {
  struct proxy_ctx *ctx = (struct proxy_ctx *)ptr;
  printf("connection captured, begin init proxy\n");
  struct pxy_conn *conn = pxy_conn_new(ctx);

  /* get the real socket. using the nat table. */
  conn->dstsocklen = sizeof(struct sockaddr_storage);
  if (nat_netfilter_lookup((struct sockaddr *)&(conn->dstsock),
                           &(conn->dstsocklen), fd, peeraddr,
                           peeraddrlen) == -1) {
    printf(
        "Connection not found in NAT "
        "state table, aborting connection\n");
    evutil_closesocket(fd);
    free(ctx);
    return;
  }

  /* We got a new connection! Set up a bufferevent for it. */
  struct event_base *base = evconnlistener_get_base(listener);
  conn->serv_bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);

  bufferevent_setcb(conn->serv_bev, serv_readcb, writecb, eventcb, conn);

  bufferevent_enable(conn->serv_bev, EV_READ | EV_WRITE);

  // then we setup client side socket.
  conn->cli_bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

  bufferevent_setcb(conn->cli_bev, cli_readcb, writecb, eventcb, conn);

  if (bufferevent_socket_connect(conn->cli_bev,
                                 (struct sockaddr *)&conn->dstsock,
                                 conn->dstsocklen) < 0) {
    /* Error starting connection */
    printf("start connection wrong");
    /* pxy_conn_free(conn); */
    return;
  }

  bufferevent_enable(conn->cli_bev, EV_READ | EV_WRITE);
  evtimer_add(ctx->timer, &usec);
}

int main(void) {
  struct evconnlistener *listener;
  struct sockaddr_in sin;

  struct proxy_ctx *proxy = proxy_ctx_new();
  proxy->timer = evtimer_new(proxy->base, copydata, proxy);
  proxy->cleantimer = evtimer_new(proxy->base, cleanconn, proxy);
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons(8443); /* Port 8443 */

  // TCP connection listener. no need to pass options arguments.
  listener = evconnlistener_new_bind(proxy->base, accept_conn_cb, proxy,
                                     LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
                                     -1, (struct sockaddr *)&sin, sizeof(sin));
  if (!listener) {
    printf("Couldn't create listener");
    return -1;
  }

  int result = event_base_dispatch(proxy->base);
  printf("running here %d\n", result);
  proxy_ctx_free(proxy);
  return 0;
}
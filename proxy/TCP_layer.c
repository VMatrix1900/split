#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <string.h>

#include <fcntl.h>
#include <linux/netfilter_ipv4.h>
#include <semaphore.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/types.h>

#include "channel.h"
#include "proxy_tcp.h"

struct timeval msec = {0, 1};

struct proxy_ctx *proxy_ctx_new()
{
    struct proxy_ctx *proxy = malloc(sizeof(struct proxy_ctx));
    init_shm();

    printf("initiated shared memory\n");
    proxy->base = event_base_new();
    proxy->counts = 0;
    memset(proxy->conns, 0, MAXCONNS * sizeof(struct pxy_conns *));
    return proxy;
}

int nat_netfilter_lookup(struct sockaddr *dst_addr, socklen_t *dst_addrlen,
                         evutil_socket_t s, struct sockaddr *src_addr,
                         socklen_t src_addrlen)
{
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

void copydata(evutil_socket_t fd, short what, void *ptr)
{
    // globol timer trigger this one ptr is proxy_ctx
    struct proxy_ctx *ctx = (struct proxy_ctx *)ptr;
    struct bufferevent *bev;
    struct pxy_conn *conn;
    event_del(ctx->timer);
    struct packet_info pi;
    pi = PullFromSSL();
    if (pi.valid) {
        conn = ctx->conns[pi.id];
        // send to client side or server side.
        if (pi.side == server) {
            /*printf("server send down:");*/
            bev = conn->serv_bev;
        } else if (pi.side == client) {
            /*printf("client send down:");*/
            bev = conn->cli_bev;
        } else {
            printf("Wrong server indicator:%d\n", server);
            exit(1);
        }
        /*printf("packet size:%zu\n", length);*/
        char **packet_buffer = (char **)sharedmem_pull_addr(pi.address);
        bufferevent_write(bev, *packet_buffer, pi.size);
    }
    event_add(ctx->timer, &msec);
}

void readcb(struct bufferevent *bev, void *ptr, int server)
{
    struct pxy_conn *ctx = (struct pxy_conn *)ptr;

    struct packet_info pi;
    pi.id = ctx->index;
    pi.server = server;
    pi.valid = true;
    int avali_size = 0;
    char **write_pointer = NULL;
    write_pointer = (char **)sharedmem_get_addr(&avali_size);
    pi.size = bufferevent_read(bev, *write_pointer, avali_size);
    while (PushToSSL(pi, (void *)(*write_pointer)) < 0) {
        ;
    }
    /*printf("read %zu data from network\n", read);*/
    (*write_pointer) += pi.size;
}

void cli_readcb(struct bufferevent *bev, void *ptr)
{
    /*printf("client:");*/
    readcb(bev, ptr, 0);
}

void serv_readcb(struct bufferevent *bev, void *ptr)
{
    /*printf("server:");*/
    readcb(bev, ptr, 1);
}

void writecb(struct bufferevent *bev, void *ptr)
{
    /*printf("packet sent to network layer\n");*/
}

void eventcb(struct bufferevent *bev, short events, void *ptr)
{
    struct pxy_conn *ctx = ptr;
    if (events & BEV_EVENT_CONNECTED) {
        printf("client socket: connected\n");
    } else if (events & BEV_EVENT_ERROR) {
        /* An error occured while connecting. */
        ctx->closed = 1;
    } else if (events & BEV_EVENT_EOF) {
        printf("socket is closed\n");
        ctx->closed = 1;
    }
}

void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd,
                    struct sockaddr *peeraddr, int peeraddrlen, void *ptr)
{
    struct proxy_ctx *ctx = ptr;
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
        pxy_conn_free(conn);
        return;
    }

    bufferevent_enable(conn->cli_bev, EV_READ | EV_WRITE);
    evtimer_add(ctx->timer, &msec);
}

int main(void)
{
    struct evconnlistener *listener;
    struct sockaddr_in sin;

    struct proxy_ctx *proxy = proxy_ctx_new();
    proxy->timer = evtimer_new(proxy->base, copydata, proxy);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(8443); /* Port 8443 */

    // TCP connection listener. no need to pass options arguments.
    listener =
        evconnlistener_new_bind(proxy->base, accept_conn_cb, proxy,
                                LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
                                (struct sockaddr *)&sin, sizeof(sin));
    if (!listener) {
        perror("Couldn't create listener");
        return 1;
    }

    event_base_dispatch(proxy->base);
    proxy_ctx_free(proxy);
    return 0;
}

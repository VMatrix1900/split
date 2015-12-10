#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/netfilter_ipv4.h>

#include "shm_and_sem.h"
#include "proxy.h"


int
nat_netfilter_lookup(struct sockaddr *dst_addr, socklen_t *dst_addrlen,
                        evutil_socket_t s,
                        struct sockaddr *src_addr, socklen_t src_addrlen)
{
	int rv;

	if (src_addr->sa_family != AF_INET) {
		printf("The netfilter NAT engine only "
		               "supports IPv4 state lookups\n");
		return -1;
	}

	rv = getsockopt(s, SOL_IP, SO_ORIGINAL_DST, dst_addr, dst_addrlen);
	if (rv == -1) {
		perror("Error from getsockopt(SO_ORIGINAL_DST):");
	}
	return rv;
}


void
copydata(evutil_socket_t fd, short what, void* ptr){
    struct shm_ctx_t *ctx = (struct shm_ctx_t *) ptr;
    event_del(ctx->timer);
    if(!sem_trywait(ctx->down)){
        printf("begin writing data. The size is %zu\n",*(size_t *)(ctx->shm));
        bufferevent_write(ctx->bev, ctx->shm + sizeof(size_t), *((size_t *)(ctx->shm)));
    }
    event_add(ctx->timer, &msec);
}

void
readcb(struct bufferevent *bev, void *ptr) {
    struct shm_ctx_t *ctx = (struct shm_ctx_t *) ptr;
    printf("begin reading data:\n");
    // when packet arrived, just copy it from input buffer to shared memory.
    // since we can not determine the packet lenght easily, we need to write it at the front of shared memory.
    memset(ctx->shm, 0, BUFSZ);
    size_t read = bufferevent_read(bev, ctx->shm + sizeof(size_t), BUFSZ);
    if (read >= 0) {
        printf("read %zu data from network\n", read);
        memcpy(ctx->shm, &read, sizeof(size_t));
    } else {
        perror("read callback error");
    }
    // notify openssl process
    sem_post(ctx->up);
    // add timer to wait for client write buffer.
    evtimer_add(ctx->timer, &msec);
}

void
writecb(struct bufferevent *bev, void *ptr) {
    struct shm_ctx_t *ctx = (struct shm_ctx_t *) ptr;
    printf("packet send to network layer\n");
    printf("The msg size: %zu\n", *((size_t *)(ctx->shm)));
}

void
serv_eventcb(struct bufferevent *bev, short events, void *ptr){
    if (events & BEV_EVENT_ERROR) {
        perror("error from server buffer event");
    }
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        bufferevent_free(bev);
    }
}

void
cli_eventcb(struct bufferevent *bev, short events, void *ptr){
    struct shm_ctx_t *ctx = (struct shm_ctx_t *) ptr;
    if (events & BEV_EVENT_CONNECTED) {
        printf("socket: connected\n");
        /* We're connected to dst socket, we can start send hello msg */
        sem_wait(ctx->down);
        bufferevent_write(bev, ctx->shm + sizeof(size_t), *((size_t *)(ctx->shm)));
    } else if (events & BEV_EVENT_ERROR) {
         /* An error occured while connecting. */
    }
}

void
accept_conn_cb(struct evconnlistener *listener,
        evutil_socket_t fd, struct sockaddr *peeraddr, int peeraddrlen,
        void *ptr)
{
    struct proxy_ctx_t *ctx = (struct proxy_ctx_t *) ptr;
    printf("connection captured, begin init proxy\n");
    // setup the proxy struct;
    /* get the real socket. using the nat table. */
    ctx->dstsocklen = sizeof(struct sockaddr_storage);
    if (nat_netfilter_lookup((struct sockaddr *)&(ctx->dstsock), &(ctx->dstsocklen),
                fd, peeraddr, peeraddrlen) == -1) {
        printf("Connection not found in NAT "
                "state table, aborting connection\n");
        evutil_closesocket(fd);
        proxy_ctx_free(ctx);
        return;
    }

    /* We got a new connection! Set up a bufferevent for it. */
    struct event_base *base = evconnlistener_get_base(listener);
    ctx->serv_shm_ctx->bev = bufferevent_socket_new(
            base, fd, BEV_OPT_CLOSE_ON_FREE);

    bufferevent_setcb(ctx->serv_shm_ctx->bev, readcb, writecb, serv_eventcb, ctx->serv_shm_ctx);

    bufferevent_enable(ctx->serv_shm_ctx->bev, EV_READ|EV_WRITE);
    ctx->serv_shm_ctx->timer = evtimer_new(base, copydata, ctx->serv_shm_ctx);

    // then we setup client side socket.
    ctx->cli_shm_ctx->bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

    bufferevent_setcb(ctx->cli_shm_ctx->bev, readcb, writecb, cli_eventcb, ctx->cli_shm_ctx);

    if (bufferevent_socket_connect(ctx->cli_shm_ctx->bev,
                (struct sockaddr *)&ctx->dstsock, ctx->dstsocklen) < 0) {
        /* Error starting connection */
        bufferevent_free(ctx->cli_shm_ctx->bev);
        return;
    }

    bufferevent_enable(ctx->cli_shm_ctx->bev, EV_READ|EV_WRITE);

    ctx->cli_shm_ctx->timer = evtimer_new(base, copydata, ctx->cli_shm_ctx);
}


int main(void)
{
    struct event_base *base;
    struct evconnlistener *listener;
    struct sockaddr_in sin;

    struct proxy_ctx_t *ctx = malloc(sizeof(struct proxy_ctx_t));
    ctx->cli_shm_ctx = malloc(sizeof(struct shm_ctx_t));// act as a client, receive msg from the server
    ctx->serv_shm_ctx = malloc(sizeof(struct shm_ctx_t));// act as a server, receive msg from the client

    init_shm(ctx->cli_shm_ctx, "client");
    init_shm(ctx->serv_shm_ctx, "server");

    printf("initiated shared memory");
    base = event_base_new();

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(8443); /* Port 8443 */

    // TCP connection listener. no need to pass options arguments.
    listener = evconnlistener_new_bind(base, accept_conn_cb, ctx,
            LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
            (struct sockaddr*)&sin, sizeof(sin));
    if (!listener) {
        perror("Couldn't create listener");
        return 1;
    }

    event_base_dispatch(base);
    return 0;
}

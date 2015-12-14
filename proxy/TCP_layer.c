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
    struct proxy_ctx_t *ctx = (struct proxy_ctx_t *) ptr;
    char *shm = ctx->shm_ctx->shm_down;
    struct bufferevent *bev;
    event_del(ctx->timer);
    if(!sem_trywait(ctx->shm_ctx->down)){
        // how many record to send?
        int number = *((int *)shm);
        shm += sizeof(int);
        int i;
        for (i = 0; i < number; i++) {
            int server = *((int *)shm);
            shm += sizeof(int);
            // determine send to client side or server side.
            if (1 == server) {
                bev = ctx->serv_bev;
            } else if (0 == server) {
                bev = ctx->cli_bev;
            } else {
                printf("Wrong server indicator:%d\n", server);
                exit(1);
            }
            size_t length = *((size_t *) shm);
            shm += sizeof(size_t);
            bufferevent_write(bev, shm, length);
            shm += length;
        }
    }
    event_add(ctx->timer, &msec);
}

void
readcb(struct bufferevent *bev, void *ptr, int server) {
    // tag the data indicate it's server side or client side.
    // only when the data is processed by ssl process
    struct proxy_ctx_t *ctx = (struct proxy_ctx_t *) ptr;
    // when packet arrived, just copy it from input buffer to shared memory.
    char *shm = ctx->shm_ctx->shm_up;
    // get the write lock
    sem_wait(ctx->shm_ctx->write_lock);
    // TODO only send 1 packet 1 time?
    int number = 1;
    memcpy(shm, &number, sizeof(int));
    shm += sizeof(int);
    // tag the server.
    memcpy(shm, &server, sizeof(int));
    shm += sizeof(int);
    // since we can not determine the packet length easily, we need to write it at the front of SSL record.
    size_t read = bufferevent_read(bev, shm + sizeof(size_t), BUFSZ);
    if (read >= 0) {
        printf("read %zu data from network\n", read);
        memcpy(shm, &read, sizeof(size_t));
    } else {
        perror("read callback error");
    }
    // after send the msg wait for 1msec for response
    evtimer_add(ctx->timer, &msec);
    // notify openssl process
    sem_post(ctx->shm_ctx->up);
}

void
cli_readcb(struct bufferevent *bev, void *ptr){
    printf("begin read client data:\n");
    readcb(bev, ptr, 0);
}

void
serv_readcb(struct bufferevent *bev, void *ptr){
    printf("begin read server data:\n");
    readcb(bev, ptr, 1);
}

void
writecb(struct bufferevent *bev, void *ptr) {
    printf("packet send to network layer\n");
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
    if (events & BEV_EVENT_CONNECTED) {
        printf("client socket: connected\n");
    } else if (events & BEV_EVENT_ERROR) {
         /* An error occured while connecting. */
    }
}

void
accept_conn_cb(struct evconnlistener *listener,
        evutil_socket_t fd, struct sockaddr *peeraddr, int peeraddrlen,
        void *ptr)
{
    struct proxy_ctx_t *ctx = malloc(sizeof(struct proxy_ctx_t));
    printf("connection captured, begin init proxy\n");
    // setup the proxy struct;
    ctx->shm_ctx = (struct shm_ctx_t *) ptr;
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

    // enable the up channel write permission.
    sem_post(ctx->shm_ctx->write_lock);
    /* We got a new connection! Set up a bufferevent for it. */
    struct event_base *base = evconnlistener_get_base(listener);
    ctx->serv_bev = bufferevent_socket_new(
            base, fd, BEV_OPT_CLOSE_ON_FREE);

    bufferevent_setcb(ctx->serv_bev, serv_readcb, writecb, serv_eventcb, ctx);

    bufferevent_enable(ctx->serv_bev, EV_READ|EV_WRITE);

    // then we setup client side socket.
    ctx->cli_bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

    bufferevent_setcb(ctx->cli_bev, cli_readcb, writecb, cli_eventcb, ctx);

    if (bufferevent_socket_connect(ctx->cli_bev,
                (struct sockaddr *)&ctx->dstsock, ctx->dstsocklen) < 0) {
        /* Error starting connection */
        bufferevent_free(ctx->cli_bev);
        return;
    }

    bufferevent_enable(ctx->cli_bev, EV_READ|EV_WRITE);

    ctx->timer = evtimer_new(base, copydata, ctx);
}


int main(void)
{
    struct shm_ctx_t *shm_ctx = malloc(sizeof(struct shm_ctx_t));
    struct event_base *base;
    struct evconnlistener *listener;
    struct sockaddr_in sin;

    init_shm(shm_ctx);

    printf("initiated shared memory\n");
    base = event_base_new();

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(8443); /* Port 8443 */

    // TCP connection listener. no need to pass options arguments.
    listener = evconnlistener_new_bind(base, accept_conn_cb, shm_ctx,
            LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
            (struct sockaddr*)&sin, sizeof(sin));
    if (!listener) {
        perror("Couldn't create listener");
        return 1;
    }

    event_base_dispatch(base);
    return 0;
}

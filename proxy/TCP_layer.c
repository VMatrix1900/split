#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <stdio.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/netfilter_ipv4.h>

#include "proxy_tcp.h"
#include "shm_and_sem.h"

struct proxy_ctx *
proxy_ctx_new() {
    struct proxy_ctx *proxy = malloc(sizeof(struct proxy_ctx));
    proxy->shm_ctx = malloc(sizeof(struct shm_ctx_t));

    if (init_shm(proxy->shm_ctx)) {
        printf("init shm wrong!\n");
        return NULL;
    }

    printf("initiated shared memory\n");
    proxy->base = event_base_new();
    proxy->counts = 0;
    memset(proxy->conns, 0, MAXCONNS * sizeof(struct pxy_conns *));
    return proxy;
}

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
    // globol timer trigger this one ptr is proxy_ctx
    struct proxy_ctx *ctx = (struct proxy_ctx *) ptr;
    unsigned char *shm = ctx->shm_ctx->shm_down;
    struct bufferevent *bev;
    struct pxy_conn *conn;
    event_del(ctx->timer);
    if(!sem_trywait(ctx->shm_ctx->down)){
        // how many record to send?
        int number = *((int *)shm);
        shm += sizeof(int);
        int i;
        for (i = 0; i < number; i++) {
            int index = *((int *)shm);
            shm += sizeof(int);
            conn = ctx->conns[index];
            int server = *((int *)shm);
            shm += sizeof(int);
            // determine send to client side or server side.
            if (1 == server) {
                printf("server send down:");
                bev = conn->serv_bev;
            } else if (0 == server) {
                printf("client send down:");
                bev = conn->cli_bev;
            } else {
                printf("Wrong server indicator:%d\n", server);
                exit(1);
            }
            size_t length = *((size_t *) shm);
            printf("packet size:%zu\n", length);
            shm += sizeof(size_t);
            bufferevent_write(bev, shm, length);
            shm += length;
        }
        psemvalue(ctx->shm_ctx->read_lock, "after copy read_lock");
        sem_post(ctx->shm_ctx->read_lock);
    }
    event_add(ctx->timer, &msec);
}

void
readcb(struct bufferevent *bev, void *ptr, int server) {
    // tag the data indicate it's server side or client side.
    // only when the data is processed by ssl process
    struct pxy_conn *ctx = (struct pxy_conn *) ptr;
    // when packet arrived, just copy it from input buffer to shared memory.
    unsigned char *shm = ctx->shm_ctx->shm_up;
    // get the write lock
    psemvalue(ctx->shm_ctx->write_lock, "before send writelock");
    sem_wait(ctx->shm_ctx->write_lock);
    // TODO only send 1 packet 1 time?
    int number = 1;
    memcpy(shm, &number, sizeof(int));
    shm += sizeof(int);
    // tag the index
    memcpy(shm, &(ctx->index), sizeof(int));
    shm += sizeof(int);
    // tag the server.
    memcpy(shm, &server, sizeof(int));
    shm += sizeof(int);
    // since we can not determine the packet length easily, we need to write it at the front of SSL record.
    size_t read = bufferevent_read(bev, shm + sizeof(size_t), BUFSZ);
    /*printf("read %zu data from network\n", read);*/
    memcpy(shm, &read, sizeof(size_t));
    // notify openssl process
    psemvalue(ctx->shm_ctx->up, "before send up");
    sem_post(ctx->shm_ctx->up);
}

void
cli_readcb(struct bufferevent *bev, void *ptr){
    /*printf("client:");*/
    readcb(bev, ptr, 0);
}

void
serv_readcb(struct bufferevent *bev, void *ptr){
    /*printf("server:");*/
    readcb(bev, ptr, 1);
}

void
writecb(struct bufferevent *bev, void *ptr) {
    /*printf("packet sent to network layer\n");*/
}

void
eventcb(struct bufferevent *bev, short events, void *ptr){
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

    void
accept_conn_cb(struct evconnlistener *listener,
        evutil_socket_t fd, struct sockaddr *peeraddr, int peeraddrlen,
        void *ptr)
{
    struct proxy_ctx *ctx =  ptr;
    printf("connection captured, begin init proxy\n");
    struct pxy_conn *conn = pxy_conn_new(ctx);

    /* get the real socket. using the nat table. */
    conn->dstsocklen = sizeof(struct sockaddr_storage);
    if (nat_netfilter_lookup((struct sockaddr *)&(conn->dstsock), &(conn->dstsocklen),
                fd, peeraddr, peeraddrlen) == -1) {
        printf("Connection not found in NAT "
                "state table, aborting connection\n");
        evutil_closesocket(fd);
        free(ctx);
        return;
    }

    /* We got a new connection! Set up a bufferevent for it. */
    struct event_base *base = evconnlistener_get_base(listener);
    conn->serv_bev = bufferevent_socket_new(
            base, fd, BEV_OPT_CLOSE_ON_FREE);

    bufferevent_setcb(conn->serv_bev, serv_readcb, writecb, eventcb, conn);

    bufferevent_enable(conn->serv_bev, EV_READ|EV_WRITE);

    // then we setup client side socket.
    conn->cli_bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

    bufferevent_setcb(conn->cli_bev, cli_readcb, writecb, eventcb, conn);

    if (bufferevent_socket_connect(conn->cli_bev,
                (struct sockaddr *)&conn->dstsock, conn->dstsocklen) < 0) {
        /* Error starting connection */
        pxy_conn_free(conn);
        return;
    }

    bufferevent_enable(conn->cli_bev, EV_READ|EV_WRITE);
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
    listener = evconnlistener_new_bind(proxy->base, accept_conn_cb, proxy,
            LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
            (struct sockaddr*)&sin, sizeof(sin));
    if (!listener) {
        perror("Couldn't create listener");
        return 1;
    }

    // enable the up channel write permission.
    sem_post(proxy->shm_ctx->write_lock);
    psemvalue(proxy->shm_ctx->write_lock, "writelock begin");
    event_base_dispatch(proxy->base);
    proxy_ctx_free(proxy);
    return 0;
}

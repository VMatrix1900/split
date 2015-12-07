#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <sys/socket.h>
#include <string.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "shm_and_sem.h"

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
serv_readcb(struct bufferevent *bev, void *ptr) {
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
serv_writecb(struct bufferevent *bev, void *ptr) {
    struct shm_ctx_t *ctx = (struct shm_ctx_t *) ptr;
    printf("packet send to client\n");
    printf("The msg size: %zu\n", *((size_t *)(ctx->shm)));
}

void
eventcb(struct bufferevent *bev, short events, void *ptr){
    struct shm_ctx_t *ctx = (struct shm_ctx_t *) ptr;
    if (events & BEV_EVENT_ERROR) {
        perror("error from server buffer event");
    }
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        bufferevent_free(bev);
    }
}

void
accept_conn_cb(struct evconnlistener *listener,
        evutil_socket_t fd, struct sockaddr *address, int socklen,
        void *ptr)
{
    struct shm_ctx_t *ctx = (struct shm_ctx_t *) ptr;
    /* We got a new connection! Set up a bufferevent for it. */
    struct event_base *base = evconnlistener_get_base(listener);
    ctx->bev = bufferevent_socket_new(
            base, fd, BEV_OPT_CLOSE_ON_FREE);

    bufferevent_setcb(ctx->bev, serv_readcb, serv_writecb, eventcb, ctx);

    bufferevent_enable(ctx->bev, EV_READ|EV_WRITE);
}

int main(void)
{
    struct shm_ctx_t cli_shm_ctx;// act as a client, receive msg from the server
    struct shm_ctx_t serv_shm_ctx;// act as a server, receive msg from the client
    memset(&cli_shm_ctx, 0, sizeof(cli_shm_ctx));
    memset(&serv_shm_ctx, 0, sizeof(serv_shm_ctx));

    init_shm(&cli_shm_ctx, "client");
    init_shm(&serv_shm_ctx, "server");

    struct event_base *base;
    struct evconnlistener *listener;
    struct sockaddr_in sin;

    base = event_base_new();

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(8443); /* Port 8443 */

    // TCP connection listener.
    listener = evconnlistener_new_bind(base, accept_conn_cb, &serv_shm_ctx,
            LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
            (struct sockaddr*)&sin, sizeof(sin));
    if (!listener) {
        perror("Couldn't create listener");
        return 1;
    }

    serv_shm_ctx.timer = evtimer_new(base, copydata, &serv_shm_ctx);

    event_base_dispatch(base);
    return 0;
}

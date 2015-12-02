#include <event2/bufferevent.h>
#include <event2/event.h>
#include <string.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <semaphore.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/types.h>

// name and the size of the shared memory segment.
key_t key = 1000;
#define SHMSZ 8192
#define BUFSZ 4096

// names of 2 semophores.
char UP_SEM[] = "up";
char DOWN_SEM[] = "down";

// store the info about the semophores and shared memory.
struct shm_ctx_t {
    sem_t *down;
    sem_t *up;
    int shmid;
    char *shm;
    struct bufferevent *bev;
    struct event *timer;
    struct timeval *msec;
};

void copydata(evutil_socket_t fd, short what, void *ptr)
{
    struct shm_ctx_t *ctx = (struct shm_ctx_t *)ptr;
    event_del(ctx->timer);
    if (!sem_trywait(ctx->down)) {
        printf("begin writing data. The size is %zu\n", *(size_t *)(ctx->shm));
        bufferevent_write(ctx->bev, ctx->shm + sizeof(size_t),
                          *((size_t *)(ctx->shm)));
    }
    event_add(ctx->timer, ctx->msec);
}

void readcb(struct bufferevent *bev, void *ptr)
{
    struct shm_ctx_t *ctx = (struct shm_ctx_t *)ptr;
    printf("begin reading data:\n");
    // when packet arrived, just copy it from input buffer to shared memory.
    // since we can not determine the packet lenght easily, we need to write it
    // at the front of shared memory.
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
    evtimer_add(ctx->timer, ctx->msec);
}

void writecb(struct bufferevent *bev, void *ptr)
{
    struct shm_ctx_t *ctx = (struct shm_ctx_t *)ptr;
    printf("packet send to underlying port\n");
    printf("The msg size: %zu\n", *((size_t *)(ctx->shm)));
}

void eventcb(struct bufferevent *bev, short events, void *ptr)
{
    struct shm_ctx_t *ctx = (struct shm_ctx_t *)ptr;
    if (events & BEV_EVENT_CONNECTED) {
        printf("socket: connected\n");
        /* We're connected to 127.0.0.1:8443. we can start send hello msg */
        sem_wait(ctx->down);
        printf("begin sending the hello msg to server\n");
        bufferevent_write(bev, ctx->shm + sizeof(size_t),
                          *((size_t *)(ctx->shm)));
    } else if (events & BEV_EVENT_ERROR) {
        /* An error occured while connecting. */
    }
}

int main(void)
{
    struct shm_ctx_t shm_ctx;
    memset(&shm_ctx, 0, sizeof(shm_ctx));
    struct timeval temp = {0, 100};

    shm_ctx.msec = &temp;
    // create & initialize existing semaphore
    shm_ctx.down = sem_open(DOWN_SEM, 0, 0644, 0);
    if (shm_ctx.down == SEM_FAILED) {
        perror("socket:unable to execute semaphore");
        sem_close(shm_ctx.down);
        exit(-1);
    }

    shm_ctx.up = sem_open(UP_SEM, 0, 0644, 0);
    if (shm_ctx.up == SEM_FAILED) {
        perror("unable to create semaphore");
        sem_unlink(UP_SEM);
        exit(-1);
    }

    // create the shared memory segment with this key
    shm_ctx.shmid = shmget(key, SHMSZ, 0666);
    if (shm_ctx.shmid < 0) {
        perror("socket:failure in shmget");
        exit(-1);
    }

    // attach this segment to virtual memory
    shm_ctx.shm = shmat(shm_ctx.shmid, NULL, 0);

    struct event_base *base;
    struct sockaddr_in sin;

    base = event_base_new();

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
    sin.sin_port = htons(8453);              /* Port 8080 */

    shm_ctx.bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

    bufferevent_setcb(shm_ctx.bev, readcb, writecb, eventcb, &shm_ctx);

    if (bufferevent_socket_connect(shm_ctx.bev, (struct sockaddr *)&sin,
                                   sizeof(sin)) < 0) {
        /* Error starting connection */
        bufferevent_free(shm_ctx.bev);
        return -1;
    }

    bufferevent_enable(shm_ctx.bev, EV_READ | EV_WRITE);

    shm_ctx.timer = evtimer_new(base, copydata, &shm_ctx);

    event_base_dispatch(base);
    return 0;
}

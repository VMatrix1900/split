#include <event2/event.h>
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

//name and the size of the shared memory segment.
key_t key= 1000;
#define SHMSZ 4096
#define BUFSZ 4096

// names of 2 semophores.
char UP_SEM[]= "up";
char DOWN_SEM[]= "down";

#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

// store the info about the semophores and shared memory.
struct shm_ctx_t {
    sem_t *down;
    sem_t *up;
    int shmid;
    char *shm;
};

int init_shm(struct shm_ctx_t * shm_ctx){

    //create & initialize existing semaphore
    shm_ctx->down = sem_open(DOWN_SEM,0,0644,0);
    if(shm_ctx->down == SEM_FAILED)
    {
        perror("socket:unable to execute semaphore");
        sem_close(shm_ctx->down);
        return -1;
    }

    shm_ctx->up = sem_open(UP_SEM,0,0644,0);
    if(shm_ctx->up == SEM_FAILED)
    {
        perror("unable to create semaphore");
        sem_unlink(UP_SEM);
        return -1;
    }

    //create the shared memory segment with this key
    shm_ctx->shmid = shmget(key,SHMSZ,0666);
    if(shm_ctx->shmid<0)
    {
        perror("socket:failure in shmget");
        return -1;
    }

    //attach this segment to virtual memory
    shm_ctx->shm = shmat(shm_ctx->shmid,NULL,0);
    return 0;
}

int main(void)
{
    int err;
    int sd;
    struct shm_ctx_t shm_ctx;

    memset(&shm_ctx, 0, sizeof(shm_ctx));

    err = init_shm(&shm_ctx);   CHK_ERR(err, "shared memory");

    struct sockaddr_in sin;
    sd = socket(AF_INET, SOCK_STREAM, 0);       CHK_ERR(sd, "socket");
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
    sin.sin_port = htons(8453); /* Port 8453 */
    err = connect(sd, (struct sockaddr*) &sin, sizeof(sin)); CHK_ERR(err, "connect");

    // connected, begin transfer data
    // send
    while (1) {
        sem_wait(shm_ctx.down);
        send(sd, shm_ctx.shm + sizeof(size_t), *((size_t *) shm_ctx.shm), 0);
        // recv
        size_t read = (size_t) recv(sd, shm_ctx.shm + sizeof(size_t), BUFSZ, 0);
        printf("receive the msg from the server, the size is %zu\n", read);
        memcpy(&(shm_ctx.shm), &read, sizeof(size_t));
        sem_post(shm_ctx.up);
    }

    return 0;
}

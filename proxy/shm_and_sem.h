#include <semaphore.h>
//name and the size of the shared memory segment.
key_t client_key = 1001;
key_t server_key = 1000;
#define SHMSZ 4096
#define BUFSZ 4096

struct timeval msec = {0, 100};

// names of 2 semophores.
char UP_SEM[]= "up";
char DOWN_SEM[]= "down";

// store the info about the semophores and shared memory.
struct shm_ctx_t {
    sem_t *down;
    sem_t *up;
    int shmid;
    char *shm;
#ifdef TCP
    struct bufferevent *bev;
    struct event *timer;
#endif
};

int init_shm(struct shm_ctx_t * shm_ctx, char name[]){
    key_t key;
    shm_ctx->down = sem_open(strcat(DOWN_SEM, name), O_CREAT, 0644,0);
    if(shm_ctx->down == SEM_FAILED)
    {
        perror("socket:unable to execute semaphore");
        sem_close(shm_ctx->down);
        return -1;
    }

    shm_ctx->up = sem_open(strcat(UP_SEM, name), O_CREAT,0644,0);
    if(shm_ctx->up == SEM_FAILED)
    {
        perror("unable to create semaphore");
        sem_unlink(UP_SEM);
        return -1;
    }

    if (strcmp(name, "client")){
        key = client_key;
    } else if(strcmp(name, "server")){
        key = server_key;
    } else {
        perror("wrong arguments for init_shm");
        return -1;
    }

    //create the shared memory segment with this key
    shm_ctx->shmid = shmget(key,SHMSZ,IPC_CREAT|0666);
    if(shm_ctx->shmid<0)
    {
        perror("socket:failure in shmget");
        return -1;
    }

    //attach this segment to virtual memory
    shm_ctx->shm = shmat(shm_ctx->shmid,NULL,0);
    return 0;
}


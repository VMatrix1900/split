#include <semaphore.h>
//name and the size of the shared memory segment.
key_t key_up = 1000;
key_t key_down = 1001;
#define SHMSZ 4096
#define BUFSZ 4096

struct timeval msec = {0, 100};

// names of 2 semophores.
char UP_SEM[]= "up";
char DOWN_SEM[]= "down";
char LOCK_SEM[]= "lock";

// store the info about the semophores and shared memory.
struct shm_ctx_t {
    sem_t *down;
    sem_t *up;
    sem_t *write_lock;
    int shmid_up;
    int shmid_down;
    char *shm_up;
    char *shm_down;
};

int init_shm(struct shm_ctx_t *shm_ctx){
    shm_ctx->down = sem_open(DOWN_SEM, O_CREAT, 0644, 0);
    if(shm_ctx->down == SEM_FAILED)
    {
        perror("socket:unable to execute semaphore");
        sem_close(shm_ctx->down);
        return -1;
    }

    shm_ctx->up = sem_open(UP_SEM, O_CREAT, 0644, 0);
    if(shm_ctx->up == SEM_FAILED)
    {
        perror("unable to create semaphore");
        sem_unlink(UP_SEM);
        return -1;
    }

    shm_ctx->write_lock = sem_open(LOCK_SEM, O_CREAT, 0644, 0);
    if(shm_ctx->write_lock == SEM_FAILED)
    {
        perror("unable to create semaphore");
        sem_unlink(LOCK_SEM);
        return -1;
    }

    //create the shared memory segment
    shm_ctx->shmid_up = shmget(key_up,SHMSZ,IPC_CREAT|0666);
    if(shm_ctx->shmid_up<0)
    {
        perror("socket:failure in shmget");
        return -1;
    }
    shm_ctx->shm_up = shmat(shm_ctx->shmid_up,NULL,0);

    shm_ctx->shmid_down = shmget(key_down,SHMSZ,IPC_CREAT|0666);
    if(shm_ctx->shmid_down<0)
    {
        perror("socket:failure in shmget");
        return -1;
    }
    shm_ctx->shm_down = shmat(shm_ctx->shmid_down,NULL,0);
    return 0;
}

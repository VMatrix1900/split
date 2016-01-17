#ifndef SHM_AND_SEM_H
#define SHM_AND_SEM_H

#include <fcntl.h>
#include <semaphore.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
// name and the size of the shared memory segment.
key_t key_up = 1000;
key_t key_down = 1001;
#define SHMSZ 2 << 14
#define BUFSZ 2 << 14

struct timeval msec = {0, 1};

// names of 2 semophores.
char UP_SEM[] = "up";
char DOWN_SEM[] = "down";
char LOCK_SEM[] = "lock";
char READ_LOCK[] = "readlock";

// store the info about the semophores and shared memory.
struct shm_ctx_t {
    sem_t *down;
    sem_t *up;
    sem_t *write_lock;
    sem_t *read_lock;
    int shmid_up;
    int shmid_down;
    unsigned char *shm_up;
    unsigned char *shm_down;
};

void psemvalue(sem_t *sem, const char *name)
{
    int temp = 100;
    sem_getvalue(sem, &temp);
    printf("%s value is %d\n", name, temp);
}

int init_shm(struct shm_ctx_t *shm_ctx)
{
    shm_ctx->down = sem_open(DOWN_SEM, O_CREAT, 0644, 0);
    if (shm_ctx->down == SEM_FAILED) {
        perror("socket:unable to execute semaphore");
        sem_close(shm_ctx->down);
        return -1;
    }

    shm_ctx->up = sem_open(UP_SEM, O_CREAT, 0644, 0);
    if (shm_ctx->up == SEM_FAILED) {
        perror("unable to create semaphore");
        sem_unlink(UP_SEM);
        return -1;
    }

    shm_ctx->write_lock = sem_open(LOCK_SEM, O_CREAT, 0644, 0);
    if (shm_ctx->write_lock == SEM_FAILED) {
        perror("unable to create semaphore");
        sem_unlink(LOCK_SEM);
        return -1;
    }

    shm_ctx->read_lock = sem_open(READ_LOCK, O_CREAT, 0644, 0);
    if (shm_ctx->read_lock == SEM_FAILED) {
        perror("unable to create semaphore");
        sem_unlink(READ_LOCK);
        return -1;
    }
    // create the shared memory segment
    shm_ctx->shmid_up = shmget(key_up, SHMSZ, IPC_CREAT | 0666);
    if (shm_ctx->shmid_up < 0) {
        perror("socket:failure in shmget");
        return -1;
    }
    shm_ctx->shm_up = shmat(shm_ctx->shmid_up, NULL, 0);
    if (shm_ctx->shm_up == (void *)-1) {
        perror("shm_up fail.");
        return -1;
    }
    memset(shm_ctx->shm_up, 0, SHMSZ);

    shm_ctx->shmid_down = shmget(key_down, SHMSZ, IPC_CREAT | 0666);
    if (shm_ctx->shmid_down < 0) {
        perror("socket:failure in shmget");
        return -1;
    }
    shm_ctx->shm_down = shmat(shm_ctx->shmid_down, NULL, 0);
    if (shm_ctx->shm_down == (void *)-1) {
        perror("shm_down fail.");
        return -1;
    }
    memset(shm_ctx->shm_down, 0, SHMSZ);
    return 0;
}

int destroy_shm(struct shm_ctx_t *shm_ctx)
{
    if (sem_close(shm_ctx->up) < 0 || sem_unlink(UP_SEM) < 0) {
        perror("sem_up close wrong.!");
        return -1;
    }
    if (sem_close(shm_ctx->down) < 0 || sem_unlink(DOWN_SEM) < 0) {
        perror("sem_down close wrong.!");
        return -1;
    }
    if (sem_close(shm_ctx->write_lock) < 0 || sem_unlink(LOCK_SEM) < 0) {
        perror("sem_up close wrong.!");
        return -1;
    }
    if (sem_close(shm_ctx->read_lock) < 0 || sem_unlink(READ_LOCK) < 0) {
        perror("sem_down close wrong.!");
        return -1;
    }
    if (shmdt(shm_ctx->shm_up) < 0) {
        perror("shm_up detach wrong!");
        return -1;
    }
    if (shmdt(shm_ctx->shm_down) < 0) {
        perror("shm_down detach wrong!");
        return -1;
    }
    return 0;
}

#endif

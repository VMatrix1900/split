#include "channel.h"
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>

int init_shm()
{
    // create the shared memory segment
    shm_ctx = malloc(sizeof(struct shm_ctx_t));
    int shm_sz = sizeof(struct channel);
    shm_ctx->shmid_up = shmget(key_up, shm_sz, IPC_CREAT | 0666);
    if (shm_ctx->shmid_up < 0) {
        perror("socket:failure in shmget");
        return -1;
    }
    shm_ctx->up_channel = shmat(shm_ctx->shmid_up, NULL, 0);
    if (shm_ctx->up_channel == (void *)-1) {
        perror("up_channel fail.");
        return -1;
    }
    memset(shm_ctx->up_channel, 0, shm_sz);

    shm_ctx->shmid_down = shmget(key_down, shm_sz, IPC_CREAT | 0666);
    if (shm_ctx->shmid_down < 0) {
        perror("socket:failure in shmget");
        return -1;
    }
    shm_ctx->down_channel = shmat(shm_ctx->shmid_down, NULL, 0);
    if (shm_ctx->down_channel == (void *)-1) {
        perror("down_channel fail.");
        return -1;
    }
    memset(shm_ctx->down_channel, 0, shm_sz);
    return 0;
}

int destroy_shm()
{
    if (shmdt(shm_ctx->up_channel) < 0) {
        perror("up_channel detach wrong!");
        return -1;
    }
    if (shmdt(shm_ctx->down_channel) < 0) {
        perror("down_channel detach wrong!");
        return -1;
    }
    return 0;
}

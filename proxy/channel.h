#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
// name and the size of the shared memory segment.

#define CIRCULAR_SZ 50
#define BUF_SZ 2 << 14

key_t key_up = 1000;
key_t key_down = 1001;

enum packet_type { client, server };

struct packet_info {
    unsigned long addr;
    enum packet_type server;
    int session_index;
    int length;
    bool valid;
};

struct channel {
    struct packet_info circular[CIRCULAR_SZ];
    char packet_buffer[BUF_SZ];
};

// store the info about the semophores and shared memory.
struct shm_ctx_t {
    int shmid_up;
    int shmid_down;
    struct channel *up_channel;
    struct channel *down_channel;
};

struct shm_ctx_t *shm_ctx = NULL;

int init_shm();

int destroy_shm();

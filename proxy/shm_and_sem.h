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


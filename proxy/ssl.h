#include "shm_and_sem.h"
struct ssl_channel {
    SSL* ssl;
    struct shm_ctx_t *shm;
};

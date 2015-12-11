#include <openssl/ssl.h>
#include "shm_and_sem.h"
struct ssl_channel {
    struct proxy *proxies;
    struct shm_ctx_t *shm;
};

struct proxy {
    SSL *cli_ssl;
    SSL *serv_ssl;
}

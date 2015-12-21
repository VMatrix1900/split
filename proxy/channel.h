#include <openssl/ssl.h>
#include "constants.h"
#include "shm_and_sem.h"

struct ssl_channel {
    int conns;
    struct proxy *proxies[MAXCONNS];
    struct shm_ctx_t *shm_ctx;
};

struct proxy {
    int index;
    SSL *cli_ssl;
    SSL *serv_ssl;
    int client_handshake;
    int client_received;
    int server_received;
    int client_need_to_out;
    int server_need_to_out;
};

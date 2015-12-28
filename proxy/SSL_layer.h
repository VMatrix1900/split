#include <openssl/ssl.h>
#include <stdbool.h>
#include "constants.h"
#include "shm_and_sem.h"

struct ssl_channel {
    int conns;
    X509 *cacrt;             // store the cacrt for all server ssl connection
    EVP_PKEY *cakey;         // store the ca key
    EVP_PKEY *key;           // store the public key for all fake certificate.
    STACK_OF(X509) * chain;  // store the ca chain.
    struct proxy *proxies[MAXCONNS];
    struct shm_ctx_t *shm_ctx;
};

struct proxy {
    struct ssl_channel *ctx;
    X509 *origcrt;
    int index;
    char *sni;
    SSL *cli_ssl;
    SSL *serv_ssl;
    unsigned char client_hello_buf[1024];
    ssize_t hello_msg_length;
    bool SNI_parsed;
    bool client_handshake_done;
    bool server_handshake_done;
    int client_need_to_out;
    int server_need_to_out;
};

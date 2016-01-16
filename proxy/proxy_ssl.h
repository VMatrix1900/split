#include <stdbool.h>
#include <openssl/ssl.h>

#define MAXCONNS 65536
struct ssl_channel {
    X509 *cacrt; // store the cacrt for all server ssl connection
    EVP_PKEY *cakey; // store the ca key
    EVP_PKEY *key; // store the public key for all fake certificate.
    STACK_OF(X509) *chain;// store the ca chain.
    struct proxy * proxies[MAXCONNS];
    int received[MAXCONNS];
    int msgs_need_to_out;
    struct shm_ctx_t *shm_ctx;
};

struct proxy {
    int client_received;
    int server_send;
    struct ssl_channel *ctx;
    X509 *origcrt;
    int index;
    char * sni;
    SSL *cli_ssl;
    SSL *serv_ssl;
    unsigned char client_hello_buf[1024];
    ssize_t hello_msg_length;
    bool SNI_parsed;
    bool client_handshake_done;
    bool server_handshake_done;
    unsigned char *down_pointer;
};

int init_ssl_bio(SSL*);
SSL* pxy_dstssl_setup();
struct proxy* proxy_new(struct ssl_channel *, int);
void proxy_shutdown_free(struct proxy *);
void notify_tcp();

void forward_record(SSL *, SSL *, struct proxy *);

int pxy_ossl_sessnew_cb(SSL *, SSL_SESSION *);
void pxy_ossl_sessremove_cb(SSL_CTX *, SSL_SESSION *);
SSL_SESSION *pxy_ossl_sessget_cb(SSL *, unsigned char *, int , int *);
SSL_CTX * pxy_srcsslctx_create(struct proxy *, X509 *, STACK_OF(X509) *, EVP_PKEY *);

SSL *pxy_srcssl_create(struct proxy *);
void pxy_srcssl_setup(struct proxy *);

struct ssl_channel *create_channel_ctx();
unsigned char *peek_hello_msg(struct proxy *, unsigned char *);

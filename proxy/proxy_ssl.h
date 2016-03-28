#include <openssl/ssl.h>
#include <stdbool.h>
#include "channel.h"
#include "constants.h"

#ifdef __cplusplus
extern "C" {
#endif

struct proxy_ctx {
  int conns;
  X509 *cacrt;             // store the cacrt for all server ssl connection
  EVP_PKEY *cakey;         // store the ca key
  EVP_PKEY *key;           // store the public key for all fake certificate.
  STACK_OF(X509) * chain;  // store the ca chain.
  struct proxy *proxies[MAXCONNS];
};

struct proxy {
  struct proxy_ctx *ctx;
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
};

int init_ssl_bio(SSL *);
SSL *pxy_clissl_setup();
struct proxy *proxy_new(struct proxy_ctx *, int);
void proxy_shutdown_free(struct proxy *);
void notify_tcp();

void send_down(struct proxy *, enum packet_type);
void receive_up(struct proxy *, struct packet_info *);
void forward_record(SSL *, SSL *, struct proxy *);

int pxy_ossl_sessnew_cb(SSL *, SSL_SESSION *);
void pxy_ossl_sessremove_cb(SSL_CTX *, SSL_SESSION *);
SSL_SESSION *pxy_ossl_sessget_cb(SSL *, unsigned char *, int, int *);
SSL_CTX *pxy_servsslctx_create(struct proxy *, X509 *, STACK_OF(X509) *,
                              EVP_PKEY *);

SSL *pxy_servssl_create(struct proxy *);
void pxy_servssl_setup(struct proxy *);

struct proxy_ctx *create_channel_ctx();
void peek_hello_msg(struct proxy *, struct packet_info *);

#ifdef __cplusplus
}
#endif /* extern c */

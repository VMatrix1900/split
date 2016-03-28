#include <openssl/ssl.h>
#include "ssl.h"
class Proxy
{
 private:
  X509 *origcrt;
  X509 *fakecrt;
  X509 *cacrt;
  EVP_PKEY *cakey;         // store the ca key
  EVP_PKEY *key;           // store the public key for all fake certificate.
  STACK_OF(X509) * chain;  // store the ca chain.
  char *sni;
  SSL *cli_ssl;
  SSL *serv_ssl;
  unsigned char client_hello_buf[1024];
  ssize_t hello_msg_length;
  bool SNI_parsed;
  bool client_handshake_done;
  bool server_handshake_done;
  void receive_up(struct packet_info *);
  void pxy_clissl_setup();
  SSL_CTX *pxy_servsslctx_create();

  void notify_tcp();
  void pxy_servssl_create();
  void pxy_servssl_setup();
  void peek_hello_msg(struct packet_info *);

 public:
  Proxy(X509 *cacrt, EVP_PKEY *cakey, EVP_PKEY *key, STACK_OF(X509) *chain)
      : cacrt(cacrt),
        cakey(cakey),
        key(key),
        chain(chain),
        hello_msg_length(0),
        SNI_parsed(false),
        client_handshake_done(false),
        server_handshake_done(false)
  {
    pxy_clissl_setup();
  }

  ~Proxy() {
    // guarantee this will only be called once for each SSL
    if (0 == SSL_get_shutdown(cli_ssl)) {
      SSL_shutdown(cli_ssl);
      // TODO send down the shutdown alert
      notify_tcp();
    }
    if (0 == SSL_get_shutdown(serv_ssl)) {
      SSL_shutdown(serv_ssl);
      notify_tcp();
    }
    if (sni) {
      free(sni);
    }
    if (origcrt) {
      free(origcrt);
    }
  }
};

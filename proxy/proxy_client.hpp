#include "ProxyBase.hpp"
#include "ssl.h"
class ProxyClient : public ProxyBase
{
 private:
  void sendCrt();

 public:
  virtual void receivePacket(char *packetbuffer, int length);
  void receiveSNI(char *SNIbuffer);
  ProxyClient(struct cert_ctx *ctx, int id, shared_buffer *down, shared_buffer *sendto) : ProxyBase(ctx, id, down, sendto)
  {
    const SSL_METHOD *meth = TLSv1_2_method();
    SSL_CTX *sslctx = SSL_CTX_new(meth);
    // now we ban begin initialize the client side.
    SSL_CTX_set_options(sslctx, SSL_OP_ALL);
#ifdef SSL_OP_TLS_ROLLBACK_BUG
    SSL_CTX_set_options(sslctx, SSL_OP_TLS_ROLLBACK_BUG);
#endif /* SSL_OP_TLS_ROLLBACK_BUG */
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    SSL_CTX_set_options(sslctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif /* SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION */
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    SSL_CTX_set_options(sslctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif /* SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS */
#ifdef SSL_OP_NO_TICKET
    SSL_CTX_set_options(sslctx, SSL_OP_NO_TICKET);
#endif /* SSL_OP_NO_TICKET */
#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(sslctx, SSL_OP_NO_COMPRESSION);
#endif /* SSL_OP_NO_COMPRESSION */

    SSL_CTX_set_cipher_list(sslctx, "ALL:-aNULL");
    SSL_CTX_set_verify(sslctx, SSL_VERIFY_NONE, NULL);

    ssl = SSL_new(sslctx);

    if (init_ssl_bio(ssl) < 0) {
      return;
    }
    SSL_set_connect_state(ssl);

    SSL_CTX_free(sslctx);

#ifdef SSL_MODE_RELEASE_BUFFERS
    /* lower memory footprint for idle connections */
    SSL_set_mode(ssl, SSL_get_mode(ssl) | SSL_MODE_RELEASE_BUFFERS);
#endif /* SSL_MODE_RELEASE_BUFFERS */
    in_bio = SSL_get_rbio(ssl);
    out_bio = SSL_get_wbio(ssl);
  };
  ~ProxyClient() { delete sendto; };
};

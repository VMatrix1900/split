#include "proxy.hpp"
#include "cert.h"
/*
 * Create and set up a new SSL_CTX instance for terminating SSL.
 * Set up all the necessary callbacks, the certificate, the cert chain and
 * key.
 */
SSL_CTX *Proxy::pxy_servsslctx_create()
{
  SSL_CTX *sslctx = SSL_CTX_new(TLSv1_2_method());
  if (!sslctx) return NULL;
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
#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
  SSL_CTX_set_options(sslctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
#endif /* SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION */

  /*SSL_CTX_set_cipher_list(sslctx, ctx->opts->ciphers);*/
  /* SSL_CTX_sess_set_new_cb(sslctx, pxy_ossl_sessnew_cb); */
  /* SSL_CTX_sess_set_remove_cb(sslctx, pxy_ossl_sessremove_cb); */
  /* SSL_CTX_sess_set_get_cb(sslctx, pxy_ossl_sessget_cb); */
  SSL_CTX_set_session_cache_mode(
      sslctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL);
#ifdef USE_SSL_SESSION_ID_CONTEXT
  SSL_CTX_set_session_id_context(sslctx, (void *)(&ssl_session_context),
                                 sizeof(ssl_session_context));
#endif /* USE_SSL_SESSION_ID_CONTEXT */
  SSL_CTX_use_certificate(sslctx, this->fakecrt);
  SSL_CTX_use_PrivateKey(sslctx, this->key);
  for (int i = 0; i < sk_X509_num(this->chain); i++) {
    X509 *c = sk_X509_value(this->chain, i);
    ssl_x509_refcount_inc(c); /* next call consumes a reference */
    SSL_CTX_add_extra_chain_cert(sslctx, c);
  }
  return sslctx;
}

void Proxy::pxy_servssl_create()
{
  this->origcrt = SSL_get_peer_certificate(this->cli_ssl);
  if (!this->origcrt) {
    printf("get real certificate wrong!\n");
  }
  this->fakecrt =
      ssl_x509_forge(this->cacrt, this->cakey, this->origcrt, NULL, this->key);

  SSL_CTX *sslctx = this->pxy_servsslctx_create();
  if (!sslctx) return;
  this->serv_ssl = SSL_new(sslctx);
  SSL_CTX_free(sslctx); /* SSL_new() increments refcount */
}

void Proxy::pxy_clissl_setup()
{
  SSL_CTX *sslctx;
  const SSL_METHOD *meth;
  meth = TLSv1_2_method();
  sslctx = SSL_CTX_new(meth);
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

  this->cli_ssl = SSL_new(sslctx);

  if (init_ssl_bio(this->cli_ssl) < 0) {
    return ;
  }
  SSL_set_connect_state(this->cli_ssl);

  SSL_CTX_free(sslctx);

#ifdef SSL_MODE_RELEASE_BUFFERS
  /* lower memory footprint for idle connections */
  SSL_set_mode(this->cli_ssl, SSL_get_mode(this->cli_ssl) | SSL_MODE_RELEASE_BUFFERS);
#endif /* SSL_MODE_RELEASE_BUFFERS */
}

void Proxy::notify_tcp()
{  // TODO
  printf("SSL connection shutdown!\n");
}


void Proxy::pxy_servssl_setup()
{
  pxy_servssl_create();
  if (!serv_ssl) {
    printf("server ssl create wrong.\n");
    proxy_shutdown_free(proxy);
  }
  init_ssl_bio(serv_ssl);
  SSL_set_accept_state(serv_ssl);
}

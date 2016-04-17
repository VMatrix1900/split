#include "proxy_server.hpp"
#include "ssl.h"
#include "constants.h"
#include <cassert>

void ProxyServer::receivePacket(char *packetbuffer, int length)
{
  // serv ssl is not setup until client handshake is done.
  if (!SNI_parsed) {
    memcpy(client_hello_buf + hello_msg_length, packetbuffer, length);
    hello_msg_length += length;
    ssize_t result = hello_msg_length;
    SNI = ssl_tls_clienthello_parse_sni(client_hello_buf, &result);
    if (!SNI && (-1 == result)) {
      // client hello msg is incomplete. set the flag, wait for another
      // msg.
    } else {
// sni parse is finished. now the server ssl is not ready. so we can
// only initiate client hanshake.
#ifdef DEBUG
      printf("sni is parsed for proxy %d", id);
#endif
      SNI_parsed = true;
      if (SNI) {
        sendSNI();
      }
    }
  } else if (!handshake_done) {
    int written = BIO_write(in_bio, packetbuffer, length);
    assert(written == length);
    int r = SSL_do_handshake(ssl);
    sendPacket();
    if (r < 0) {
      switch (SSL_get_error(ssl, r)) {
        case SSL_ERROR_WANT_WRITE:
          break;
        case SSL_ERROR_WANT_READ:
          // need more data, do nothing;
          break;
        default:
          printf("Server handshake error!");
          ERR_print_errors_fp(stderr);
      }
    } else {
      // handshake is done
      printf("Server handshake done!\n");
      handshake_done = true;
    }
  } else if (handshake_done) {
    int written = BIO_write(in_bio, packetbuffer, length);
    assert(written == length);
    forwardRecord();
  }
}

void ProxyServer::sendSNI() {
  sendMessage(sni, SNI, strlen(SNI) + 1);
}
void ProxyServer::receiveCrt(char *crtbuffer, int length)
{
  // TODO get certificate from shared memory
  X509 *origcrt = getCertificate();
  if (!origcrt) {
    printf("get real certificate wrong!\n");
  }
  X509 *fakecrt =
      ssl_x509_forge(ctx->cacrt, ctx->cakey, origcrt, NULL, ctx->key);

  SSL_CTX *sslctx = SSL_CTX_new(TLSv1_2_method());
  if (!sslctx) return;
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
  SSL_CTX_use_certificate(sslctx, fakecrt);
  SSL_CTX_use_PrivateKey(sslctx, ctx->key);
  for (int i = 0; i < sk_X509_num(ctx->chain); i++) {
    X509 *c = sk_X509_value(ctx->chain, i);
    ssl_x509_refcount_inc(c); /* next call consumes a reference */
    SSL_CTX_add_extra_chain_cert(sslctx, c);
  }
  if (!sslctx) return;
  ssl = SSL_new(sslctx);
  SSL_CTX_free(sslctx); /* SSL_new() increments refcount */
  if (!ssl) {
    printf("server ssl create wrong.\n");
    sendCloseAlert();
  }
  init_ssl_bio(ssl);
  SSL_set_accept_state(ssl);
  // copy the hello msg from buffer to bio;
  in_bio = SSL_get_rbio(ssl);
  out_bio = SSL_get_wbio(ssl);
  BIO_write(in_bio, client_hello_buf, hello_msg_length);
  SSL_do_handshake(ssl);
  // TODO make sure it's want write
  sendPacket();
}

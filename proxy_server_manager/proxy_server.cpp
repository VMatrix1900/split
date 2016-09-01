#include "proxy_server.hpp"
#include "ssl.h"
#include "constants.h"

void ProxyServer::receivePacket(const char *packetbuffer, int length) {
  // serv ssl is not setup until client handshake is done.
  if (!SNI_parsed) {
    // printf("[%d]::begin[%lu] \n", id, Genode::Trace::timestamp() / 1000000);
    memcpy(client_hello_buf + hello_msg_length, packetbuffer, length);
    hello_msg_length += length;
    ssize_t result = hello_msg_length;
    SNI_buffer = ssl_tls_clienthello_parse_sni(client_hello_buf, &result);
    if (!SNI_buffer && (-1 == result)) {
      // client hello msg is incomplete. set the flag, wait for another
      // msg.
    } else {
      SNI_parsed = true;
      if (SNI_buffer) {
        printf("[%d] sni is parsed %s\n", id, SNI_buffer);
        // sni parse is finished. now the server ssl is not ready. so we can
        // only initiate client hanshake.
        // check to see if we have fake certificate cached here;
        Cache::const_iterator it = cert_cache->find(std::string(SNI_buffer));
        if (it != cert_cache->end()) {
          // printf("[%d] cache hit, begin receive crt\n", id);
          createSSL(load_certificate(it->second.c_str()));
        }
        // printf("[%d]::SNI parsed[%lu] \n", id, Genode::Trace::timestamp() /
        // 1000000);
      } else {
        SNI_buffer = (char *)malloc(1);
        SNI_buffer[0] = '\0';
      }
      sendSNI();
    }
  } else if (!handshake_done) {
    // printf("[%d]::before handshake function: [%lu]\n", id,
    // Genode::Trace::timestamp() / 1000000);
    int written = BIO_write(in_bio, packetbuffer, length);
    // assert(written == length);
    int r = SSL_do_handshake(ssl);
    sendPacket();
    // printf("[%d]::after handshake function: [%lu]\n", id,
    // Genode::Trace::timestamp() / 1000000);
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
      // fprintf(stderr, "[%d] Server handshake done!\n", id);
      handshake_done = true;
      if (!first_msg_buf.empty()) {
        receiveRecord(first_msg_buf.c_str(), first_msg_buf.length());
      }
      // printf("[%d]::end[%lu]\n", id, Genode::Trace::timestamp() / 1000000);
    }
  } else if (handshake_done) {
    // printf("begin forward\n");
    int written = BIO_write(in_bio, packetbuffer, length);
    // assert(written == length);
    forwardRecord();
  }
}

void ProxyServer::sendSNI() {
  // fprintf(stderr, "[%d] ps send sni\n", id);
  if (SNI_buffer) {
    sendMessage(SNI, SNI_buffer, strlen(SNI_buffer) + 1);
  }
}

void ProxyServer::createSSL(X509 *fakecrt) {
  // printf("[%d]::before new ctx[%lu] \n", id, Genode::Trace::timestamp() /
  // 1000000);
  SSL_CTX *sslctx = SSL_CTX_new(TLSv1_2_method());
  if (!sslctx) {
    fprintf(stderr, "ssl_ctx_new wrong\n");
    return;
  } else {
  }
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
  int i;
  for (i = 0; i < sk_X509_num(ctx->chain); i++) {
    X509 *c = sk_X509_value(ctx->chain, i);
    if (!c) {
      fprintf(stderr, "sk_X509_value wrong\n");
    } else {
    }
    ssl_x509_refcount_inc(c); /* next call consumes a reference */
    SSL_CTX_add_extra_chain_cert(sslctx, c);
  }
  if (!sslctx) {
    fprintf(stderr, "ssl_ctx_new wrong\n");
    return;
  } else {
  }
  ssl = SSL_new(sslctx);
  SSL_CTX_free(sslctx); /* SSL_new() increments refcount */
  if (!ssl) {
    printf("server ssl create wrong.\n");
    sendCloseAlertDown();
  } else {
  }
  init_ssl_bio(ssl);
  SSL_set_accept_state(ssl);

  // copy the hello msg from buffer to bio;
  in_bio = SSL_get_rbio(ssl);
  out_bio = SSL_get_wbio(ssl);
  // printf("[%d]::before handshake function: [%lu]\n", id,
  // Genode::Trace::timestamp() / 1000000);
  BIO_write(in_bio, client_hello_buf, hello_msg_length);
  SSL_do_handshake(ssl);
  // TODO make sure it's want write
  sendPacket();
  // printf("[%d]::after handshake function: [%lu]\n", id,
  // Genode::Trace::timestamp() / 1000000);
}

void ProxyServer::receiveCrt(const char *crtbuffer) {
  if (ssl) {
    // which mean we already call this function.
    // fprintf(stderr, "[%d] cache hit ignore the crt buffer\n", id);
    return;
  }

  // printf("[%d]::before load cert[%lu] \n", id, Genode::Trace::timestamp() /
  // 1000000);
  X509 *origcrt = load_certificate(crtbuffer);
  if (!origcrt) {
    printf("[%d] get real certificate wrong!: %s\n", id, SNI_buffer);
  }

  // printf("[%d]::before fake cert[%lu] \n", id, Genode::Trace::timestamp() /
  // 1000000);
  X509 *fakecrt =
      ssl_x509_forge(ctx->cacrt, ctx->cakey, origcrt, NULL, ctx->key);
  if (!fakecrt) {
    printf("get fake certificate wrong\n");
  } else {
  }

  char *cert_buffer = store_cert(fakecrt);
  cert_cache->insert(
      std::make_pair(std::string(SNI_buffer), std::string(cert_buffer)));
  createSSL(fakecrt);
}

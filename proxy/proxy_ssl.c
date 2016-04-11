#include <assert.h>
#include <openssl/ssl.h>
#include "proxy_ssl.h"
#include "cachemgr.h"
#include "cert.h"
#include "log.h"
#include "ssl.h"

static EVP_PKEY *load_key() {
  EVP_PKEY *key = NULL;
  SSL_CTX *tmpctx;
  SSL *tmpssl;
  int rv;

  if (ssl_init() == -1) return NULL;

  tmpctx = SSL_CTX_new(SSLv23_server_method());
  if (!tmpctx) goto leave1;
    BIO *kbio;
    EVP_PKEY * keytemp = NULL;
    char pkey[] = "-----BEGIN RSA PRIVATE KEY-----\n"
"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\n"
      "-----END RSA PRIVATE KEY-----\n";

    kbio = BIO_new_mem_buf((void*)pkey, -1);
    keytemp = PEM_read_bio_PrivateKey(kbio, NULL, 0, NULL);
  rv = SSL_CTX_use_PrivateKey(tmpctx, keytemp);
  if (rv != 1) goto leave2;
  tmpssl = SSL_new(tmpctx);
  if (!tmpssl) goto leave2;
  key = SSL_get_privatekey(tmpssl);
  if (key) ssl_key_refcount_inc(key);
  SSL_free(tmpssl);
 leave2:
  SSL_CTX_free(tmpctx);
 leave1:
  return key;
    ssl_key_refcount_inc(key);
    return key;
}

static X509 * load_certificate() {
  X509 *crt = NULL;
  SSL_CTX *tmpctx;
  SSL *tmpssl;
  int rv;

  if (ssl_init() == -1) return NULL;

  tmpctx = SSL_CTX_new(SSLv23_server_method());
  if (!tmpctx) goto leave1;

    BIO *cbio;
    X509 * c = NULL;
 char cert_buffer[] = "-----BEGIN CERTIFICATE-----\n"
"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\n"
   "-----END CERTIFICATE-----\n";

    cbio = BIO_new_mem_buf((void*)cert_buffer, -1);
    c = PEM_read_bio_X509(cbio, NULL, 0, NULL);
  rv = SSL_CTX_use_certificate(tmpctx, c);
  if (rv != 1) goto leave2;
  tmpssl = SSL_new(tmpctx);
  if (!tmpssl) goto leave2;
  crt = SSL_get_certificate(tmpssl);
  if (crt) ssl_x509_refcount_inc(crt);
  SSL_free(tmpssl);
 leave2:
  SSL_CTX_free(tmpctx);
 leave1:
  return crt;
}

struct proxy_ctx *create_channel_ctx()
{
  struct proxy_ctx *channel = malloc(sizeof(struct proxy_ctx));
  memset(channel->proxies, 0, MAXCONNS * sizeof(struct proxy *));
  channel->cacrt = load_certificate();
  if (!channel->cacrt) {
    printf("certf load error\n");
    return NULL;
  } else {
    char *ca_subject = ssl_x509_subject(channel->cacrt);
    printf("Loaded CA: %s\n", ca_subject);
    free(ca_subject);
  }
  ssl_x509_refcount_inc(channel->cacrt);
  sk_X509_insert(channel->chain, channel->cacrt, 0);
  channel->cakey = load_key();
  if (!channel->cakey) {
    printf("keyf load error\n");
    return NULL;
  }
  if (X509_check_private_key(channel->cacrt, channel->cakey) != 1) {
    printf("CA cert does not match key.\n");
    return NULL;
  }
  channel->key = ssl_key_genrsa(1024);
  if (!channel->key) {
    printf("public key generation wrong!\n");
    return NULL;
  }
  return channel;
}

int init_ssl_bio(SSL *ssl)
{
  BIO *in_bio, *out_bio;
  in_bio = BIO_new(BIO_s_mem());
  if (in_bio == NULL) {
    printf("Error: cannot allocate read bio.\n");
    return -1;
  }

  BIO_set_mem_eof_return(
      in_bio,
      -1);  // see: https://www.openserv_ssl.org/docs/crypto/BIO_s_mem.html

  out_bio = BIO_new(BIO_s_mem());
  if (out_bio == NULL) {
    printf("Error: cannot allocate write bio.\n");
    return -1;
  }

  BIO_set_mem_eof_return(out_bio, -1);

  SSL_set_bio(ssl, in_bio, out_bio);
  return 0;
}

SSL *pxy_dstssl_setup()
{
  SSL *ssl;
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

  ssl = SSL_new(sslctx);
  if (!ssl) {
    return NULL;
  }

  if (init_ssl_bio(ssl) < 0) {
    return NULL;
  }
  SSL_set_connect_state(ssl);

  SSL_CTX_free(sslctx);

#ifdef SSL_MODE_RELEASE_BUFFERS
  /* lower memory footprint for idle connections */
  SSL_set_mode(ssl, SSL_get_mode(ssl) | SSL_MODE_RELEASE_BUFFERS);
#endif /* SSL_MODE_RELEASE_BUFFERS */
  return ssl;
}

void notify_tcp()
{  // TODO
  printf("SSL connection shutdown!\n");
}

struct proxy *proxy_new(struct proxy_ctx *ctx, int index)
{
  struct proxy *proxy = malloc(sizeof(struct proxy));
  proxy->ctx = ctx;
  proxy->SNI_parsed = false;
  proxy->client_handshake_done = false;
  proxy->server_handshake_done = false;
  proxy->hello_msg_length = 0;
  proxy->client_received = 0;
  proxy->server_send = 0;
  proxy->cli_ssl = pxy_dstssl_setup();
  if (!proxy->cli_ssl) {
    return NULL;
  }
  proxy->index = index;
  ctx->proxies[index] = proxy;

  return proxy;
}
void proxy_shutdown_free(struct proxy *proxy)
{
  // guarantee this will only be called once for each SSL
  if (0 == SSL_get_shutdown(proxy->cli_ssl)) {
    SSL_shutdown(proxy->cli_ssl);
    // TODO send down the shutdown alert
    notify_tcp();
  }
  if (0 == SSL_get_shutdown(proxy->serv_ssl)) {
    SSL_shutdown(proxy->serv_ssl);
    notify_tcp();
  }
  if (proxy->sni) {
    free(proxy->sni);
  }
  if (proxy->origcrt) {
    free(proxy->origcrt);
  }
  proxy->ctx->proxies[proxy->index] = NULL;
  free(proxy);
}

// OpenSSL create the session when the handshake is finished.
// Of course, you need the premaster key.
/*
 * Called by OpenSSL when a new src SSL session is created.
 * OpenSSL increments the refcount before calling the callback and will
 * decrement it again if we return 0.  Returning 1 will make OpenSSL skip
 * the refcount decrementing.  In other words, return 0 if we did not
 * keep a pointer to the object (which we never do here).
 */
#ifdef WITH_SSLV2
#define MAYBE_UNUSED
#else /* !WITH_SSLV2 */
#define MAYBE_UNUSED UNUSED
#endif /* !WITH_SSLV2 */
int pxy_ossl_sessnew_cb(MAYBE_UNUSED SSL *ssl, SSL_SESSION *sess)
#undef MAYBE_UNUSED
{
#ifdef DEBUG_SESSION_CACHE
  log_dbg_printf("===> OpenSSL new session callback:\n");
  if (sess) {
    log_dbg_print_free(ssl_session_to_str(sess));
  } else {
    log_dbg_printf("(null)\n");
  }
#endif /* DEBUG_SESSION_CACHE */
#ifdef WITH_SSLV2
  /* Session resumption seems to fail for SSLv2 with protocol
   * parsing errors, so we disable caching for SSLv2. */
  if (SSL_version(ssl) == SSL2_VERSION) {
    log_err_printf(
        "Warning: Session resumption denied to SSLv2"
        "client.\n");
    return 0;
  }
#endif /* WITH_SSLV2 */
  if (sess) {
    cachemgr_ssess_set(sess);
  }
  return 0;
}

/*
 * Called by OpenSSL when a src SSL session should be removed.
 * OpenSSL calls SSL_SESSION_free() after calling the callback;
 * we do not need to free the reference here.
 */
void pxy_ossl_sessremove_cb(UNUSED SSL_CTX *sslctx, SSL_SESSION *sess)
{
#ifdef DEBUG_SESSION_CACHE
  log_dbg_printf("===> OpenSSL remove session callback:\n");
  if (sess) {
    log_dbg_print_free(ssl_session_to_str(sess));
  } else {
    log_dbg_printf("(null)\n");
  }
#endif /* DEBUG_SESSION_CACHE */
  if (sess) {
    cachemgr_ssess_del(sess);
  }
}

/*
 * Called by OpenSSL when a src SSL session is requested by the client.
 */
SSL_SESSION *pxy_ossl_sessget_cb(UNUSED SSL *ssl, unsigned char *id, int idlen,
                                 int *copy)
{
  SSL_SESSION *sess;

#ifdef DEBUG_SESSION_CACHE
  log_dbg_printf("===> OpenSSL get session callback:\n");
#endif /* DEBUG_SESSION_CACHE */

  *copy = 0; /* SSL should not increment reference count of session */
  sess = cachemgr_ssess_get(id, idlen);

#ifdef DEBUG_SESSION_CACHE
  if (sess) {
    log_dbg_print_free(ssl_session_to_str(sess));
  }
#endif /* DEBUG_SESSION_CACHE */

  return sess;
}

/*
 * Create and set up a new SSL_CTX instance for terminating SSL.
 * Set up all the necessary callbacks, the certificate, the cert chain and
 * key.
 */
SSL_CTX *pxy_srcsslctx_create(struct proxy *ctx, X509 *crt,
                              STACK_OF(X509) * chain, EVP_PKEY *key)
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
  SSL_CTX_sess_set_new_cb(sslctx, pxy_ossl_sessnew_cb);
  SSL_CTX_sess_set_remove_cb(sslctx, pxy_ossl_sessremove_cb);
  SSL_CTX_sess_set_get_cb(sslctx, pxy_ossl_sessget_cb);
  SSL_CTX_set_session_cache_mode(
      sslctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL);
#ifdef USE_SSL_SESSION_ID_CONTEXT
  SSL_CTX_set_session_id_context(sslctx, (void *)(&ssl_session_context),
                                 sizeof(ssl_session_context));
#endif /* USE_SSL_SESSION_ID_CONTEXT */
  SSL_CTX_use_certificate(sslctx, crt);
  SSL_CTX_use_PrivateKey(sslctx, key);
  for (int i = 0; i < sk_X509_num(chain); i++) {
    X509 *c = sk_X509_value(chain, i);
    ssl_x509_refcount_inc(c); /* next call consumes a reference */
    SSL_CTX_add_extra_chain_cert(sslctx, c);
  }
  return sslctx;
}

SSL *pxy_srcssl_create(struct proxy *proxy)
{
  cert_t *cert = cert_new();
  proxy->origcrt = SSL_get_peer_certificate(proxy->cli_ssl);
  if (!proxy->origcrt) {
    printf("get real certificate wrong!\n");
    return NULL;
  }
  cert->crt = cachemgr_fkcrt_get(proxy->origcrt);
  if (!cert->crt) {
    cert->crt = ssl_x509_forge(proxy->ctx->cacrt, proxy->ctx->cakey,
                               proxy->origcrt, NULL, proxy->ctx->key);
  }
  cachemgr_fkcrt_set(proxy->origcrt, cert->crt);
  cert_set_key(cert, proxy->ctx->key);
  cert_set_chain(cert, proxy->ctx->chain);
  if (!cert) return NULL;

  SSL_CTX *sslctx =
      pxy_srcsslctx_create(proxy, cert->crt, cert->chain, cert->key);
  cert_free(cert);
  if (!sslctx) return NULL;
  SSL *ssl = SSL_new(sslctx);
  SSL_CTX_free(sslctx); /* SSL_new() increments refcount */
  if (!ssl) {
    return NULL;
  }
  return ssl;
}

void pxy_srcssl_setup(struct proxy *proxy)
{
  proxy->serv_ssl = pxy_srcssl_create(proxy);
  if (!proxy->serv_ssl) {
    printf("server ssl create wrong.\n");
    proxy_shutdown_free(proxy);
  }
  init_ssl_bio(proxy->serv_ssl);
  SSL_set_accept_state(proxy->serv_ssl);
}

// send the ssl out_bio packet to shared memory, update the pointer.
void send_down(struct proxy *proxy, enum packet_type side)
{
  SSL *ssl = (side == client) ? proxy->cli_ssl : proxy->serv_ssl;
  BIO *out_bio = SSL_get_wbio(ssl);
  int avaliable = 0;
  if (BIO_ctrl_pending(out_bio) > 0) {
    struct packet_info pi;
    void *write_pointer = GetToTCPBufferAddr(&avaliable);
    pi.side = side;
    pi.id = proxy->index;
    pi.valid = true;
    pi.length = BIO_read(out_bio, write_pointer, avaliable);
    if (pi.length > 0) {
      while (PushToTCP(pi, write_pointer) < 0) {
        ;
      }
      printf("%s down: %d\n", (side == client) ? "Client" : "Server",
             pi.length);
    }
  }
}

// receive the ssl in_bio packet from shared memory, update the pointer.
void receive_up(struct proxy *proxy, struct packet_info *pi)
{
  SSL *ssl = (pi->side == client) ? proxy->cli_ssl : proxy->serv_ssl;
  BIO *in_bio = SSL_get_rbio(ssl);
  assert(pi->length > 0);
  printf((pi->side == client) ? "Client " : "Server ");
  printf("begin receive up msg. The size is %d\n", pi->length);
  void *read_pointer = GetToSSLReadPointer();
  // copy the packet to in_bio
  int written = BIO_write(in_bio, read_pointer, pi->length);
  assert(written == pi->length);
  UpdateToSSLReadPointer(pi->length);
}

void forward_record(SSL *from, SSL *to, struct proxy *proxy)
{
  char buf[PACKET_MAX_SZ] = {'0'};
  char *write_pointer = buf;
  int size = 0;
  int length = 0;

  while ((length = SSL_read(from, write_pointer, (PACKET_MAX_SZ)-size)) > 0) {
    write_pointer += length;
    size += length;
    if (size == PACKET_MAX_SZ) {
      printf("BUFfer is full!\n");
      break;
    }
  }
  /*buf[size] = '\0';*/
  /*printf("%s buf received\n", buf);*/
  switch (SSL_get_error(from, length)) {
    case SSL_ERROR_WANT_WRITE:
      // TODO rehandshake !!
      printf("rehandshake happens");
      break;
    case SSL_ERROR_WANT_READ:
      break;
    case SSL_ERROR_ZERO_RETURN:
      printf("ssl clean closed\n");
      proxy_shutdown_free(proxy);
    case SSL_ERROR_WANT_CONNECT:
      printf("want connect!\n");
      break;
    case SSL_ERROR_WANT_ACCEPT:
      printf("want accept");
      break;
    case SSL_ERROR_WANT_X509_LOOKUP:
      printf("want x509 lookup!");
      break;
    case SSL_ERROR_SSL:
      printf("%s: SSL library error!fatal need to shutdown\n",
             (from == proxy->cli_ssl) ? "client" : "server");
      ERR_print_errors_fp(stderr);
      proxy_shutdown_free(proxy);
      break;
    case SSL_ERROR_SYSCALL:
      printf("syscall error");
      ERR_print_errors_fp(stderr);
      break;
    case SSL_ERROR_NONE:
      break;
    default:
      perror("Forward error!");
      exit(1);
  }
  if (!size) {
    return;
  }
  int r = SSL_write(to, buf, size);
  if (r <= 0) {
    switch (SSL_get_error(to, r)) {
      case SSL_ERROR_WANT_READ:
        // TODO handle rehandshake;
        printf("write fail: want read");
        break;
      case SSL_ERROR_ZERO_RETURN:
        printf("write fail:ssl closed");
        proxy_shutdown_free(proxy);
        return;
      case SSL_ERROR_WANT_WRITE:
        // TODO will this happen? we have unlimited bio memory buffer
        perror("BIO memory buffer full");
        exit(1);
      default:
        exit(1);
    }
  } else {
    // we need to send down the msg;
    /*if (from == proxy->cli_ssl) {*/
    /*    proxy->client_received += length;*/
    /*    proxy->server_send += r;*/
    /*    printf("received: %d, send: %d\n", proxy->client_received,
     * proxy->server_send);*/
    /*}*/
    send_down(proxy, (to == proxy->cli_ssl) ? client : server);
  }
}

void peek_hello_msg(struct proxy *proxy, struct packet_info *pi)
{
  void *msg = GetToSSLReadPointer();
  memcpy(proxy->client_hello_buf + proxy->hello_msg_length, msg, pi->length);
  proxy->hello_msg_length += pi->length;
  UpdateToSSLReadPointer(pi->length);
  ssize_t length = proxy->hello_msg_length;
  proxy->sni = ssl_tls_clienthello_parse_sni(proxy->client_hello_buf, &length);
  if (!proxy->sni && (-1 == length)) {
    // client hello msg is incomplete. set the flag, wait for another
    // msg.
  } else {
// sni parse is finished. now the server ssl is not ready. so we can
// only initiate client hanshake.
#ifdef DEBUG
    printf("sni is parsed for proxy %d\n", proxy->index);
#endif
    proxy->SNI_parsed = true;
    if (proxy->sni) {
      SSL_set_tlsext_host_name(proxy->cli_ssl, proxy->sni);
    }
    SSL_do_handshake(proxy->cli_ssl);
    send_down(proxy, client);
  }
}

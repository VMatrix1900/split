#include "proxy_ssl.h"
#include <assert.h>
#include <openssl/ssl.h>
#include "cert.h"
#include "ssl.h"

struct proxy_ctx *load_cert_ctx()
{
  char pkey[] =
      "-----BEGIN RSA PRIVATE KEY-----\n"
      "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\n"
      "-----END RSA PRIVATE KEY-----\n";

  char cert_buffer[] =
      "-----BEGIN CERTIFICATE-----\n"
      "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\n"
      "-----END CERTIFICATE-----\n";
  struct proxy_ctx *channel = malloc(sizeof(struct proxy_ctx));
  channel->cacrt = load_certificate(cert_buffer);
  if (!channel->cacrt) {
    printf("certf load error\n");
    return NULL;
  } else {
    char *ca_subject = ssl_x509_subject(channel->cacrt);
    printf("Loaded CA: %s\n", ca_subject);
    free(ca_subject);
  }
  channel->cakey = load_key(pkey);
  ssl_x509_refcount_inc(channel->cacrt);
  sk_X509_insert(channel->chain, channel->cacrt, 0);
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
  printf("===> OpenSSL new session callback:\n");
  if (sess) {
    printf(ssl_session_to_str(sess));
  } else {
    printf("(null)\n");
  }
#endif /* DEBUG_SESSION_CACHE */
#ifdef WITH_SSLV2
  /* Session resumption seems to fail for SSLv2 with protocol
   * parsing errors, so we disable caching for SSLv2. */
  if (SSL_version(ssl) == SSL2_VERSION) {
    fprintf(stderr,
            "Warning: Session resumption denied to SSLv2"
            "client.\n");
    return 0;
  }
#endif /* WITH_SSLV2 */
  if (sess) {
    /* cachemgr_ssess_set(sess); */
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
  printf("===> OpenSSL remove session callback:\n");
  if (sess) {
    printf(ssl_session_to_str(sess));
  } else {
    printf("(null)\n");
  }
#endif /* DEBUG_SESSION_CACHE */
  if (sess) {
    /* cachemgr_ssess_del(sess); */
  }
}

/*
 * Called by OpenSSL when a src SSL session is requested by the client.
 */
/* SSL_SESSION *pxy_ossl_sessget_cb(UNUSED SSL *ssl, unsigned char *id, int
 * idlen, */
/*                                  int *copy) */
/* { */
/*   SSL_SESSION *sess; */

/* #ifdef DEBUG_SESSION_CACHE */
/*   printf("===> OpenSSL get session callback:\n"); */
/* #endif /\* DEBUG_SESSION_CACHE *\/ */

/*   *copy = 0; /\* SSL should not increment reference count of session *\/ */
/*   sess = cachemgr_ssess_get(id, idlen); */

/* #ifdef DEBUG_SESSION_CACHE */
/*   if (sess) { */
/*     printf(ssl_session_to_str(sess)); */
/*   } */
/* #endif /\* DEBUG_SESSION_CACHE *\/ */

/*   return sess; */
/* } */


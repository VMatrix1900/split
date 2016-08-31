#pragma once
#include <openssl/ssl.h>
#include <stdbool.h>
#include "constants.h"

#ifdef __cplusplus
extern "C" {
#endif

struct cert_ctx {
  X509 *cacrt;             // store the cacrt for all server ssl connection
  EVP_PKEY *cakey;         // store the ca key
  EVP_PKEY *key;           // store the public key for all fake certificate.
  STACK_OF(X509) * chain;  // store the ca chain.
};

struct cert_ctx *load_cert_ctx();
int pxy_ossl_sessnew_cb(SSL *, SSL_SESSION *);
void pxy_ossl_sessremove_cb(SSL_CTX *, SSL_SESSION *);
SSL_SESSION *pxy_ossl_sessget_cb(SSL *, unsigned char *, int, int *);

#ifdef __cplusplus
}
#endif /* extern c */

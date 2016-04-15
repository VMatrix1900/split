#include "proxy.hpp"
#include "cert.h"
/*
 * Create and set up a new SSL_CTX instance for terminating SSL.
 * Set up all the necessary callbacks, the certificate, the cert chain and
 * key.
 */


void Proxy::notify_tcp()
{  // TODO
  printf("SSL connection shutdown!\n");
}



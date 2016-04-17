#include "proxy_ssl.h"

int main() {
  struct cert_ctx * temp= load_cert_ctx();
  if (!temp) {
    printf("something is wrong.\n");
  }
  return 0;
}

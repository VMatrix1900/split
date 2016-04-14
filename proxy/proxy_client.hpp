#include <openssl/ssl.h>
class ProxyClient
{
 private:
  bool handshake_done;
  int id;
  SSL *ssl;
  struct proxy_ctx *ctx;

  sendPacket();

 public:
  receivePacket(char *packetbuffer, int length);
  receiveSNI(char *SNIbuffer);
  receiveRecord(char *recordbuffer, int length);
  ProxyClient(struct proxy_ctx *ctx, int id)
      : handshake_done(false),
        id(id),
        ssl(NULL),
        ctx(ctx) {};
  ~ProxyClient()
  {
    if (0 == SSL_get_shutdown(ssl)) {
      SSL_shutdown(ssl);
    }
    if (sni) {
      free(sni);
    }
  };
}

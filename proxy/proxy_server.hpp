#include <openssl/ssl.h>
class ProxyServer
{
 private:
  bool handshake_done;
  bool SNI_parsed;
  int id;
  SSL *ssl;
  struct proxy_ctx *ctx;
  unsigned char client_hello_buf[1024];
  char *SNI;
  ssize_t hello_msg_length;
  sendSNI();

 public:
  receivePacket(char *packetbuffer, int length);
  receiveCrt(char *crtbuffer, int length);
  receiveRecord(char *recordbuffer, int length);
  ProxyServer(struct proxy_ctx *ctx, int id)
      : handshake_done(false),
        SNI_parsed(false),
        id(id),
        ssl(NULL),
        ctx(ctx),
        SNI(NULL),
        hello_msg_length(0){};
  ~ProxyServer()
  {
    if (0 == SSL_get_shutdown(ssl)) {
      SSL_shutdown(ssl);
    }
    if (sni) {
      free(sni);
    }
  };
}

#include "ProxyBase.hpp"
#include "ssl.h"
#include "http2stream.hpp"


class ProxyClient : public ProxyBase
{
 private:
  unsigned long begin_handshake;
  unsigned long end_handshake;
  void sendCrt();
  HTTP2Stream stream_data;

 public:
  bool http2_selected;
  void receivePacket(const char *packetbuffer, int length);
  void receiveSNI(char *SNIbuffer);
  void forwardRecordForHTTP2();
  void receiveRecord(const char *recordbuffer, int length);
  ProxyClient(struct cert_ctx *ctx, int id, Secure_box::shared_buffer *down,
              Secure_box::shared_buffer *otherside,
              Secure_box::shared_buffer *to_mb, struct packet *pkt,
              struct message *msg);
  ~ProxyClient() { delete otherside; };
};

namespace
{
#define warnx(format, args...) fprintf(stderr, format "\n", ##args)
#define errx(exitcode, format, args...)         \
  {                                             \
    warnx(format, ##args);                      \
    exit(exitcode);                             \
  }

  int select_next_proto_cb(SSL *ssl _U_, unsigned char **out,
                           unsigned char *outlen, const unsigned char *in,
                           unsigned int inlen, void *arg)
  {
    int rv = nghttp2_select_next_protocol(out, outlen, in, inlen);
    ::ProxyClient *pc = (::ProxyClient *)arg;
    if (rv < 0) {
      errx(1, "Server did not advertise " NGHTTP2_PROTO_VERSION_ID);
    } else if (rv == 1) {
      pc->http2_selected = true;
    } else if (rv == 0) {
      pc->http2_selected = false;
    }
    return SSL_TLSEXT_ERR_OK;
  }
}

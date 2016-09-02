#include "ProxyBase.hpp"
#include "ssl.h"
#include "http2client.hpp"

class ProxyClient : public ProxyBase {
 private:
#ifdef MEASURE_TIME
  unsigned long begin_handshake;
  unsigned long end_handshake;
#endif
  void sendCrt();
  HTTP2Client http2_client;

 public:
  bool http2_selected;
  std::string domain;
  void receivePacket(const char *packetbuffer, int length);
  void receiveSNI(char *SNIbuffer);
  void forwardRecordForHTTP2();
  void receiveRecord(int id, const char *recordbuffer, int length);
  ProxyClient(struct cert_ctx *ctx, int id, Channel *down, Channel *otherside,
              Channel *to_mb, struct TLSPacket *pkt, struct Plaintext *msg);
  ~ProxyClient() {  // TODO reconsider the delete
    delete otherside;
  };
};

namespace {
#define warnx(format, args...) fprintf(stderr, format "\n", ##args)
#define errx(exitcode, format, args...) \
  {                                     \
    warnx(format, ##args);              \
    exit(exitcode);                     \
  }

int select_next_proto_cb(SSL *ssl _U_, unsigned char **out,
                         unsigned char *outlen, const unsigned char *in,
                         unsigned int inlen, void *arg) {
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

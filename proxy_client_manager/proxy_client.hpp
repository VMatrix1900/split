#pragma once
#include "ProxyBase.hpp"
#include "ssl.h"
#include <nghttp2/nghttp2.h>
#include "httpstream.hpp"
#define _U_ __attribute__((unused))

class ProxyClient : public ProxyBase {
 private:
#ifdef MEASURE_TIME
  unsigned long begin_handshake;
  unsigned long end_handshake;
#endif

  std::vector<struct Plaintext*> msg_buf;
  void sendCrt();
  std::string sendHTTP1Request(int packet_id, const char *buf, size_t len);
  ssize_t parseHTTP2Response(const uint8_t *in, size_t len);
  // void set_send_callback(send_data_callback send_data);

 public:
  bool http2_selected;
  std::string domain;
  nghttp2_session *session;
  std::map<int32_t, HTTPStream *> stream_id_to_stream;
  std::map<int, HTTPStream *> pkt_id_to_stream;

  ProxyClient(struct cert_ctx *ctx, int id, Channel *down, Channel *otherside,
              Channel *to_mb, struct TLSPacket *pkt, struct Plaintext *msg);
  ~ProxyClient() {  // TODO reconsider the delete
    delete otherside;
  };

  void init_http2_session();
  void receivePacket(const char *packetbuffer, int length);
  void receiveSNI(char *SNIbuffer);
  void receiveCloseAlert(int pkt_id);
  void forwardRecordForHTTP2();
  void receiveRecord(int id, const char *recordbuffer, int length);
  void processResponse(int id);
  void submit_client_connection_setting();
  void submit_client_request(int pkt_id);
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
    log("HTTP2 selected: " + pc->domain);
    pc->init_http2_session();
  } else if (rv == 0) {
    pc->http2_selected = false;
  }
  return SSL_TLSEXT_ERR_OK;
}
}

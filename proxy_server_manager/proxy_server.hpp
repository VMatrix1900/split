#pragma once
#include "ProxyBase.hpp"
#include <map>

typedef std::map<std::string, std::string> Cache;

class ProxyServer : public ProxyBase {
 private:
  bool SNI_parsed;
  unsigned char client_hello_buf[1024];
  char *SNI;
  Cache *cert_cache;
  ssize_t hello_msg_length;

  void createSSL(X509 *);
  void sendSNI();

 public:
  void receivePacket(const char *packetbuffer, int length);
  void receiveCrt(const char *crtbuffer);
  ProxyServer(struct cert_ctx *ctx, int id, Secure_box::shared_buffer *down,
              Secure_box::shared_buffer *otherside,
              Secure_box::shared_buffer *to_mb, struct packet *pkt,
              struct message *msg, Cache *cert_cache)
      : ProxyBase(ctx, id, down, otherside, to_mb, pkt, msg),
        SNI_parsed(false),
        SNI(NULL),
        cert_cache(cert_cache),
        hello_msg_length(0){};
  ~ProxyServer() {
    delete otherside;
    if (SNI) {
      free(SNI);
    }
  };
};

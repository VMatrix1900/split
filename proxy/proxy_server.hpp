#include "ProxyBase.hpp"
class ProxyServer : public ProxyBase
{
 private:
  bool SNI_parsed;
  unsigned char client_hello_buf[1024];
  char *SNI;
  ssize_t hello_msg_length;

  void sendSNI();

 public:
  virtual void receivePacket(char *packetbuffer, int length);
  void receiveCrt(char *crtbuffer);
  ProxyServer(struct cert_ctx *ctx, int id, shared_buffer *down,
              shared_buffer *sendto)
      : ProxyBase(ctx, id, down, sendto),
        SNI_parsed(false),
        SNI(NULL),
        hello_msg_length(0){};
  ~ProxyServer()
  {
    delete sendto;
    if (SNI) {
      free(SNI);
    }
  };
};

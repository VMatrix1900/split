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
  void receiveCrt(char *crtbuffer, int length);
  ProxyServer(struct proxy_ctx *ctx, int id)
      : ProxyBase(ctx, id), SNI_parsed(false), SNI(NULL), hello_msg_length(0)
  {
    sendto = new Shared_buffer("PS2PC");
  };
  ~ProxyServer()
  {
    delete sendto;
    delete getfrom;
    if (SNI) {
      free(SNI);
    }
  };
};

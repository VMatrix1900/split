#include "proxy_ssl.h"
int main() {
  initSharedMemory();
  struct cert_ctx *ctx = load_cert_ctx();
  while (true) {
    while(pullPacket(packetbuffer)) {
      ps.receivePacket(packetbuffer);
    }
    while(pullFromOtherSide(messagebuffer)) {
      //distribute the message:
      ps.receiveRecord(messagebuffer);
      ps.receiveCrt(messagebuffer);
    }
  }
}

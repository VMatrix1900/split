int main() {
  initSharedMemory();
  loadProxyCtx();
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

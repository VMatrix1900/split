#include "proxy_server.hpp"

ProxyServer::receivePacket(char *packetbuffer, int length) {
  if (!SNI_parsed) {
    memcpy(client_hello_buf, packetbuffer, length);
    hello_msg_length += length;
    int result = hello_msg_length;
    SNI = ssl_tls_clienthello_parse_sni(client_hello_buf, &result);
    if (!SNI && (-1 == result)) {
      // client hello msg is incomplete. set the flag, wait for another
      // msg.
    } else {
      // sni parse is finished. now the server ssl is not ready. so we can
      // only initiate client hanshake.
#ifdef DEBUG
      printf("sni is parsed for proxy %d", id);
#endif
      SNI_parsed = true;
      if (SNI) {
        sendSNI();
      }
  }
}

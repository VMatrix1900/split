#include "channel.hpp"
#include "message.h"

Channel TCP_to_SSL("tcp_to_ssl");
Channel SSL_to_TCP("ssl_to_tcp");
Channel up_client("up_client");
Channel down_client("down_client");
Channel up_server("up_server");
Channel down_server("down_server");

int main(int argc, char *argv[])
{
  struct TLSPacket pi;
  while(true) {
    TCP_to_SSL.pull_data(&pi, 35000);
    if (pi.side == server) {
      while (up_server.put_data((void*)&pi,
                               pi.size + offsetof(struct TLSPacket, buffer)) <
             0) {
        ;
      }
      // PINF("[%d] forward to server: [%lu]", pi.id, t);
    } else if (pi.side == client) {
      while (up_client.put_data((void*)&pi,
                               pi.size + offsetof(struct TLSPacket, buffer)) <
             0) {
        ;
      }
      // up_client->print_headers();
    } else if (pi.side == close_client) {
      pi.size = -1;
      while (up_client.put_data((void*)&pi,
                                 offsetof(struct TLSPacket, buffer)) <
             0) {
        ;
      }
      // PINF("[%d] forward close to client:", pi.id);
      // up_client->print_headers();
    } else if (pi.side == close_server) {
      pi.size = -1;
      // PINF("[%d] forward close to client", pi.id);
      while (up_server.put_data((void*)&pi,
                                 offsetof(struct TLSPacket, buffer)) <
             0) {
        ;
      }
      // PINF("[%d] forward close to server", pi.id);
      // up_client->print_headers();
    }

    if (down_server.pull_data(&pi, 35000) > 0) {
      if (pi.size > 0) {
        pi.side = server;
      } else {
        pi.size = 10;
        pi.side = close_server;
      }
      SSL_to_TCP.put_data(&pi, pi.size + offsetof(struct TLSPacket, buffer));
    }
    if (down_client.pull_data(&pi, 35000) > 0) {
      if (pi.size > 0) {
        pi.side = client;
      } else {
        pi.size = 10;
        pi.side = close_client;
      }
      SSL_to_TCP.put_data(&pi, pi.size + offsetof(struct TLSPacket, buffer));
    }
  }
  return 0;
}

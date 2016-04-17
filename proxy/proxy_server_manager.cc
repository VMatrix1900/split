#include "proxy_ssl.h"
#include "constants.h"
#include "shared_buffer.hpp"
#include "proxy_server.hpp"
static shared_buffer up;
static shared_buffer down;
static shared_buffer ps_to_pc;
static shared_buffer pc_to_ps;

int main() {
  struct cert_ctx *ctx = load_cert_ctx();
  up.initialize((char*)"up");
  down.initialize((char*)"down");
  ps_to_pc.initialize((char *)"ps_to_pc");
  pc_to_ps.initialize((char *)"pc_to_ps");
  ProxyServer *pss[MAXCONNS] = {NULL};
  for (int i = 0; i < MAXCONNS; i ++) {
    pss[i] = new ProxyServer(ctx, i, &down, &ps_to_pc);
  }

  struct packet packet;
  struct message msg;
  while (true) {
    while(up.pullData((char *)&packet, MAX_PACKET_SIZE)>0) {
      ProxyServer *ps = pss[packet.id];
      ps->receivePacket(packet.buffer, packet.size);
    }
    while(pc_to_ps.pullData((char *)&msg, MAX_MSG_SIZE) > 0) {
      //distribute the message:
      enum message_type tp = msg.type;
      ProxyServer *ps = pss[msg.id];
      if (tp == record) {
        ps->receiveRecord(msg.buffer, msg.size);
      } else if (tp == crt) {
        ps->receiveCrt(msg.buffer);
      }
    }
  }
}

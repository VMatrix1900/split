#include "proxy_ssl.h"
#include "constants.h"
#include "shared_buffer.hpp"
#include "proxy_client.hpp"
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
  ProxyClient *pcs[MAXCONNS] = {NULL};
  for (int i = 0; i < MAXCONNS; i ++) {
    pcs[i] = new ProxyClient(ctx, i, &down, &pc_to_ps);
  }

  struct packet packet;
  struct message msg;
  while (true) {
    while(up.pullData((char *)&packet, MAX_PACKET_SIZE)>0) {
      ProxyClient *pc = pcs[packet.id];
      pc->receivePacket(packet.buffer, packet.size);
    }
    while(ps_to_pc.pullData((char *)&msg, MAX_MSG_SIZE) > 0) {
      //distribute the message:
      enum message_type tp = msg.type;
      ProxyClient *pc = pcs[msg.id];
      if (tp == record) {
        pc->receiveRecord(msg.buffer, msg.size);
      } else if (tp == sni) {
        pc->receiveSNI(msg.buffer);
      }
    }
  }
}

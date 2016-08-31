#include "proxy_ssl.h"
#include "channel.h"
#include "proxy_server.hpp"
#include <timer_session/connection.h>  //timer
#include "ssl.h"
Secure_box::shared_buffer up;
Secure_box::shared_buffer down;
Secure_box::shared_buffer ps_to_pc;
Secure_box::shared_buffer pc_to_ps;
Secure_box::shared_buffer mb_to_server;
Secure_box::shared_buffer server_to_mb;
Timer::Connection timer;
Cache cert_cache;

int main() {
  timer.msleep(35 * 1000);
  if (ssl_init() < 0) {
    printf("init wrong");
  }
  ERR_load_BIO_strings();
  struct cert_ctx *ctx = load_cert_ctx();
  if (!ctx) {
    fprintf(stderr, "ctx load wrong\n");
    return -1;
  } else {
  }
  up.initialize_queue((char *)"up_server");
  down.initialize_queue((char *)"down_server");
  ps_to_pc.initialize_queue((char *)"ps_to_pc");
  pc_to_ps.initialize_queue((char *)"pc_to_ps");
  server_to_mb.initialize_queue((char *)"server_to_mb");
  mb_to_server.initialize_queue((char *)"mb_to_server");
  struct packet *pkt = (struct packet *)malloc(sizeof(struct packet));
  struct message *msg = (struct message *)malloc(sizeof(struct message));
  ProxyServer **pss = (ProxyServer **)malloc(MAXCONNS * sizeof(ProxyServer *));
  for (int i = 0; i < MAXCONNS; i++) {
    pss[i] = new (Genode::env()->heap()) ProxyServer(ctx, i, &down, &ps_to_pc, &server_to_mb, pkt, msg, &cert_cache);
  }

  printf("proxy server is running\n");
  while (true) {
    bool newdata = false;
    if (up.pull_data((void *)pkt, sizeof(struct packet)) > 0) {
      ProxyServer *ps = pss[pkt->id];
      if (pkt->size < 0) {
        // printf("%d receive %d from lb\n", pkt->id, pkt->size);
        ps->sendCloseAlertToOther();
      } else {
        ps->receivePacket(pkt->buffer, pkt->size);
      }
      newdata = true;
    }
    if (pc_to_ps.pull_data((void *)msg, sizeof(struct message)) > 0) {
      // distribute the message:
      // printf("%d receive %d from pc\n", msg->id, msg->size);
      enum message_type tp = msg->type;
      ProxyServer *ps = pss[msg->id];
      if (tp == crt) {
        ps->receiveCrt(msg->buffer);
      } else {
        fprintf(stderr, "wrong type\n");
      }
    }  // pc_to_ps.print_headers();
    if (mb_to_server.pull_data((void *)msg, sizeof(struct message)) > 0) {
      // distribute the message:
      // printf("%d receive %d from mb\n", msg->id, msg->size);
      enum message_type tp = msg->type;
      ProxyServer *ps = pss[msg->id];
      if (tp == record) {
        ps->receiveRecord(msg->buffer, msg->size);
      } else if (tp == close){
        // printf("%d receive close from mb\n", msg->id);
        ps->receiveCloseAlert();
      } else {
        fprintf(stderr, "wrong type\n");
      }
    }  // pc_to_ps.print_headers();
    // if (!newdata) {
    //   timer.usleep(15);
    // }
  }
}

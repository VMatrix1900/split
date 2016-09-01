#include "proxy_ssl.h"
#include "message.h"
#include "proxy_server.hpp"
#ifndef IN_LINUX
#include <timer_session/connection.h>  //timer
#endif
#include "ssl.h"

Channel up("up_client");
Channel down("down_client");
Channel ps_to_pc("ps_to_pc");
Channel pc_to_ps("pc_to_ps");
Channel mb_to_server("mb_to_server");
Channel server_to_mb("server_to_mb");
Cache cert_cache;

int main() {
#ifndef IN_LINUX
  Timer::Connection timer;
  timer.msleep(35 * 1000);
#endif
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
  // up.initialize_queue((char *)"up_server");
  // down.initialize_queue((char *)"down_server");
  // ps_to_pc.initialize_queue((char *)"ps_to_pc");
  // pc_to_ps.initialize_queue((char *)"pc_to_ps");
  // server_to_mb.initialize_queue((char *)"server_to_mb");
  // mb_to_server.initialize_queue((char *)"mb_to_server");
  struct TLSPacket *pkt = (struct TLSPacket *)malloc(sizeof(struct TLSPacket));
  struct Plaintext *msg = (struct Plaintext *)malloc(sizeof(struct Plaintext));
  ProxyServer **pss = (ProxyServer **)malloc(MAXCONNS * sizeof(ProxyServer *));
  for (int i = 0; i < MAXCONNS; i++) {
    // pss[i] = new (Genode::env()->heap()) ProxyServer(ctx, i, &down, &ps_to_pc, &server_to_mb, pkt, msg, &cert_cache);
    pss[i] = new ProxyServer(ctx, i, &down, &ps_to_pc, &server_to_mb, pkt, msg, &cert_cache);
  }

  printf("proxy server is running\n");
  while (true) {
    bool newdata = false;
    if (up.pull_data((void *)pkt, sizeof(struct TLSPacket)) > 0) {
      ProxyServer *ps = pss[pkt->id];
      if (pkt->size < 0) {
        // printf("%d receive %d from lb\n", pkt->id, pkt->size);
        ps->sendCloseAlertToOther();
      } else {
        ps->receivePacket(pkt->buffer, pkt->size);
      }
      newdata = true;
    }
    if (pc_to_ps.pull_data((void *)msg, sizeof(struct Plaintext)) > 0) {
      // distribute the message:
      // printf("%d receive %d from pc\n", msg->id, msg->size);
      enum TextType tp = msg->type;
      ProxyServer *ps = pss[msg->id];
      if (tp == CRT) {
        ps->receiveCrt(msg->buffer);
      } else {
        fprintf(stderr, "wrong type\n");
      }
    }  // pc_to_ps.print_headers();
    if (mb_to_server.pull_data((void *)msg, sizeof(struct Plaintext)) > 0) {
      // distribute the message:
      // printf("%d receive %d from mb\n", msg->id, msg->size);
      enum TextType tp = msg->type;
      ProxyServer *ps = pss[msg->id];
      if (tp == HTTP) {
        ps->receiveRecord(msg->buffer, msg->size);
      } else if (tp == CLOSE){
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

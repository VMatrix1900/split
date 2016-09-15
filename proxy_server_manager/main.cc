#include "proxy_ssl.h"
#include "message.h"
#include "proxy_server.hpp"
#ifndef IN_LINUX
#include <timer_session/connection.h>  //timer
#endif
#include "ssl.h"

int main() {
  Channel up("up_server");
  Channel down("down_server");
  Channel ps_to_pc("ps_to_pc");
  Channel pc_to_ps("pc_to_ps");
  Channel mb_to_server("mb_to_server");
  Channel server_to_mb("server_to_mb");
  Cache cert_cache;
#ifndef IN_LINUX
  Timer::Connection timer;
  timer.msleep(35 * 1000);
  PDBG("hello server");
#else
  // FILE *logfile = fopen("/home/vincent/Downloads/split/build/ps.log", "a");
  // set_logoutput(logfile);
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
  struct TLSPacket *pkt = (struct TLSPacket *)malloc(sizeof(struct TLSPacket));
  struct Plaintext *msg = (struct Plaintext *)malloc(sizeof(struct Plaintext));
  ProxyServer **pss = (ProxyServer **)malloc(MAXCONNS * sizeof(ProxyServer *));
  for (int i = 0; i < MAXCONNS; i++) {
#ifdef IN_LINUX
    pss[i] = new ProxyServer(ctx, i, &down, &ps_to_pc, &server_to_mb, pkt, msg,
                             &cert_cache);
#else
    pss[i] = new (Genode::env()->heap()) ProxyServer(ctx, i, &down,
    &ps_to_pc, &server_to_mb, pkt, msg, &cert_cache);
#endif
  }

  printf("proxy server is running\n");
  while (true) {
    bool newdata = false;
    if (up.pull_data((void *)pkt, sizeof(struct TLSPacket)) > 0) {
      ProxyServer *ps = pss[pkt->id];
      if (pkt->size < 0) {
        // log_receive(pkt->id, "close", "LB");
        ps->sendCloseAlertToOther();
      } else {
        log_receive(pkt->id, "packet", "LB", pkt->size);
        ps->receivePacket(pkt->buffer, pkt->size);
      }
      newdata = true;
    }
    if (pc_to_ps.pull_data((void *)msg, sizeof(struct Plaintext)) > 0) {
// distribute the message:
      enum TextType tp = msg->type;
      ProxyServer *ps = pss[msg->id];
      if (tp == CRT) {
        log_receive(msg->id, "message", "PC", msg->size);
        ps->receiveCrt(msg->buffer);
      } else {
        fprintf(stderr, "wrong type\n");
      }
    }  // pc_to_ps.print_headers();
    if (mb_to_server.pull_data((void *)msg, sizeof(struct Plaintext)) > 0) {
// distribute the message:
      enum TextType tp = msg->type;
      ProxyServer *ps = pss[msg->id];
      if (tp == HTTP) {
        log_receive(msg->id, "message", "MB", msg->size);
        ps->receiveRecord(msg->id, msg->buffer, msg->size);
      } else if (tp == CLOSE) {
        // log_receive(msg->id, "close", "MB");
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

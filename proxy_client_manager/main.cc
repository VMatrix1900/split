#include "proxy_ssl.h"
#include "message.h"
#include "proxy_client.hpp"
#include "ssl.h"
#include <stdio.h>
#ifdef MEASURE_TIME
#include <trace/timestamp.h>  //timestamp
#endif
#ifndef IN_LINUX
#include <timer_session/connection.h>  //timer
#endif
Channel up("up_client");
Channel down("down_client");
Channel ps_to_pc("ps_to_pc");
Channel pc_to_ps("pc_to_ps");
Channel mb_to_client("mb_to_client");
Channel client_to_mb("client_to_mb");

typedef std::map<int, ProxyClient *> PacketsClientPair;
int main() {
#ifndef IN_LINUX
  Timer::Connection timer;
  timer.msleep(45 * 1000);
#else
  // FILE *logfile = fopen("/home/vincent/Downloads/split/build/pc.log", "a");
  // set_logoutput(logfile);
#endif
#ifdef MEASURE_TIME
  volatile unsigned int t1 = 0, t2 = 0, overhead = 0;
  t1 = Genode::Trace::timestamp();
  overhead = Genode::Trace::timestamp() - t1;  // time measuring overhead
  PDBG("time measuring overhead is: %u\n", overhead);
#endif
  // time_t tmp;
  // time(&tmp);
  // printf("time is %s\n", ctime(&tmp));
  if (ssl_init() < 0) {
    printf("init wrong");
  }
  ERR_load_BIO_strings();
  // printf("get ctx\n");
  struct TLSPacket *pkt = (struct TLSPacket *)malloc(sizeof(struct TLSPacket));
  struct Plaintext *msg = (struct Plaintext *)malloc(sizeof(struct Plaintext));
  // TODO in_pkt and out_pkt
  PacketsClientPair pcs;

  printf("proxy client is running\n");
#ifdef MEASURE_TIME
  int i = 0;
  double pkt_speed = 0;
#endif
  while (true) {
    bool newdata = false;
    if (up.pull_data((void *)pkt, sizeof(struct TLSPacket)) > 0) {
      newdata = true;
#ifdef MEASURE_TIME
      t1 = Genode::Trace::timestamp();
#endif
      ProxyClient *pc = pcs[pkt->id];
      // up.print_headers();
      if (pkt->size < 0) {
        // log_receive(pkt->id, "close", "LB");
        pc->sendCloseAlertToOther();
      } else {
        log_receive(pkt->id, "packet", "LB", pkt->size);
        pc->receivePacket(pkt->buffer, pkt->size);
      }
      // t2 = Genode::Trace::timestamp();
      // if (pc->handshakedone()) {
      //   pkt_speed += (double)pkt->size / (t2 - t1 -overhead);
      //   i ++;
      // }
      // if (i == 1000) {
      //   printf("%d crypto speed: %d\n", pkt->size, (int)pkt_speed);
      //   pkt_speed = 0;
      //   i = 0;
      // }
    }
    if (ps_to_pc.pull_data((char *)msg, sizeof(struct Plaintext)) > 0) {
      // distribute the message:
      log_receive(msg->id, "message", "PS", msg->size);
      enum TextType tp = msg->type;
      ProxyClient *pc = (ProxyClient *)0;
      if (tp == SNI) {
        // when receive the SNI, that means a new connection, can we reuse the
        // existing TLS connection?
        std::string domainname = std::string(msg->buffer);
        log(domainname);
        bool reuse = false;
        for (PacketsClientPair::const_iterator it = pcs.begin();
             it != pcs.end(); it++) {
          pc = it->second;
          if (pc->http2_selected && pc->domain == domainname) {
            log(pc->id, "found an existing TLS connection." + domainname);
            reuse = true;
            break;
          }
        }
        if (!reuse) {
          log(msg->id, "Create a new connection");
          #ifdef IN_LINUX
          pcs[msg->id] = new ProxyClient(NULL, msg->id, &down, &pc_to_ps,
                                         &client_to_mb, pkt, msg);
          #else
          pcs[msg->id] = new (Genode::env()->heap())
                 ProxyClient(NULL, msg->id, &down, &pc_to_ps, &client_to_mb, pkt, msg);
          #endif
          pc = pcs[msg->id];
          pc->receiveSNI(msg->buffer);
        } else {
          pcs[msg->id] = pc;
        }
      } else {
        fprintf(stderr, "wrong type\n");
      }
    }
    if (mb_to_client.pull_data((char *)msg, sizeof(struct Plaintext)) > 0) {
      // distribute the message:
      // std::cerr << std::string(msg->buffer, msg->size);
      enum TextType tp = msg->type;
      ProxyClient *pc = pcs[msg->id];
      if (tp == HTTP) {
        log_receive(msg->id, "packet", "MB", msg->size);
        pc->receiveRecord(msg->id, msg->buffer, msg->size);
      } else if (tp == CLOSE) {
        // log_receive(msg->id, "close", "MB");
        pc->receiveCloseAlert(msg->id);
      } else {
        fprintf(stderr, "wrong type\n");
      }
    }
    // if (!newdata) {
    //   timer.usleep(15);
    // }
  }
}

#include "proxy_ssl.h"
#include "channel.h"
#include "proxy_client.hpp"
#include "ssl.h"
#include <stdio.h>
#include <trace/timestamp.h>           //timestamp
#include <timer_session/connection.h>  //timer
Secure_box::shared_buffer up;
Secure_box::shared_buffer down;
Secure_box::shared_buffer ps_to_pc;
Secure_box::shared_buffer pc_to_ps;
Secure_box::shared_buffer mb_to_client;
Secure_box::shared_buffer client_to_mb;
Timer::Connection timer;

int main() {
  timer.msleep(35 * 1000);
  volatile unsigned int t1 = 0, t2 = 0, overhead = 0;
  t1 = Genode::Trace::timestamp();
  overhead = Genode::Trace::timestamp() - t1;  // time measuring overhead
  PDBG("time measuring overhead is: %u\n", overhead);
  // time_t tmp;
  // time(&tmp);
  // printf("time is %s\n", ctime(&tmp));
  if (ssl_init() < 0) {
    printf("init wrong");
  }
  ERR_load_BIO_strings();
  // printf("get ctx\n");
  up.initialize_queue((char *)"up_client");
  down.initialize_queue((char *)"down_client");
  ps_to_pc.initialize_queue((char *)"ps_to_pc");
  pc_to_ps.initialize_queue((char *)"pc_to_ps");
  client_to_mb.initialize_queue((char *)"client_to_mb");
  mb_to_client.initialize_queue((char *)"mb_to_client");
  struct packet *pkt = (struct packet *)malloc(sizeof(struct packet));
  struct message *msg = (struct message *)malloc(sizeof(struct message));
  ProxyClient **pcs = (ProxyClient **)malloc(MAXCONNS * sizeof(ProxyClient *));
  for (int i = 0; i < MAXCONNS; i++) {
    pcs[i] = new (Genode::env()->heap())
        ProxyClient(NULL, i, &down, &pc_to_ps, &client_to_mb, pkt, msg);
  }

  printf("proxy client is running\n");
  int i = 0;
  double pkt_speed = 0;
  while (true) {
    bool newdata = false;
    if (up.pull_data((void *)pkt, sizeof(struct packet)) > 0) {
      newdata = true;
      t1 = Genode::Trace::timestamp();
      ProxyClient *pc = pcs[pkt->id];
      // printf("%d receive %d from lb\n", pkt->id, pkt->size);
      // up.print_headers();
      if (pkt->size < 0) {
        // printf("%d receive %d from lb\n", pkt->id, pkt->size);
        pc->sendCloseAlertToOther();
      } else {
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
    if (ps_to_pc.pull_data((char *)msg, sizeof(struct message)) > 0) {
      // distribute the message:
      // printf("%d receive from ps\n", msg->id);
      enum message_type tp = msg->type;
      ProxyClient *pc = pcs[msg->id];
      if (tp == sni) {
        pc->receiveSNI(msg->buffer);
      } else {
        fprintf(stderr, "wrong type\n");
      }
    }
    if (mb_to_client.pull_data((char *)msg, sizeof(struct message)) > 0) {
      // distribute the message:
      // printf("%d receive from mb\n", msg->id);
      // std::cerr << std::string(msg->buffer, msg->size);
      enum message_type tp = msg->type;
      ProxyClient *pc = pcs[msg->id];
      if (tp == record) {
        pc->receiveRecord(msg->buffer, msg->size);
      } else if (tp == close){
        // printf("%d receive close from mb\n", msg->id);
        pc->receiveCloseAlert();
      } else {
        fprintf(stderr, "wrong type\n");
      }
    }
    // if (!newdata) {
    //   timer.usleep(15);
    // }
  }
}

#include "http_parser_cache.hpp"
#include <iostream>
#include <stdlib.h>
#ifndef IN_LINUX
#include <timer_session/connection.h>  //timer
#endif

Channel mb_to_client("mb_to_client");
Channel client_to_mb("client_to_mb");
Channel mb_to_server("mb_to_server");
Channel server_to_mb("server_to_mb");

int main() {
#ifndef IN_LINUX
  Timer::Connection timer;
  timer.msleep(35 * 1000);
#else
  // FILE *logfile = fopen("/home/vincent/Downloads/split/build/cache.log", "a");
  // set_logoutput(logfile);
#endif

  struct Plaintext *server_msg =
      (struct Plaintext *)malloc(sizeof(struct Plaintext));
  struct Plaintext *client_msg =
      (struct Plaintext *)malloc(sizeof(struct Plaintext));

#ifdef IN_LINUX
  Secure_box::Web_cache *cache_mb =
      new Secure_box::Web_cache(&mb_to_client, &mb_to_server);
#else
  Secure_box::Web_cache *cache_mb = new (Genode::env()->heap())
      Secure_box::Web_cache(&mb_to_client, &mb_to_server);
#endif
  while (true) {
    bool newdata = false;
    if (server_to_mb.pull_data((void *)server_msg, sizeof(struct Plaintext)) >
        0) {
      newdata = true;
      cache_mb->GetParser(server_msg->id);
      if (server_msg->type == CLOSE) {
        // log_receive(server_msg->id, "close", "PS");
        // cache_mb->SendCloseAlert(Secure_box::client, server_msg->id);
      } else {
        // log_receive(server_msg->id, "message", "PS", server_msg->size);
        std::string content = cache_mb->ParseHTTPRequest(server_msg->id, server_msg->buffer,
                                                         server_msg->size);
        if (!content.empty()) {
          log("Get body: " + content);
          char len[25];
          sprintf(len, "%d", content.length());

          std::string headerline;
          headerline += "HTTP/1.1 200 OK";
          // headerline += "\r\n" ;headerline += "Content-length: ";
          // headerline += std::string(len);
          headerline += "\r\nContent-Type: text/html; charset=utf-8 \r\n";
          headerline += "Date: Tue, 20 Sep 2016 12:09:59 GMT\r\n";
          headerline += "Server: Cowboy\r\n \r\n";
          log (headerline);
          cache_mb->SendRecord(headerline + content + "\r\n\r\n", Secure_box::server, server_msg->id);
          cache_mb->SendCloseAlert(Secure_box::server, server_msg->id);
        }
      }
    }
#ifndef IN_LINUX
    if (!newdata) {
      timer.usleep(15);
    }
#endif
  }
}

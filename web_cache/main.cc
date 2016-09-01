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
#endif
  // client_to_mb.initialize_queue((char *)"client_to_mb");
  // server_to_mb.initialize_queue((char *)"server_to_mb");
  // mb_to_client.initialize_queue((char *)"mb_to_client");
  // mb_to_server.initialize_queue((char *)"mb_to_server");

  struct Plaintext *server_msg =
      (struct Plaintext *)malloc(sizeof(struct Plaintext));
  struct Plaintext *client_msg =
      (struct Plaintext *)malloc(sizeof(struct Plaintext));
  // Secure_box::Web_cache *cache_mb = new (Genode::env()->heap())
  //     Secure_box::Web_cache(&mb_to_client, &mb_to_server);

  Secure_box::Web_cache *cache_mb =
      new Secure_box::Web_cache(&mb_to_client, &mb_to_server);
  while (true) {
    bool newdata = false;
    if (client_to_mb.pull_data((void *)client_msg, sizeof(struct Plaintext)) >
        0) {
      newdata = true;
      cache_mb->GetParser(client_msg->id);
      if (client_msg->type == CLOSE) {
        // std::cerr << "receive close from client" << client_msg->id;
        cache_mb->SendCloseAlert(Secure_box::server, client_msg->id);
      } else {
        cache_mb->ParseHTTPResponse(client_msg->id, client_msg->buffer,
                                    client_msg->size);
      }
    }
    if (server_to_mb.pull_data((void *)server_msg, sizeof(struct Plaintext)) >
        0) {
      newdata = true;
      cache_mb->GetParser(server_msg->id);
      if (server_msg->type == CLOSE) {
        // std::cerr << "receive close from server" << server_msg->id;
        cache_mb->SendCloseAlert(Secure_box::client, server_msg->id);
      } else {
        cache_mb->ParseHTTPRequest(server_msg->id, server_msg->buffer,
                                   server_msg->size);
      }
    }
#ifndef IN_LINUX
    if (!newdata) {
      timer.usleep(15);
    }
#endif
  }
}

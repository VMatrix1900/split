#pragma once
#include "constants.h"
enum message_type { record, sni, crt, close };
struct message {
  enum message_type type;
  int id;
  int size;
  char buffer[MAX_MSG_SIZE];
};
struct packet {
  int id;
  int size;
  char buffer[MAX_PACKET_SIZE];
};

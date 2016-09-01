#pragma once
#include "constants.h"
enum TextType {HTTP, SNI, CRT, CLOSE };
struct Plaintext {
  enum TextType type;
  int id;
  int size;
  char buffer[MAX_MSG_SIZE];
};

struct TLSPacket {
  int id;
  int size;
  char buffer[MAX_PACKET_SIZE];
};

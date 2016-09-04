#pragma once
#include "constants.h"
enum TextType {HTTP, SNI, CRT, CLOSE };
struct Plaintext {
  enum TextType type;
  int id;
  int size;
  char buffer[MAX_MSG_SIZE];
};

enum packet_type {client = 1, server = 2, close_client = 3, close_server = 4};
struct TLSPacket {
  int id;
  enum packet_type side;
  int size;
  char buffer[MAX_PACKET_SIZE];
};

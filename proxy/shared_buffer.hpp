#include "constants.h"
enum message_type { record, sni, crt };
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

class shared_buffer
{
 public:
  shared_buffer(){

  };
  ~shared_buffer(){

  };
  void initialize(char *name){

  };
  int putData(char *data, int length){

  };
  int pullData(char *buf, int length){

  };
};

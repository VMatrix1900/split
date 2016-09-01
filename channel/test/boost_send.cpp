#include <iostream>
#include <vector>
#include "channel.hpp"

int main() {
  boost::interprocess::message_queue::remove("message_queue");

  Channel cl("message_queue");

  // Send 100 numbers
  for (int i = 0; i < 100; ++i) {
    while (cl.put_data(&i, sizeof(int)) < 0) {
      ;
    }
    std::cout << "Send number " << i << std::endl;
  }
  return 0;
}

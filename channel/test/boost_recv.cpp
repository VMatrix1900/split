#include <iostream>
#include <vector>
#include "channel.hpp"

int main ()
{
    Channel cl("message_queue");

    //Receive 100 numbers
    for(int i = 0; i < 100; ++i){
      int number[35000];
      while (cl.pull_data(number, sizeof(number)) < 0) {
        ;
      }

      std::cout << "Receive number " << number[0] << std::endl;
    }
  boost::interprocess::message_queue::remove("message_queue");
  return 0;
}

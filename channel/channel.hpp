#pragma once
#include <iostream>
#include <boost/interprocess/ipc/message_queue.hpp>

class Channel {
private:
  boost::interprocess::message_queue mq;

public:
  Channel(const char *name);
  ~Channel();
  int pull_data(void *data_ptr, std::size_t size);
  int put_data(void *data_ptr, std::size_t size);
};

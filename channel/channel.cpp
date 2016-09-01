#include "channel.hpp"
Channel::Channel(const char *name): mq(boost::interprocess::open_or_create, name, 50, 35000) {
}

Channel::~Channel() {
}

// send the data, if success return the size sent(== size); if fail, return -1
// may block
int Channel::put_data(void *data_ptr, std::size_t size) {
  try{
    mq.send(data_ptr, size, 0);
    return size;
  } catch(boost::interprocess::interprocess_exception &ex) {
    std::cerr << ex.what() << std::endl;
    return -1;
  }
}

// receive the data, if success, return the data size received; if fail, return -1;
// the size argmument must be greater than 35000;
// may block
int Channel::pull_data(void *data_ptr, std::size_t size) {
  boost::interprocess::message_queue::size_type recevdsize;
  unsigned int prio;
  try{
    mq.receive(data_ptr, size, recevdsize, prio);
    return recevdsize;
  } catch(boost::interprocess::interprocess_exception &ex) {
    std::cerr << ex.what() << std::endl;
    return -1;
  }
}

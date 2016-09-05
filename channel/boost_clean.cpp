#include "channel.hpp"

int main(int argc, char *argv[])
{
  boost::interprocess::message_queue::remove("tcp_to_ssl");
  boost::interprocess::message_queue::remove("ssl_to_tcp");
  boost::interprocess::message_queue::remove("up_client");
  boost::interprocess::message_queue::remove("down_client");
  boost::interprocess::message_queue::remove("down_server");
  boost::interprocess::message_queue::remove("up_server");
  boost::interprocess::message_queue::remove("mb_to_server");
  boost::interprocess::message_queue::remove("server_to_mb");
  boost::interprocess::message_queue::remove("pc_to_ps");
  boost::interprocess::message_queue::remove("ps_to_pc");
  boost::interprocess::message_queue::remove("client_to_mb");
  boost::interprocess::message_queue::remove("mb_to_client");
  std::cout << "all cleaned";
  return 0;
}


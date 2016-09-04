#pragma once
#include <map>
#include "httpstream.hpp"
#include <nghttp2/nghttp2.h>

// typedef ssize_t (*send_data_callback)(const uint8_t *data, size_t length);
#define _U_ __attribute__((unused))
class HTTP2Client {
public:
  nghttp2_session *session;

  std::map<int32_t, HTTPStream*> stream_id_to_stream;
  std::map<int, HTTPStream*> pkt_id_to_stream;
  volatile bool responseParsed;

public:
  HTTP2Client();

  std::string sendHTTP1Request(int packet_id, const char *buf, size_t len);
  ssize_t parseHTTP2Response(const uint8_t *in, size_t len);
  // void set_send_callback(send_data_callback send_data);
  std::string getQueuedFrame();
  void processResponse();

private:

  void submit_client_connection_setting();
  void submit_client_request(int pkt_id);
  nghttp2_nv make_nv(const std::string& name, const std::string& value);
};

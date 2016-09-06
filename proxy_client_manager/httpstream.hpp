#pragma once
#include "httpxx/http.hpp"
#include "log.h"

class HTTPStream {
public:
  int pkt_id;
  http::BufferedRequest request;
  http::BufferedResponse tmp;
  http::ResponseBuilder response;

  HTTPStream(int id) : pkt_id(id) {
    response = http::ResponseBuilder(tmp);
  }
  ~HTTPStream() {
    log(pkt_id, "Stream destroyed");
  }
};

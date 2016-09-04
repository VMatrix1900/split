#pragma once
#include "httpxx/http.hpp"

class HTTPStream {
public:
  int pkt_id;
  http::BufferedRequest request;
  http::BufferedResponse tmp;
  http::ResponseBuilder response;

  HTTPStream(int id) : pkt_id(id) {
  }
};

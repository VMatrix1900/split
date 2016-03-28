#pragma once
#include "httpxx/http.hpp"
#define MAXCONNS 65536
enum packet_type { client, server };
class HTTPStreamParser
{
 public:
  HTTPStreamParser();
  ~HTTPStreamParser();

  http::BufferedRequest request;
  http::BufferedResponse response;
  bool interested;
  std::string url;
};

void ParseHTTPRequest(int id, const char *buf, int size, char *result,
                      int result_length, enum packet_type side);
void ParseHTTPResponse(int id, const char *buf, int size, char *result,
                       int result_length);

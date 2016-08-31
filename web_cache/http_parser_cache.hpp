#ifndef _SECUREBOX_HTTP_PARSER_CACHE_H_
#define _SECUREBOX_HTTP_PARSER_CACHE_H_
#include <string>
#include <stddef.h>
#include "httpxx/http.hpp"
#include "channel.h"
#include "cache.hpp"
#include <sharedmem_session/connection.h>
#include <securebox_session/shared_buffer.h>

namespace Secure_box
{
class HTTPStreamParser;
class Web_cache;
enum packet_type { client, server };
}

class Secure_box::HTTPStreamParser
{
 public:
  HTTPStreamParser() : interested(false) {}
  ~HTTPStreamParser() {}
  http::BufferedRequest request;
  http::BufferedResponse response;
  bool interested;
  std::string url;
};

class Secure_box::Web_cache
{
 private:
  Secure_box::HTTPStreamParser
      *_parsers[MAXCONNS];  // this will cause inster_traslation assertion
  cache::Resource _resourcecache;
  Secure_box::shared_buffer *to_client;
  Secure_box::shared_buffer *to_server;

 public:
  Web_cache(Secure_box::shared_buffer *to_client,
            Secure_box::shared_buffer *to_server)
      : to_client(to_client), to_server(to_server)
  {
    for (unsigned i = 0; i < MAXCONNS; i++) {
      _parsers[i] = (Secure_box::HTTPStreamParser *)0;
    }
  }

  Secure_box::HTTPStreamParser *GetParser(int id);

  void Delete_parser(int id);

  void SendRecord(std::string msg, enum packet_type side, int id);

  void SendCloseAlert(enum packet_type side, int id);

  void ParseHTTPRequest(int id, const char *buf, int size);

  void ParseHTTPResponse(int id, const char *buf, int size);

  bool AllowCache(std::string policy);
};

#endif
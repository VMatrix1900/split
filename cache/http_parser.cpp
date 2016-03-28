#include "http_parser.hpp"
#include <cstdlib>
#include <iostream>
#include <regex>
#include "cache.hpp"
#define MAXCONNS 65536

HTTPStreamParser parsers[MAXCONNS];
cache::Resource resourcecache;

void ParseHTTPRequest(int id, const char *buf, int size, const char *result,
                      int result_length, enum packet_type side)
{
  http::BufferedRequest &request = parsers[id].request;
  while (size > 0) {
    // Parse as much data as possible.
    while ((size > 0) && !request.complete()) {
      std::size_t pass = request.feed(data, size);
      data += pass, size -= pass;
    }

    // Check that we've parsed an entire request.
    if (!request.complete()) {  // which means size == 0
      std::cerr << "Request still needs data." << std::endl;
    } else {  // size > 0 add the logic of detect url
      if (request.method_name() == "GET") {
        parser[id].url = request.header("HOST") + request.url();
        std::string cached = resourcecache.GetResource(parser[id].url);
        if (cached != "") {
          result_length = cached.length();
          result = malloc(result_length + 1);
          strcpy(result, cached.c_str());
          side = server;
        } else {
          parser[id].interested = true;
          // rebuild the request, forward it
          http::RequestBuilder rebuild_request(request);
          std::string requststring = rebuild_request.to_string();
          result_length = requeststring.length();
          result = malloc(result_length + 1);
          strcpy(result, requeststring.c_str());
          side = client;
        }
      } else {
        // other request, just forward it.
        http::RequestBuilder rebuild_request(request);
        std::string requststring = rebuild_request.to_string();
        result_length = requeststring.length();
        result = malloc(result_length + 1);
        strcpy(result, requeststring.c_str());
        side = client;
      }
      // Prepare to receive another request.
      request.clear();
    }
  }
}

bool AllowCache(std::string policy) {
  std::regex public("public");
  return std::regex_match(policy, public);
}

void ParseHTTPResponse(int id, const char *buf, int size, const char *result,
                       int result_length)
{
  http::BufferedResponse &response = parsers[id].response;
  while (size > 0) {
    // Parse as much data as possible.
    while ((size > 0) && !response.complete()) {
      std::size_t pass = response.feed(data, size);
      data += pass, size -= pass;
    }

    int time = 900;
    // Check that we've parsed an entire response.
    if (!response.complete()) {  // which means size == 0
      std::cerr << "Response still needs data." << std::endl;
    } else {  // size > 0 check cache control policy
      http::ResponseBuilder rebuild_response(response);
      std::string responsestring = rebuild_response.to_string();
      result_length = responsestring.length();
      result = malloc(result_length + 1);
      strcpy(result, responsestring.c_str());
      if (response.status() == 200 && parser[id].interested &&
          AllowCache(
              response.header("Cache-Control"))) {  // ok get the resource
        resourcecache.AddResource(parser[id].url, responsestring, time);
      }
      // Prepare to receive another response.
      response.clear();
    }
  }
}

// Copyright(c) Andre Caron <andre.l.caron@gmail.com>, 2011
//
// This document is covered by the an Open Source Initiative approved license. A
// copy of the license should have been provided alongside this software package
// (see "LICENSE.txt"). If not, terms of the license are available online at
// "http://www.opensource.org/licenses/mit".

#include "http.hpp"
#include <cstdlib>
#include <fstream>
#include <iostream>
#include "constants.h"

namespace
{
HTTPStreamParser parsers[MAXCONNS];

int run(std::istream &stream)
{
  // Parse HTTP request.
  http::BufferedRequest request;
  char data[1024];
  do {
    stream.read(data, sizeof(data));
    std::size_t size = stream.gcount();
    std::size_t pass = 0;
  } while ((stream.gcount() > 0) && !request.complete());

  // Extract header.
  std::cout << request.body() << std::endl;
  return (EXIT_SUCCESS);
}
}

ParseHTTPRequest(int id, const char *buf, int size, const char *result,
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
        if (cachehit()) {
          // TODO build the response, don't forward the packet.
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

ParseHTTPResponse(int id, const char *buf, int size, const char *result,
                  int result_length)
{
  http::BufferedResponse &response = parsers[id].response;
  while (size > 0) {
    // Parse as much data as possible.
    while ((size > 0) && !response.complete()) {
      std::size_t pass = response.feed(data, size);
      data += pass, size -= pass;
    }

    // Check that we've parsed an entire response.
    if (!response.complete()) {  // which means size == 0
      std::cerr << "Response still needs data." << std::endl;
    } else {  // size > 0 check cache control policy
      if (response.status() == 200 &&
          parser[id].interested && AllowCache(response.header("Cache-Control") {  // ok get the resource
        cachestore(time, parser[id].url, response.body());
      } else {
        // other response, just forward it.
        http::ResponseBuilder rebuild_response(response);
        std::string requststring = rebuild_response.to_string();
        result_length = responsestring.length();
        result = malloc(result_length + 1);
        strcpy(result, responsestring.c_str());
      }
      // Prepare to receive another response.
      response.clear();
    }
  }
}

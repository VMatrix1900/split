#include "http_parser_cache.hpp"
#ifndef IN_LINUX
#include <base/env.h>
#endif
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <regex>

Secure_box::HTTPStreamParser *Secure_box::Web_cache::GetParser(int id) {
  // search the existing one first
  if (_parsers[id] == (Secure_box::HTTPStreamParser *)0) {
    // _parsers[id] = new (Genode::env()->heap()) Secure_box::HTTPStreamParser;
    _parsers[id] = new Secure_box::HTTPStreamParser;
  }

  return _parsers[id];
}

void Secure_box::Web_cache::Delete_parser(int id) {
  if (_parsers[id] != (Secure_box::HTTPStreamParser *)0) {
    // Genode::destroy(Genode::env()->heap(), _parsers[id]);
    delete _parsers[id];
    _parsers[id] = (Secure_box::HTTPStreamParser *)0;
  }
}

void Secure_box::Web_cache::SendRecord(std::string text, enum packet_type side,
                                       int id) {
  struct Plaintext *msg = (struct Plaintext *)malloc(sizeof(struct Plaintext));
  int length = text.length();
  int size = length;
  const char *buf = text.c_str();
  Channel *dst = (side == client) ? to_client : to_server;
  msg->type = HTTP;
  msg->id = id;
  while (length > 0) {
    msg->size = std::min(length, MAX_MSG_SIZE);
    memcpy(msg->buffer, buf, msg->size);
    while (dst->put_data((void *)msg,
                         msg->size + offsetof(struct Plaintext, buffer)) == 0) {
      ;
    }
    length -= msg->size;
    buf += msg->size;
    // printf("[%d] send record [%d] to %s\n", id, msg->size,
    //        (side == client) ? "client" : "server");
  }
  free(msg);
#ifdef DEBUG
  std::clog << "ID[" << id << "] send request. size: " << size << std::endl;
#endif
}

void Secure_box::Web_cache::SendCloseAlert(enum packet_type side, int id) {
  struct Plaintext *msg = (struct Plaintext *)malloc(sizeof(struct Plaintext));
  Channel *dst = (side == client) ? to_client : to_server;
  msg->type = CLOSE;
  msg->id = id;
  msg->size = 0;
  while (dst->put_data((void *)msg,
                       msg->size + offsetof(struct Plaintext, buffer)) == 0) {
    ;
  }
  free(msg);
}

void Secure_box::Web_cache::ParseHTTPRequest(int id, const char *buf,
                                             int size) {
  http::BufferedRequest &request = _parsers[id]->request;
  char *data = (char *)buf;
  while (size > 0) {
    // Parse as much data as possible.
    while ((size > 0) && !request.complete()) {
      try {
        std::size_t pass = request.feed(data, size);
        data += pass, size -= pass;
      } catch (http::Error &e) {
        std::string buffer = std::string(buf, size);
        std::cerr << "request " << id << "is " << buffer;
        std::cerr << e.what();
      }
    }

    // Check that we've parsed an entire request.
    if (!request.complete()) {  // which means size == 0
      // std::cerr << "Request still needs data." << std::endl;
    } else {  // size > 0 add the logic of detect url
      if (request.method_name() == "GET") {
        _parsers[id]->url = request.header("HOST") + request.url();
        std::string cached = _resourcecache.GetResource(_parsers[id]->url);
        if (cached != "") {
          // printf("[%d] web cache hit, length is %d", id, cached.length());
          // std::cerr << _parsers[id]->url;
          SendRecord(cached, server, id);
        } else {
          // printf("[%d] web cache miss", id);
          _parsers[id]->interested = true;
          http::RequestBuilder rebuild_request(request);
          SendRecord(rebuild_request.to_string() + request.body(), client, id);
        }
      } else {
        // other request, just forward it.
        http::RequestBuilder rebuild_request(request);
        SendRecord(rebuild_request.to_string() + request.body(), client, id);
      }
      // Prepare to receive another request.
      request.clear();
    }
  }
}

bool Secure_box::Web_cache::AllowCache(std::string policy) {
  return policy.find("no-cache") == std::string::npos &&
         policy.find("private") == std::string::npos &&
         policy.find("must-revalidate") == std::string::npos &&
         policy.find("no-store") == std::string::npos;
}

template <typename T>
std::string to_string(T val) {
  std::stringstream stream;
  stream << val;
  return stream.str();
}

void Secure_box::Web_cache::ParseHTTPResponse(int id, const char *buf,
                                              int size) {
  http::BufferedResponse &response = _parsers[id]->response;
  char *data = (char *)buf;
  SendRecord(std::string(buf, size), server, id);
  while (size > 0) {
    // Parse as much data as possible.
    while ((size > 0) && !response.complete()) {
      try {
        std::size_t pass = response.feed(data, size);
        data += pass, size -= pass;
      } catch (http::Error &e) {
        std::string buffer = std::string(buf, size);
        std::cerr << "response is " << buffer << std::endl;
        std::cerr << e.what() << std::endl;
      }
    }

    int time = 900;
    // Check that we've parsed an entire response.
    if (!response.complete()) {  // which means size == 0
      // std::cerr << "Response still needs data." << std::endl;
    } else {  // size > 0 check cache control policy
      // std::cerr <<  id << "reponse parsed: " << _parsers[id]->url;
      // std::cout << "body length: " << response.body().length();
      if (response.status() == 200 && _parsers[id]->interested &&
          AllowCache(
              response.header("Cache-Control"))) {  // ok get the resource
        // std::cerr << "Begin cache";
        http::ResponseBuilder rebuild_response(response);
        if (response.has_header("Transfer-Encoding")) {
          // std::cout << "chunked:";
          http::Message::Headers &headers = rebuild_response.headers();
          headers.erase("Transfer-Encoding");
          headers.insert(std::make_pair("Content-Length",
                                        to_string(response.body().length())));
        } else {
          // std::cout << "content-length:" <<
          // response.header("Content-Length");
        }
        std::string responsestring = rebuild_response.to_string();
        _resourcecache.AddResource(_parsers[id]->url,
                                   responsestring + response.body(), time);
      }
      // Prepare to receive another response.
      response.clear();
    }
  }
}

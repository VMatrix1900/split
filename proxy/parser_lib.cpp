#include "Error.hpp"
#include "Flags.hpp"
#include "Method.hpp"
#include "Message.hpp"
#include "Request.hpp"
#include "Response.hpp"

#include <iostream>
#include <ctime>
#include <cstdlib>

namespace
{
http::Request request_parser[100];
}

void ParseHTTPStream(int id, const char *buf, int size, const char *result,
                     int result_length)
{
  std::size_t used = 0;
  http::Request &request = request_parser[id];
  // while ((used < size) && !request.headers_complete()) {
  //   const std::size_t pass = request.feed(REQUEST + used, size - used);
  //   used += pass, head += pass;
  //   if (request.headers_complete()) {
  //     std::cerr << "Head size: " << head << "." << std::endl;
  //   }
  // }
  while ((used < size) && !request.complete())
    {
      const std::size_t pass = request.feed(data+used, size-used);
      used += pass;
      if (request.complete())
        {
          std::cerr
            << "message size: " << body << "."
            << std::endl;
        }
    }
  if ( !request.complete() ) {
    std::cerr << "Request still needs data." << std::endl;
  }

  // Extract header.
  std::cout
    << request.header("Host") << request.url()
    << std::endl;
}


try {
  // Parse request in random increments.
  std::size_t size = sizeof(REQUEST);
  std::size_t head = 0;

  // feed(request, REQUEST, sizeof(REQUEST));
  if (!request.headers_complete()) {
    std::cerr << "Request still needs data." << std::endl;
    // return (EXIT_FAILURE);
  }
  // Show that we've parsed it correctly.
  std::cout << "Connection: '" << request.header("Connection") << "'."
            << std::endl;
  std::cout << "Host: '" << request.header("Host") << "'." << std::endl;
  std::cout << "url: " << request.url() << "'." << std::endl;
  std::cout << "dnt: " << request.header("DNT") << "'." << std::endl;
  std::cout << "Accept-language: " << request.header("Accept-Language") << "'."
            << std::endl;
 } catch (const std::exception &error) {
  std::cerr << error.what() << std::endl;
  return (EXIT_FAILURE);
 }

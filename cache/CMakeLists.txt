
cmake_minimum_required(VERSION 2.6)

project(cache)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
add_subdirectory(httpparserlib)

set(sources
  http_parser.cpp)

add_library(cache
  STATIC
  ${sources})

add_dependencies(cache httpxx)
target_link_libraries(cache httpxx)

include_directories(${CMAKE_CURRENT_SOURCE_DIR} httpparserlib)


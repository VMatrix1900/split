cmake_minimum_required(VERSION 3.0)
project(cache)
set(CMAKE_CXX_STANDARD 11)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/httpparserlib ../proxy_base)
add_executable(cache main.cc http_parser_cache.cpp cache.cpp)
target_link_libraries(cache LINK_PUBLIC channel httpxx)

cmake_minimum_required(VERSION 3.0)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_STANDARD 11)
project (proxy_client)
find_package(OpenSSL)

add_subdirectory(httpxx)
add_subdirectory(nghttp2)

include_directories(${OPENSSL_INCLUDE_DIR} ../proxy_base)
add_executable(pc main.cc proxy_client.cpp)

target_link_libraries(pc LINK_PUBLIC channel ssl_util proxy_ssl httpxx nghttp2 ${OPENSSL_LIBRARIES})

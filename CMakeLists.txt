cmake_minimum_required (VERSION 3.0)
project (proxy)

add_definitions(-DIN_LINUX)
add_subdirectory(channel)
add_subdirectory(proxy_base)
add_subdirectory(proxy_server_manager)
add_subdirectory(proxy_client_manager)
add_subdirectory(web_cache)

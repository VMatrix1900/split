cmake_minimum_required (VERSION 3.0)
project (boost_mq_test CXX)
find_package(Threads)
find_package(Boost)
if (Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIRS})
  # add_executable(send boost_send.cpp)
  # add_executable(recv boost_recv.cpp)
  add_library(channel STATIC channel.cpp)
  target_link_libraries(channel ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} rt)
  # target_link_libraries(send channel)
  # target_link_libraries(recv channel)
  target_include_directories(channel PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
endif()





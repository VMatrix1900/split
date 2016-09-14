#pragma once
#include <iostream>
#include <stdio.h>
#include <string>

namespace {
  void log(std::string name, int id, int size)
  {
#ifdef DEBUG
    printf("ID[%d] %s Size: %d\n", id, name.c_str(), size);
    /* std::clog << "ID[" << id << "] " << name << " Size: " << size << std::endl; */
#endif
  }

  void log(std::string txt)
  {
#ifdef DEBUG
    /* std::clog << txt << std::endl; */
    printf("%s\n", txt.c_str());
#endif
  }

  void log(int id, std::string txt)
  {
#ifdef DEBUG
    /* std::clog << "ID[" << id << "]" << txt << std::endl; */
    printf("ID[%d] %s\n", id, txt.c_str());
#endif
  }

  void log(std::string name, size_t size)
  {
#ifdef DEBUG
    /* std::clog << name << " Size: " << size << std::endl; */
    printf("%s Size: %zu\n", name.c_str(), size);
#endif
  }

  void log_receive(int id, const char *packet, const char *from)
  {
#ifdef DEBUG
    printf("ID[%d] receive %s from %s\n", id, packet, from);
#endif
  }

  void log_receive(int id, const char *packet, const char *from, int size)
  {
#ifdef DEBUG
    printf("ID[%d] receive %s from %s. Size[%d]\n", id, packet, from, size);
#endif
  }
}

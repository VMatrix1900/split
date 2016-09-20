#pragma once
#include <iostream>
#include <stdio.h>
#include <string>

namespace {
FILE *logoutfile = stdout;

void set_logoutput(FILE *file) { logoutfile = file; }

void logtime() {
#ifdef DEBUG
  time_t tm;
  time(&tm);
  struct tm *now = localtime(&tm);
  std::clog << now->tm_min << "min" << now->tm_sec << "s" << std::endl;
#endif
}

void log(std::string name, int id, int size) {
#ifdef DEBUG
  /* fprintf(logoutfile, "ID[%d] %s Size: %d\n", id, name.c_str(), size); */
  logtime();
  std::clog << "ID[" << id << "] " << name << " Size: " << size << std::endl;
#endif
}

void log(std::string txt) {
#ifdef DEBUG
  logtime();
  std::clog << txt << std::endl;
/* fprintf(logoutfile, "%s\n", txt.c_str()); */
#endif
}

void log(int id, std::string txt) {
#ifdef DEBUG
  logtime();
  std::clog << "ID[" << id << "]" << txt << std::endl;
/* fprintf(logoutfile, "ID[%d] %s\n", id, txt.c_str()); */
#endif
}

void log(std::string name, size_t size) {
#ifdef DEBUG
  logtime();
  std::clog << name << " Size: " << size << std::endl;
/* fprintf(logoutfile, "%s Size: %zu\n", name.c_str(), size); */
#endif
}

void log_receive(int id, const char *packet, const char *from) {
#ifdef DEBUG
  logtime();
  std::clog << "ID[" << id << "] receive " << std::string(packet) << " from "
            << std::string(from) << std::endl;
/* fprintf(logoutfile, "ID[%d] receive %s from %s\n", id, packet, from); */
/* printf("ID[%d] receive %s from %s\n", id, packet, from); */
#endif
}

void log_receive(int id, const char *packet, const char *from, int size) {
#ifdef DEBUG
  /* fprintf(logoutfile, "ID[%d] receive %s from %s. Size[%d]\n", id, packet,
   * from, */
  /*         size); */
  logtime();
  std::clog << "ID[" << id << "] receive " << std::string(packet) << " from "
            << std::string(from) << ". Size[" << size << "]" << std::endl;
/* printf("ID[%d] receive %s from %s. Size[%d]\n", id, packet, from, size); */
#endif
}
}

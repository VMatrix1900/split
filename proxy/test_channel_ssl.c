#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "channel.h"


int main() {
  char buffer[100];
  for (int i = 0; i < 100; i++) {
    buffer[i] = 'a';
  }
  init_shm();
  srandom(time(NULL));
  struct packet_info pi;
  int count = 0;
  while (count < 100) {
    pi = PullFromTCP();
    if (pi.valid) {
      char temp[100];
      void *read = GetToSSLReadPointer();
      memcpy(temp, read, pi.length);
      UpdateToSSLReadPointer(pi.length);
      temp[pi.length] = '\0';
      printf("%d count: ", count);
      printf("received from TCP %d data: %s\n", pi.length, temp);
      count ++;
    }
  }
  count = 0;
  while (count < 100) {
    pi.id = count;
    pi.length = random() % 100;
    pi.valid = true;
    int aval;
    void *write = GetToTCPBufferAddr(&aval);
    memcpy(write, buffer, pi.length);
    while (0 > PushToTCP(pi,write)) {
      ;
    }
    printf("%d count: ", count);
    printf("push to TCP %d data\n", pi.length);
    count ++;
  }
  return 0;
}

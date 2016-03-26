#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "channel.h"


int main() {
  char buffer[101];
  init_shm();
  srandom(time(NULL));
  int count = 0;
  struct packet_info pi;
  while (count < 100) {
    pi.id = count;
    pi.length = random() % 100;
    if (pi.length > 0) {
      for (int i = 0; i < 100; i++) {
        buffer[i] = 65 + random() % 26;
      }
      buffer[100] = '\0';
      printf("The buffer content is %s\n", buffer);
      pi.valid = true;
      int aval;
      void *write = GetToSSLBufferAddr(&aval);
      memcpy(write, buffer, pi.length);
      while (0 > PushToSSL(pi,write)) {
        ;
      }
      printf("%d count: ", count);
      printf("push to SSL %d data\n", pi.length);
      count ++;
    }
  }
  count = 0;
  while (count < 100) {
    pi = PullFromSSL();
    if (pi.valid) {
      char temp[100];
      void *read = GetToTCPReadPointer();
      memcpy(temp, read, pi.length);
      UpdateToTCPReadPointer(pi.length);
      temp[pi.length] = '\0';
      printf("%d count: ", count);
      printf("received from SSL %d data: %s\n", pi.length, temp);
      count ++;
    }
  }
  return 0;
}

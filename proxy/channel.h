#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
// name and the size of the shared memory segment.
key_t key_up = 1000;
key_t key_down = 1001;

#define CIRCULAR_SZ 50
#define BUF_SZ (2 << 20)
#define PACKET_MAX_SZ (2 << 14)

enum packet_type { client, server };

struct packet_info {
  int addr_offset;
  enum packet_type side;
  int id;
  int length;
  bool valid;
};

struct channel {
  int read_head;
  int write_head;
  struct packet_info circular[CIRCULAR_SZ];
  char packet_buffer[BUF_SZ];
  int read, write;
};

// store the info about the semophores and shared memory.
struct shm_ctx_t {
  int shmid_up;
  int shmid_down;
  struct channel *up_channel;
  struct channel *down_channel;
};

struct shm_ctx_t *shm_ctx = NULL;

int init_shm();
int destroy_shm();
struct packet_info _pullPacketInfo(struct channel *channel);
struct packet_info PullFromSSL();
struct packet_info PullFromTCP();
void *_getReadPointer(struct channel *channel);
void *GetToSSLReadPointer();
void *GetToTCPReadPointer();
void _updateReadPointer(struct channel *channel, int delta);
void UpdateToSSLReadPointer(int delta);
void UpdateToTCPReadPointer(int delta);
int _pushPacketInfo(struct packet_info pi, struct channel *channel);
int PushToSSL(struct packet_info pi, void *write_pointer);
int PushToTCP(struct packet_info pi, void *write_pointer);
void *_getBufferAddress(struct channel *channel, int *avaliable);
void *GetToSSLBufferAddr(int *avaliable);
void *GetToTCPBufferAddr(int *avaliable);

#include "channel.h"
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <assert.h>
// name and the size of the shared memory segment.
key_t key_up = 1000;
key_t key_down = 1001;

struct shm_ctx_t *shm_ctx = NULL;

int init_shm()
{
  // create the shared memory segment
  shm_ctx = malloc(sizeof(struct shm_ctx_t));
  int shm_sz = sizeof(struct channel);
  shm_ctx->shmid_up = shmget(key_up, shm_sz, IPC_CREAT | 0666);
  if (shm_ctx->shmid_up < 0) {
    perror("socket:failure in shmget");
    return -1;
  }
  shm_ctx->up_channel = shmat(shm_ctx->shmid_up, NULL, 0);
  if (shm_ctx->up_channel == (void *)-1) {
    perror("up_channel fail.");
    return -1;
  }

  shm_ctx->shmid_down = shmget(key_down, shm_sz, IPC_CREAT | 0666);
  if (shm_ctx->shmid_down < 0) {
    perror("socket:failure in shmget");
    return -1;
  }
  shm_ctx->down_channel = shmat(shm_ctx->shmid_down, NULL, 0);
  if (shm_ctx->down_channel == (void *)-1) {
    perror("down_channel fail.");
    return -1;
  }
  return 0;
}

int destroy_shm()
{
  if (shmdt(shm_ctx->up_channel) < 0) {
    perror("up_channel detach wrong!");
    return -1;
  }
  if (shmdt(shm_ctx->down_channel) < 0) {
    perror("down_channel detach wrong!");
    return -1;
  }
  return 0;
}

struct packet_info _pullPacketInfo(struct channel *channel)
{
  struct packet_info pi = channel->circular[channel->read_head];
  if (pi.valid) {
    printf("read head is %d\n", channel->read_head);
    assert(pi.length > 0);
    channel->circular[channel->read_head].valid = false;
    channel->read_head = (channel->read_head + 1) % CIRCULAR_SZ;
  }
  return pi;
}

struct packet_info PullFromSSL()
{
  return _pullPacketInfo(shm_ctx->down_channel);
}

struct packet_info PullFromTCP()
{
  return _pullPacketInfo(shm_ctx->up_channel);
}

void *_getReadPointer(struct channel *channel)
{
  return channel->packet_buffer + channel->read;
}

void *GetToSSLReadPointer() { return _getReadPointer(shm_ctx->up_channel); }
void *GetToTCPReadPointer() { return _getReadPointer(shm_ctx->down_channel); }
void _updateReadPointer(struct channel *channel, int delta)
{
  channel->read = (channel->read + delta) % BUF_SZ;
}

void UpdateToSSLReadPointer(int delta)
{
  _updateReadPointer(shm_ctx->up_channel, delta);
}

void UpdateToTCPReadPointer(int delta)
{
  _updateReadPointer(shm_ctx->down_channel, delta);
}

int _pushPacketInfo(struct packet_info pi, struct channel *channel)
{
  if (channel->circular[channel->write_head]
          .valid) {  // circular buffer is full
    return -1;
  } else {
    channel->circular[channel->write_head] = pi;
    printf((pi.side == client) ? "Client " : "Server ");
    printf("write head is %d\n", channel->write_head);
    assert(channel->circular[channel->write_head].length > 0);
    channel->write_head = (channel->write_head + 1) % CIRCULAR_SZ;
    channel->write = (channel->write + pi.length) % BUF_SZ;
    return 0;
  }
}

int PushToSSL(struct packet_info pi, void *write_pointer)
{
  pi.addr_offset = (char *)write_pointer - shm_ctx->up_channel->packet_buffer;
  return _pushPacketInfo(pi, shm_ctx->up_channel);
}

int PushToTCP(struct packet_info pi, void *write_pointer)
{
  pi.addr_offset = (char *)write_pointer - shm_ctx->down_channel->packet_buffer;
  return _pushPacketInfo(pi, shm_ctx->down_channel);
}

void *GetToSSLBufferAddr(int *avaliable)
{
  return _getBufferAddress(shm_ctx->up_channel, avaliable);
}

void *GetToTCPBufferAddr(int *avaliable)
{
  return _getBufferAddress(shm_ctx->down_channel, avaliable);
}

void *_getBufferAddress(struct channel *channel, int *avaliable)
{
  *avaliable = (channel->read <= channel->write)
                   ? BUF_SZ - channel->write
                   : channel->read - channel->write - 1;
  return channel->packet_buffer + channel->write;
}

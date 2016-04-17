#include <openssl/ssl.h>
#include <openssl/err.h>
#include "constants.h"
#include "proxy_ssl.h"
#include "shared_buffer.hpp"
#include <cassert>
class ProxyBase
{
 protected:
  bool handshake_done;
  bool closed;
  int id;
  SSL *ssl;
  BIO *in_bio;
  BIO *out_bio;
  struct cert_ctx *ctx;
  shared_buffer *down;
  shared_buffer *sendto;

  void sendPacket();
  void forwardRecord();
  void sendMessage(enum message_type, char *, int);
  void sendRecord(char *record, int length);
  void sendCloseAlert();

 public:
  virtual void receivePacket(char *packetbuffer, int length);
  void receiveRecord(char *recordbuffer, int length);
  ProxyBase(struct cert_ctx *ctx, int id, shared_buffer *down,
            shared_buffer *sendto)
      : handshake_done(false),
        closed(false),
        id(id),
        ssl(NULL),
        in_bio(NULL),
        out_bio(NULL),
        ctx(ctx),
        down(down),
        sendto(sendto){};
  ~ProxyBase()
  {
    if (0 == SSL_get_shutdown(ssl)) {
      SSL_shutdown(ssl);
    }
  };
};

void ProxyBase::sendPacket()
{
  if (BIO_ctrl_pending(out_bio) > 0) {
    // int avaliable = down.getAvaliable();  // do we have this interface?
    int avaliable = MAX_PACKET_SIZE;  // do we have this interface?
    struct packet *pi = (struct packet *)malloc(sizeof(struct packet));
    pi->id = id;
    pi->size = BIO_read(out_bio, pi->buffer, avaliable);
    down->putData((char *)pi, pi->size + offsetof(struct packet, buffer));
    free(pi);
  }
}

void ProxyBase::forwardRecord()
{
  char buf[MAX_PACKET_SIZE] = {'0'};
  char *write_head = buf;
  int size = 0;
  int length = 0;

  while ((length = SSL_read(ssl, write_head, (MAX_PACKET_SIZE)-size)) > 0) {
    write_head += length;
    size += length;
    if (size == MAX_PACKET_SIZE) {
      printf("BUFfer is full!\n");
      break;
    }
  }
  /*buf[size] = '\0';*/
  /*printf("%s buf received\n", buf);*/
  switch (SSL_get_error(ssl, length)) {
    case SSL_ERROR_WANT_WRITE:
      // TODO rehandshake !!
      printf("rehandshake happens");
      break;
    case SSL_ERROR_WANT_READ:
      break;
    case SSL_ERROR_ZERO_RETURN:
      printf("ssl clean closed\n");
      sendCloseAlert();
    case SSL_ERROR_WANT_CONNECT:
      printf("want connect!\n");
      break;
    case SSL_ERROR_WANT_ACCEPT:
      printf("want accept");
      break;
    case SSL_ERROR_WANT_X509_LOOKUP:
      printf("want x509 lookup!");
      break;
    case SSL_ERROR_SSL:
      printf("server SSL library error!fatal need to shutdown\n");
      ERR_print_errors_fp(stderr);
      sendCloseAlert();
      break;
    case SSL_ERROR_SYSCALL:
      printf("syscall error");
      ERR_print_errors_fp(stderr);
      break;
    case SSL_ERROR_NONE:
      break;
    default:
      perror("Forward error!");
      exit(1);
  }
  if (!size) {
    return;
  }
  sendRecord(buf, size);
}

void ProxyBase::sendMessage(enum message_type type, char *msgbuffer, int length)
{
  struct message *msg = (struct message *)malloc(sizeof(struct message));
  msg->type = type;
  msg->id = id;
  msg->size = length;
  memcpy(msg->buffer, msgbuffer, length);
  sendto->putData((char *)msg, length + offsetof(struct message, buffer));
  free(msg);
}

void ProxyBase::sendRecord(char *recordbuffer, int length)
{
  sendMessage(record, recordbuffer, length);
}

void ProxyBase::receiveRecord(char *recordbuffer, int length)
{
  int r = SSL_write(ssl, recordbuffer, length);
  if (r <= 0) {
    switch (SSL_get_error(ssl, r)) {
      case SSL_ERROR_WANT_READ:
        // TODO handle rehandshake;
        printf("write fail: want read");
        break;
      case SSL_ERROR_ZERO_RETURN:
        printf("write fail:ssl closed");
        sendCloseAlert();
        return;
      case SSL_ERROR_WANT_WRITE:
        // TODO will this happen? we have unlimited bio memory buffer
        perror("BIO memory buffer full");
        exit(1);
      default:
        exit(1);
    }
  } else {
    // we need to send down the msg;
    sendPacket();
  }
}

void ProxyBase::sendCloseAlert() { closed = true; }

#include <openssl/ssl.h>
#include <cassert>
#define PACKET_MAX_SZ (2 << 14)
class ProxyBase
{
protected:
  bool handshake_done;
  int id;
  SSL *ssl;
  BIO *in_bio;
  BIO *out_bio;
  struct proxy_ctx *ctx;
  void sendPacket();
  void forwardRecord();
  void sendRecord();
  void sendCloseAlert();

public:
  virtual void receivePacket(char *packetbuffer, int length);
  void receiveRecord(char *recordbuffer, int length);
  ProxyBase(struct proxy_ctx *ctx, int id)
    : handshake_done(false),
      id(id),
      ssl(NULL),
      in_bio(NULL),
      out_bio(NULL),
      ctx(ctx) {};
  ~ProxyBase()
  {
    if (0 == SSL_get_shutdown(ssl)) {
      SSL_shutdown(ssl);
    }
  };
};

void ProxyBase::sendPacket() {
  int avaliable = 0;
  // rethink about the communication.
  if (BIO_ctrl_pending(out_bio) > 0) {
    struct packet_info pi;
    void *write_pointer = GetToTCPBufferAddr(&avaliable);
    pi.side = side;
    pi.id = proxy->index;
    pi.valid = true;
    pi.length = BIO_read(out_bio, write_pointer, avaliable);
    if (pi.length > 0) {
      while (PushToTCP(pi, write_pointer) < 0) {
        ;
      }
    }
  }
}

void ProxyBase::forwardRecord() {
  char buf[PACKET_MAX_SZ] = {'0'};
  char *write_head = buf;
  int size = 0;
  int length = 0;

  while ((length = SSL_read(ssl, write_head, (PACKET_MAX_SZ)-size)) > 0) {
    write_head += length;
    size += length;
    if (size == PACKET_MAX_SZ) {
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
  sendRecord();
}

void ProxyBase::receiveRecord(char* recordbuffer,int length) {
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

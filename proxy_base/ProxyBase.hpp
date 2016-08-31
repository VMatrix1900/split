#pragma once
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>
#include <iostream>
#include "channel.h"
#include "proxy_ssl.h"
#include <trace/timestamp.h>  //timestamp
#include <sharedmem_session/connection.h>
#include <securebox_session/shared_buffer.h>

class ProxyBase {
 protected:
  bool handshake_done;
  bool closed;
  int id;
  SSL *ssl;
  BIO *in_bio;
  BIO *out_bio;
  struct cert_ctx *ctx;
  Secure_box::shared_buffer *down;
  Secure_box::shared_buffer *otherside;
  Secure_box::shared_buffer *to_mb;
  struct packet *pkt;
  struct message *msg;
  std::string first_msg_buf;
  volatile unsigned int t1, t2, overhead, t3, t4;
  int i, j;
  double pkt_speed;
  double record_speed;

  void sendPacket() {
    if (BIO_ctrl_pending(out_bio) > 0) {
      // int avaliable = down.getAvaliable();  // do we have this interface?
      int avaliable = MAX_PACKET_SIZE;  // do we have this interface?
      pkt->id = id;
      pkt->size = BIO_read(out_bio, pkt->buffer, avaliable);
      while (down->put_data((void *)pkt,
                            pkt->size + offsetof(struct packet, buffer)) == 0) {
        ;
      }
      // printf("packet sent down\n");
    }
  }

  void forwardRecord() {
    // printf("forward for proxy [%d]\n", id);
    char buf[MAX_MSG_SIZE] = {'0'};
    char *write_head = buf;
    int size = 0;
    int length = 0;

    t3 = Genode::Trace::timestamp();
    while ((length = SSL_read(ssl, write_head, (MAX_MSG_SIZE)-size)) > 0) {
      write_head += length;
      size += length;
      if (size == MAX_MSG_SIZE) {
        std::clog << "TLS record is full";
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
        printf("[%d] ssl clean closed\n", id);
        sendCloseAlertDown();
        sendCloseAlertToOther();
        break;
      case SSL_ERROR_WANT_CONNECT:
        printf("[%d] ssl want connect!\n", id);
        break;
      case SSL_ERROR_WANT_ACCEPT:
        printf("want accept");
        break;
      case SSL_ERROR_WANT_X509_LOOKUP:
        printf("want x509 lookup!");
        break;
      case SSL_ERROR_SSL:
        printf("SSL library error!fatal need to shutdown\n");
        ERR_print_errors_fp(stderr);
        sendCloseAlertDown();
        sendCloseAlertToOther();
        break;
      case SSL_ERROR_SYSCALL:
        printf("syscall error");
        ERR_print_errors_fp(stderr);
        break;
      case SSL_ERROR_NONE:
        break;
      default:
        perror("Forward error!");
        exit(-3);
    }
    if (!size) {
      return;
    }
    t4 = Genode::Trace::timestamp();
    record_speed += (double)size / (t4 - t3 - overhead);
    j++;
    if (j == 1000) {
      // printf("%d record forward speed: %d\n", size, (int)record_speed);
      record_speed = 0;
      j = 0;
    }
    sendRecord(buf, size);
    // sendRecord(buf, size >> 1);
    // sendRecord(buf + (size >> 1), size - (size >> 1));
  }

  void sendMessage(enum message_type type, char *msgbuffer, int length) {
    msg->type = type;
    msg->id = id;
    Secure_box::shared_buffer *sendto;
    if (type == record || type == close) {  // send it to middlebox
      sendto = to_mb;
    } else {
      sendto = otherside;
    }
    while (length > 0) {
      msg->size = (length <= MAX_MSG_SIZE) ? length : MAX_MSG_SIZE;
      memcpy(msg->buffer, msgbuffer, length);
      while (sendto->put_data((void *)msg,
                              msg->size + offsetof(struct message, buffer)) == 0) {
        ;
      }
      length -= msg->size;
      msgbuffer += msg->size;
    }
    // printf("send record [%d]\n", length);
    // otherside->print_headers();
  }

  void sendRecord(char *recordbuffer, int length) {
    sendMessage(record, recordbuffer, length);
  }

  void sendCloseAlertDown() {
    pkt->id = id;
    pkt->size = -1;
    while (down->put_data((void *)pkt, offsetof(struct packet, buffer)) == 0) {
      ;
    }
  }

 public:
  bool handshakedone() { return handshake_done; }

  void sendCloseAlertToOther() {
    sendMessage(close, NULL, -1);
  }

  void receiveCloseAlert() {
    sendPacket();
    sendCloseAlertDown();
  }

  void receiveRecord(const char *recordbuffer, int length) {
    if (!handshake_done) {
      first_msg_buf += std::string(recordbuffer, length);
      return;
    }
    t1 = Genode::Trace::timestamp();
    int r = SSL_write(ssl, recordbuffer, length);
    // printf("dig into receive record\n");
    // t2 = Genode::Trace::timestamp();
    // pkt_speed += (double)length / (t2 - t1 - overhead);
    // i++;
    // if (i == 1000) {
    //   // printf("%d record send speed: %d\n", length, (int)pkt_speed);
    //   pkt_speed = 0;
    //   i = 0;
    // }
    if (r <= 0) {
      switch (SSL_get_error(ssl, r)) {
        case SSL_ERROR_WANT_READ:
          // TODO handle rehandshake;
          printf("write fail: want read");
          break;
        case SSL_ERROR_ZERO_RETURN:
          printf("write fail:ssl closed");
          sendCloseAlertDown();
          return;
        case SSL_ERROR_WANT_WRITE:
          // TODO will this happen? we have unlimited bio memory buffer
          perror("BIO memory buffer full");
          exit(-1);
        default:
          exit(-2);
      }
    } else {
      // we need to send down the msg;
      // printf("begin send packet\n");
      sendPacket();
    }
  }
  ProxyBase(struct cert_ctx *ctx, int id, Secure_box::shared_buffer *down,
            Secure_box::shared_buffer *otherside,
            Secure_box::shared_buffer *to_mb, struct packet *pkt,
            struct message *msg)
      : handshake_done(false),
        closed(false),
        id(id),
        ssl(NULL),
        in_bio(NULL),
        out_bio(NULL),
        ctx(ctx),
        down(down),
        otherside(otherside),
        to_mb(to_mb),
        pkt(pkt),
        msg(msg),
        first_msg_buf("") {
    t1 = 0;
    t2 = 0;
    t3 = 0;
    t4 = 0;
    overhead = 0;
    i = 0;
    j = 0;
    pkt_speed = 0;
    record_speed = 0;
    t1 = Genode::Trace::timestamp();
    overhead = Genode::Trace::timestamp() - t1;  // time measuring overhead
  };
  ~ProxyBase() {
    if (0 == SSL_get_shutdown(ssl)) {
      SSL_shutdown(ssl);
    }
  };
};
#include "proxy_client.hpp"

ProxyClient::ProxyClient(struct cert_ctx *ctx, int id, Channel *down,
              Channel *otherside,
              Channel *to_mb, struct TLSPacket *pkt,
              struct Plaintext *msg)
  : ProxyBase(ctx, id, down, otherside, to_mb, pkt, msg) {
    const SSL_METHOD *meth = TLSv1_2_method();
    SSL_CTX *sslctx = SSL_CTX_new(meth);
    // now we ban begin initialize the client side.
    SSL_CTX_set_options(sslctx, SSL_OP_ALL);
#ifdef SSL_OP_TLS_ROLLBACK_BUG
    SSL_CTX_set_options(sslctx, SSL_OP_TLS_ROLLBACK_BUG);
#endif /* SSL_OP_TLS_ROLLBACK_BUG */
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    SSL_CTX_set_options(sslctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif /* SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION */
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    SSL_CTX_set_options(sslctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif /* SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS */
#ifdef SSL_OP_NO_TICKET
    SSL_CTX_set_options(sslctx, SSL_OP_NO_TICKET);
#endif /* SSL_OP_NO_TICKET */
#ifdef SSL_OP_NO_COMPRESSION
    SSL_CTX_set_options(sslctx, SSL_OP_NO_COMPRESSION);
#endif /* SSL_OP_NO_COMPRESSION */

    SSL_CTX_set_cipher_list(sslctx, "ALL:-aNULL");
    SSL_CTX_set_verify(sslctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_next_proto_select_cb(sslctx, select_next_proto_cb, this);

    ssl = SSL_new(sslctx);

    if (init_ssl_bio(ssl) < 0) {
      return;
    }
    SSL_set_connect_state(ssl);

    SSL_CTX_free(sslctx);

#ifdef SSL_MODE_RELEASE_BUFFERS
    /* lower memory footprint for idle connections */
    SSL_set_mode(ssl, SSL_get_mode(ssl) | SSL_MODE_RELEASE_BUFFERS);
#endif /* SSL_MODE_RELEASE_BUFFERS */
    in_bio = SSL_get_rbio(ssl);
    out_bio = SSL_get_wbio(ssl);
}

void ProxyClient::receiveSNI(char* SNIbuffer) {
  #ifdef MEASURE_TIME
  begin_handshake = Genode::Trace::timestamp();
  // printf("[%d]::begin[%lu]\n", id, begin_handshake / 1000000);
  #endif
  if (strlen(SNIbuffer) != 0) {
    SSL_set_tlsext_host_name(ssl, SNIbuffer);
  }
  // fprintf(stderr, "[%d] receive sni buffer: %s\n", id, SNIbuffer);
  SSL_do_handshake(ssl);
  sendPacket();
}

void ProxyClient::sendCrt() {
  char* cert = store_cert(SSL_get_peer_certificate(ssl));
  sendMessage(CRT, cert, strlen(cert) + 1);
  free(cert);
}

void ProxyClient::forwardRecordForHTTP2() {
    char buf[MAX_MSG_SIZE] = {'0'};
    char *write_head = buf;
    int size = 0;
    int length = 0;

    #ifdef MEASURE_TIME
    t3 = Genode::Trace::timestamp();
    #endif
    while ((length = SSL_read(ssl, write_head, (MAX_MSG_SIZE)-size)) > 0) {
      // printf("read %d data", length);
      write_head += length;
      size += length;
      if (size == MAX_MSG_SIZE) {
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
    // t4 = Genode::Trace::timestamp();
    // record_speed += (double)size / (t4 - t3 - overhead);
    // j++;
    // if (j == 1000) {
    //   // printf("%d record forward speed: %d\n", size, (int)record_speed);
    //   record_speed = 0;
    //   j = 0;
    // }
    std::clog << "Send to http2 parser: " << size << std::endl;
    ssize_t rv = stream_data.parseHTTP2Response((const uint8_t *)buf, size);
    if (rv < 0) {
      std::cerr << "nghttp2 session mem recv wrong:  " << rv << std::endl;
      exit(-1);
    }
    std::clog << "http2 parser parsed: " << rv << std::endl;
    if (stream_data.responseParsed) {
      std::clog << "http2 response parsed" << std::endl;
      std::string msg = stream_data.response.to_string() + stream_data.tmp.body();
      sendRecord((char *)msg.c_str(), msg.size());
      std::clog << "record sent: " << msg.size() << std::endl;
    }
    // TODO check queue stream
}

void ProxyClient::receiveRecord(const char *recordbuffer, int length) {
  if (http2_selected) {
    std::string frame = stream_data.sendHTTP1Request(recordbuffer, length);
    ProxyBase::receiveRecord(frame.c_str(), frame.size());
  } else {
    ProxyBase::receiveRecord(recordbuffer, length);
  }
}

void ProxyClient::receivePacket(const char* packetbuffer, int length) {
  char *tmp = (char *)packetbuffer;
  while (length > 0) {
    int written = BIO_write(in_bio, tmp, length);
    if (written > 0) {
      tmp += written;
      length -= written;
    }
  }
  if (!handshake_done) {
    int r = SSL_do_handshake(ssl);
    if (r < 0) {
      sendPacket();
      switch (SSL_get_error(ssl, r)) {
        case SSL_ERROR_WANT_WRITE:
          break;
        case SSL_ERROR_WANT_READ:
          // need more data, do nothing;
          break;
        case SSL_ERROR_WANT_CONNECT:
          printf("[%d]::Client handshake want connect error!\n", id);
          break;
        default:
          printf("[%d]::Client handshake error!\n", id);
          ERR_print_errors_fp(stderr);
      }
    } else {
      // fprintf(stderr, "[%d] client handshake done!\n", id);
      // printf("SSL connected: %s %s\n", SSL_get_version(ssl),
      //        SSL_get_cipher(ssl));
      handshake_done = true;
      if (!first_msg_buf.empty()) {
        receiveRecord(first_msg_buf.c_str(), first_msg_buf.length());
      }
      #ifdef MEASURE_TIME
      end_handshake = Genode::Trace::timestamp();
      // printf("[%d]:: end[%lu]\n", id, end_handshake / 1000000);
      #endif
      sendCrt();
    }
  } else {
    if (http2_selected) {
      forwardRecordForHTTP2();
    } else {
      forwardRecord();
    }
  }
}

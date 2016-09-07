#include <sstream>
#include "proxy_client.hpp"
#include "util.hpp"

static ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
                             size_t length, int flags, void *user_data) {
  ProxyClient *stream = (ProxyClient *)user_data;
  stream->receiveRecord((const char *)data, (int)length);
  // TODO assume the length is equal to the sent
  return length;
}

static int on_header_callback(nghttp2_session *session _U_,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags _U_,
                              void *user_data) {
  // std::cout << "receive header:  "  << frame->hd.type << std::endl;
  ProxyClient *stream = (ProxyClient *)user_data;
  nghttp2_nv nv = {const_cast<uint8_t *>(name), const_cast<uint8_t *>(value),
                   namelen, valuelen};
  switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
      int32_t stream_id = frame->hd.stream_id;
      http::ResponseBuilder &response =
          stream->stream_id_to_stream[stream_id]->response;
      if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
        /* Print response headers for the initiated request. */
        // check for ":status" pseudo header
        // print_nv(&nv);
        if (*name == ':') {
          response.set_status(std::atoi((const char *)value));
        } else {
          response.insert_header(std::string((const char *)name, namelen),
                                 std::string((const char *)value, valuelen));
        }
        break;
      }
  }
  return 0;
}

/* nghttp2_on_frame_recv_callback: Called when nghttp2 library
    received a complete frame from the remote peer. */
static int on_frame_recv_callback(nghttp2_session *session _U_,
                                  const nghttp2_frame *frame, void *user_data) {
  // print_frame(PRINT_RECV, frame);
  ProxyClient *stream = (ProxyClient *)user_data;
  switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
      if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
        stream->processResponse(frame->hd.stream_id);
      }
      break;
    // TODO settting frame change parameter.
    case NGHTTP2_SETTINGS:
      if ((frame->hd.flags & NGHTTP2_FLAG_ACK) == 0) {
        break;
      } else {
        break;
      }
    case NGHTTP2_DATA:
      if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
        stream->processResponse(frame->hd.stream_id);
      }
      break;
    case NGHTTP2_PING:
      nghttp2_session_send(session);
      break;
    default:
      // std::cout << "Others" << std::endl;
      break;
  }
  return 0;
}

static int on_frame_send_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
  // print_frame(PRINT_SEND, frame);
  return 0;
}

static int on_begin_frame_callback(nghttp2_session *session,
                                   const nghttp2_frame_hd *hd,
                                   void *user_data) {
  // std::cout << "begin recvframe" << std::endl;
  return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
  ProxyClient *session_data = (ProxyClient *)user_data;
#ifdef DEBUG
  std::cout << "Stream " << stream_id
            << " closed with error_code=" << error_code << std::endl;
#endif
  HTTPStream *stream = session_data->stream_id_to_stream[stream_id];

  session_data->pkt_id_to_stream.erase(stream->pkt_id);
#ifdef IN_LINUX
  delete session_data->stream_id_to_stream[stream_id];
#else
  Genode::destroy(Genode::env()->heap(), session_data->stream_id_to_stream[stream_id]);
#endif
  session_data->stream_id_to_stream.erase(stream_id);

  // TODO when do we close the session.
  // int rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
  // if (rv != 0) {
  //   return NGHTTP2_ERR_CALLBACK_FAILURE;
  // }
  // }
  return 0;
}

/* nghttp2_on_data_chunk_recv_callback: Called when DATA frame is
    received from the remote peer. In this implementation, if the frame
    is meant to the stream we initiated, print the received data in
    stdout, so that the user can redirect its output to the file
    easily. */
static int on_data_chunk_recv_callback(nghttp2_session *session _U_,
                                       uint8_t flags _U_, int32_t stream_id,
                                       const uint8_t *data, size_t len,
                                       void *user_data) {
  log("receive data chunk", stream_id, len);
  // log(std::string((const char*)data, len));
  ProxyClient *session_data = (ProxyClient *)user_data;

  session_data->stream_id_to_stream[stream_id]->tmp.append_body(
      (const char *)data, len);
  return 0;
}

static ssize_t body_read_callback(nghttp2_session *session _U_,
                                  int32_t stream_id _U_, uint8_t *buf,
                                  size_t length, uint32_t *data_flags,
                                  nghttp2_data_source *source,
                                  void *user_data _U_) {
  log("call body read calback");
  http::BufferedRequest *request = (http::BufferedRequest *)source->ptr;
  const std::string &body = request->body();
  ssize_t r = body.copy((char *)buf, length, request->copied);
  request->copied += r;
  if (r == 0) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  }
  return r;
}
#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

ProxyClient::ProxyClient(struct cert_ctx *ctx, int id, Channel *down,
                         Channel *otherside, Channel *to_mb,
                         struct TLSPacket *pkt, struct Plaintext *msg)
    : ProxyBase(ctx, id, down, otherside, to_mb, pkt, msg),
      http2_selected(false) {
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

void ProxyClient::init_http2_session() {
  nghttp2_session_callbacks *callbacks;

  nghttp2_session_callbacks_new(&callbacks);

  nghttp2_session_callbacks_set_on_begin_frame_callback(
      callbacks, on_begin_frame_callback);

  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                       on_frame_recv_callback);

  nghttp2_session_callbacks_set_on_frame_send_callback(callbacks,
                                                       on_frame_send_callback);

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      callbacks, on_data_chunk_recv_callback);

  nghttp2_session_callbacks_set_on_stream_close_callback(
      callbacks, on_stream_close_callback);

  nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                   on_header_callback);

  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);

  nghttp2_session_client_new(&session, callbacks, (void *)this);

  nghttp2_session_callbacks_del(callbacks);
}

void ProxyClient::receiveSNI(char *SNIbuffer) {
#ifdef MEASURE_TIME
  begin_handshake = Genode::Trace::timestamp();
// printf("[%d]::begin[%lu]\n", id, begin_handshake / 1000000);
#endif
  if (strlen(SNIbuffer) != 0) {
    domain = std::string(SNIbuffer);
    SSL_set_tlsext_host_name(ssl, SNIbuffer);
  }
  // fprintf(stderr, "[%d] receive sni buffer: %s\n", id, SNIbuffer);
  SSL_do_handshake(ssl);
  sendPacket();
}

void ProxyClient::sendCrt() {
  char *cert = store_cert(SSL_get_peer_certificate(ssl));
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
    log("No record");
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
  ssize_t rv = parseHTTP2Response((const uint8_t *)buf, size);
  if (rv < 0) {
    std::cerr << "nghttp2 session mem recv wrong:  " << rv << std::endl;
    exit(-1);
  }
}

void ProxyClient::receiveRecord(int pkt_id, const char *recordbuffer,
                                int length) {
  if (http2_selected) {
    std::string frame = sendHTTP1Request(pkt_id, recordbuffer, length);
  } else {
    receiveRecord(recordbuffer, length);
  }
}

void ProxyClient::receivePacket(const char *packetbuffer, int length) {
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
        // TODO receive record fake id
        ProxyBase::receiveRecord(first_msg_buf.c_str(), first_msg_buf.length());
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

void ProxyClient::processResponse(int stream_id) {
  log("Process the reponse");
  http::BufferedResponse &tmp = stream_id_to_stream[stream_id]->tmp;
  http::ResponseBuilder &response = stream_id_to_stream[stream_id]->response;
  log("http2 response parsed");
  if (!tmp.has_header(std::string("content-length"))) {
    log("insert the content length header");
    size_t body_length = tmp.body().size();
    std::ostringstream ost;
    ost << body_length;
    std::string content_length = ost.str();
    response.insert_header(std::string("content-length"), content_length);
  }
  response.set_minor_version(1);
  std::string msg = response.to_string() + tmp.body();
  int msg_id = stream_id_to_stream[stream_id]->pkt_id;
  sendRecordWithId(msg_id, (char *)msg.c_str(), msg.size());
  log("record sent", msg_id, msg.size());
}

void ProxyClient::submit_client_connection_setting() {
  nghttp2_settings_entry iv[3] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
      {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, NGHTTP2_INITIAL_WINDOW_SIZE},
      {NGHTTP2_SETTINGS_ENABLE_PUSH, 0}};
  int rv;

  /* client 24 bytes magic string will be sent by nghttp2 library */
  rv = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, iv, ARRLEN(iv));
  if (rv != 0) {
    std::cerr << "Could not submit SETTINGS: " << nghttp2_strerror(rv);
  } else {
    // std::cout << "Settings submitted." << std::endl;
  }
}

void ProxyClient::submit_client_request(int pkt_id) {
  int stream_id;
  http::BufferedRequest &request = pkt_id_to_stream[pkt_id]->request;
  http::Message::Headers headers = request.headers();
  size_t hdr_sz = 3 + headers.size();
  std::vector<nghttp2_nv> nva = std::vector<nghttp2_nv>();
  nva.reserve(hdr_sz);
  http::Message::Headers pseudoheaders = {
      {std::string(":method"), request.method_name()},
      {std::string(":scheme"), std::string("https")},
      {std::string(":path"), request.url()},
      {std::string("user-agent"), std::string("nghttp2/1.14.0-DEV")}};
  for (http::Message::Headers::const_iterator cit = pseudoheaders.begin();
       cit != pseudoheaders.end(); ++cit) {
    nva.push_back(make_nv(cit->first, cit->second));
  }
  // log("Before the NVA");
  // print_nv(nva.data(), nva.size());
  for (http::Message::Headers::const_iterator cit = headers.begin();
       cit != headers.end(); ++cit) {
    if (!http::icmp("Host", cit->first)) {
      // log("insert the authority");
      nva.insert(nva.begin(), make_nv_ls(":authority", cit->second));
      // print_nv(nva.data(), nva.size());
    } else if (http::icmp(cit->first, "Connection") && http::icmp("user-agent", cit->first)) {
      nva.push_back(make_nv(cit->first, cit->second));
    }
  }

  // log("After the NVA");
  // print_nv(nva.data(), nva.size());
  if (pkt_id_to_stream[pkt_id]->request.body().size() != 0) {
    nghttp2_data_provider data_pdr;
    data_pdr.source.ptr = &(pkt_id_to_stream[pkt_id]->request);
    data_pdr.read_callback = body_read_callback;
    stream_id = nghttp2_submit_request(session, NULL, nva.data(), nva.size(),
                                       &data_pdr, (void *)(this));
  } else {
    stream_id = nghttp2_submit_request(session, NULL, nva.data(), nva.size(),
                                       NULL, (void *)(this));
  }
  if (stream_id < 0) {
    std::cerr << "Could not submit HTTP request:"
              << nghttp2_strerror(stream_id);
    // TODO destructor;
  } else {
    log(pkt_id, "http request submitted.");
    stream_id_to_stream[stream_id] = pkt_id_to_stream[pkt_id];
  }
}

std::string ProxyClient::sendHTTP1Request(int pkt_id, const char *buf,
                                          size_t size) {
  std::string frame;
  char *data = (char *)buf;
  if (pkt_id_to_stream.find(pkt_id) == pkt_id_to_stream.end()) {
    #ifdef IN_LINUX
    pkt_id_to_stream[pkt_id] = new HTTPStream(pkt_id);
    #else
    pkt_id_to_stream[pkt_id] = new (Genode::env()->heap()) HTTPStream(pkt_id);
    #endif
  }
  http::BufferedRequest &request = pkt_id_to_stream[pkt_id]->request;
  while (size > 0) {
    // Parse as much data as possible.
    while ((size > 0) && !request.complete()) {
      try {
        std::size_t pass = request.feed(data, size);
        data += pass, size -= pass;
      } catch (http::Error &e) {
        std::string buffer = std::string(buf, size);
        std::cerr << "request is " << buffer;
        std::cerr << e.what();
      }
    }

    // Check that we've parsed an entire request.
    if (!request.complete()) {  // which means size == 0
      std::cerr << "Request still needs data." << std::endl;
    } else {  // size > 0 add the logic of detect url
      log(pkt_id, "http1 request parsed.");
      // open a new http2 connection, send a setting frame.
      // std::cerr << "request parsed" << std::endl;
      submit_client_connection_setting();
      submit_client_request(pkt_id);
      nghttp2_session_send(session);
    }
  }
  return frame;
}

ssize_t ProxyClient::parseHTTP2Response(const uint8_t *in, size_t len) {
  return nghttp2_session_mem_recv(session, in, len);
}

#include "http2client.hpp"
#include <cstdlib>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include "util.hpp"

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

static int on_header_callback(nghttp2_session *session _U_,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags _U_,
                              void *user_data)
{
  // std::cout << "receive header:  "  << frame->hd.type << std::endl;
  HTTP2Client *stream = (HTTP2Client *)user_data;
  nghttp2_nv nv = {const_cast<uint8_t *>(name), const_cast<uint8_t *>(value),
                   namelen, valuelen};
  switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
      int32_t stream_id = frame->hd.stream_id;
      http::ResponseBuilder &response =
          *stream_id_to_stream[stream_id]->response;
      // TODO make sure this is okay.
      if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
        /* Print response headers for the initiated request. */
        // check for ":status" pseudo header
        print_nv(&nv);
        if (*name == ':') {
          response.set_status(std::atoi((const char *)value));
        } else {
          // TODO call the right API.
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
                                  const nghttp2_frame *frame, void *user_data)
{
  print_frame(PRINT_RECV, frame);
  HTTP2Client *stream = (HTTP2Client *)user_data;
  switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
      std::cout << "Headers" << std::endl;
      if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
        stream->processResponse(frame->hd.stream_id);
        // std::cout << stream->response.to_string() << stream->tmp.body()
        //           << std::endl;
      }
      break;
    // ?? settting frame change parameter.
    case NGHTTP2_SETTINGS:
      if ((frame->hd.flags & NGHTTP2_FLAG_ACK) == 0) {
        break;
      } else {
        break;
      }
    case NGHTTP2_DATA:
      if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
        stream->processResponse(frame->hd.stream_id);
        // std::cout << stream->response.to_string() << stream->tmp.body()
        //           << std::endl;
      }
      break;
    default:
      // std::cout << "Others" << std::endl;
      break;
  }
  return 0;
}

static int on_frame_send_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data)
{
  print_frame(PRINT_SEND, frame);
  return 0;
}

static int on_begin_frame_callback(nghttp2_session *session,
                                   const nghttp2_frame_hd *hd, void *user_data)
{
  // std::cout << "begin recvframe" << std::endl;
  return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data)
{
  HTTP2Client *session_data = (HTTP2Client *)user_data;

  // TODO clean the HTTPStream; when? conflict with the reponse send?
  // if (session_data->stream_id == stream_id) {
  // std::cout << "Stream " << stream_id
  // << " closed with error_code=" << error_code;
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
                                       void *user_data)
{
  // std::cout << "receive datachunk " << std::endl;
  HTTP2Client *session_data = (HTTP2Client *)user_data;

  session_data->stream_id_to_stream[stream_id]->tmp.append_body(
      (const char *)data, len);
  return 0;
}

static ssize_t body_read_callback(nghttp2_session *session _U_,
                                  int32_t stream_id _U_, uint8_t *buf,
                                  size_t length, uint32_t *data_flags,
                                  nghttp2_data_source *source,
                                  void *user_data _U_)
{
  http::BufferedRequest *request = (http::BufferedRequest *)source;
  std::string body = request->body();
  ssize_t r = body.copy((char *)buf, length, request->copied);
  request->copied += r;
  if (r == 0) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  }
  return r;
}

void print_headers(nghttp2_nv *nva, size_t nvalen)
{
  for (size_t i = 0; i < nvalen; i++) {
    std::cout << "header pair NO." << i << std::endl;
    std::string name((char *)nva[i].name, (size_t)nva[i].namelen);
    std::string value((char *)nva[i].value, (size_t)nva[i].valuelen);
    std::cout << name << " : " << value << std::endl;
  }
}

HTTP2Client::HTTP2Client()
{
  response = http::ResponseBuilder(tmp);
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

  nghttp2_session_client_new(&session, callbacks, (void *)this);

  nghttp2_session_callbacks_del(callbacks);
}

void HTTP2Client::processResponse(int stream_id)
{
  responseParsed = true;
  http::BufferedResponse &tmp = stream_id_to_stream[stream_id]->tmp;
  http::ResponseBuilder &response = stream_id_to_stream[stream_id]->response;
  if (!tmp.has_header(std::string("Content-Length"))) {
    size_t body_length = tmp.body().size();
    std::ostringstream ost;
    ost << body_length;
    std::string content_length = ost.str();
    response.insert_header(std::string("Content-Length"), content_length);
  }
  response.set_minor_version(1);
  std::clog << "The response header is: " << response.to_string();
  std::clog << "http2 response parsed" << std::endl;
  std::string msg = response.to_string() + tmp.body();
  ProxyBase::sendRecordWithId(stream_id_to_stream[stream_id]->pkt_id,
                              (char *)msg.c_str(), msg.size());
  std::clog << "record sent: " << msg.size() << std::endl;
}

nghttp2_nv HTTP2Client::make_nv(const std::string &name,
                                const std::string &value)
{
  return {(uint8_t *)name.c_str(), (uint8_t *)value.c_str(), name.size(),
          value.size(), NGHTTP2_NV_FLAG_NONE};
}

void HTTP2Client::submit_client_connection_setting()
{
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
    std::cout << "Settings submitted." << std::endl;
  }
}

void HTTP2Client::submit_client_request(int pkt_id)
{
  int stream_id;
  http::Message::Headers headers = request.headers();
  size_t hdr_sz = 3 + headers.size();
  std::vector<nghttp2_nv> nva = std::vector<nghttp2_nv>();
  nva.reserve(hdr_sz);
  http::Message::Headers pseudoheaders = {
      {std::string(":method"), request.method_name()},
      {std::string(":scheme"), std::string("https")},
      {std::string(":path"), request.url()}};
  for (http::Message::Headers::const_iterator cit = pseudoheaders.begin();
       cit != pseudoheaders.end(); ++cit) {
    nva.push_back(make_nv(cit->first, cit->second));
  }
  for (http::Message::Headers::const_iterator cit = headers.begin();
       cit != headers.end(); ++cit) {
    if (!cit->first.compare("Host")) {
      nva.insert(nva.begin(), make_nv(":authority", cit->second));
    } else if (cit->first.compare("Connection")) {
      nva.push_back(make_nv(cit->first, cit->second));
    }
  }

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
    std::clog << "http request submitted." << stream_id << std::endl;
    stream_id_to_stream[stream_id] = pkt_id_to_stream[pkt_id];
  }
}

std::string HTTP2Client::getQueuedFrame()
{
  std::string frame;
  ssize_t sent = 0;
  const uint8_t *bufp;
  while (true) {
    sent = nghttp2_session_mem_send(session, &bufp);
    if (sent < 0) {
      std::cerr << "session_send err";
      exit(-1);
    } else if (sent == 0) {
      break;
    } else {
      frame += std::string((char *)bufp, sent);
    }
  }
  return frame;
}

std::string HTTP2Client::sendHTTP1Request(int pkt_id, const char *buf,
                                          size_t size)
{
  std::string frame;
  char *data = (char *)buf;
  if (pkt_id_to_stream.find(pkt_id) == pkt_id_to_stream.end()) {
    pkt_id_to_stream[pkt_id] = new HTTPStream(pkt_id);
  }
  http::BufferedRequest &request = *pkt_id_to_stream[pkt_id];
  // TODO constructor called when derefrence the pointer?
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
      std::clog << "An http1 request parsed." << std::endl;
      // open a new http2 connection, send a setting frame.
      // std::cerr << "request parsed" << std::endl;
      submit_client_connection_setting();
      submit_client_request(pkt_id);
      ssize_t sent = 0;
      const uint8_t *bufp;
      while (true) {
        sent = nghttp2_session_mem_send(session, &bufp);
        if (sent < 0) {
          std::cerr << "session_send err";
          exit(-1);
        } else if (sent == 0) {
          break;
        } else {
          frame += std::string((char *)bufp, sent);
        }
      }
    }
  }
  return frame;
}

ssize_t HTTP2Client::parseHTTP2Response(const uint8_t *in, size_t len)
{
  return nghttp2_session_mem_recv(session, in, len);
}

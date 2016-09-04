#pragma once
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <nghttp2/nghttp2.h>
namespace {
  const char LOWER_XDIGITS[] = "0123456789abcdef";
} // namespace

namespace {
  nghttp2_nv make_nv(const std::string &name,
                                  const std::string &value)
  {
    return {(uint8_t *)name.c_str(), (uint8_t *)value.c_str(), name.size(),
        value.size(), NGHTTP2_NV_FLAG_NONE};
  }
}

namespace util {
  std::string ascii_dump(const uint8_t *data, size_t len) {
    std::string res;

    for (size_t i = 0; i < len; ++i) {
      auto c = data[i];

      if (c >= 0x20 && c < 0x7f) {
        res += c;
      } else {
        res += '.';
      }
    }

    return res;
  }

  std::string format_hex(const unsigned char *s, size_t len) {
    std::string res;
    res.resize(len * 2);

    for (size_t i = 0; i < len; ++i) {
      unsigned char c = s[i];

      res[i * 2] = LOWER_XDIGITS[c >> 4];
      res[i * 2 + 1] = LOWER_XDIGITS[c & 0x0f];
    }
    return res;
  }
}

namespace {
const char *strsettingsid(int32_t id) {
  switch (id) {
  case NGHTTP2_SETTINGS_HEADER_TABLE_SIZE:
    return "SETTINGS_HEADER_TABLE_SIZE";
  case NGHTTP2_SETTINGS_ENABLE_PUSH:
    return "SETTINGS_ENABLE_PUSH";
  case NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
    return "SETTINGS_MAX_CONCURRENT_STREAMS";
  case NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
    return "SETTINGS_INITIAL_WINDOW_SIZE";
  case NGHTTP2_SETTINGS_MAX_FRAME_SIZE:
    return "SETTINGS_MAX_FRAME_SIZE";
  case NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
    return "SETTINGS_MAX_HEADER_LIST_SIZE";
  default:
    return "UNKNOWN";
  }
}
} // namespace

namespace {
std::string strframetype(uint8_t type) {
  switch (type) {
  case NGHTTP2_DATA:
    return "DATA";
  case NGHTTP2_HEADERS:
    return "HEADERS";
  case NGHTTP2_PRIORITY:
    return "PRIORITY";
  case NGHTTP2_RST_STREAM:
    return "RST_STREAM";
  case NGHTTP2_SETTINGS:
    return "SETTINGS";
  case NGHTTP2_PUSH_PROMISE:
    return "PUSH_PROMISE";
  case NGHTTP2_PING:
    return "PING";
  case NGHTTP2_GOAWAY:
    return "GOAWAY";
  case NGHTTP2_WINDOW_UPDATE:
    return "WINDOW_UPDATE";
  case NGHTTP2_ALTSVC:
    return "ALTSVC";
  }

  std::string s = "extension(0x";
  s += util::format_hex(&type, 1);
  s += ')';

  return s;
};
} // namespace

namespace {
bool color_output = false;
} // namespace

void set_color_output(bool f) { color_output = f; }

namespace {
FILE *outfile = stdout;
} // namespace

void set_output(FILE *file) { outfile = file; }

namespace {
void print_frame_attr_indent() { fprintf(outfile, "          "); }
} // namespace

namespace {
const char *ansi_esc(const char *code) { return code ; }
} // namespace

namespace {
const char *ansi_escend() { return "\033[0m"; }
} // namespace

namespace {
void print_nv(nghttp2_nv *nv) {
  fprintf(outfile, "%s%s%s: %s\n", ansi_esc("\033[1;34m"), nv->name,
          ansi_escend(), nv->value);
}
} // namespace
namespace {
void print_nv(nghttp2_nv *nva, size_t nvlen) {
  auto end = nva + nvlen;
  for (; nva != end; ++nva) {
    print_frame_attr_indent();

    print_nv(nva);
  }
}
} // namelen


namespace {
void print_frame_hd(const nghttp2_frame_hd &hd) {
  fprintf(outfile, "<length=%zu, flags=0x%02x, stream_id=%d>\n", hd.length,
          hd.flags, hd.stream_id);
}
} // namespace

namespace {
void print_flags(const nghttp2_frame_hd &hd) {
  std::string s;
  switch (hd.type) {
  case NGHTTP2_DATA:
    if (hd.flags & NGHTTP2_FLAG_END_STREAM) {
      s += "END_STREAM";
    }
    if (hd.flags & NGHTTP2_FLAG_PADDED) {
      if (!s.empty()) {
        s += " | ";
      }
      s += "PADDED";
    }
    break;
  case NGHTTP2_HEADERS:
    if (hd.flags & NGHTTP2_FLAG_END_STREAM) {
      s += "END_STREAM";
    }
    if (hd.flags & NGHTTP2_FLAG_END_HEADERS) {
      if (!s.empty()) {
        s += " | ";
      }
      s += "END_HEADERS";
    }
    if (hd.flags & NGHTTP2_FLAG_PADDED) {
      if (!s.empty()) {
        s += " | ";
      }
      s += "PADDED";
    }
    if (hd.flags & NGHTTP2_FLAG_PRIORITY) {
      if (!s.empty()) {
        s += " | ";
      }
      s += "PRIORITY";
    }

    break;
  case NGHTTP2_PRIORITY:
    break;
  case NGHTTP2_SETTINGS:
    if (hd.flags & NGHTTP2_FLAG_ACK) {
      s += "ACK";
    }
    break;
  case NGHTTP2_PUSH_PROMISE:
    if (hd.flags & NGHTTP2_FLAG_END_HEADERS) {
      s += "END_HEADERS";
    }
    if (hd.flags & NGHTTP2_FLAG_PADDED) {
      if (!s.empty()) {
        s += " | ";
      }
      s += "PADDED";
    }
    break;
  case NGHTTP2_PING:
    if (hd.flags & NGHTTP2_FLAG_ACK) {
      s += "ACK";
    }
    break;
  }
  fprintf(outfile, "; %s\n", s.c_str());
}
} // namespace

enum print_type { PRINT_SEND, PRINT_RECV };

namespace {
const char *frame_name_ansi_esc(print_type ptype) {
  return ansi_esc(ptype == PRINT_SEND ? "\033[1;35m" : "\033[1;36m");
}
} // namespace

namespace {
void print_frame(print_type ptype, const nghttp2_frame *frame) {
  fprintf(outfile, "%s%s%s frame ", frame_name_ansi_esc(ptype),
          strframetype(frame->hd.type).c_str(), ansi_escend());
  print_frame_hd(frame->hd);
  if (frame->hd.flags) {
    print_frame_attr_indent();
    print_flags(frame->hd);
  }
  switch (frame->hd.type) {
  case NGHTTP2_DATA:
    if (frame->data.padlen > 0) {
      print_frame_attr_indent();
      fprintf(outfile, "(padlen=%zu)\n", frame->data.padlen);
    }
    break;
  case NGHTTP2_HEADERS:
    print_frame_attr_indent();
    fprintf(outfile, "(padlen=%zu", frame->headers.padlen);
    if (frame->hd.flags & NGHTTP2_FLAG_PRIORITY) {
      fprintf(outfile, ", dep_stream_id=%d, weight=%u, exclusive=%d",
              frame->headers.pri_spec.stream_id, frame->headers.pri_spec.weight,
              frame->headers.pri_spec.exclusive);
    }
    fprintf(outfile, ")\n");
    switch (frame->headers.cat) {
    case NGHTTP2_HCAT_REQUEST:
      print_frame_attr_indent();
      fprintf(outfile, "; Open new stream\n");
      break;
    case NGHTTP2_HCAT_RESPONSE:
      print_frame_attr_indent();
      fprintf(outfile, "; First response header\n");
      break;
    case NGHTTP2_HCAT_PUSH_RESPONSE:
      print_frame_attr_indent();
      fprintf(outfile, "; First push response header\n");
      break;
    default:
      break;
    }
    print_nv(frame->headers.nva, frame->headers.nvlen);
    break;
  case NGHTTP2_PRIORITY:
    print_frame_attr_indent();

    fprintf(outfile, "(dep_stream_id=%d, weight=%u, exclusive=%d)\n",
            frame->priority.pri_spec.stream_id, frame->priority.pri_spec.weight,
            frame->priority.pri_spec.exclusive);

    break;
  case NGHTTP2_RST_STREAM:
    print_frame_attr_indent();
    fprintf(outfile, "(error_code=%s(0x%02x))\n",
            nghttp2_http2_strerror(frame->rst_stream.error_code),
            frame->rst_stream.error_code);
    break;
  case NGHTTP2_SETTINGS:
    print_frame_attr_indent();
    fprintf(outfile, "(niv=%lu)\n",
            static_cast<unsigned long>(frame->settings.niv));
    for (size_t i = 0; i < frame->settings.niv; ++i) {
      print_frame_attr_indent();
      fprintf(outfile, "[%s(0x%02x):%u]\n",
              strsettingsid(frame->settings.iv[i].settings_id),
              frame->settings.iv[i].settings_id, frame->settings.iv[i].value);
    }
    break;
  case NGHTTP2_PUSH_PROMISE:
    print_frame_attr_indent();
    fprintf(outfile, "(padlen=%zu, promised_stream_id=%d)\n",
            frame->push_promise.padlen, frame->push_promise.promised_stream_id);
    print_nv(frame->push_promise.nva, frame->push_promise.nvlen);
    break;
  case NGHTTP2_PING:
    print_frame_attr_indent();
    fprintf(outfile, "(opaque_data=%s)\n",
            util::format_hex(frame->ping.opaque_data, 8).c_str());
    break;
  case NGHTTP2_GOAWAY:
    print_frame_attr_indent();
    fprintf(outfile, "(last_stream_id=%d, error_code=%s(0x%02x), "
                     "opaque_data(%u)=[%s])\n",
            frame->goaway.last_stream_id,
            nghttp2_http2_strerror(frame->goaway.error_code),
            frame->goaway.error_code,
            static_cast<unsigned int>(frame->goaway.opaque_data_len),
            util::ascii_dump(frame->goaway.opaque_data,
                             frame->goaway.opaque_data_len).c_str());
    break;
  case NGHTTP2_WINDOW_UPDATE:
    print_frame_attr_indent();
    fprintf(outfile, "(window_size_increment=%d)\n",
            frame->window_update.window_size_increment);
    break;
  case NGHTTP2_ALTSVC: {
    auto altsvc = static_cast<nghttp2_ext_altsvc *>(frame->ext.payload);
    print_frame_attr_indent();
    fprintf(outfile, "(origin=[%.*s], altsvc_field_value=[%.*s])\n",
            static_cast<int>(altsvc->origin_len), altsvc->origin,
            static_cast<int>(altsvc->field_value_len), altsvc->field_value);
    break;
  }
  default:
    break;
  }
}
} // namespace

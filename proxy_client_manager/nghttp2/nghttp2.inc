SRC_C += nghttp2_pq.c nghttp2_map.c nghttp2_queue.c \
      nghttp2_frame.c nghttp2_buf.c \
      nghttp2_stream.c nghttp2_outbound_item.c \
      nghttp2_session.c nghttp2_submit.c \
      nghttp2_helper.c \
      nghttp2_npn.c \
      nghttp2_hd.c nghttp2_hd_huffman.c nghttp2_hd_huffman_data.c \
      nghttp2_version.c \
      nghttp2_priority_spec.c \
      nghttp2_option.c \
      nghttp2_callbacks.c \
      nghttp2_mem.c \
      nghttp2_http.c \
      nghttp2_rcbuf.c

vpath %c $(PRG_DIR)/nghttp2/
INC_DIR += $(PRG_DIR)/nghttp2/includes

CC_OPT += -DHAVE_CONFIG_H -DHAVE_NETINET_IN_H
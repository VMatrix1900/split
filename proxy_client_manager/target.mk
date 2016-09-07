TARGET = proxy_client_manager
SRC_CC += main.cc proxy_client.cpp

include $(PRG_DIR)/../proxy_base/proxy_base.inc
include $(PRG_DIR)/nghttp2/nghttp2.inc
include $(PRG_DIR)/httpxx/httpxx.inc

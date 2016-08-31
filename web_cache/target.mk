TARGET    = web_cache
SRC_CC   += main.cc cache.cpp http_parser_cache.cpp
LIBS      = base cxx config stdcxx
INC_DIR  += $(PRG_DIR) $(PRG_DIR)/httpparserlib/
INC_DIR  += $(PRG_DIR)/../proxy_base
#memcpy
SRC_S    += user_memcpy_linux.S
#include library
include $(PRG_DIR)/httpparserlib/http_parser.inc
vpath user_memcpy_linux.S $(PRG_DIR)/../custom_memcpy_src/

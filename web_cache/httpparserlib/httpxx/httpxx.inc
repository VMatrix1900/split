#include file for httpxx

SRC_CC   += Error.cpp Flags.cpp icompare.cpp MessageBuilder.cpp Message.cpp Method.cpp RequestBuilder.cpp Request.cpp
SRC_CC   += ResponseBuilder.cpp Response.cpp Url.cpp
SRC_C    += http_parser.c
#SRC_C    += parsertrace.c url_parser.c

INC_DIR  += $(PRG_DIR)/httpparserlib/httpxx/http-parser/

vpath %.cpp $(PRG_DIR)/httpparserlib/httpxx
vpath http_parser.c $(PRG_DIR)/httpparserlib/httpxx/http-parser/
vpath %.c $(PRG_DIR)/httpparserlib/httpxx/http-parser/contrib/

CC = clang++
HTTPLIB = ./httpparserlib
LIBDIR = $(HTTPLIB)/httpxx

test: testCache.cpp
	$(CC) -o $@ $<

run_test: test
	./test

http: http_parse.cpp
	$(CC) -I$(HTTPLIB) -L$(LIBDIR) -o $@ $< -lhttpxx -lhttp-parser

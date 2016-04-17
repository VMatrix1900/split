BINDIR := ../bin
BUILDDIR := ../build
CC := gcc
SSL_LIB := -I/home/vincent/Downloads/openssl-1.0.1i/include -L/home/vincent/Downloads/openssl-1.0.1i
CFLAGS := -g -Wall -Wextra -std=c99 -pthread -fstack-protector-all -pedantic -D_GNU_SOURCE -DDEBUG
SRCS := $(filter-out genode_library_c.c, $(wildcard *.c))
SSL_SRCS := SSL_layer.c channel.c proxy_ssl.c ssl.c \
			cert.c
OBJS := $(SRCS:.c=.o)
TCP_OBJ := TCP_layer.o proxy_tcp.o
SHARED_LIB_OBJ := $(BUILDDIR)/channel.o

SSL_OBJS := $(addprefix $(BUILDDIR)/, $(SSL_SRCS:.c=.o))
TCP_OBJS := $(addprefix $(BUILDDIR)/, $(TCP_OBJ))

$(BUILDDIR)/%.o: %.c makefile
	$(CC) -c $(CFLAGS) -include pthread.h -o $@ $<

$(BINDIR)/tcp: $(TCP_OBJS) $(SHARED_LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ -levent

$(BINDIR)/ssl: $(SSL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto

.PHONY: ssl tcp

ssl: $(BINDIR)/ssl

tcp: $(BINDIR)/tcp

all: ssl tcp

$(BINDIR)/test_TCP: test_channel.c channel.c
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/test_SSL: test_channel_ssl.c channel.c
	$(CC) $(CFLAGS) -o $@ $^

test: $(BINDIR)/test_TCP $(BINDIR)/test_SSL
	ipcrm -M 1000
	ipcrm -M 1001

$(BINDIR)/test_load: $(BUILDDIR)/test_load.o $(BUILDDIR)/ssl.o $(BUILDDIR)/proxy_ssl.o
	$(CC) $(CFLAGS) -o $@ $^ -lssl -lcrypto

test_load: $(BINDIR)/test_load
	$(BINDIR)/test_load

run_tcp: tcp
	$(BINDIR)/tcp

run_ssl: ssl
	$(BINDIR)/ssl

clean:
	rm -f ../build/*
	rm -f ../bin/ssl
	rm -f ../bin/tcp

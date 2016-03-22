BINDIR := ../bin
BUILDDIR := ../build
CC := gcc
SSL_LIB := -I/home/vincent/Downloads/openssl-1.0.1i/include -L/home/vincent/Downloads/openssl-1.0.1i
CFLAGS := -g -Wall -Wextra -std=c99 -pthread -fstack-protector-all -pedantic -D_GNU_SOURCE -DDEBUG_SESSION_CACHE
SRCS := $(filter-out genode_library_c.c, $(wildcard *.c))
OBJS := $(SRCS:.c=.o)
TCP_OBJ := channel.o TCP_layer.o proxy_tcp.o

SSL_OBJS := $(filter-out $(TCP_OBJ), $(OBJS))
BUILD_OBJS := $(addprefix $(BUILDDIR)/, $(SSL_OBJS))
TCP_OBJS := $(addprefix $(BUILDDIR)/, $(TCP_OBJ))

$(BUILDDIR)/%.o: %.c makefile
	$(CC) -c $(CFLAGS) -include pthread.h -o $@ $<

$(BINDIR)/tcp: $(TCP_OBJS)
	$(CC) $(CFLAGS) -o $(BINDIR)/tcp $^ -levent

$(BINDIR)/ssl: $(BUILD_OBJS)
	$(CC) $(CFLAGS) -o $(BINDIR)/ssl $^ -lssl -lcrypto

.PHONY: ssl tcp

ssl: $(BINDIR)/ssl

tcp: $(BINDIR)/tcp

run_tcp: tcp
	$(BINDIR)/tcp

run_ssl: ssl
	$(BINDIR)/ssl

clean:
	rm -f ../build/*
	rm -f ../bin/ssl
	rm -f ../bin/tcp

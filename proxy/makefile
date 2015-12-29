BINDIR := ../bin
BUILDDIR := ../build
CC := gcc
CFLAGS := -g -Wall -Wextra -std=c99 -pthread -fstack-protector-all -pedantic -D_GNU_SOURCE
SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)

SSL_OBJS := $(filter-out TCP_layer.o, $(OBJS))

%.o: %.c
	$(CC) -c $(CFLAGS) -include pthread.h -o $(BUILDDIR)/$@ $<

tcp: TCP_layer.o
	gcc $(CFLAGS) -o $(BINDIR)/tcp $(BUILDDIR)/$< -levent

ssl: $(SSL_OBJS)
	gcc $(CFLAGS) -o $(BINDIR)/ssl $(addprefix $(BUILDDIR)/, $(SSL_OBJS)) -lssl -lcrypto

run_tcp: tcp
	$(BINDIR)/tcp

run_ssl: ssl
	$(BINDIR)/ssl

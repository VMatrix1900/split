BINDIR := ../bin
BUILDDIR := ../build
CC := gcc
CFLAGS := -g -Wall -std=c99
SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)

SSL_OBJS := $(filter-out TCP_layer.o, $(OBJS))

%.o: %.c
	$(CC) -c $(CFLAGS) -o $(BUILDDIR)/$@ $<

tcp: TCP_layer.o
	gcc $(CFLAGS) -o $(BINDIR)/tcp $(BUILDDIR)/$< -levent -lpthread

ssl: $(SSL_OBJS)
	gcc $(CFLAGS) -o $(BINDIR)/ssl $(addprefix $(BUILDDIR)/, $(SSL_OBJS)) -lssl -lcrypto -lpthread

run_tcp: tcp
	$(BINDIR)/tcp

run_ssl: ssl
	$(BINDIR)/ssl

BINDIR := ../bin
BUILDDIR := ../build
nat: nat.c
	gcc -std=c99 -c -o $(BUILDDIR)/nat.o nat.c

tcp: TCP_layer.c nat
	gcc -c -o $(BUILDDIR)/tcp.o -Wall -D TCP TCP_layer.c
	gcc -g -o $(BINDIR)/tcp $(BUILDDIR)/tcp.o  $(BUILDDIR)/nat.o -levent -lpthread

ssl: SSL_proxy.c
	gcc -Wall -g -o $(BINDIR)/ssl SSL_proxy.c -lssl -lcrypto -lpthread

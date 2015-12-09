BINDIR := ../bin
BUILDDIR := ../build

tcp: TCP_layer.c
	gcc -c -g -o $(BUILDDIR)/tcp.o -Wall -DTCP TCP_layer.c
	gcc -g -o $(BINDIR)/tcp $(BUILDDIR)/tcp.o -levent -lpthread

ssl: SSL_proxy.c
	gcc -Wall -g -o $(BINDIR)/ssl SSL_proxy.c -lssl -lcrypto -lpthread

run_tcp: tcp
	$(BINDIR)/tcp

run_ssl: ssl
	$(BINDIR)/ssl

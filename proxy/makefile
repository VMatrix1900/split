BINDIR := ../bin
BUILDDIR := ../build
CC := gcc
CFLAGS := -g -Wall -std=c99

dynbuf.o: dynbuf.c
	$(CC) -c $(CFLAGS) -o $(BUILDDIR)/$@ $<

log.o: log.c
	$(CC) -c $(CFLAGS) -o $(BUILDDIR)/$@ $<

cert.o: cert.c
	$(CC) -c $(CFLAGS) -o $(BUILDDIR)/$@ $<

cache.o: cache.c
	$(CC) -c $(CFLAGS) -o $(BUILDDIR)/$@ $<

cachedsess.o: cachedsess.c
	$(CC) -c $(CFLAGS) -o $(BUILDDIR)/$@ $<

cachefkcrt.o: cachefkcrt.c
	$(CC) -c $(CFLAGS) -o $(BUILDDIR)/$@ $<

cachemgr.o: cachemgr.c
	$(CC) -c $(CFLAGS) -o $(BUILDDIR)/$@ $<

cachessess.o: cachessess.c
	$(CC) -c $(CFLAGS) -o $(BUILDDIR)/$@ $<

cachetgcrt.o: cachetgcrt.c
	$(CC) -c $(CFLAGS) -o $(BUILDDIR)/$@ $<

ssl.o: ssl.c
	$(CC) -c $(CFLAGS) -o $(BUILDDIR)/$@ $<

tcp: TCP_layer.c
	gcc -c $(CFLAGS) -o $(BUILDDIR)/tcp.o TCP_layer.c
	gcc $(CFLAGS) -o $(BINDIR)/tcp $(BUILDDIR)/tcp.o -levent -lpthread

ssl: SSL_layer.c
	gcc $(CFLAGS) -o $(BINDIR)/ssl $^ $(BUILDDIR)/*.o -lssl -lcrypto -lpthread

run_tcp: tcp
	$(BINDIR)/tcp

run_ssl: ssl
	$(BINDIR)/ssl

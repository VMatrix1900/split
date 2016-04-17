#include "proxy_client.hpp"

void ProxyClient::receiveSNI(char* SNIbuffer)
{
  SSL_set_tlsext_host_name(ssl, SNIbuffer);
  SSL_do_handshake(ssl);
  sendPacket();
}

void ProxyClient::sendCrt() {
  unsigned char cert[2 * 1024];
  BIO *bio = BIO_new_mem_buf(BIO_s_mem());
  PEM_write_bio_X509(bio, SSL_get_certificate(ssl));
  int length = BIO_read(bio, cert, sizeof(cert));
  cert[length] = '\0';
  sendMessage(crt,cert,length + 1);
}

void ProxyClient::receivePacket(char* packetbuffer, int length)
{
  int written = BIO_write(in_bio, packetbuffer, length);
  assert(written == length);
  if (!handshake_done) {
    int r = SSL_do_handshake(ssl);
    if (r < 0) {
      sendPacket();
      switch (SSL_get_error(ssl, r)) {
        case SSL_ERROR_WANT_WRITE:
          break;
        case SSL_ERROR_WANT_READ:
          // need more data, do nothing;
          break;
        default:
          printf("Client handshake error!\n");
          ERR_print_errors_fp(stderr);
      }
    } else {
      printf("client handshake is done\n");
      printf("SSL connected: %s %s\n", SSL_get_version(ssl),
             SSL_get_cipher(ssl));
      handshake_done = true;
      // TODO send the crt
      sendCrt();
    }
  } else {
    forwardRecord();
  }
}

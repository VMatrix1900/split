// client part and server part. pass the data through the middlebox application.
// client part do handshake with real server. just send down msg and receive up
// msg.
// server part use fake certificate to do handshake with real client.
#include <fcntl.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "cert.h"
#include "proxy_ssl.h"
#include "ssl.h"

int main()
{
  init_shm();
  if (ssl_init() < 0) {
    printf("OpenSSL library init wrong!\n");
    exit(-1);
  }
  ERR_load_BIO_strings();

  /* if (cachemgr_preinit() < 0) { */
  /*   printf("cachemgr preinit wrong! exit!\n"); */
  /*   exit(-1); */
  /* } */
  /* if (cachemgr_init() < 0) { */
  /*   printf("cachemgr init wrong! exit!\n"); */
  /*   exit(-1); */
  /* } */

  struct proxy_ctx *channel = create_channel_ctx();
  if (!channel) {
    printf("channel initiate wrong!\n");
    exit(-1);
  }

  struct proxy *proxy;
  struct packet_info pi;

  while (true) {
    pi = PullFromTCP();
    if (pi.valid) {
      int index = pi.id;
      if (channel->proxies[index]) {
        proxy = channel->proxies[index];
      } else {
        // that means a new clienthello is coming. must be the server
        // side.
        printf("begin new proxy NO.%d\n", index);
        proxy = proxy_new(channel, index);
        if (!proxy) {
          printf("proxy new wrong!\n");
          proxy_shutdown_free(proxy);
          exit(-1);
        }
      }
      if (pi.side == server) {
        // first we need to copy the data to ssl in_bio/ hellomsg
        // buffer.
        if (!proxy->SNI_parsed) {
          peek_hello_msg(proxy, &pi);
        } else if (proxy->client_handshake_done &&
                   !proxy->server_handshake_done) {
          printf("server ");
          receive_up(proxy, &pi);
          int r = SSL_do_handshake(proxy->serv_ssl);
          send_down(proxy, server);
          if (r < 0) {
            switch (SSL_get_error(proxy->serv_ssl, r)) {
              case SSL_ERROR_WANT_WRITE:
                break;
              case SSL_ERROR_WANT_READ:
                // need more data, do nothing;
                break;
              default:
                printf("Server handshake error!");
                ERR_print_errors_fp(stderr);
            }
          } else {
            // handshake is done
            printf("Server handshake done!\n");
            proxy->server_handshake_done = true;
          }
        } else if (proxy->server_handshake_done) {
          printf("server ");
          receive_up(proxy, &pi);
          forward_record(proxy->serv_ssl, proxy->cli_ssl, proxy);
        } else {
          printf("wrong state!\n");
          exit(-1);
        }
      } else if (pi.side == client) {
        printf("client ");
        receive_up(proxy, &pi);
        // all record has been read into the SSL in_bio
        if (!proxy->client_handshake_done) {
          int r = SSL_do_handshake(proxy->cli_ssl);
          if (r < 0) {
            send_down(proxy, client);
            switch (SSL_get_error(proxy->cli_ssl, r)) {
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
            printf("SSL connected: %s %s\n", SSL_get_version(proxy->cli_ssl),
                   SSL_get_cipher(proxy->cli_ssl));
            proxy->client_handshake_done = true;
            pxy_servssl_setup(proxy);
            // copy the hello msg from buffer to bio;
            BIO_write(SSL_get_rbio(proxy->serv_ssl), proxy->client_hello_buf,
                      proxy->hello_msg_length);
            SSL_do_handshake(proxy->serv_ssl);
            // TODO make sure it's want write
            send_down(proxy, server);
          }
        } else if (!proxy->server_handshake_done) {
          // dst server push to client but server side ssl isn't ready
        } else {
          forward_record(proxy->cli_ssl, proxy->serv_ssl, proxy);
        }
      } else {
        printf("Wrong server indicator:%d\n", server);
        exit(-1);
      }
    }
  }

  return 0;
}

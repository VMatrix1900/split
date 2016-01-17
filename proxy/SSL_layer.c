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
#include "cachemgr.h"
#include "cert.h"
#include "proxy_ssl.h"
#include "shm_and_sem.h"
#include "ssl.h"

// send the ssl out_bio packet to shared memory, update the pointer.
void send_down(struct proxy *proxy, int server)
{
    SSL *ssl = (server == 0) ? proxy->cli_ssl : proxy->serv_ssl;
    BIO *out_bio = SSL_get_wbio(ssl);
    psemvalue(proxy->ctx->shm_ctx->read_lock, "before send down, read lock ");
    sem_wait(proxy->ctx->shm_ctx->read_lock);
    size_t pending;
    size_t read = 0;
    unsigned char *index_pointer = proxy->down_pointer;
    proxy->down_pointer += sizeof(int);
    unsigned char *server_pointer = proxy->down_pointer;
    proxy->down_pointer += sizeof(int);
    unsigned char *size_pointer = proxy->down_pointer;
    proxy->down_pointer += sizeof(size_t);
    while ((pending = BIO_ctrl_pending(out_bio)) > 0) {
        /* begin send_down the packet to shared memory */
        read += BIO_read(out_bio, proxy->down_pointer, BUFSZ);
        proxy->down_pointer += read;
    }
    memcpy(size_pointer, &read, sizeof(size_t));
    printf("%s down: %zu\n", (0 == server) ? "client" : "server", read);
    if (read == 0) {
        proxy->down_pointer = index_pointer;
        sem_post(proxy->ctx->shm_ctx->read_lock);
    } else {
        memcpy(index_pointer, &proxy->index, sizeof(int));
        memcpy(server_pointer, &server, sizeof(int));
        proxy->msgs_need_to_out += 1;
    }
}

// receive the ssl in_bio packet from shared memory, update the pointer.
unsigned char *receive_up(SSL *ssl, unsigned char *shm)
{
    BIO *in_bio = SSL_get_rbio(ssl);
    /*printf("begin receive up msg. The size is %zu\n", *((size_t
     * *)shm_ctx->shm));*/
    size_t length = *((size_t *)shm);
    shm += sizeof(size_t);
    // copy the packet to in_bio
    int written = BIO_write(in_bio, shm, length);
    printf("up : %d\n", written);
    shm += written;
    return shm;
}

void forward_record(SSL *from, SSL *to, struct proxy *proxy)
{
    char buf[BUFSZ] = {'0'};
    char *write_head = buf;
    int size = 0;
    int length = 0;

    while ((length = SSL_read(from, write_head, (BUFSZ)-size)) > 0) {
        write_head += length;
        size += length;
        if (size == BUFSZ) {
            printf("BUFfer is full!\n");
            break;
        }
    }
    /*buf[size] = '\0';*/
    /*printf("%s buf received\n", buf);*/
    switch (SSL_get_error(from, length)) {
    case SSL_ERROR_WANT_WRITE:
        // TODO rehandshake !!
        printf("rehandshake happens");
        break;
    case SSL_ERROR_WANT_READ:
        break;
    case SSL_ERROR_ZERO_RETURN:
        printf("ssl clean closed\n");
        proxy_shutdown_free(proxy);
    case SSL_ERROR_WANT_CONNECT:
        printf("want connect!\n");
        break;
    case SSL_ERROR_WANT_ACCEPT:
        printf("want accept");
        break;
    case SSL_ERROR_WANT_X509_LOOKUP:
        printf("want x509 lookup!");
        break;
    case SSL_ERROR_SSL:
        printf("%s: SSL library error!fatal need to shutdown\n",
               (from == proxy->cli_ssl) ? "client" : "server");
        ERR_print_errors_fp(stderr);
        proxy_shutdown_free(proxy);
        break;
    case SSL_ERROR_SYSCALL:
        printf("syscall error");
        ERR_print_errors_fp(stderr);
        break;
    case SSL_ERROR_NONE:
        break;
    default:
        perror("Forward error!");
        exit(1);
    }
    if (!size) {
        return;
    }
    int r = SSL_write(to, buf, size);
    if (r <= 0) {
        switch (SSL_get_error(to, r)) {
        case SSL_ERROR_WANT_READ:
            // TODO handle rehandshake;
            printf("write fail: want read");
            break;
        case SSL_ERROR_ZERO_RETURN:
            printf("write fail:ssl closed");
            proxy_shutdown_free(proxy);
            return;
        case SSL_ERROR_WANT_WRITE:
            // TODO will this happen? we have unlimited bio memory buffer
            perror("BIO memory buffer full");
            exit(1);
        default:
            exit(1);
        }
    } else {
        // we need to send down the msg;
        /*if (from == proxy->cli_ssl) {*/
        /*    proxy->client_received += length;*/
        /*    proxy->server_send += r;*/
        /*    printf("received: %d, send: %d\n", proxy->client_received,
         * proxy->server_send);*/
        /*}*/
        send_down(proxy, (to == proxy->cli_ssl) ? 0 : 1);
    }
}

unsigned char *peek_hello_msg(struct proxy *proxy, unsigned char *msg)
{
    size_t size = *(size_t *)msg;
    msg += sizeof(size_t);
    memcpy(proxy->client_hello_buf + proxy->hello_msg_length, msg, size);
    // all record has been read into the SSL in_bio, now we can release the
    // write lock
    sem_post(proxy->ctx->shm_ctx->write_lock);
    proxy->hello_msg_length += size;
    msg += size;
    ssize_t length = proxy->hello_msg_length;
    proxy->sni =
        ssl_tls_clienthello_parse_sni(proxy->client_hello_buf, &length);
    if (!proxy->sni && (-1 == length)) {
        // client hello msg is incomplete. set the flag, wait for another msg.
    } else {
        // sni parse is finished. now the server ssl is not ready. so we can
        // only initiate client hanshake.
        proxy->SNI_parsed = true;
        if (proxy->sni) {
            SSL_set_tlsext_host_name(proxy->cli_ssl, proxy->sni);
        }
        SSL_do_handshake(proxy->cli_ssl);
        send_down(proxy, 0);
    }
    return msg;
}

struct proxy *proxy_new(struct ssl_channel *ctx, int index)
{
    struct proxy *proxy = malloc(sizeof(struct proxy));
    proxy->ctx = ctx;
    proxy->SNI_parsed = false;
    proxy->client_handshake_done = false;
    proxy->server_handshake_done = false;
    proxy->hello_msg_length = 0;
    proxy->msgs_need_to_out = 0;
    proxy->client_received = 0;
    proxy->server_send = 0;
    proxy->down_pointer = ctx->shm_ctx->shm_down + sizeof(int);
    proxy->cli_ssl = pxy_dstssl_setup();
    if (!proxy->cli_ssl) {
        return NULL;
    }
    proxy->index = index;
    ctx->proxies[index] = proxy;

    return proxy;
}

struct ssl_channel *create_channel_ctx()
{
    struct ssl_channel *channel = malloc(sizeof(struct ssl_channel));
    channel->shm_ctx = malloc(sizeof(struct shm_ctx_t));
    init_shm(channel->shm_ctx);
    memset(channel->proxies, 0, MAXCONNS * sizeof(struct proxy *));
    channel->cacrt = NULL;
    channel->cakey = NULL;
    channel->key = ssl_key_genrsa(1024);
    if (!channel->key) {
        printf("public key generation wrong!\n");
        return NULL;
    }

    return channel;
}

int main()
{
    if (ssl_init() < 0) {
        printf("OpenSSL library init wrong!\n");
        exit(-1);
    }
    ERR_load_BIO_strings();

    if (cachemgr_preinit() < 0) {
        printf("cachemgr preinit wrong! exit!\n");
        exit(-1);
    }
    if (cachemgr_init() < 0) {
        printf("cachemgr init wrong! exit!\n");
        exit(-1);
    }

    struct ssl_channel *channel = create_channel_ctx();
    if (!channel) {
        printf("channel initiate wrong!\n");
        exit(-1);
    }

    if (channel->cacrt) {
        X509_free(channel->cacrt);
    }
    channel->cacrt = ssl_x509_load("ca.crt");
    if (!channel->cacrt) {
        printf("certf load error\n");
        exit(-1);
    } else {
        char *ca_subject = ssl_x509_subject(channel->cacrt);
        printf("Loaded CA: %s\n", ca_subject);
        free(ca_subject);
    }
    ssl_x509_refcount_inc(channel->cacrt);
    sk_X509_insert(channel->chain, channel->cacrt, 0);
    channel->cakey = ssl_key_load("ca.key");
    if (!channel->cakey) {
        printf("keyf load error\n");
        exit(-1);
    }
    if (X509_check_private_key(channel->cacrt, channel->cakey) != 1) {
        printf("CA cert does not match key.\n");
        exit(-1);
    }
    unsigned char *shm_up = channel->shm_ctx->shm_up;
    unsigned char *shm_down = channel->shm_ctx->shm_down;
    struct proxy *proxy;
    // enable write to down channel
    sem_post(channel->shm_ctx->read_lock);

    while (!sem_wait(channel->shm_ctx->up)) {
        int number = *((int *)shm_up);
        shm_up += sizeof(int);
        int i;
        // actually now the number is always 1; because every time TCP layer
        // receive the msg, it will trigger this process;
        for (i = 0; i < number; i++) {
            // find the proxy, create one if needed;
            int index = *((int *)shm_up);
            shm_up += sizeof(int);
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
            int server = *((int *)shm_up);
            // determine send to client side or server side.
            shm_up += sizeof(int);
            if (1 == server) {
                // first we need to copy the data to ssl in_bio/ hellomsg
                // buffer.
                if (!proxy->SNI_parsed) {
                    shm_up = peek_hello_msg(proxy, shm_up);
                } else if (proxy->client_handshake_done &&
                           !proxy->server_handshake_done) {
                    printf("server ");
                    shm_up = receive_up(proxy->serv_ssl, shm_up);
                    // all record has been read into the SSL in_bio, now we can
                    // release the write lock
                    sem_post(channel->shm_ctx->write_lock);
                    int r = SSL_do_handshake(proxy->serv_ssl);
                    send_down(proxy, 1);
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
                    shm_up = receive_up(proxy->serv_ssl, shm_up);
                    // all record has been read into the SSL in_bio, now we can
                    // release the write lock
                    sem_post(channel->shm_ctx->write_lock);
                    forward_record(proxy->serv_ssl, proxy->cli_ssl, proxy);
                } else {
                    printf("wrong state!\n");
                    exit(-1);
                }
            } else if (0 == server) {
                printf("client ");
                shm_up = receive_up(proxy->cli_ssl, shm_up);
                // all record has been read into the SSL in_bio, now we can
                // release the write lock
                sem_post(channel->shm_ctx->write_lock);
                if (!proxy->client_handshake_done) {
                    int r = SSL_do_handshake(proxy->cli_ssl);
                    if (r < 0) {
                        send_down(proxy, 0);
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
                        printf("SSL connected: %s %s\n",
                               SSL_get_version(proxy->cli_ssl),
                               SSL_get_cipher(proxy->cli_ssl));
                        proxy->client_handshake_done = true;
                        pxy_srcssl_setup(proxy);
                        // copy the hello msg from buffer to bio;
                        BIO_write(SSL_get_rbio(proxy->serv_ssl),
                                  proxy->client_hello_buf,
                                  proxy->hello_msg_length);
                        SSL_do_handshake(proxy->serv_ssl);
                        // TODO make sure it's want write
                        send_down(proxy, 1);
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

        // now we finish the SSL record process; begin to send down the record.
        // reset the shm pointer
        if (proxy->msgs_need_to_out) {
            memcpy(shm_down, &proxy->msgs_need_to_out, sizeof(int));
            proxy->msgs_need_to_out = 0;
            sem_post(channel->shm_ctx->down);
        }
        shm_up = channel->shm_ctx->shm_up;
        proxy->down_pointer = shm_down + sizeof(int);
    }

    return 0;
}

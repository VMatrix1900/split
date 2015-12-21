// client part and server part. pass the data through the middlebox application.
// client part do handshake with real server. just send down msg and receive up
// msg.
// server part use fake certificate to do handshake with real client.
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "channel.h"

#define CHK_NULL(x) \
    if ((x) == NULL) exit(1)
#define CHK_ERR(err, s) \
    if ((err) == -1) {  \
        perror(s);      \
        exit(1);        \
    }
#define CHK_SSL(err)                 \
    if ((err) == -1) {               \
        ERR_print_errors_fp(stderr); \
        exit(2);                     \
    }

/* define HOME to be dir for key and cert files... */
#define HOME "../SSLandTCP/"
/* Make these what you want for cert & key files */
#define CERTF HOME "server-cert.pem"
#define KEYF HOME "server-key.pem"

// send the ssl out_bio packet to shared memory, update the pointer.
char *send_down(SSL *ssl, char *shm, int server)
{
    memcpy(shm, &server, sizeof(int));
    shm += sizeof(int);
    BIO *out_bio = SSL_get_wbio(ssl);
    /* begin send_down the packet to shared memory */
    size_t pending = BIO_ctrl_pending(out_bio);
    if (pending > 0) {
        memcpy(shm, &pending, sizeof(size_t));
        shm += sizeof(size_t);
        int read = BIO_read(out_bio, shm, pending);
        printf("send_down the packet completed. packet size is: %d\n", read);
        shm += read;
    }
    return shm;
}

// receive the ssl in_bio packet from shared memory, update the pointer.
char *receive_up(SSL *ssl, char *shm)
{
    BIO *in_bio = SSL_get_rbio(ssl);
    /*printf("begin receive up msg. The size is %zu\n", *((size_t
     * *)shm_ctx->shm));*/
    size_t length = *((size_t *)shm);
    shm += sizeof(size_t);
    // copy the packet to in_bio
    int written = BIO_write(in_bio, shm, length);
    printf("receive_up the packet completed. Packet size is: %d\n", written);
    shm += written;
    return shm;
}

int init_ssl_bio(SSL *ssl)
{
    BIO *in_bio, *out_bio;
    in_bio = BIO_new(BIO_s_mem());
    if (in_bio == NULL) {
        printf("Error: cannot allocate read bio.\n");
        return -1;
    }

    BIO_set_mem_eof_return(
        in_bio,
        -1); /* see: https://www.openserv_ssl.org/docs/crypto/BIO_s_mem.html */

    out_bio = BIO_new(BIO_s_mem());
    if (out_bio == NULL) {
        printf("Error: cannot allocate write bio.\n");
        return -2;
    }

    BIO_set_mem_eof_return(
        out_bio,
        -1); /* see: https://www.openserv_ssl.org/docs/crypto/BIO_s_mem.html */

    SSL_set_bio(ssl, in_bio, out_bio);
    return 0;
}

void forward_record(SSL *from, SSL *to)
{
    char buf[BUFSZ];
    int length = SSL_read(from, buf, BUFSZ);
    int r = SSL_write(to, buf, length);
    if (r < 0) {
        switch (SSL_get_error(to, r)) {
        case SSL_ERROR_WANT_READ:
            printf("want read more data, give up");
        }
    }
}

void clean_state(struct proxy *proxy)
{
    proxy->server_received = 0;
    proxy->client_received = 0;
    proxy->client_need_to_out = 0;
    proxy->server_need_to_out = 0;
}

struct proxy *proxy_new(int index)
{
    struct proxy *proxy = malloc(sizeof(struct proxy));
    proxy->index = index;
    proxy->client_handshake = 0;
    SSL_CTX *ctx;
    const SSL_METHOD *meth;
    meth = TLSv1_2_method();
    ctx = SSL_CTX_new(meth);
    // now we ban begin initialize the client side.

    proxy->cli_ssl = SSL_new(ctx);
    CHK_NULL(proxy->cli_ssl);

    init_ssl_bio(proxy->cli_ssl);
    SSL_set_connect_state(proxy->cli_ssl);
    // since SSL_new is copy ctx object to ssl object. so we can reuse the ctx
    // obj.

    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
        perror("certificate wrong:");
        exit(3);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
        perror("key wrong");
        exit(4);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        perror("Private key does not match the certificate public key");
        exit(5);
    }

    proxy->serv_ssl = SSL_new(ctx);
    CHK_NULL(proxy->serv_ssl);

    init_ssl_bio(proxy->serv_ssl);

    SSL_set_accept_state(proxy->serv_ssl);
    SSL_CTX_free(ctx);

    return proxy;
}

int main()
{
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    ERR_load_BIO_strings();

    struct ssl_channel *channel = malloc(sizeof(struct ssl_channel));
    channel->shm_ctx = malloc(sizeof(struct shm_ctx_t));
    init_shm(channel->shm_ctx);
    channel->conns = 0;

    char *shm_up = channel->shm_ctx->shm_up;
    char *shm_down = channel->shm_ctx->shm_down;
    struct proxy *proxy;

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
            if (index < channel->conns) {
                proxy = channel->proxies[index];
            } else {
                proxy = proxy_new(index);
                channel->proxies[index] = proxy;
                channel->conns++;
            }
            int server = *((int *)shm_up);
            // determine send to client side or server side.
            shm_up += sizeof(int);
            if (1 == server) {
                // first we need to copy the data to ssl in_bio.
                // mark from server side.
                proxy->server_received = 1;
                printf("server side receive up");
                shm_up = receive_up(proxy->serv_ssl, shm_up);

            } else if (0 == server) {
                // do client staff
                // has a record for ssl client, do handhshake or forward.
                proxy->client_received = 1;
                printf("client side receive up");
                shm_up = receive_up(proxy->cli_ssl, shm_up);
            } else {
                printf("Wrong server indicator:%d\n", server);
                exit(1);
            }
        }
        // all record has been read into the SSL in_bio, now we can release the
        // write lock
        sem_post(channel->shm_ctx->write_lock);
        // do handshake or forward.

        if (proxy->server_received) {
            // do server side staff
            // has a record for ssl server, either do handshake or forward the
            // msg.
            // server in_bio has some data to process;
            if (!SSL_is_init_finished(proxy->serv_ssl)) {
                SSL_do_handshake(proxy->serv_ssl);
                proxy->server_need_to_out = 1;

                if (!proxy->client_handshake) {
                    // initiate client handshake.
                    SSL_do_handshake(proxy->cli_ssl);
                    proxy->client_need_to_out = 1;
                    proxy->client_handshake = 1;
                    // now the record is in the out_bio of client ssl and
                    // proxy->serv_ssl
                    // we need to copy it to the shared memory
                }
            } else {
                printf("server side handshake is done.");
                printf("begin forward ssl record to client\n");
                forward_record(proxy->serv_ssl, proxy->cli_ssl);
                proxy->client_need_to_out = 1;
            }
        }
        if (proxy->client_received) {
            // client bio has some data to process;
            if (!SSL_is_init_finished(proxy->cli_ssl)) {
                int r = SSL_do_handshake(proxy->cli_ssl);
                if (r <
                    0) {  // handshake not finished, need to send down the msg
                    proxy->client_need_to_out = 1;
                } else {
                    printf("client handshake is done");
                }
            } else {
                printf("begin forward client data to server.\n");
                forward_record(proxy->cli_ssl, proxy->serv_ssl);
                proxy->server_need_to_out = 1;
            }
        }

        // now we finish the SSL record process; begin to send down the record.
        int num = proxy->server_need_to_out + proxy->client_need_to_out;
        memcpy(shm_down, &num, sizeof(int));
        shm_down += sizeof(int);
        if (proxy->server_need_to_out) {
            printf("server side send down\n");
            memcpy(shm_down, &proxy->index, sizeof(int));
            shm_down += sizeof(int);
            shm_down = send_down(proxy->serv_ssl, shm_down, 1);
        }
        if (proxy->client_need_to_out) {
            printf("client side send down\n");
            memcpy(shm_down, &proxy->index, sizeof(int));
            shm_down += sizeof(int);
            shm_down = send_down(proxy->cli_ssl, shm_down, 0);
        }
        clean_state(proxy);

        // reset the shm pointer
        shm_up = channel->shm_ctx->shm_up;
        shm_down = channel->shm_ctx->shm_down;

        sem_post(channel->shm_ctx->down);
    }

    return 0;
}

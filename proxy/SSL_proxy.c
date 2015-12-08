// client part and server part. pass the data through the middlebox application.
// client part do handshake with real server. just send down msg and receive up msg.
// server part use fake certificate to do handshake with real client.
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "channel.h"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

/* define HOME to be dir for key and cert files... */
#define HOME "../SSLandTCP/"
/* Make these what you want for cert & key files */
#define CERTF  HOME "server-cert.pem"
#define KEYF  HOME  "server-key.pem"

void send_down(struct ssl_channel *channel) {
    BIO* out_bio = SSL_get_wbio(channel->ssl);
    struct shm_ctx_t *shm_ctx = channel->shm;
    /* begin send_down the packet to shared memory */
    size_t pending = BIO_ctrl_pending(out_bio);
    if (pending > 0) {
        memset(shm_ctx->shm, 0, BUFSZ);
        memcpy(shm_ctx->shm, &pending, sizeof(size_t));
        int read = BIO_read(out_bio, shm_ctx->shm + sizeof(size_t), pending);
        sem_post(shm_ctx->down);
        printf("client send_down the packet completed. packet size is: %d\n", read);
    }
}

void receive_up(struct ssl_channel *channel) {
    BIO* in_bio = SSL_get_rbio(channel->ssl);
    struct shm_ctx_t *shm_ctx = channel->shm;
    sem_wait(shm_ctx->up);
    printf("begin receive up msg. The size is %zu\n", *((size_t *)shm_ctx->shm));
    // copy the packet to in_bio
    BIO_write(in_bio, shm_ctx->shm + sizeof(size_t), *((size_t *)shm_ctx->shm));
    printf("Client receive_up the packet completed\n");
}

int
init_ssl_bio(SSL *ssl){
    BIO *in_bio, *out_bio;
    in_bio = BIO_new(BIO_s_mem());
    if(in_bio == NULL) {
        printf("Error: cannot allocate read bio.\n");
        return -1;
    }

    BIO_set_mem_eof_return(in_bio, -1); /* see: https://www.openserv_ssl.org/docs/crypto/BIO_s_mem.html */

    out_bio = BIO_new(BIO_s_mem());
    if(out_bio == NULL) {
        printf("Error: cannot allocate write bio.\n");
        return -2;
    }

    BIO_set_mem_eof_return(out_bio, -1); /* see: https://www.openserv_ssl.org/docs/crypto/BIO_s_mem.html */

    SSL_set_bio(ssl, in_bio, out_bio);
    return 0;
}

int main ()
{
    int err;
    char     buf [4096];
    struct ssl_channel *client = malloc(sizeof(struct ssl_channel));
    struct ssl_channel *server = malloc(sizeof(struct ssl_channel));
    client->shm = malloc(sizeof(struct shm_ctx_t));
    server->shm = malloc(sizeof(struct shm_ctx_t));
    init_shm(client->shm, "client");
    init_shm(server->shm, "server");

    SSL_CTX* ctx;
    SSL_METHOD *meth;

    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    ERR_load_BIO_strings();

    meth = TLSv1_2_method();
    ctx = SSL_CTX_new (meth);
    // now we ban begin initialize the client side.

    client->ssl = SSL_new(ctx);                         CHK_NULL(client->ssl);

    init_ssl_bio(client->ssl);
    SSL_set_connect_state(client->ssl);
    // since SSL_new is copy ctx object to ssl object. so we can reuse the ctx obj.

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(2);
    }
    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(3);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(4);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr,"Private key does not match the certificate public key\n");
        exit(5);
    }
    server->ssl = SSL_new(ctx);                         CHK_NULL(server->ssl);

    init_ssl_bio(server->ssl);

    SSL_set_accept_state(server->ssl);

    // do server side handshake
    while(!SSL_is_init_finished(server->ssl)){
        receive_up(server);
        int r = SSL_do_handshake(server->ssl);
        send_down(server);
    }
    printf ("SSL connection using %s\n", SSL_get_cipher (server->ssl));

    // do client  side handshake
    SSL_do_handshake(client->ssl); // This will write the hello message to the out_bio

    while(!SSL_is_init_finished(client->ssl)){
        send_down(client);
        receive_up(client);
        int r = SSL_do_handshake(client->ssl);
        if(r < 0){
            switch(SSL_get_error(client->ssl, r)){
                case SSL_ERROR_WANT_READ:
                    printf("want to read more data!\n");
                    /*receive_up(in_bio, &shm_ctx);*/
                    break;
                case SSL_ERROR_WANT_WRITE:
                    printf("want to write more data!\n");
                    /*send_down(client->ssl, &shm_ctx);*/
                    break;
            }
        }else {
            printf("handshake is done!\n");
            break;
        }
    }
    // now we get both side ssl connection established.
    // begin the proxy;

    /* --------------------------------------------------- */
    /* DATA EXCHANGE - Receive message and send reply. */
    /*assume the client send, server response mode*/
    while(1){
        receive_up(server);
        err = SSL_read(server->ssl, buf + sizeof(int), sizeof(buf) - 1);                   CHK_SSL(err);
        memcpy(buf, &err, sizeof(int));

        err = SSL_write(client->ssl, buf + sizeof(int), *((int *)buf));  CHK_SSL(err);

        send_down(client);

        receive_up(client);
        err = SSL_read(client->ssl, buf + sizeof(int), sizeof(buf) - 1);                   CHK_SSL(err);
        memcpy(buf, &err, sizeof(int));

        err = SSL_write(server->ssl, buf + sizeof(int), *((int *)buf));  CHK_SSL(err);

        send_down(server);
    }
    /* Clean up. */

    SSL_free(server->ssl);
    SSL_free(client->ssl);
    SSL_CTX_free (ctx);
    return 0;
}

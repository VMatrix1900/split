// client part and server part. pass the data through the middlebox application.
// client part do handshake with real server. just send down msg and receive up
// msg.
// server part use fake certificate to do handshake with real client.
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "cachemgr.h"
#include "cert.h"
#include "channel.h"
#include "ssl.h"

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

struct proxy *proxy_new(struct ssl_channel *ctx)
{
    struct proxy *proxy = malloc(sizeof(struct proxy));
    proxy->client_handshake_begin = 0;
    proxy->client_handshake_done = 0;
    SSL_CTX *sslctx;
    const SSL_METHOD *meth;
    meth = TLSv1_2_method();
    sslctx = SSL_CTX_new(meth);
    // now we ban begin initialize the client side.

    proxy->cli_ssl = SSL_new(sslctx);
    CHK_NULL(proxy->cli_ssl);

    init_ssl_bio(proxy->cli_ssl);
    SSL_set_connect_state(proxy->cli_ssl);

    SSL_CTX_free(sslctx);

    return proxy;
}

// OpenSSL create the session when the handshake is finished.
// Of course, you need the premaster key.
/*
 * Called by OpenSSL when a new src SSL session is created.
 * OpenSSL increments the refcount before calling the callback and will
 * decrement it again if we return 0.  Returning 1 will make OpenSSL skip
 * the refcount decrementing.  In other words, return 0 if we did not
 * keep a pointer to the object (which we never do here).
 */
#ifdef WITH_SSLV2
#define MAYBE_UNUSED
#else /* !WITH_SSLV2 */
#define MAYBE_UNUSED UNUSED
#endif /* !WITH_SSLV2 */
static int pxy_ossl_sessnew_cb(MAYBE_UNUSED SSL *ssl, SSL_SESSION *sess)
#undef MAYBE_UNUSED
{
#ifdef DEBUG_SESSION_CACHE
    log_dbg_printf("===> OpenSSL new session callback:\n");
    if (sess) {
        log_dbg_print_free(ssl_session_to_str(sess));
    } else {
        log_dbg_print("(null)\n");
    }
#endif /* DEBUG_SESSION_CACHE */
#ifdef WITH_SSLV2
    /* Session resumption seems to fail for SSLv2 with protocol
     * parsing errors, so we disable caching for SSLv2. */
    if (SSL_version(ssl) == SSL2_VERSION) {
        log_err_printf(
            "Warning: Session resumption denied to SSLv2"
            "client.\n");
        return 0;
    }
#endif /* WITH_SSLV2 */
    if (sess) {
        cachemgr_ssess_set(sess);
    }
    return 0;
}

/*
 * Called by OpenSSL when a src SSL session should be removed.
 * OpenSSL calls SSL_SESSION_free() after calling the callback;
 * we do not need to free the reference here.
 */
static void pxy_ossl_sessremove_cb(UNUSED SSL_CTX *sslctx, SSL_SESSION *sess)
{
#ifdef DEBUG_SESSION_CACHE
    log_dbg_printf("===> OpenSSL remove session callback:\n");
    if (sess) {
        log_dbg_print_free(ssl_session_to_str(sess));
    } else {
        log_dbg_print("(null)\n");
    }
#endif /* DEBUG_SESSION_CACHE */
    if (sess) {
        cachemgr_ssess_del(sess);
    }
}

/*
 * Called by OpenSSL when a src SSL session is requested by the client.
 */
static SSL_SESSION *pxy_ossl_sessget_cb(UNUSED SSL *ssl, unsigned char *id,
                                        int idlen, int *copy)
{
    SSL_SESSION *sess;

#ifdef DEBUG_SESSION_CACHE
    log_dbg_printf("===> OpenSSL get session callback:\n");
#endif /* DEBUG_SESSION_CACHE */

    *copy = 0; /* SSL should not increment reference count of session */
    sess = cachemgr_ssess_get(id, idlen);

#ifdef DEBUG_SESSION_CACHE
    if (sess) {
        log_dbg_print_free(ssl_session_to_str(sess));
    }
#endif /* DEBUG_SESSION_CACHE */

    return sess;
}

/*
 * Create and set up a new SSL_CTX instance for terminating SSL.
 * Set up all the necessary callbacks, the certificate, the cert chain and key.
 */
static SSL_CTX *pxy_srcsslctx_create(struct proxy *ctx, X509 *crt,
                                     STACK_OF(X509) * chain, EVP_PKEY *key)
{
    SSL_CTX *sslctx = SSL_CTX_new(TLSv1_2_method());
    if (!sslctx) return NULL;
    SSL_CTX_set_options(sslctx, SSL_OP_ALL);
#ifdef SSL_OP_TLS_ROLLBACK_BUG
    SSL_CTX_set_options(sslctx, SSL_OP_TLS_ROLLBACK_BUG);
#endif /* SSL_OP_TLS_ROLLBACK_BUG */
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    SSL_CTX_set_options(sslctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif /* SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION */
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    SSL_CTX_set_options(sslctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif /* SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS */
#ifdef SSL_OP_NO_TICKET
    SSL_CTX_set_options(sslctx, SSL_OP_NO_TICKET);
#endif /* SSL_OP_NO_TICKET */
#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
    SSL_CTX_set_options(sslctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
#endif /* SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION */

    /*SSL_CTX_set_cipher_list(sslctx, ctx->opts->ciphers);*/
    SSL_CTX_sess_set_new_cb(sslctx, pxy_ossl_sessnew_cb);
    SSL_CTX_sess_set_remove_cb(sslctx, pxy_ossl_sessremove_cb);
    SSL_CTX_sess_set_get_cb(sslctx, pxy_ossl_sessget_cb);
    SSL_CTX_set_session_cache_mode(
        sslctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL);
#ifdef USE_SSL_SESSION_ID_CONTEXT
    SSL_CTX_set_session_id_context(sslctx, (void *)(&ssl_session_context),
                                   sizeof(ssl_session_context));
#endif /* USE_SSL_SESSION_ID_CONTEXT */
    SSL_CTX_use_certificate(sslctx, crt);
    SSL_CTX_use_PrivateKey(sslctx, key);
    for (int i = 0; i < sk_X509_num(chain); i++) {
        X509 *c = sk_X509_value(chain, i);
        ssl_x509_refcount_inc(c); /* next call consumes a reference */
        SSL_CTX_add_extra_chain_cert(sslctx, c);
    }
    return sslctx;
}

SSL *create_proxy_server_ssl(struct proxy *proxy)
{
    cert_t *cert;
    X509 *origcrt;

    cert = cert_new();
    origcrt = SSL_get_peer_certificate(proxy->cli_ssl);
    cert->crt = cachemgr_fkcrt_get(origcrt);
    if (!cert->crt) {
        cert->crt = ssl_x509_forge(proxy->ctx->cacrt, proxy->ctx->cakey,
                                   origcrt, NULL, proxy->ctx->key);
    }
    X509_free(origcrt);
    cert_set_key(cert, proxy->ctx->key);
    cert_set_chain(cert, proxy->ctx->chain);
    if (!cert) return NULL;

    SSL_CTX *sslctx =
        pxy_srcsslctx_create(proxy, cert->crt, cert->chain, cert->key);
    cert_free(cert);
    if (!sslctx) return NULL;
    SSL *ssl = SSL_new(sslctx);
    SSL_CTX_free(sslctx); /* SSL_new() increments refcount */
    if (!ssl) {
        return NULL;
    }
    return ssl;
}

void setup_proxy_server_ssl(struct proxy *proxy)
{
    proxy->serv_ssl = create_proxy_server_ssl(proxy);
    init_ssl_bio(proxy->serv_ssl);
    SSL_set_accept_state(proxy->serv_ssl);
}

struct ssl_channel *create_channel_ctx(const char *certf, const char *keyf)
{
    struct ssl_channel *channel = malloc(sizeof(struct ssl_channel));
    channel->shm_ctx = malloc(sizeof(struct shm_ctx_t));
    init_shm(channel->shm_ctx);
    channel->conns = 0;
    channel->cacrt = ssl_x509_load(certf);
    ssl_x509_refcount_inc(channel->cacrt);
    sk_X509_insert(channel->chain, channel->cacrt, 0);
    channel->cakey = ssl_key_load(keyf);
    channel->key = ssl_key_genrsa(1024);

    return channel;
}

int main()
{
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    ERR_load_BIO_strings();

    struct ssl_channel *channel = create_channel_ctx(CERTF, KEYF);
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
                // that means a new clienthello is coming. must be the server
                // side.
                if (1 == *((int *)shm_up)) {
                    // actually this index = conns ++; used as a sync variable.
                    unsigned char *buf = (unsigned char *)shm_up + sizeof(int);
                    size_t length = *((size_t *)buf);
                    buf += sizeof(size_t);
                    proxy = proxy_new(channel);
                    proxy->index = index;
                    proxy->sni =
                        ssl_tls_clienthello_parse_sni(buf, (ssize_t *)&length);
                    // TODO check the msg
                    channel->proxies[index] = proxy;
                    channel->conns++;

                } else {
                    printf("Not server hello message, wrong!\n");
                }
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
            if (!proxy->client_handshake_begin) {
                // initiate client handshake.
                SSL_do_handshake(proxy->cli_ssl);
                proxy->client_need_to_out = 1;
                proxy->client_handshake_begin = 1;
            } else if (proxy->client_handshake_done) {
                if (!SSL_is_init_finished(proxy->serv_ssl)) {
                    SSL_do_handshake(proxy->serv_ssl);
                    proxy->server_need_to_out = 1;
                } else {
                    printf("server side handshake is done.");
                    printf("begin forward ssl record to client\n");
                    forward_record(proxy->serv_ssl, proxy->cli_ssl);
                    proxy->client_need_to_out = 1;
                }
                proxy->server_received = 0;
            } else {
                // this means client handshake began bt not finished.
                // but receive another server msg. wrong. or maybe another
                // client hello msg.
                // TODO ignore the duplicate handshake msg.
                printf("Client handshake not finished yet! Wrong!\n");
                exit(1);
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
                    printf("client handshake is done\n");
                    proxy->client_handshake_done = 1;
                    setup_proxy_server_ssl(proxy);
                    SSL_do_handshake(proxy->serv_ssl);
                    proxy->server_need_to_out = 1;
                }
            } else {
                printf("begin forward client data to server.\n");
                forward_record(proxy->cli_ssl, proxy->serv_ssl);
                proxy->server_need_to_out = 1;
            }
            proxy->client_received = 0;
        }

        // now we finish the SSL record process; begin to send down the record.
        int num =
            (proxy->client_handshake_done ? proxy->server_need_to_out : 0) +
            proxy->client_need_to_out;
        memcpy(shm_down, &num, sizeof(int));
        shm_down += sizeof(int);
        if (proxy->client_handshake_done && proxy->server_need_to_out) {
            printf("server side send down\n");
            memcpy(shm_down, &proxy->index, sizeof(int));
            shm_down += sizeof(int);
            shm_down = send_down(proxy->serv_ssl, shm_down, 1);
            proxy->server_need_to_out = 0;
        }
        if (proxy->client_need_to_out) {
            printf("client side send down\n");
            memcpy(shm_down, &proxy->index, sizeof(int));
            shm_down += sizeof(int);
            shm_down = send_down(proxy->cli_ssl, shm_down, 0);
            proxy->client_need_to_out = 0;
        }

        // reset the shm pointer
        shm_up = channel->shm_ctx->shm_up;
        shm_down = channel->shm_ctx->shm_down;

        sem_post(channel->shm_ctx->down);
    }

    return 0;
}

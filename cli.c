/* cli.c  -  Minimal ssleay client for Unix
   30.9.1996, Sampo Kellomaki <sampo@iki.fi> */

/* mangled to work with OpenSSL 0.9.2b
   Simplified to be even more minimal
   12/98 - 4/99 Wade Scholine <wades@mail.cybg.com> */

#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define SHMSZ 4096
#define BUFSZ 4096
char UP_SEM[]= "up";
char DOWN_SEM[]= "down";
key_t key = 1000;

// store the info about the semophores and shared memory.
struct shm_ctx_t {
    sem_t *down;
    sem_t *up;
    int shmid;
    char *shm;
};

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int init_shm(struct shm_ctx_t * shm_ctx){

    //create & initialize existing semaphore
    shm_ctx->down = sem_open(DOWN_SEM, O_CREAT, 0644, 0);
    if(shm_ctx->down == SEM_FAILED)
    {
        perror("socket:unable to execute semaphore");
        sem_close(shm_ctx->down);
        return -1;
    }

    shm_ctx->up = sem_open(UP_SEM, O_CREAT,0644,0);
    if(shm_ctx->up == SEM_FAILED)
    {
        perror("unable to create semaphore");
        sem_unlink(UP_SEM);
        return -1;
    }

    //create the shared memory segment with this key
    shm_ctx->shmid = shmget(key,SHMSZ,IPC_CREAT|0666);
    if(shm_ctx->shmid<0)
    {
        perror("socket:failure in shmget");
        return -1;
    }

    //attach this segment to virtual memory
    shm_ctx->shm = shmat(shm_ctx->shmid,NULL,0);
    return 0;

}

void send_down(BIO *out_bio, struct shm_ctx_t *shm_ctx) {
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

void receive_up(BIO *in_bio, struct shm_ctx_t *shm_ctx) {
    sem_wait(shm_ctx->up);
    printf("begin receive up msg. The size is %zu\n", *((size_t *)shm_ctx->shm));
    // copy the packet to in_bio
    BIO_write(in_bio, shm_ctx->shm + sizeof(size_t), *((size_t *)shm_ctx->shm));
    printf("Client receive_up the packet completed\n");
}

int main ()
{
    int err;
    SSL_CTX* ctx;
    SSL*     ssl;
    char     buf [4096];
    BIO *in_bio, *out_bio;
    SSL_METHOD *meth;

    struct shm_ctx_t shm_ctx;

    memset(&shm_ctx, 0, sizeof(shm_ctx));

    if (init_shm(&shm_ctx) < 0){
        perror("shared memory wrong!\n");
        exit(-1);
    }

    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    meth = TLSv1_2_method();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ctx = SSL_CTX_new (meth);                        CHK_NULL(ctx);

    ssl = SSL_new (ctx);                         CHK_NULL(ssl);

    in_bio = BIO_new(BIO_s_mem());
    if(in_bio == NULL) {
        printf("Error: cannot allocate read bio.\n");
        return -2;
    }

    BIO_set_mem_eof_return(in_bio, -1); /* see: https://www.openssl.org/docs/crypto/BIO_s_mem.html */

    out_bio = BIO_new(BIO_s_mem());
    if(out_bio == NULL) {
        printf("Error: cannot allocate write bio.\n");
        return -3;
    }

    BIO_set_mem_eof_return(out_bio, -1); /* see: https://www.openssl.org/docs/crypto/BIO_s_mem.html */

    SSL_set_bio(ssl, in_bio, out_bio);

    SSL_set_connect_state(ssl);

    SSL_do_handshake(ssl); // This will write the hello message to the out_bio

    while(!SSL_is_init_finished(ssl)){
        send_down(out_bio, &shm_ctx);
        receive_up(in_bio, &shm_ctx);
        int r = SSL_do_handshake(ssl);
        if(r < 0){
            switch(SSL_get_error(ssl, r)){
                case SSL_ERROR_WANT_READ:
                    printf("want to read more data!\n");
                    /*receive_up(in_bio, &shm_ctx);*/
                    break;
                case SSL_ERROR_WANT_WRITE:
                    printf("want to write more data!\n");
                    /*send_down(out_bio, &shm_ctx);*/
                    break;
            }
        }else {
            printf("handshake is done!\n");
            break;
        }
    }

    /* --------------------------------------------------- */
    /* DATA EXCHANGE - send_down a message and receive_up a reply. */

    err = SSL_write (ssl, "Hello World!", strlen("Hello World!"));  CHK_SSL(err);

    send_down(out_bio, &shm_ctx);

    receive_up(in_bio, &shm_ctx);

    err = SSL_read(ssl, buf, sizeof(buf) - 1);                     CHK_SSL(err);
    buf[err] = '\0';
    printf ("Got %d chars:'%s'\n", err, buf);
    SSL_shutdown (ssl);  /* send_down SSL/TLS close_notify */

    /* Clean up. */

    SSL_free (ssl);
    SSL_CTX_free (ctx);
    return 0;
}
/* EOF - cli.c */

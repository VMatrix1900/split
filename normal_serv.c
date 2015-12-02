/* serv.cpp  -  Minimal ssleay server for Unix
   30.9.1996, Sampo Kellomaki <sampo@iki.fi> */


/* mangled to work with OpenSSL 0.9.2b
   Simplified to be even more minimal
   12/98 - 4/99 Wade Scholine <wades@mail.cybg.com> */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


/* define HOME to be dir for key and cert files... */
#define HOME "./"
/* Make these what you want for cert & key files */
#define CERTF  HOME "server-cert.pem"
#define KEYF  HOME  "server-key.pem"


#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int main ()
{
    int err;
    int listen_sd;
    int sd;
    struct sockaddr_in sa_serv;
    struct sockaddr_in sa_cli;
    size_t client_len;
    SSL_CTX* ctx;
    SSL*     ssl;
    X509*    client_cert;
    char*    str;
    char     buf [4096];
    SSL_METHOD *meth;

    /* SSL preliminaries. We keep the certificate and key with the context. */

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    meth = TLSv1_2_server_method();
    ctx = SSL_CTX_new (meth);
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

    /* ----------------------------------------------- */
    /* Prepare TCP socket for receiving connections */

    listen_sd = socket (AF_INET, SOCK_STREAM, 0);   CHK_ERR(listen_sd, "socket");

    memset(&sa_serv, 0, sizeof(sa_serv));
    sa_serv.sin_family      = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port        = htons (8453);          /* Server Port number */

    err = bind(listen_sd, (struct sockaddr*) &sa_serv,
            sizeof (sa_serv));                   CHK_ERR(err, "bind");

    /* Receive a TCP connection. */

    err = listen (listen_sd, 5);                    CHK_ERR(err, "listen");

    client_len = sizeof(sa_cli);
    sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
    CHK_ERR(sd, "accept");
    close (listen_sd);

    printf ("Connection from %lx, port %x\n",
            sa_cli.sin_addr.s_addr, sa_cli.sin_port);

    /* ----------------------------------------------- */
    /* TCP connection is ready. Do server side SSL. */

    ssl = SSL_new (ctx);                           CHK_NULL(ssl);
    SSL_set_fd (ssl, sd);
    SSL_set_accept_state(ssl);
    /*while(!SSL_is_init_finished(ssl)){*/
    /*SSL_accept(ssl);*/
    /*}*/
    int accepted = SSL_accept(ssl);
    if(accepted < 0) {
        printf("error code is:%d", SSL_get_error(ssl, accepted));
        /*switch(SSL_get_error(ssl, accepted)){*/
        /*    case k*/
        /*}*/
    }
    /* Get the cipher - opt */

    printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
    /* DATA EXCHANGE - Receive message and send reply. */

    err = SSL_read (ssl, buf, sizeof(buf) - 1);                   CHK_SSL(err);
    buf[err] = '\0';
    printf ("Got %d chars:'%s'\n", err, buf);

    err = SSL_write (ssl, "I hear you.", strlen("I hear you."));  CHK_SSL(err);

    /* Clean up. */

    close (sd);
    SSL_free (ssl);
    SSL_CTX_free (ctx);
    return 0;
}
/* EOF - serv.c */

/* A TCP echo server with timeouts.
 *
 * Note that you will not need to use select and the timeout for a
 * tftp server. However, select is also useful if you want to receive
 * from multiple sockets at the same time. Read the documentation for
 * select on how to do this (Hint: Iterate with FD_ISSET()).
 */

#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <glib.h>

#define CERTIFICATE_FILE "fd.crt"
#define PRIVATE_KEY_FILE "fd.key"
#define CA_PEM "ca.pem"

/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
    const struct sockaddr_in *_addr1 = addr1;
    const struct sockaddr_in *_addr2 = addr2;

    /* If either of the pointers is NULL or the addresses
       belong to different families, we abort. */
    g_assert((_addr1 == NULL) || (_addr2 == NULL) ||
            (_addr1->sin_family != _addr2->sin_family));

    if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) {
        return -1;
    } else if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) {
        return 1;
    } else if (_addr1->sin_port < _addr2->sin_port) {
        return -1;
    } else if (_addr1->sin_port > _addr2->sin_port) {
        return 1;
    }
    return 0;
}

/* This function logs an activity to the log file.
 * <client> a struct which holds the ip and port number of the client
 * <user> the client user name
 * <log_info> the log message 
 */ 
void log_to_file(struct sockaddr_in client, char * user, char * log_info) 
{
    time_t now;
    time(&now);
    char timestamp[sizeof "2011-10-08T07:07:09Z"];
    strftime(timestamp, sizeof timestamp, "%FT%TZ", gmtime(&now));

    FILE *f = fopen("log.txt", "a");
    if (f == NULL) {
        fprintf(stdout, "ERROR when opening log file");
        fflush(stdout);
    } else {
        fprintf(f, "%s : ", timestamp); // log the timestamp
        // log the ip address and port number
        fprintf(f, "%s:%d ", inet_ntoa(client.sin_addr), client.sin_port);
        fprintf(f, "%s ", user); // log the user
        fprintf(f, "%s ", log_info); // log the message
        fclose(f);
    }
}

int main(int argc, char **argv)
{
    printf("Number of arguments %d\n", argc);
    printf("Portnumber : %s\n", argv[1]);
    int myport = argv[1];

    int sockfd;
    struct sockaddr_in server, client;
    char message[512];

    SSL_library_init(); /* load encryption & hash algorithms for SSL */                
    SSL_load_error_strings(); /* load the error strings for good error reporting */

    SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv3_method()); // initilize ssl context
    
    if ( !ssl_ctx ) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // Load certificate file into the structure 
    if (SSL_CTX_use_certificate_file(ssl_ctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM) <= 0) {
        printf("Error loading certificate file");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    // Load private key file into the structure
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, PRIVATE_KEY_FILE, SSL_FILETYPE_PEM <= 0)) {
        printf("Error loading private key");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if ( !SSL_CTX_check_private_key(ssl_ctx) ) {
        printf("Private key does not match the certificate public key\n");
        exit(1);
    }


    if ( !SSL_CTX_load_verify_locations(ssl_ctx, CA_PEM, NULL) ) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ssl_ctx, 1);


    /* Create and bind a TCP socket */
    sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    /* Network functions need arguments in network byte order instead of
       host byte order. The macros htonl, htons convert the values, */
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(myport);
    bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));

    /* Before we can accept messages, we have to listen to the port. We allow one
     * 1 connection to queue for simplicity.
     */
    listen(sockfd, 1);
    SSL *ssl = SSL_new(ssl_ctx);
    if ( !ssl ) {
        printf("ERROR: SSL new\n");
        exit(1);
    }

    for (;;) {
        fd_set rfds;
        struct timeval tv;
        int retval;

        /* Check whether there is data on the socket fd. */
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);

        // Set the socket into the SSL structure
        SSL_set_fd(ssl, sockfd);

        /* Wait for five seconds. */
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        retval = select(sockfd + 1, &rfds, NULL, NULL, &tv);

        if (retval == -1) {
            perror("select()");
        } else if (retval > 0) {
            /* Data is available, receive it. */
            assert(FD_ISSET(sockfd, &rfds));

            /* Copy to len, since recvfrom may change it. */
            socklen_t len = (socklen_t) sizeof(client);

            /* For TCP connectios, we first have to accept. */
            int connfd;
            connfd = accept(sockfd, (struct sockaddr *) &client,
                    &len);

            printf("Connection from %lx, port %x\n", client.sin_addr.s_addr, 
                    client.sin_port);

           

            int err = SSL_accept(ssl);
            if ( err == -1 ) {
                ERR_print_errors_fp(stderr);
                exit(1);
            }

            printf("SSL connection using %s\n", SSL_get_cipher (ssl));

            X509 *client_cert = SSL_get_peer_certificate(ssl);
            if ( client_cert ) {
                printf ("Client certificate:\n");
                char * str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
                if ( !str ) {
                    printf("Error: get_subject_name\n");
                    exit(1);
                }
                printf ("\t subject: %s\n", str);
                free (str);
                str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
                if ( str ) {
                    printf("Error: get_issuer_name\n");
                    exit(1);
                }
                printf ("\t issuer: %s\n", str);
                free (str);
                X509_free(client_cert);
            } else {
                printf("The SSL client does not have certificate\n");
            }
            
            char buf [4096];
            err = SSL_read(ssl, buf, sizeof(buf) -1);
            if ( err == -1 ) {
                printf("Error: SSL_read");
                exit(1);
            }

            printf ("Received %d chars:'%s'\n", err, buf);

            char * server_message = "This message is from the SSL server";
            err = SSL_write(ssl, server_message, strlen(server_message)); 
            if ( err == -1 ) {
                printf("Error: SSL_write\n");
                exit(1);
            }
            /* Receive one byte less than declared,
               because it will be zero-termianted
               below. */
            ssize_t n = read(connfd, message, sizeof(message) - 1);

            char ssl_message[512];
            memset(&ssl_message, 0, sizeof(ssl_message));
            err = SSL_read(ssl, ssl_message, sizeof(ssl_message) - 1);

            printf("ssl_message: %s\n", ssl_message);

            /* Send the message back. */
            write(connfd, message, (size_t) n);

            /* We should close the connection. */
            shutdown(connfd, SHUT_RDWR);
            close(connfd);

            /* Zero terminate the message, otherwise
               printf may access memory outside of the
               string. */
            message[n] = '\0';
            /* Print the message to stdout and flush. */
            fprintf(stdout, "Received:\n%s\n", message);
            fflush(stdout);
        } else {
            fprintf(stdout, "No message in five seconds.\n");
            fflush(stdout);
        }
    }
}

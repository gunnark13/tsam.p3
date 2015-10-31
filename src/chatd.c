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
#include <time.h>

#define CERTIFICATE_FILE "fd.crt"
#define PRIVATE_KEY_FILE "fd.key"

#define MAX_CLIENTS 5 

struct client_info {
    int connfd;
    time_t time;
    struct sockaddr_in socket;
    SSL *ssl;
};


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

gboolean set_highest_connfd(gpointer key, gpointer value, gpointer data)
{
    printf("Test\n");
    return TRUE;
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
        if ( user ) {
            fprintf(f, "%s ", user); // log the user
        }
        fprintf(f, "%s\n", log_info); // log the message
        fclose(f);
    }
}

int main(int argc, char **argv)
{
    printf("Number of arguments %d\n", argc);
    printf("Portnumber : %s\n", argv[1]);
    int my_port = atoi(argv[1]);

    struct sockaddr_in server, client;

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
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, PRIVATE_KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        printf("Error loading private key");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if ( !SSL_CTX_check_private_key(ssl_ctx) ) {
        printf("Private key does not match the certificate public key\n");
        exit(1);
    }

    /* Create and bind a TCP socket */
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( sockfd == -1 ) {
        printf("Error binding a tcp socket\n");
        exit(1);
    } 
    int highestConnfd = sockfd;

    printf("Sockfd : %d\n", sockfd);
    printf("Port : %d\n", my_port);

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    /* Network functions need arguments in network byte order instead of
       host byte order. The macros htonl, htons convert the values, */
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(my_port);
    int err = bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));
    if ( err == -1 ) {
        printf("Error binding name to socket\n");
        exit(1);
    }

    /* Before we can accept messages, we have to listen to the port. We allow one
     * 1 connection to queue for simplicity.
     */
    listen(sockfd, MAX_CLIENTS);

    GTree *client_tree = g_tree_new(sockaddr_in_cmp);

    struct client_info clients[MAX_CLIENTS];
    int ci = 0; // client index
    for (; ci < MAX_CLIENTS; ci++) {
        clients[ci].connfd = -1; // initialize all clients as inactive
    }

    for (;;) {
        fd_set rfds;
        struct timeval tv;
        int retval;

        /* Check whether there is data on the socket fd. */
        FD_ZERO(&rfds);
        highestConnfd = sockfd;
        FD_SET(sockfd, &rfds);
        ci = 0; // client index
        
        g_tree_foreach(client_tree, set_highest_connfd, &highestConnfd);

        for (; ci < MAX_CLIENTS; ci++) {
            if (clients[ci].connfd > highestConnfd) {
                highestConnfd = clients[ci].connfd; // Update highest connfd
            }
            if (clients[ci].connfd != -1) {
                FD_SET(clients[ci].connfd, &rfds);
            }
        }
        
        /* Wait for five seconds. */
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        retval = select(highestConnfd + 1, &rfds, NULL, NULL, &tv);
        if (retval == -1) {
            perror("select()");
        } else if (retval > 0) {
            
            if ( FD_ISSET(sockfd, &rfds) ) {
                /* Copy to len, since recvfrom may change it. */
                socklen_t len = (socklen_t) sizeof(client);
                /* For TCP connectios, we first have to accept. */
                int connfd = accept(sockfd, (struct sockaddr *) &client, &len);

                printf("Connection from %s, port %d\n", 
                        inet_ntoa(client.sin_addr), 
                        ntohs(client.sin_port));

                SSL *ssl = SSL_new(ssl_ctx);
                if ( !ssl ) {
                    printf("ERROR: SSL new\n");
                } else {
                    SSL_set_fd(ssl, connfd);
                    
                    err = SSL_accept(ssl);
                    if ( err == -1 ) {
                        ERR_print_errors_fp(stderr);
                        printf("SSL connectio failed. SS_accept()");
                    } else {
                        int foundSpace = -1;
                        ci = 0;
                        for (; ci < MAX_CLIENTS; ci++) {
                            if ( clients[ci].connfd == -1 ) {
                                clients[ci].connfd = connfd;
                                time_t now;
                                clients[ci].time = time(&now);
                                clients[ci].socket = client;
                                clients[ci].ssl = ssl;
                                foundSpace = ci;
                                break;
                            }
                        }
                        if ( foundSpace != -1 ) {
                            char * server_message = "Welcome";
                            err = SSL_write(ssl, server_message, strlen(server_message)); 
                            if ( err == -1 ) {
                                printf("Error: SSL_write\n");
                            } else { 
                                
                                g_tree_insert(client_tree, &clients[ci].socket, &clients[ci]);
                                char * log_info = "connected";
                                log_to_file(client, NULL, log_info);
                            }
                        } else {
                            shutdown(connfd, SHUT_RDWR);
                            close(connfd);
                        }
                    }
                }
            }

            ci = 0;
            for (; ci < MAX_CLIENTS; ci++) {
                time_t now; 
                if ( clients[ci].connfd != -1 && FD_ISSET(clients[ci].connfd, &rfds)) {
                    char buf [4096];
                    err = SSL_read(clients[ci].ssl, buf, sizeof(buf) -1);
                    if ( err <= 0 ) {
                        printf("Error: SSL_read, disconnecting client\n");
                        close(clients[ci].connfd);
                        SSL_free(clients[ci].ssl);
                        clients[ci].connfd = -1;
                        char * log_info = "disconnected";
                        log_to_file(clients[ci].socket, NULL, log_info);
                    } else {
                        buf[err] = '\0';
                        printf ("Received %d chars:'%s'\n", err, buf);
                        clients[ci].time = time(&now);
                    }
                }
                int clientConnectionSec = (int) difftime(time(&now), clients[ci].time);
                if ( clients[ci].connfd != -1 && clientConnectionSec >= 15 ) {
                    shutdown(clients[ci].connfd, SHUT_RDWR);
                    close(clients[ci].connfd);
                    clients[ci].connfd = -1;
                    char * log_info = "disconnected, timed out";
                    log_to_file(clients[ci].socket, NULL, log_info);

                    err = SSL_shutdown(clients[ci].ssl);
                    if ( err == -1 ) {
                        printf("Error : failed to shutdown\n");
                    } else {
                        close(clients[ci].connfd);
                        SSL_free(clients[ci].ssl);
                    }
                }
            }
        } else {
            fprintf(stdout, "No message in five seconds.\n");
            fflush(stdout);
        }
    }
}

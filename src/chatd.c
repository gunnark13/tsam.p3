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

#define UNUSED(x) (void)(x)
#define MAX_CLIENTS 5 

struct client_info {
    int connfd; 
    gboolean active; 
    time_t time;
    struct sockaddr_in socket;
    SSL *ssl;
    char * username;
    char * password;
    char * room;
};

struct chat_room {
    char * name;
    GList * users;
};

GTree *chat_room_tree;
GTree *client_tree;

/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
    const struct sockaddr_in *_addr1 = addr1;
    const struct sockaddr_in *_addr2 = addr2;

    /* If either of the pointers is NULL or the addresses
       belong to different families, we abort. */
    g_assert((_addr1 != NULL) && (_addr2 != NULL) &&
            (_addr1->sin_family == _addr2->sin_family));

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

int chat_room_cmp(const void * room_a, const void * room_b)
{
    const char * a = room_a;
    const char * b = room_b;

    int cmp = strcmp(a, b);
    if ( cmp == -1 ) {
        return 1;
    } else if ( cmp == 1 ) {
        return -1;
    } else {
        return 0;
    }
}

gboolean starts_with(const char * substring, const char * str)
{
    if(strncmp(str, substring, strlen(substring)) == 0) {
        return TRUE;
    }
    return FALSE;
}


/* This function sets the highest_connfd varible (data) as the 
 * value of the connfd.  
 */ 
gboolean set_highest_connfd(gpointer key, gpointer value, gpointer data)
{
    UNUSED(key);
    const struct client_info * _value = value;
    int connfd = _value->connfd;
    if ( connfd > * (int *)data ) {
        *(int *)data = connfd;
    }
    return FALSE;
}


gboolean set_file_descriptor(gpointer key, gpointer value, gpointer data)
{
    UNUSED(key);
    const struct client_info * _value = value;
    int connfd = _value->connfd;
    FD_SET(connfd, (fd_set *)data);
    return FALSE;
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

/*This function finds all users and concatenates their info to the string data.*/
gboolean build_client_list (gpointer key, gpointer value, gpointer data)
{
    UNUSED(key);
    struct client_info * ci = value;
    struct sockaddr_in socket = ci->socket;
    strcat((char *) data, inet_ntoa(socket.sin_addr));
    strcat((char *) data, ":");
    char buffer[20];
    sprintf(buffer, "%d", socket.sin_port);
    strcat((char *) data, buffer);
    strcat((char *) data, "\n");
    return FALSE;
}

gboolean build_chat_room_list (gpointer key, gpointer value, gpointer data)
{
    UNUSED(key);
    const struct chat_room * cr = value;
    strcat((char *) data, cr->name);
    strcat((char *) data, "\n");
    return FALSE;
}

void check_command (char * buf, struct client_info * ci)
{
    if ( strcmp(buf, "/who\n") == 0 ) {
        printf("TODO: get list of users\n");
        char  clients[4096];
        memset(&clients, 0, sizeof(clients));
        g_tree_foreach(client_tree, build_client_list, &clients);
        SSL_write(ci->ssl, clients, strlen(clients));
    }
    if ( strcmp(buf, "/list\n") == 0 ) {
        // List all available public chat rooms 
        char chat_rooms[4096];
        memset(&chat_rooms, 0, sizeof(chat_rooms));
        g_tree_foreach(chat_room_tree, build_chat_room_list, chat_rooms);
        SSL_write(ci->ssl, chat_rooms, strlen(chat_rooms));
    } 
    if ( starts_with("/join\n", buf) == TRUE ) {
        printf("TODO: Add the client to chat room with the name after the command /join\n");
        //SSL_write(ci->ssl, clients, strlen(clients));
    }

}

gboolean read_from_client(gpointer key, gpointer value, gpointer data)
{
    UNUSED(key);
    struct client_info * ci = value;
    int connfd = ci->connfd;
    if ( FD_ISSET(connfd, (fd_set *)data) ) {
        char buf[4096];
        int err = SSL_read(ci->ssl, buf, sizeof(buf) - 1);
        if ( err <= 0 ) {
            printf("Error: SSL_read, disconnecting client\n");
            close(ci->connfd);
            SSL_free(ci->ssl);
            char * log_info = "disconnected";
            log_to_file(ci->socket, NULL, log_info);
            g_tree_remove(client_tree, key); 
        } else {
            buf[err] = '\0';
            printf("Received %d chars:'%s'\n", err, buf);
            time_t now;
            ci->time = time(&now); 
            check_command(buf, ci);
        }
    }
    return FALSE;
}

gboolean timeout_client(gpointer key, gpointer value, gpointer data)
{
    UNUSED(key);
    UNUSED(data);
    struct client_info * ci = value;
    time_t now;
    int client_connection_sec = (int) difftime(time(&now), ci->time);
    if ( client_connection_sec >= 15 ) {
        printf("Timout, client_port : %d\n", ci->socket.sin_port);
        int err = SSL_shutdown(ci->ssl);
        if (err == -1 ) {
            printf("Error shuting down ssl!\n");
        }
        close(ci->connfd);
        SSL_free(ci->ssl);
        char * log_info = "timed out.";
        log_to_file(ci->socket, NULL, log_info);
        g_tree_remove(client_tree, key); 
    }
    return FALSE;
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

    client_tree = g_tree_new(sockaddr_in_cmp);
    
    chat_room_tree = g_tree_new(chat_room_cmp);
    
    // Initilize rooms
    struct chat_room * room1 = g_new0(struct chat_room, 1);
    room1->name = "room1";
    struct chat_room * room2 = g_new0(struct chat_room, 1);
    room2->name = "room2";

    g_tree_insert(chat_room_tree, room1->name, room1);
    g_tree_insert(chat_room_tree, room2->name, room2);

    printf("Number of rooms : %d\n", g_tree_nnodes(chat_room_tree));

    for (;;) {
        fd_set rfds;
        struct timeval tv;
        int retval;

        /* Check whether there is data on the socket fd. */
        FD_ZERO(&rfds);
        highestConnfd = sockfd;
        FD_SET(sockfd, &rfds);

        g_tree_foreach(client_tree, set_highest_connfd, &highestConnfd);

        printf("Number of nodes : %d\n", g_tree_nnodes(client_tree));

        g_tree_foreach(client_tree, set_file_descriptor, &rfds); 

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

                printf("Connection from %s, port %d\n", inet_ntoa(client.sin_addr), 
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
                        struct client_info *ci = g_new0(struct client_info, 1);
                        ci->connfd = connfd;
                        time_t now;
                        ci->time = time(&now);
                        ci->socket = client;
                        ci->ssl = ssl;

                        char * server_message = "Welcome";
                        err = SSL_write(ssl, server_message, strlen(server_message)); 
                        if ( err == -1 ) {
                            printf("Error: SSL_write\n");
                        } else {
                            g_tree_insert(client_tree, &ci->socket, ci);
                            printf("Number of nodes : %d\n", g_tree_nnodes(client_tree));
                            char * log_info = "connected";
                            log_to_file(client, NULL, log_info);
                        }
                    }
                }
            }
            g_tree_foreach(client_tree, read_from_client, &rfds);
            // g_tree_foreach(client_tree, timeout_client, &rfds);
        } else {
            fprintf(stdout, "No message in five seconds.\n");
            fflush(stdout);
        }
    }
}

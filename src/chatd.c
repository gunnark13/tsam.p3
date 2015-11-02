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

#define CONNECTED "connected"
#define DISCONNECTED "disconnected"
#define AUTHENTICATED "authenticated"
#define AUTHENTICATION_ERROR "authentication error"
#define TIMED_OUT "timed out"
#define WELCOME "Welcome"

#define CERTIFICATE_FILE "fd.crt"
#define PRIVATE_KEY_FILE "fd.key"

#define UNUSED(x) (void)(x)
#define MAX_CLIENTS 5 

struct client_info {
    int connfd; 
    gboolean active;
    int authentication_tries;
    gboolean authenticated;
    time_t time;
    struct sockaddr_in socket;
    SSL *ssl;
    GString * username;
    GString * nickname;
    GString * password;
    char * room;
};

struct chat_room {
    char * name;
    GList * users;
};

struct username_search {
    GString * username;
    struct sockaddr_in * key;
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

int sockaddr_in_cmp_search(const void *addr1, const void *addr2)
{
    const struct sockaddr_in *_addr1 = addr1;
    const struct sockaddr_in *_addr2 = addr2;
    
    /* If either of the pointers is NULL or the addresses
       belong to different families, we abort. */
    g_assert((_addr1 != NULL) && (_addr2 != NULL) &&
            (_addr1->sin_family == _addr2->sin_family));

    if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) {
        return -1;
    } else if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) {
        return 1;
    } else if (_addr1->sin_port > _addr2->sin_port) {
        return -1;
    } else if (_addr1->sin_port < _addr2->sin_port) {
        return 1;
    }
    return 0;
}

int chat_room_cmp(const void * room_a, const void * room_b)
{
    const char * a = room_a;
    const char * b = room_b;
    return strcmp(a, b);
}

/*
 * This function compares two rooms for searching chat_room tree.
 * @param room_a        The former room for comparison.
 * @param room_b        The latter room for comparison.
 * @return int          Negative, positive or zero for decision making.
 */
int chat_room_cmp_search(const void * room_a, const void * room_b)
{
    const char * a = room_a;
    const char * b = room_b;
    int cmp = g_strcmp0(a, b);
    printf("a:'%s' | b:'%s'  ==> %d\n", a, b, cmp); 
    if ( cmp == 0 ) {
        return 0;
    } else if ( cmp > 0 ) {
        return -1;
    } else {
        return 1;
    }
}

/*
 * This function checks for a substring of a string.
 * @param substring   The substring in question.
 * @param str         The string in question.
 * @return            Boolean.
 */
gboolean starts_with(const char * substring, const char * str)
{
    if(strncmp(str, substring, strlen(substring)) == 0) {
        return TRUE;
    }
    return FALSE;
}

/* This function sets the highest_connfd varible as the value of the connfd.
 * @param key       The key for tree, unused.
 * @param value     The client_info struct.
 * @param data      The current highest_connfd. 
 * @return          Boolean for GTraverseFunc
 */ 
gboolean set_highest_connfd(gpointer key, gpointer value, gpointer data)
{
    UNUSED(key);
    const struct client_info * ci = value;
    if ( ci->active == TRUE ) {
        int connfd = ci->connfd;
        if ( connfd > * (int *)data ) {
            *(int *)data = connfd;
        }
    }
    return FALSE;
}

/*
 * This function sets the file descriptor for a client.
 * @param key       The key for tree, unused.
 * @param value     The client_info struct.
 * @param data      The fd_set.
 * @return          Booelan for GTraverseFunc.
 */
gboolean set_file_descriptor(gpointer key, gpointer value, gpointer data)
{
    UNUSED(key);
    const struct client_info * ci = value;
    if ( ci->active == TRUE ) {
        int connfd = ci->connfd;
        FD_SET(connfd, (fd_set *)data);
    }
    return FALSE;
}

/* This function logs an activity to the log file.
 * @param client        Struct with ip and port of the client.
 * @param user          The client user name.
 * @param log_info      The log message.
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

/*
 * This function finds all users and concatenates their info to the parameter string, data.
 * @param key       The key, for tree.
 * @param value     The client_info struct.
 * @param data      The char array for concatenating the list to.
 * @return          Boolean for GTraverseFunc.
 */
gboolean build_client_list (gpointer key, gpointer value, gpointer data)
{
    UNUSED(key);
    struct client_info * ci = value;
    if ( ci->active == TRUE ) {
        struct sockaddr_in socket = ci->socket;
        strcat((char *) data, inet_ntoa(socket.sin_addr));
        strcat((char *) data, ":");
        char buffer[20];
        sprintf(buffer, "%d", socket.sin_port);
        strcat((char *) data, buffer);
        strcat((char *) data, "\n");
    }
    return FALSE;
}

/*
 * This function builds the client list when requested with /list
 * @param key       The key, for tree.
 * @param value     The chat room that contains the requested list
 * @param data      The char array for concatenating the list to.
 */
gboolean build_chat_room_list (gpointer key, gpointer value, gpointer data)
{
    UNUSED(key);
    const struct chat_room * cr = value;
    strcat((char *) data, cr->name);
    strcat((char *) data, "\n");
    return FALSE;
}

/*
 * This function enrolls a client to a chat room.
 * @param room_name     The room the client wants to join.
 * @param ci            The client_info struct.
 */
void join_chat_room(char * room_name, struct client_info * ci)
{
    // Search for the room in question.
    struct chat_room * cr = g_tree_search(chat_room_tree, chat_room_cmp_search, room_name);
    char buf[4096];
    memset(&buf, 0, sizeof(buf));
    
    // Check if the room exists
    if ( cr == NULL ) {
        // No room is found, write that message to client.
        strcat(buf, "Room not found.\n");
        SSL_write(ci->ssl, buf, strlen(buf));
        return;
    } 

    printf("cr->name: '%s'\n", cr->name);
    printf("ci->room: '%s'\n", ci->room);
    // Remove user from his old room
    if(ci->room != NULL && strcmp(cr->name, ci->room) != 0) {
        // The client is already in a room, find that room "old_room".
        struct chat_room * old_room = g_tree_search(chat_room_tree, chat_room_cmp_search, ci->room);
        if( old_room != NULL ) {
            printf("removing user for his old room\n");
            old_room->users = g_list_remove(old_room->users, ci);
        } else {
            printf("Old room not found\n");
        }
    }

    // Register the user in the room
    ci->room = cr->name;
    if(g_list_find(cr->users, ci) == NULL) {
        // Add the client to his room unless he is there already.
        printf("registering user in new room\n");
        cr->users = g_list_append(cr->users, ci);
    }
    // Write registration message to client.
    strcat(buf, "Registered to room: ");
    strcat(buf, cr->name);
    strcat(buf, "\n");
    SSL_write(ci->ssl, buf, strlen(buf));
}

/*
 * This function writes to a client.
 * @param value     The client_info struct.
 * @param data      The message to send.
 */
void write_to_client(gpointer value, gpointer data) 
{
    const struct client_info * ci = value;
    const char * message = data;
    SSL_write(ci->ssl, message, strlen(message)); 
}

/*
 * This function broadcasts a message to all users of a chat_room.
 * @param message       The message to broadcast.
 * @param ci            The sender client_info struct.
 */
void broadcast(char * buf, struct client_info * ci)
{
    struct chat_room * cr = g_tree_search(chat_room_tree, chat_room_cmp_search, ci->room);
    if ( cr != NULL ) {
        printf("Broadcasting to %d users. Message : '%s'\n", g_list_length(cr->users),
            buf);
        g_list_foreach(cr->users, write_to_client, buf);
    }
}

gboolean find_user_by_username(gpointer key, gpointer value, gpointer data)
{
    struct client_info * ci = value;
    struct username_search * us = data;
    
    if ( ci->username == NULL ) {
        return FALSE;
    }
    printf("ci->user: '%s' | us->user : '%s' \n", ci->username->str, us->username->str);
    if ( g_strcmp0(ci->username->str, us->username->str) == 0 ) {
        us->key = key;
        return TRUE;
    }
    return FALSE;
}

void handle_login(char * buf, struct client_info * ci)
{
    // Splitting the request string to acces the user name and password fields
    char ** split_0 = g_strsplit(buf, "/user ", 0);
    if ( !split_0[1] ) {
        return;
    }
    char ** split_1 = g_strsplit(split_0[1], "/password ", 0);
    if ( !split_1[0] || !split_1[1] ) {
        return;
    }
    GString * username = g_string_new(g_strchomp(split_1[0]));
    GString * password = g_string_new(g_strchomp(split_1[1]));

    struct username_search * us = g_new0(struct username_search, 1);
    us->username = username;
    printf("us->username->str : '%s'\n", us->username->str); 
    g_tree_foreach(client_tree, find_user_by_username, us);
    if ( us->key != NULL ) {
        struct client_info * found_client = g_tree_search(client_tree, sockaddr_in_cmp_search,
                                                us->key);
        if ( found_client ) {
            // Check if the password is not correct
            if ( g_strcmp0(found_client->password->str, password->str) != 0 ) {
                printf("InCorrect password\n");
                printf("p: '%s' | q: '%s'\n", password->str, found_client->password->str);
                GString * message = g_string_new(NULL);
                ci->authentication_tries += 1;
                // Log the attempt
                GString * log_info = g_string_new("authentication error");
                log_to_file(ci->socket, found_client->username->str, log_info->str);
                
                if ( ci->authentication_tries >= 3 ) {
                    printf("To many login attempts\n");
                    message = g_string_append(message, "To many login attempts\n");
                    SSL_write(ci->ssl, message->str, message->len);
                    close(ci->connfd);
                    SSL_free(ci->ssl);
                    log_to_file(ci->socket, NULL, DISCONNECTED); 
                    return;
                } 
                return;
            }
            
            printf("Correct password\n");
            if ( found_client->authenticated == TRUE ) {
                printf("Already logged in from somewhere else.\n");
                char * message = "Already logged in from somewhere else.\n";
                SSL_write(ci->ssl, message, strlen(message));
                return;
            }
            // Authentication successfull, update properties for user 
            ci->authenticated = TRUE;
            ci->authentication_tries = 0;
            ci->username = found_client->username;
            ci->password = found_client->password;
            printf("Username of new client %s", ci->username->str);
            ci->socket = found_client->socket;
            // remove the old instance of the user
            g_tree_remove(client_tree, &found_client->socket);
            // remove the old instance of the user from the room he/she
            // is in and insert the new instance.
            struct chat_room * room = g_tree_search(chat_room_tree, chat_room_cmp_search,
                                                    ci->room);
            if ( room != NULL ) {
                printf("Switching rooms.\n");
                room->users = g_list_remove(room->users, found_client);
                room->users = g_list_append(room->users, ci);
            }
            GString * message = g_string_new("Authentication successfull");
            SSL_write(ci->ssl, message->str, message->len);

            log_to_file(ci->socket, ci->username->str, "authenticated");
            return;
        }
    }
    printf("Creating new account.\n");
    ci->authenticated = TRUE;
    ci->authentication_tries = 0;
    ci->username = username; // username
    ci->password = password; // password
    GString * message = g_string_new("Authentication successfull");
    SSL_write(ci->ssl, message->str, message->len);
    return;
}

/*
 * This function changes the nick name for a given user. All nick names will have the 
 * appended text '(nick)' to ensure that user names and nick names are not confused 
 * together.
 * @param nick      the new nick name 
 * @param ci        the user requesting for the nick name
 */ 
void change_nick_name(char * nick, struct client_info * ci)
{
    ci->nickname = g_string_new(nick);
    char * nickappend = " (nick)";
    ci->nickname = g_string_append(ci->nickname, nickappend);
    printf("Nick name: %s\n", ci->nickname->str);
}

void check_command (char * buf, struct client_info * ci)
{
    printf("Request : '%s'\n", buf);
    // Get list of all users
    if ( strcmp(buf, "/who\n") == 0 ) {
        char  clients[4096];
        memset(&clients, 0, sizeof(clients));
        g_tree_foreach(client_tree, build_client_list, &clients);
        SSL_write(ci->ssl, clients, strlen(clients));
        return;
    }

    if ( strcmp(buf, "/list\n") == 0 ) {
        // List all available public chat rooms 
        char chat_rooms[4096];
        memset(&chat_rooms, 0, sizeof(chat_rooms));
        g_tree_foreach(chat_room_tree, build_chat_room_list, chat_rooms);
        SSL_write(ci->ssl, chat_rooms, strlen(chat_rooms));
        return;
    } 

    if ( starts_with("/join", buf) == TRUE ) {
        int i = 5;
        while (buf[i] != '\0' && isspace(buf[i])) { i++; }
        join_chat_room(g_strchomp(&buf[i]), ci); 
        return;
    }
    
    if ( starts_with("/nick", buf) == TRUE ) {
        int i = 5;
        while (buf[i] != '\0' && isspace(buf[i])) { i++; }
        change_nick_name(g_strchomp(&buf[i]), ci);
        return;
    }

    if ( starts_with("/user", buf) == TRUE ) {
        GString * message = g_string_new(NULL);
        if ( ci->authenticated == TRUE ) {
            message = g_string_append(message, "Already authenticated\n");
            SSL_write(ci->ssl, message->str, message->len);
            return;
        }
        handle_login(buf, ci);
        return;
    }

    if ( ci->room != NULL ) {
        // preappend the nick name, user name or 'anonymous' to the message
        GString * message = g_string_new(NULL);
        //printf("username : %s \n", ci->username);
        printf("nickname : %s \n", ci->nickname->str);
        if ( ci->nickname ) {
            printf("appending nickname to message : '%s'\n", ci->nickname->str);
            message = g_string_append(message, ci->nickname->str);
        } else if ( ci->username ) {
            message = g_string_append(message, ci->username->str);
        } else {        
            message = g_string_append(message, "anonymous");
        }
        message = g_string_append(message, ": ");
        message = g_string_append(message, buf);

        broadcast(message->str, ci); // broadcast message to room
    }
}

gboolean read_from_client(gpointer key, gpointer value, gpointer data)
{
    UNUSED(key);
    struct client_info * ci = value;
    int connfd = ci->connfd;
    if ( FD_ISSET(connfd, (fd_set *)data) && ci->active == 1 ) {
        char buf[4096];
        int err = SSL_read(ci->ssl, buf, sizeof(buf) - 1);
        if ( err <= 0 ) {
            printf("Error: SSL_read, disconnecting client\n");
            
            // Remove user from chat room
            if ( ci->room ) {
                struct chat_room * cr = g_tree_search(chat_room_tree, chat_room_cmp_search, 
                                                        ci->room);
                if ( cr != NULL ) {
                    printf("Removeing user from room.\n");
                    cr->users = g_list_remove(cr->users, ci);
                }
            }
            // Close the connection to the user
            close(ci->connfd);
            SSL_shutdown(ci->ssl);
            SSL_free(ci->ssl);
            char * log_info = "disconnected";
            log_to_file(ci->socket, NULL, log_info);
            ci->active = FALSE;
            ci->authenticated = FALSE;
        } else {
            buf[err] = '\0';
            printf("Received %d chars:'%s'\n", err, buf);
            time_t now;
            ci->time = time(&now); // update the last active time
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
    room1->name = "blue";
    struct chat_room * room2 = g_new0(struct chat_room, 1);
    room2->name = "red";
    struct chat_room * room3 = g_new0(struct chat_room, 1);
    room3->name = "green";

    g_tree_insert(chat_room_tree, room1->name, room1);
    g_tree_insert(chat_room_tree, room2->name, room2);
    g_tree_insert(chat_room_tree, room3->name, room3);

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
                        ci->authenticated = FALSE;
                        ci->active = TRUE;

                        err = SSL_write(ssl, WELCOME, strlen(WELCOME)); 
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

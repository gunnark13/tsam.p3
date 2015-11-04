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
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <glib.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>

#define CONNECTED "connected"
#define DISCONNECTED "disconnected"
#define AUTHENTICATED "authenticated"
#define AUTHENTICATION_ERROR "authentication error"
#define TIMED_OUT "timed out"
#define WELCOME "Welcome"

#define PASSWORDS_FILE "passwords.ini"
#define CERTIFICATE_FILE "fd.crt"
#define PRIVATE_KEY_FILE "fd.key"

#define UNUSED(x) (void)(x)
#define MAX_CLIENTS 5 

// Struct to maintain client information.
struct client_info {
    int connfd; 
    int authentication_tries;
    gboolean authenticated;
    time_t time;
    struct sockaddr_in socket;
    SSL *ssl;
    GString * username;
    GString * nickname;
    char * room;
};

// Struct to maintain chat room information.
struct chat_room {
    char * name;
    GList * users;
};

// Trees with chat_room or client_info structs.
struct username_search {
    GString * username;
    struct sockaddr_in * key;
};

SSL_CTX *ssl_ctx;

static GTree* chat_room_tree;
static GTree* client_tree;

/* http://stackoverflow.com/questions/2262386/generate-sha256-with-openssl-and-c
*/ 
void sha256(char *string, char outputBuffer[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
}

/* This can be used to build instances of GTree that index on
   the address of a connection. */
gint sockaddr_in_cmp(const void *addr1, const void *addr2, gpointer userData)
{
    UNUSED(userData);
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

/*
 * This function compares sockaddresses for search in GTree.
 * @param addr1     The first address.
 * @param addr2     The second address.
 */
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

/*
 * This function compares two chat room names.
 * @param room_a        The first room.
 * @param room_2        The second room.
 * @return int          Positive, negative or zero.*/
gint chat_room_cmp(const void * room_a, const void * room_b, gpointer userData)
{
    UNUSED(userData);
    const char * a = room_a;
    const char * b = room_b;
    return strcmp(a, b);
}

/*
 * This function compares two chat rooms for searching in a GTree, helper since incorrect decisions
 * are made in a GTree if the return value from strcmp is used directly Negative becomes pos and vice versa.
 * @param room_a        The first room.
 * @param room_b        The second room.
 * @return int          Negative, positive or zero for decision making.
 */
int chat_room_cmp_search(const void * room_a, const void * room_b)
{
    const char * a = room_a;
    const char * b = room_b;
    int cmp = g_strcmp0(a, b);
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
    int connfd = ci->connfd;
    if ( connfd > * (int *)data ) {
        *(int *)data = connfd;
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
    int connfd = ci->connfd;
    FD_SET(connfd, (fd_set *)data);
    return FALSE;
}

/* This function closes the connection to the user and sets the user's
 * properties to the appropiate values for a logged out user.
 * @param ci The client_info struct for the user
 */ 
void close_connection(struct client_info * ci) 
{
    if ( ci->room ) {
        // Find the client's room 
        struct chat_room * cr = g_tree_search(chat_room_tree, chat_room_cmp_search, ci->room);
        if ( cr ) {
            cr->users = g_list_remove(cr->users, ci);
        }
    }
    // Remove the client from the client tree
    g_tree_remove(client_tree, &ci->socket);
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
    GString * users = data;
    users = g_string_append(users, inet_ntoa(ci->socket.sin_addr));
    gchar * port = g_strdup_printf(":%i ", ci->socket.sin_port);
    users = g_string_append(users, port);
    g_free(port);
    // Check if the user has a username
    if ( ci->username ) {
        users = g_string_append(users, ci->username->str);
    }
    // Check if the user has a room
    if ( ci->room ) {
        gchar * room = g_strdup_printf(" room='%s'", ci->room);
        users = g_string_append(users, room); 
        g_free(room);
    }
    users = g_string_append(users, "\n");
    return FALSE;
}

/*
 * This function builds the client list when requested with /list
 * @param key       The key, for tree.
 * @param value     The chat room that contains the requested list
 * @param data      The char array for concatenating the list to.i
 * @return          Boolean for GTraverseFunc
 */
gboolean build_chat_room_list (gpointer key, gpointer value, gpointer data)
{
    UNUSED(key);
    const struct chat_room * cr = value;
    GString * rooms = data;
    rooms = g_string_append(rooms, cr->name);
    rooms = g_string_append(rooms, "\n");
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

    // Remove user from his old room
    if (ci->room != NULL && strcmp(cr->name, ci->room) != 0) {
        // The client is already in a room, find that room "old_room".
        struct chat_room * old_room = g_tree_search(chat_room_tree, chat_room_cmp_search, ci->room);
        if ( old_room != NULL ) {
            old_room->users = g_list_remove(old_room->users, ci);
        }
    }

    // Register the user in the room
    ci->room = cr->name;
    if(g_list_find(cr->users, ci) == NULL) {
        // Add the client to his room unless he is there already.
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
        g_list_foreach(cr->users, write_to_client, buf);
    }
}

/* This function searches for a active user with a matching username
 * @param key       the key of the current user in the client tree
 * @param value     the value of the current user in the client tree
 * @param data      the username to be found
 */ 
gboolean find_user_by_username(gpointer key, gpointer value, gpointer data)
{
    struct client_info * ci = value;
    struct username_search * us = data;

    if ( ci->username == NULL ) {
        return FALSE;
    }
    if ( g_strcmp0(ci->username->str, us->username->str) == 0 ) {
        us->key = key;
        return TRUE;
    }
    return FALSE;
}

/* This function handles the private messages on the chat server. The function parses the 
 * user request data and finds the user the client wants to send a private message to
 * if no user is found online with the matching user name the server send back a response
 * to the client. If the user is found the private message is sent forward to the user.
 * @param message   the clients request data
 * @param ci        the client info data
 */ 
void handle_private_message(char * message, struct client_info * ci)
{
    char ** split = g_strsplit(message, "/say", 0);
    if ( !split[1] ) {
        g_strfreev(split);
        return;
    }
    char ** split_1 = g_strsplit(split[1], " ", 0);
    if ( !split_1[1] || !split_1[2] ) {
        g_strfreev(split);
        g_strfreev(split_1);
        return;
    }

    GString * user = g_string_new(g_strchomp(split_1[1]));
    GString * msg = g_string_new(g_strchomp(split_1[2]));
    g_strfreev(split);
    g_strfreev(split_1);

    struct username_search * us = g_new0(struct username_search, 1);
    us->username = g_string_new(user->str);
    g_tree_foreach(client_tree, find_user_by_username, us);
    if ( us->key ) {
        struct client_info * found_user = g_tree_search(client_tree, sockaddr_in_cmp_search, 
                us->key);
        if ( found_user ) {
            gchar * private_message = g_strdup_printf("Private message from: %s\nMessage: ", ci->username->str); 
            msg = g_string_prepend(msg, private_message);
            g_free(private_message);
            // Send the private message to the user 
            SSL_write(found_user->ssl, msg->str, msg->len);
        }
    } else { 
        GString * response = g_string_new("User not found.\n");
        SSL_write(ci->ssl, response->str, response->len);
        g_string_free(response, TRUE);
    }
    g_string_free(us->username, TRUE);
    g_free(us);
    g_string_free(user, TRUE);
    g_string_free(msg, TRUE);
}

/* This function handles the login into the chat server, the function parses the user data 
 * sent and hashes the user's password. It checks first if there is another user active with
 * the same username logged on, if so then the user is logged on from somewhere else. If the 
 * user is not found online the password file is checked if user exists there. If no user 
 * exists the user is created other wise password is checked if it matches.
 * @param buf   the request sent by the user 
 * @param ci    the client info struct data
 */ 
void handle_login(char * buf, struct client_info * ci)
{
    // Splitting the request string to access the user name and password fields
    char ** split_0 = g_strsplit(buf, "/user ", 0);
    if ( !split_0[1] ) {
        g_strfreev(split_0);
        return;
    }
    char ** split_1 = g_strsplit(split_0[1], "/password ", 0);
    if ( !split_1[0] || !split_1[1] ) {
        g_strfreev(split_0);
        g_strfreev(split_1);
        return;
    }
    GString * username = g_string_new(g_strchomp(split_1[0]));
    GString * password = g_string_new(g_strchomp(split_1[1]));
    g_strfreev(split_0);
    g_strfreev(split_1);

    // Hash the password string from the user
    char hash_p[4096], salt[4096];
    memset(&salt, 0, sizeof(salt));
    strcat(salt, "DvoS8URnIP+2%ts%AeyLenlbin^cLxb%~vegmcNEDRvjOPSB4*ItTK0BVDMK");
    strcat(salt, password->str);
    sha256(salt, hash_p);

    // Find a active user with the same user name
    struct username_search * us = g_new0(struct username_search, 1);
    us->username = g_string_new(username->str);
    g_tree_foreach(client_tree, find_user_by_username, us);
    g_string_free(us->username, TRUE);
    g_free(us);

    // Check if there is no other user with the given username logged on
    if ( us->key == NULL ) {
        // Check if we find the username in the password file and the passwords match
        gchar *passwd_attempt = g_base64_encode((const guchar *)hash_p, strlen(hash_p));
        gchar *passwd_file = NULL;
        // Load the key file
        GKeyFile * keyfile = g_key_file_new();
        if ( g_key_file_load_from_file(keyfile, PASSWORDS_FILE, G_KEY_FILE_NONE, NULL) == TRUE ) {
            passwd_file = g_key_file_get_string(keyfile, "passwords", username->str, NULL);
        }

        // Check if the is no matching user
        if ( passwd_file == NULL ) {
            // Insert the hashed password to the password file
            g_key_file_set_string(keyfile, "passwords", username->str, passwd_attempt);
            gsize length;
            gchar *keyfile_string = g_key_file_to_data(keyfile, &length, NULL);
            FILE *f = fopen(PASSWORDS_FILE, "a");
            if ( f ) {
                fprintf(f, "%s\n", keyfile_string);
                fclose(f);
            };
            g_free(keyfile_string);
            // Update the client properies
            ci->authentication_tries = 0;
            ci->authenticated = TRUE;
            ci->username = g_string_new(username->str);
            GString * message = g_string_new("New user created successfully");
            SSL_write(ci->ssl, message->str, message->len);
            // Log to file
            log_to_file(ci->socket, ci->username->str, AUTHENTICATED);
            g_string_free(message, TRUE);

            // else: cheak if password is correct and user name is matching 
        } else if ( g_strcmp0(passwd_attempt, passwd_file) == 0 ) {
            ci->authentication_tries = 0;
            ci->authenticated = TRUE;
            ci->username = g_string_new(username->str);
            GString * message = g_string_new("Authentication successfull");
            SSL_write(ci->ssl, message->str, message->len);
            // Log to file
            GString * log_info = g_string_new(AUTHENTICATED);
            log_to_file(ci->socket, ci->username->str, log_info->str);
            g_string_free(message, TRUE);
            g_string_free(log_info, TRUE);

            // else: password is incorrect
        } else {
            GString * message = g_string_new("Authentication failed.\n");
            SSL_write(ci->ssl, message->str, message->len); 
            ci->authentication_tries += 1;
            // Log the attempt
            log_to_file(ci->socket, username->str, AUTHENTICATION_ERROR);
            // Close the connection if the authentication tries exceed 3 times.
            if ( ci->authentication_tries >= 3 ) {
                message = g_string_append(message, "To many login attempts\n");
                SSL_write(ci->ssl, message->str, message->len);
                close_connection(ci);
                log_to_file(ci->socket, NULL, DISCONNECTED);
            } 
            g_string_free(message, TRUE);
        }
        g_free(passwd_attempt);
        g_free(passwd_file);
        g_key_file_free(keyfile);

        // There was some user found with the same username
    } else {
        GString * message = g_string_new("Already logged in from somewhere else.\n");
        SSL_write(ci->ssl, message->str, message->len);
        g_string_free(message, TRUE);
    }
    g_string_free(username, TRUE);
    g_string_free(password, TRUE);
}

/* This function changes the nick name for a given user. All nick names will have the 
 * appended text '(nick)' to ensure that user names and nick names are not confused 
 * together.
 * @param nick      the new nick name 
 * @param ci        the user requesting for the nick name
 */ 
void change_nick_name(char * nick, struct client_info * ci)
{
    GString * g_nick = g_string_new(nick);
    char * nickappend = " (nick)";
    g_nick = g_string_append(g_nick, nickappend);
    if ( ci->nickname ) {
        ci->nickname = g_string_assign(ci->nickname, g_nick->str);    
    } else {
        ci->nickname = g_string_new(g_nick->str);
    }
    g_string_free(g_nick, TRUE);
}

/* This function checks for commands from the client, commands start with '/'
 * @param buf       The message buffer.
 * @param ci        The client_info struct.
 */
void check_command (char * buf, struct client_info * ci)
{
    // Get list of all users
    if ( strcmp(buf, "/who\n") == 0 ) {
        GString * clients = g_string_new(NULL);
        g_tree_foreach(client_tree, build_client_list, clients);
        SSL_write(ci->ssl, clients->str, clients->len);
        g_string_free(clients, TRUE); 
        return;
    }

    if ( strcmp(buf, "/list\n") == 0 ) {
        // List all available public chat rooms 
        GString * chat_rooms = g_string_new(NULL);
        g_tree_foreach(chat_room_tree, build_chat_room_list, chat_rooms);
        SSL_write(ci->ssl, chat_rooms->str, chat_rooms->len);
        g_string_free(chat_rooms, TRUE); 
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
        if ( ci->authenticated == TRUE ) {
            GString * message = g_string_new(NULL);
            message = g_string_append(message, "Already authenticated\n");
            SSL_write(ci->ssl, message->str, message->len);
            g_string_free(message, TRUE); 
            return;
        }
        handle_login(buf, ci);
        return;
    }

    if ( starts_with("/say", buf) == TRUE ) {
        if ( ci->authenticated == FALSE ) {
            GString * message = g_string_new("Login to send private messages.\n");
            SSL_write(ci->ssl, message->str, message->len);
            g_string_free(message, TRUE);
            return;
        }
        handle_private_message(buf, ci);
        return;
    }

    if ( ci->room != NULL ) {
        // preappend the nick name, user name or 'anonymous' to the message
        GString * message = g_string_new(NULL);
        if ( ci->nickname ) {
            message = g_string_append(message, ci->nickname->str);
        } else if ( ci->username ) {
            message = g_string_append(message, ci->username->str);
        } else {        
            message = g_string_append(message, "anonymous");
        }
        message = g_string_append(message, ": ");
        message = g_string_append(message, buf);

        broadcast(message->str, ci); // broadcast message to room
        g_string_free(message, TRUE); 
    }
}
/*
 * This funcion reads from a client, on failure connection is closed.
 * @param key       The key for GTree, unused.
 * @param value     The client_info struct.
 * @param data      The fd_set.
 * @return          Boolean for GTraverseFunc.
 */
gboolean read_from_client(gpointer key, gpointer value, gpointer data)
{
    UNUSED(key);
    struct client_info * ci = value;
    int connfd = ci->connfd;
    if ( FD_ISSET(connfd, (fd_set *)data) ) {
        char buf[4096];
        int err = SSL_read(ci->ssl, buf, sizeof(buf) - 1);
        if ( err <= 0 ) {
            // Remove user from chat room
            if ( ci->room ) {
                struct chat_room * cr = g_tree_search(chat_room_tree, chat_room_cmp_search, 
                        ci->room);
                if ( cr != NULL ) {
                    cr->users = g_list_remove(cr->users, cr);
                }
            }
            // Close the connection to the user
            close_connection(ci);
            log_to_file(ci->socket, NULL, DISCONNECTED);
        } else {
            buf[err] = '\0';
            time_t now;
            ci->time = time(&now); // update the last active time
            check_command(buf, ci);
        }
    }
    return FALSE;
}

/*This function checks for a client timeout.
 * @param key       The key for GTree, unused.
 * @param value     The client_info struct
 * @param data      Unused*/
gboolean timeout_client(gpointer key, gpointer value, gpointer data)
{
    UNUSED(key);
    UNUSED(data);
    struct client_info * ci = value;
    time_t now;
    int client_connection_sec = (int) difftime(time(&now), ci->time);
    if ( client_connection_sec >= 15 ) {
        GString * message = g_string_new("Timeout. Closed the connection.\n");
        SSL_write(ci->ssl, message->str, message->len);
        if ( ci->username ) {
            log_to_file(ci->socket, ci->username->str, TIMED_OUT);
        } else {
            log_to_file(ci->socket, NULL, TIMED_OUT);
        }
        close_connection(ci);
        g_string_free(message, TRUE);
    }
    return FALSE;
}

/* This function cleans and frees the memmory for a given chat_room
 * data in the chat_room_tree
 * @param data  pointer to the chat_room to be destroyed
 */ 
void chat_room_tree_value_destroy(gpointer data)
{
    struct chat_room * room = (struct chat_room *) data;
    GList * rooms = room->users;
    while(rooms != NULL){
        GList* next_room = rooms->next;
        room->users = g_list_delete_link(room->users, rooms);
        rooms = next_room;
    }
    g_free(room);
}

/* This function cleans and frees the memmory for a given client_info
 * data in the client_tree
 * @param data  pointer to the client info to be destroyed
 */ 
void client_tree_value_destroy(gpointer data)
{
    struct client_info* ci = (struct client_info *) data;
    SSL_shutdown(ci->ssl);
    close(ci->connfd);
    SSL_free(ci->ssl);
    g_string_free(ci->username, TRUE);
    g_string_free(ci->nickname, TRUE);
    g_free(ci);
}

/* This function gets called when the server exits.
 * When CTRL-C is pressed
 */
void sigint_handler(int sig)
{
    UNUSED(sig);    
    g_tree_destroy(chat_room_tree);
    g_tree_destroy(client_tree);
    SSL_CTX_free(ssl_ctx);
    RAND_cleanup();
    ENGINE_cleanup();
    CONF_modules_unload(1);
    CONF_modules_free();
    EVP_cleanup();
    ERR_free_strings();
    ERR_remove_state(0);
    CRYPTO_cleanup_all_ex_data();
    exit(0);
}

/* Server main function.
 * @param argc      The argument count.
 * @param **argv    The argument vector.
 * @return          Exit code.
 */
int main(int argc, char **argv)
{
    // Install the sigint handler
    signal(SIGINT, sigint_handler); /* ctrl-c */
    printf("Number of arguments %d\n", argc);
    printf("Portnumber : %s\n", argv[1]);

    SSL_library_init(); /* load encryption & hash algorithms for SSL */                
    SSL_load_error_strings(); /* load the error strings for good error reporting */
    ssl_ctx = SSL_CTX_new(SSLv3_method()); // initilize ssl context
    int my_port = atoi(argv[1]);

    struct sockaddr_in server, client;

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
    client_tree = g_tree_new_full(sockaddr_in_cmp, NULL, NULL, client_tree_value_destroy);
    chat_room_tree = g_tree_new_full(chat_room_cmp , NULL, NULL, chat_room_tree_value_destroy);

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

    for (;;) {
        fd_set rfds;
        struct timeval tv;
        int retval;

        /* Check whether there is data on the socket fd. */
        FD_ZERO(&rfds);
        highestConnfd = sockfd;
        FD_SET(sockfd, &rfds);

        g_tree_foreach(client_tree, set_highest_connfd, &highestConnfd);
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

                        err = SSL_write(ssl, WELCOME, strlen(WELCOME)); 
                        if ( err == -1 ) {
                            printf("Error: SSL_write\n");
                        } else {
                            g_tree_insert(client_tree, &ci->socket, ci);
                            log_to_file(client, NULL, CONNECTED);
                        }
                    }
                }
            }
            g_tree_foreach(client_tree, read_from_client, &rfds);
        } else {
            fprintf(stdout, "No message in five seconds.\n");
            fflush(stdout);
        }
        g_tree_foreach(client_tree, timeout_client, &rfds);
    }
}

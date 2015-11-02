/* A UDP echo server with timeouts.
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
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>
#include <arpa/inet.h>

/* Secure socket layer headers */
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* For nicer interaction, we use the GNU readline library. */
#include <readline/readline.h>
#include <readline/history.h>

#define CERTIFICATE_FILE "fd.crt"
#define PRIVATE_KEY_FILE "fd.key"
#define CA_PEM "ca.pem"

/* This variable is 1 while the client is active and becomes 0 after
   a quit command to terminate the client and to clean up the
   connection. */
static int active = 1;


/* To read a password without echoing it to the console.
 *
 * We assume that stdin is not redirected to a pipe and we won't
 * access tty directly. It does not make much sense for this program
 * to redirect input and output.
 *
 * This function is not safe to termination. If the program
 * crashes during getpasswd or gets terminated, then echoing
 * may remain disabled for the shell (that depends on shell,
 * operating system and C library). To restore echoing,
 * type 'reset' into the sell and press enter.
 */
void getpasswd(const char *prompt, char *passwd, size_t size)
{
    struct termios old_flags, new_flags;

    /* Clear out the buffer content. */
    memset(passwd, 0, size);

    /* Disable echo. */
    tcgetattr(fileno(stdin), &old_flags);
    memcpy(&new_flags, &old_flags, sizeof(old_flags));
    new_flags.c_lflag &= ~ECHO;
    new_flags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &new_flags) != 0) {
        perror("tcsetattr");
        exit(EXIT_FAILURE);
    }

    printf("%s", prompt);
    fgets(passwd, size, stdin);

    /* The result in passwd is '\0' terminated and may contain a final
     * '\n'. If it exists, we remove it.
     */
    if (passwd[strlen(passwd) - 1] == '\n') {
        passwd[strlen(passwd) - 1] = '\0';
    }

    /* Restore the terminal */
    if (tcsetattr(fileno(stdin), TCSANOW, &old_flags) != 0) {
        perror("tcsetattr");
        exit(EXIT_FAILURE);
    }
}



/* If someone kills the client, it should still clean up the readline
 * library, otherwise the terminal is in a inconsistent state. We set
 * active to 0 to get out of the loop below. Also note that the select
 * call below may return with -1 and errno set to EINTR. Do not exit
 * select with this error.
 */
void sigint_handler(int signum) {
    active = 0;

    /* We should not use printf inside of signal handlers, this is not
     * considered safe. We may, however, use write() and fsync(). */
    write(STDOUT_FILENO, "Terminated.\n", 12);
    fsync(STDOUT_FILENO);
}

/* The next two variables are used to access the encrypted stream to
 * the server. The socket file descriptor server_fd is provided for
 * select (if needed), while the encrypted communication should use
 * server_ssl and the SSL API of OpenSSL.
 */
static int server_fd;
static SSL *server_ssl;

/* This variable shall point to the name of the user. The initial value
   is NULL. Set this variable to the username once the user managed to be
   authenticated. */
static char *user;

/* This variable shall point to the name of the chatroom. The initial
   value is NULL (not member of a chat room). Set this variable whenever
   the user changed the chat room successfully. */
static char *chatroom;

/* This prompt is used by the readline library to ask the user for
 * input. It is good style to indicate the name of the user and the
 * chat room he is in as part of the prompt. */
static char *prompt;



/* When a line is entered using the readline library, this function
   gets called to handle the entered line. Implement the code to
   handle the user requests in this function. The client handles the
   server messages in the loop in main(). */
void readline_callback(char *line)
{
    char buffer[256];
    if (NULL == line) {
        rl_callback_handler_remove();
        active = 0;
        return;
    }
    if (strlen(line) > 0) {
        add_history(line);
    }
    if ((strncmp("/bye", line, 4) == 0) ||
            (strncmp("/quit", line, 5) == 0)) {
        
        printf("Now exiting...\n");

        rl_callback_handler_remove();
        active = 0;
        return;
    }
    if (strncmp("/game", line, 5) == 0) {
        /* Skip whitespace */
        int i = 4;
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /game username\n",
                    29);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
        /* Start game */
        return;
    }
    if (strncmp("/join", line, 5) == 0) {
        int i = 5;
        /* Skip whitespace */
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /join chatroom\n", 22);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
        char *chatroom = strdup(&(line[i]));
        /* Process and send this information to the server. */
        snprintf(buffer, 255, "%s\n", line);
        int err = SSL_write(server_ssl, buffer, strlen(buffer));
        if ( err == -1 ) {
            printf("Error requesting joining room\n");
        }
        /* Maybe update the prompt. */
        if ( !prompt ) {
            printf("prompt is null\n");
        }
        free(prompt);
        prompt = NULL; /* What should the new prompt look like? */
        rl_set_prompt(prompt);
        return;
    }
    if (strncmp("/list", line, 5) == 0) {
        /* Query all available chat rooms */
        snprintf(buffer, 255, "%s\n", line);
        int err = SSL_write(server_ssl, buffer, strlen(buffer));
        if ( err == -1 ) {
            printf("Error requesting for list\n");
            return;
        } 

        char chat_rooms[4096];
        err = SSL_read(server_ssl, chat_rooms, sizeof(chat_rooms));
        if ( err == -1 ) {
            printf("Error getting chat rooms");
            return; 
        } else {
            chat_rooms[err] = '\0';
            printf("Available rooms:\n%s\n", chat_rooms);
        }   
        return;
    }
    if (strncmp("/roll", line, 5) == 0) {
        /* roll dice and declare winner. */
        return;
    }
    if (strncmp("/say", line, 4) == 0) {
        /* Skip whitespace */
        int i = 4;
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /say username message\n",
                    29);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
        /* Skip whitespace */
        int j = i+1;
        while (line[j] != '\0' && isgraph(line[j])) { j++; }
        if (line[j] == '\0') {
            write(STDOUT_FILENO, "Usage: /say username message\n",
                    29);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
        char *receiver = strndup(&(line[i]), j - i - 1);
        char *message = strndup(&(line[j]), j - i - 1);

        /* Send private message to receiver. */

        return;
    }
    if (strncmp("/user", line, 5) == 0) {
        int i = 5;
        /* Skip whitespace */
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /user username\n", 22);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
        char *new_user = strdup(&(line[i]));
        char passwd[48];
        getpasswd("Password: ", passwd, 48);

        /* Process and send this information to the server. */
        printf("User: %s\nPassword: %s\n", new_user, passwd);
        strcat(line, "\n/password ");
        strcat(line, passwd);
        strcat(line, "\n");

        printf("Line:%s\n", line);
        snprintf(buffer, 255, "%s\n", line);
        int err =SSL_write(server_ssl, buffer, sizeof(buffer));
        if ( err == -1 ) {
            printf("Error sending login info.\n");
        }

        /* Maybe update the prompt. */
        free(prompt);
        prompt = NULL; /* What should the new prompt look like? */
        rl_set_prompt(prompt);
        return;
    }
    if (strncmp("/nick", line, 5 ) == 0 ) {
        int i = 5;
        /* Skip whitespaces */
        while(line[i] != '\0' && isspace(line[i])){ i++; }
        if(line[i] == '\0' ){
            write(STDOUT_FILENO, "Usage : /nick nickname \n", 22);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
        char *new_nickname = strdup(&(line[i]));

        /* Process send the new nickname to the server */
        snprintf(buffer, 255, "%s\n", line);
        int err = SSL_write(server_ssl, buffer, strlen(buffer));
        if( err == -1 ) {
            printf("Error setting this nickname.\n");
        }
        if( !prompt ) {
            printf("prompt is null \n");
        }
        free(prompt);
        prompt = NULL;
        rl_set_prompt(prompt);
        return;
    }
    if (strncmp("/who", line, 4) == 0) {
        /* Query all available users */
        snprintf(buffer, 255, "%s\n", line);
        int err = SSL_write(server_ssl, buffer, strlen(buffer));
        if ( err == -1 ) {
            printf("Error requesting for users\n");
        } 
        return;
    }
    /* Sent the buffer to the server. */
    snprintf(buffer, 255, "%s\n", line);
    // write(STDOUT_FILENO, buffer, strlen(buffer));
    SSL_write(server_ssl, buffer, strlen(buffer));
    fsync(STDOUT_FILENO);
}


int main(int argc, char **argv)
{
    printf("Number of parameters : %d\n", argc);
    int i = 0;
    for (; argv[i] != NULL; i++) {
        printf("argv[%d] : %s\n", i, argv[i]);
    }

    int server_port = atoi(argv[2]);
    struct sockaddr_in server;
    char buf[4096];

    int err;

    /* Initialize OpenSSL */
    SSL_library_init(); /* load encryption & hash algorithms for SSL */                
    SSL_load_error_strings(); /* load the error strings for good error reporting */
    SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv3_client_method());
    /* We may want to use a certificate file if we self sign the
     * certificates using SSL_use_certificate_file(). If available,
     * a private key can be loaded using
     * SSL_CTX_use_PrivateKey_file(). The use of private keys with
     * a server side key data base can be used to authenticate the
     * client.
     */
    if ( !ssl_ctx ) {
        printf("Error ssl_ctx\n");
        exit(1);
    }


    if ( !SSL_CTX_load_verify_locations(ssl_ctx, CA_PEM, NULL) ) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ssl_ctx, 1);

    /* Create and set up a listening socket. The sockets you
     * create here can be used in select calls, so do not forget
     * them.
     */
    server_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( server_fd == -1 ) {
        printf("Error setting up TCP socket");
        exit(1);
    }

    printf("Server_fd : %d\n", server_fd);
    printf("Port : %d\n", server_port);

    memset(&server, '\0', sizeof(server));
    server.sin_family      = AF_INET;
    server.sin_port        = htons(server_port);  /* Server Port number */
    server.sin_addr.s_addr = inet_addr("127.0.0.1"); /* Server IP */
    err = connect(server_fd, (struct sockaddr*) &server, sizeof(server));
    if ( err == -1 ) {
        printf("Error establishing a TCP/IP connection to the SSL client");
        exit(1);
    }

    server_ssl = SSL_new (ssl_ctx);
    if ( !server_ssl ) {
        printf("Error : ssl_new\n");
        exit(1);
    }
    
    int j = 0;
    printf("%d\n", j++);

    /* Use the socket for the SSL connection. */
    SSL_set_fd(server_ssl, server_fd);

    printf("%d\n", j++);


    /* Now we can create BIOs and use them instead of the socket.
     * The BIO is responsible for maintaining the state of the
     * encrypted connection and the actual encryption. Reads and
     * writes to sock_fd will insert unencrypted data into the
     * stream, which even may crash the server.
     */

    /* Set up secure connection to the chatd server. */
    err = SSL_connect(server_ssl);
    if ( err == -1 ) {
        printf("Error perform SSL Handshake on the SSL client");
        exit(1);
    }

    printf("%d\n", j++);
    /* Read characters from the keyboard while waiting for input.
    */
    /* Get the server's certificate */
    X509 *server_cert = SSL_get_peer_certificate (server_ssl);

    if ( server_cert ) {
        printf ("Server certificate:\n");

        char *str = X509_NAME_oneline(X509_get_subject_name(server_cert),0,0);
        if ( !str ) {
            printf("get subject name");
            exit(1);
        }
        printf ("\t subject: %s\n", str);
        free (str);

        str = X509_NAME_oneline(X509_get_issuer_name(server_cert),0,0);
        if ( !str ) {
            printf("get issuer name");
            exit(1);
        }
        printf ("\t issuer: %s\n", str);
        free(str);

        X509_free (server_cert); 
    } else {
        printf("The SSL server does not have certificate.\n");
    }
    printf("%d\n", j++);

    memset(&buf, 0, sizeof(buf));
    err = SSL_read(server_ssl, buf, sizeof(buf) - 1);
    if ( err == -1 ) {
        printf("Error SSL_read\n");
        exit(1);
    }
    
    buf[err] = '\0';
    printf("%s\n", buf);

    listen(server_fd, 1);

    /* Read characters from the keyboard while waiting for input. */
    prompt = strdup("> ");
    rl_callback_handler_install(prompt, (rl_vcpfunc_t*) &readline_callback);
    while (active) {
        fd_set rfds;
        struct timeval timeout;

        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        FD_SET(server_fd, &rfds);

        int highest_fd = server_fd;
        if ( highest_fd < STDIN_FILENO ) {
            highest_fd = STDIN_FILENO;
        }

        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        int r = select(highest_fd + 1, &rfds, NULL, NULL, &timeout);
        if (r < 0) {
            if (errno == EINTR) {
                /* This should either retry the call or
                   exit the loop, depending on whether we
                   received a SIGTERM. */
                continue;
            }
            /* Not interrupted, maybe nothing we can do? */
            perror("select()");
            break;
        }
        if (r == 0) {
            write(STDOUT_FILENO, "No message?\n", 12);
            fsync(STDOUT_FILENO);
            /* Whenever you print out a message, call this
               to reprint the current input line. */
            rl_redisplay();
            continue;
        }
        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            rl_callback_read_char();
        } 
        if ( FD_ISSET(server_fd, &rfds) ) {
            memset(&buf, 0, sizeof(buf));
            int err = SSL_read(server_ssl, buf, sizeof(buf));
            if ( err == -1 ) {
                printf("Error reading from server!\n"); 
            } else {
                buf[err] = '\0';
                printf("%s\n", buf);
            }
        }
        /* Handle messages from the server here! */
    }
    /* replace by code to shutdown the connection and exit
       the program. */

    /* Shutdown the client side of the SSL connection */
    err = SSL_shutdown(server_ssl);
    /* Terminate communication on a socket */
    err = close(server_fd);
    /* Free the SSL structure */
    SSL_free(server_ssl);
    /* Free the SSL_CTX structure */
    SSL_CTX_free(ssl_ctx);
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_NAME 32
#define MAX_DATA 512
#define BUF_SIZE 580
#define MAX_COMMAND_LEN 32

// 0 to 12
typedef enum {
    LOGIN = 0,
    LO_ACK,
    LO_NAK,
    EXIT,
    JOIN,
    JN_ACK,
    JN_NAK,
    LEAVE_SESS,
    NEW_SESS,
    NS_ACK,
    MESSAGE,
    QUERY,
    QU_ACK
} message_t;

struct message {
    unsigned int  type;
    unsigned int  size;
    unsigned char source[MAX_NAME];
    unsigned char data[MAX_DATA];
};

// Serialize: "type:size:source:data"
// data is copied last since it may contain ':'
static int message_to_string(const struct message *m, char *dest)
{
    memset(dest, 0, BUF_SIZE);
    // write type:size:source: prefix first
    int prefix_len = snprintf(dest, BUF_SIZE, "%d:%d:%s:", m->type, m->size, (char *)m->source);
    // then copy data raw (may contain colons)
    memcpy(dest + prefix_len, m->data, m->size);

    return prefix_len + m->size; 
}

// Deserialize: "type:size:source:data"
static void parse_message(const char *src, struct message *m)
{
    memset(m, 0, sizeof *m); //memset(Starting address of memory to be filled, Value to be filled, size_t n)

    char tmp[BUF_SIZE];
    strncpy(tmp, src, BUF_SIZE - 1);

    char *tok;
    // type
    tok = strtok(tmp, ":");
    if (!tok) return;
    m->type = atoi(tok);

    // size
    tok = strtok(NULL, ":");
    if (!tok) return;
    m->size = atoi(tok);

    // source
    tok = strtok(NULL, ":");
    if (!tok) return;
    strncpy((char *)m->source, tok, MAX_NAME - 1);

    // data – may contain ':', so skip past 3 colons in original string
    // and copy directly rather than using strtok
    const char *p = src;
    int colons = 0;
    while (*p && colons < 3) {
        if (*p == ':') colons++;
        p++;
    }
    memcpy(m->data, p, m->size);
}

static void print_message(const struct message *m)
{
    // incoming chat message: "source: text"
    printf("%s: %s\n", (char *)m->source, (char *)m->data);
}

static int send_through(int sock, message_t type, const char *source, const char *data)
{
    struct message m;
    memset(&m, 0, sizeof m);
    m.type = type;
    strncpy((char *)m.source, source, MAX_NAME - 1);
    strncpy((char *)m.data,   data,   MAX_DATA - 1);
    m.size = strlen((char *)m.data);

    char buf[BUF_SIZE];
    int len = message_to_string(&m, buf);
    if (send(sock, buf, len, 0) == -1) { //send(int socket, const void *buffer, size_t length, int flags)
        perror("send");
        return 1;
    }
    return 0;
}

// track everything about the client's current state
static int  client_sock   = -1;
static int  is_in_session = 0;
static char cur_session[MAX_NAME] = "";
static char cur_name[MAX_NAME]    = "";
static int  logged_in     = 0;

// Receive one packet from server synchronously.
// Only used for login — all other responses come through handle_server()
static int recv_response(struct message *m)
{
    char buf[BUF_SIZE];
    memset(buf, 0, sizeof buf);
    int n = recv(client_sock, buf, BUF_SIZE - 1, 0); //recv(int sockfd, void *buf, int len, int flags)
    if (n <= 0) { //recv() returns the number of bytes actually read into the buffer, or -1 on error
        printf("Failed to receive response from server.\n");
        return 1;
    }
    buf[n] = '\0';
    parse_message(buf, m);
    return 0;
}

// /login <name> <pass> <server_ip> <server_port>
static int login(const char *name, const char *pass,
                 const char *server_ip, const char *server_port)
{
    if (logged_in) {
        printf("Already logged in as %s\n", cur_name);
        return 1;
    }

    // hints: fill this in to tell getaddrinfo what kind of connection you want
    struct addrinfo hints, *servinfo, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;   // accept IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP

    int rv;
    // gives linked list where each node is one possible way to reach the server
    if ((rv = getaddrinfo(server_ip, server_port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // one hostname/IP can map to multiple addresses — IPv4, IPv6, different protocols.
    // getaddrinfo gives all of them so we try each one until a connection succeeds.
    for (p = servinfo; p != NULL; p = p->ai_next) {
        client_sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (client_sock == -1) { perror("socket"); continue; }
        if (connect(client_sock, p->ai_addr, p->ai_addrlen) == -1) {
            close(client_sock);
            client_sock = -1;
            perror("connect");
            continue;
        }
        break;
    }
    freeaddrinfo(servinfo); // free the linked list once done

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect to %s:%s\n", server_ip, server_port);
        client_sock = -1;
        return 1;
    }

    // send LOGIN packet — source=name, data=password
    send_through(client_sock, LOGIN, name, pass);

    // wait for LO_ACK / LO_NAK synchronously before entering select loop.
    // login is a special case: nothing else can happen until we know if it succeeded.
    struct message resp;
    if (recv_response(&resp)) {
        close(client_sock);
        client_sock = -1;
        return 1;
    }

    if (resp.type == LO_ACK) {
        strncpy(cur_name, name, MAX_NAME - 1);
        logged_in = 1;
        printf("Successfully logged in as %s\n", cur_name);
        return 0;
    } else {
        // LO_NAK — data contains the reason
        printf("Login failed: %s\n", (char *)resp.data);
        close(client_sock);
        client_sock = -1;
        return 1;
    }
}

// /logout
static int logout(void)
{
    if (!logged_in) {
        printf("Not logged in yet.\n");
        return 1;
    }

    // send EXIT packet — no response expected
    send_through(client_sock, EXIT, cur_name, "");
    close(client_sock);
    client_sock   = -1;
    logged_in     = 0;
    is_in_session = 0;
    memset(cur_name, 0, sizeof cur_name);
    memset(cur_session, 0, sizeof cur_session);
    printf("Logged out.\n");
    return 0;
}

// /joinsession <session_id>
static int join_session(const char *session_id)
{
    if (!logged_in)    { printf("Not logged in.\n"); return 1; }
    if (is_in_session) { printf("Already in session '%s'. /leavesession first.\n",
                                cur_session); return 1; }

    // send JOIN — data carries the session ID we want to join
    // JN_ACK / JN_NAK will arrive asynchronously via handle_server()
    send_through(client_sock, JOIN, cur_name, session_id);
    return 0;
}

// /leavesession
static int leave_session(void)
{
    if (!logged_in)    { printf("Not logged in.\n"); return 1; }
    if (!is_in_session){ printf("Not in a session.\n"); return 1; }

    // send LEAVE_SESS — no response expected from server
    send_through(client_sock, LEAVE_SESS, cur_name, "");
    printf("Left session %s\n", cur_session);
    is_in_session = 0;
    memset(cur_session, 0, sizeof cur_session);
    return 0;
}

// /createsession <session_id>-- create new conference session and join it
static int create_session(const char *session_id)
{
    if (!logged_in)    { printf("Not logged in.\n"); return 1; }
    if (is_in_session) { printf("Already in session '%s'. /leavesession first.\n",
                                cur_session); return 1; }

    // send NEW_SESS — data carries the session ID to create
    // NS_ACK / JN_NAK will arrive asynchronously via handle_server()
    send_through(client_sock, NEW_SESS, cur_name, session_id);
    return 0;
}

// /list--get the list of the connected clients and available sessions
static int list(void)
{
    if (!logged_in) { printf("Not logged in.\n"); return 1; }

    // send QUERY — QU_ACK will arrive asynchronously via handle_server()
    send_through(client_sock, QUERY, cur_name, "");
    return 0;
}

// /quit
static int quit(void)
{
    if (logged_in) logout();
    printf("You have quit successfully.\n");
    exit(0);
}

// plain text to MESSAGE packet to current session
static int send_message(const char *text)
{
    if (!logged_in)    { printf("Not logged in.\n"); return 1; }
    if (!is_in_session){ printf("Not in a session.\n"); return 1; }

    // send MESSAGE — source=cur_name, data=chat text
    send_through(client_sock, MESSAGE, cur_name, text);
    return 0;
}

// parse and dispatch one line of user input from stdin
static void handle_stdin(void)
{
    char command[MAX_COMMAND_LEN];
    char session_id[MAX_NAME];
    char name[MAX_NAME];
    char pass[MAX_DATA];
    char server_ip[64];
    char server_port[16];

    // read first token (the command word)
    if (scanf("%s", command) != 1) return;

    if (strcmp(command, "/login") == 0) {
        scanf(" %s %s %s %s", name, pass, server_ip, server_port);
        login(name, pass, server_ip, server_port);

    } else if (strcmp(command, "/logout") == 0) {
        logout();

    } else if (strcmp(command, "/joinsession") == 0) {
        scanf(" %s", session_id);
        join_session(session_id);

    } else if (strcmp(command, "/leavesession") == 0) {
        leave_session();

    } else if (strcmp(command, "/createsession") == 0) {
        scanf(" %s", session_id);
        create_session(session_id);

    } else if (strcmp(command, "/list") == 0) {
        list();

    } else if (strcmp(command, "/quit") == 0) {
        quit();

    } else {
        // not a command — treat as chat message to current session
        if (!logged_in) {
            printf("Not logged in.\n");
            // consume rest of line so it doesn't linger in stdin buffer
            char discard[MAX_DATA];
            fgets(discard, sizeof discard, stdin);
            return;
        }
        char msg_buf[MAX_DATA];
        strncpy(msg_buf, command, MAX_DATA - 1);
        int offset = strlen(msg_buf);
        // read the rest of the line and append it
        fgets(msg_buf + offset, MAX_DATA - offset, stdin);
        // strip trailing newline
        msg_buf[strcspn(msg_buf, "\n")] = '\0';
        send_message(msg_buf);
    }
}

// handle one incoming packet from the server
static void handle_server(void)
{
    char buf[BUF_SIZE];
    memset(buf, 0, sizeof buf);

    int n = recv(client_sock, buf, BUF_SIZE - 1, 0);
    if (n <= 0) {
        if (n == 0)
            printf("\n[Server closed the connection]\n");
        else
            perror("recv");
        // clean up state
        close(client_sock);
        client_sock   = -1;
        logged_in     = 0;
        is_in_session = 0;
        return;
    }
    buf[n] = '\0';

    struct message m;
    parse_message(buf, &m);

    switch (m.type) {

    case MESSAGE:
        // incoming chat message from another user — data = text
        print_message(&m);
        break;

    case JN_ACK:
        // server confirmed join — data = session ID we joined
        strncpy(cur_session, (char *)m.data, MAX_NAME - 1);
        is_in_session = 1;
        printf("Successfully joined session: %s\n", cur_session);
        break;

    case JN_NAK:
        // server rejected join — data = reason
        printf("Could not join session: %s\n", (char *)m.data);
        break;

    case NS_ACK:
        // server confirmed session created — data = session ID
        strncpy(cur_session, (char *)m.data, MAX_NAME - 1);
        is_in_session = 1;
        printf("Successfully created session: %s\n", cur_session);
        break;

    case QU_ACK:
        // response to /list — data = formatted list of users and sessions
        printf("Users and sessions:\n%s\n", (char *)m.data);
        break;

    case LO_NAK:
        // server rejected login after connection (e.g. duplicate login)
        printf("Server rejected login: %s\n", (char *)m.data);
        break;

    default:
        printf("[Server packet type %d]: %s\n", m.type, (char *)m.data);
        break;
    }
    fflush(stdout);
}

int main(void)
{
    printf("Text Conferencing Client\n");
    printf("Commands: /login <id> <pass> <ip> <port>\n");
    printf("          /logout  /joinsession <id>  /leavesession\n");
    printf("          /createsession <id>  /list  /quit\n\n");
    //int select(int numfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
    //FD_SET(int fd, fd_set *set); Add fd to the set.
    //FD_CLR(int fd, fd_set *set); Remove fd from the set.
    fd_set fds; //file descriptor

    for (;;) {
        FD_ZERO(&fds);
        FD_SET(fileno(stdin), &fds); // always watch keyboard

        if (client_sock > 0) {
            FD_SET(client_sock, &fds); // also watch socket when connected
            select(client_sock + 1, &fds, NULL, NULL, NULL);
        } else {
            select(fileno(stdin) + 1, &fds, NULL, NULL, NULL);
        }

        // incoming data from the server
        if (client_sock > 0 && FD_ISSET(client_sock, &fds)) {
            handle_server();
        }

        // user typed something
        if (FD_ISSET(fileno(stdin), &fds)) {
            handle_stdin();
        }
    }

    return 0;
}
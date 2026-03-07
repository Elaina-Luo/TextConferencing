/*
 * client.c - Text Conferencing Lab (ECE361)
 * Self-contained single file, no external headers needed.
 *
 * Compile:  gcc -Wall -o client client.c
 * Run:      ./client
 *
 * Uses select() to simultaneously handle:
 *   - stdin (user commands / text messages)
 *   - the server socket (incoming messages)
 */

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

/* ═══════════════════════════════════════════════
   Protocol constants  (must match server.c)
   ═══════════════════════════════════════════════ */
#define MAX_NAME        32
#define MAX_DATA        512
#define MAX_SESSION_ID  32
#define BUF_SIZE        620   /* large enough for the whole serialized message */
#define MAX_COMMAND_LEN 32

/* Packet type codes */
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

/* Message struct */
struct message {
    unsigned int  type;
    unsigned int  size;
    char          source[MAX_NAME];
    char          session_id[MAX_SESSION_ID];
    char          data[MAX_DATA];
};

/* ═══════════════════════════════════════════════
   Serialization  –  "type:size:source:session:data"
   ═══════════════════════════════════════════════ */
static void message_to_string(const struct message *m, char *dest)
{
    memset(dest, 0, BUF_SIZE);
    snprintf(dest, BUF_SIZE, "%d:%d:%s:%s:%s",
             m->type, m->size, m->source, m->session_id, m->data);
}

static void parse_message(const char *src, struct message *m)
{
    memset(m, 0, sizeof *m);

    /* work on a mutable copy */
    char tmp[BUF_SIZE];
    strncpy(tmp, src, BUF_SIZE - 1);

    char *tok;
    /* type */
    tok = strtok(tmp, ":");
    if (!tok) return;
    m->type = atoi(tok);

    /* size */
    tok = strtok(NULL, ":");
    if (!tok) return;
    m->size = atoi(tok);

    /* source */
    tok = strtok(NULL, ":");
    if (!tok) return;
    strncpy(m->source, tok, MAX_NAME - 1);

    /* session_id */
    tok = strtok(NULL, ":");
    if (!tok) return;
    strncpy(m->session_id, tok, MAX_SESSION_ID - 1);

    /* data – may contain ':', so copy the rest of the string directly */
    /* find offset of data field: skip past the 4 colons already consumed */
    const char *p = src;
    int colons = 0;
    while (*p && colons < 4) {
        if (*p == ':') colons++;
        p++;
    }
    strncpy(m->data, p, MAX_DATA - 1);
}

static void print_message(const struct message *m)
{
    if (m->session_id[0])
        printf("[%s] %s: %s\n", m->session_id, m->source, m->data);
    else
        printf("%s: %s\n", m->source, m->data);
}

/* ═══════════════════════════════════════════════
   Send a message over a socket
   ═══════════════════════════════════════════════ */
static int send_through(int sock, message_t type,
                        const char *source,
                        const char *session_id,
                        const char *data)
{
    struct message m;
    memset(&m, 0, sizeof m);
    m.type = type;
    strncpy(m.source,     source,     MAX_NAME       - 1);
    strncpy(m.session_id, session_id, MAX_SESSION_ID - 1);
    strncpy(m.data,       data,       MAX_DATA       - 1);
    m.size = strlen(m.data);

    char buf[BUF_SIZE];
    message_to_string(&m, buf);

    if (send(sock, buf, BUF_SIZE, 0) == -1) {
        perror("send");
        return 1;
    }
    return 0;
}

/* ═══════════════════════════════════════════════
   Global client state
   ═══════════════════════════════════════════════ */
static int  client_sock   = -1;
static int  is_in_session = 0;
static char cur_session[MAX_SESSION_ID] = "";
static char cur_name[MAX_NAME]          = "";
static int  logged_in     = 0;

/* ═══════════════════════════════════════════════
   Receive exactly one ACK/NAK from the server.
   Fills *m with the parsed message.
   Returns 0 on success, 1 on error.
   ═══════════════════════════════════════════════ */
static int recv_response(struct message *m)
{
    char buf[BUF_SIZE];
    memset(buf, 0, sizeof buf);
    int n = recv(client_sock, buf, BUF_SIZE - 1, 0);
    if (n <= 0) {
        printf("Failed to receive response from server.\n");
        return 1;
    }
    buf[n] = '\0';
    parse_message(buf, m);
    return 0;
}

/* ═══════════════════════════════════════════════
   /login <name> <pass> <server_ip> <server_port>
   ═══════════════════════════════════════════════ */
static int login(const char *name, const char *pass,
                 const char *server_ip, const char *server_port)
{
    if (logged_in) {
        printf("Already logged in as %s\n", cur_name);
        return 1;
    }

    struct addrinfo hints, *servinfo, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rv;
    if ((rv = getaddrinfo(server_ip, server_port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

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
    freeaddrinfo(servinfo);

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect to %s:%s\n",
                server_ip, server_port);
        client_sock = -1;
        return 1;
    }

    /* Send LOGIN */
    send_through(client_sock, LOGIN, name, "", pass);

    /* Wait for LO_ACK / LO_NAK synchronously */
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
        printf("Login failed: %s\n", resp.data);
        close(client_sock);
        client_sock = -1;
        return 1;
    }
}

/* ═══════════════════════════════════════════════
   /logout
   ═══════════════════════════════════════════════ */
static int logout(void)
{
    if (!logged_in) { printf("Not logged in.\n"); return 1; }

    send_through(client_sock, EXIT, cur_name, "", "");
    close(client_sock);
    client_sock   = -1;
    logged_in     = 0;
    is_in_session = 0;
    memset(cur_name,    0, sizeof cur_name);
    memset(cur_session, 0, sizeof cur_session);
    printf("Logged out.\n");
    return 0;
}

/* ═══════════════════════════════════════════════
   /joinsession <session_id>
   ═══════════════════════════════════════════════ */
static int join_session(const char *session_id)
{
    if (!logged_in)   { printf("Not logged in.\n"); return 1; }
    if (is_in_session){ printf("Already in session '%s'. /leavesession first.\n",
                               cur_session); return 1; }

    send_through(client_sock, JOIN, cur_name, session_id, "");

    struct message resp;
    if (recv_response(&resp)) return 1;

    if (resp.type == JN_ACK) {
        strncpy(cur_session, session_id, MAX_SESSION_ID - 1);
        is_in_session = 1;
        printf("Successfully joined session %s\n", cur_session);
        return 0;
    } else {
        printf("Failed to join session: %s\n", resp.data);
        return 1;
    }
}

/* ═══════════════════════════════════════════════
   /leavesession
   ═══════════════════════════════════════════════ */
static int leave_session(void)
{
    if (!logged_in)    { printf("Not logged in.\n"); return 1; }
    if (!is_in_session){ printf("Not in a session.\n"); return 1; }

    send_through(client_sock, LEAVE_SESS, cur_name, cur_session, "");
    printf("Left session %s\n", cur_session);
    is_in_session = 0;
    memset(cur_session, 0, sizeof cur_session);
    return 0;
}

/* ═══════════════════════════════════════════════
   /createsession <session_id>
   ═══════════════════════════════════════════════ */
static int create_session(const char *session_id)
{
    if (!logged_in)    { printf("Not logged in.\n"); return 1; }
    if (is_in_session) { printf("Already in session '%s'. /leavesession first.\n",
                                cur_session); return 1; }

    send_through(client_sock, NEW_SESS, cur_name, session_id, "");

    struct message resp;
    if (recv_response(&resp)) return 1;

    if (resp.type == NS_ACK) {
        strncpy(cur_session, session_id, MAX_SESSION_ID - 1);
        is_in_session = 1;
        printf("Successfully created session %s\n", cur_session);
        return 0;
    } else {
        printf("Failed to create session: %s\n", resp.data);
        return 1;
    }
}

/* ═══════════════════════════════════════════════
   /list
   ═══════════════════════════════════════════════ */
static int list(void)
{
    if (!logged_in) { printf("Not logged in.\n"); return 1; }

    send_through(client_sock, QUERY, cur_name, "", "");

    struct message resp;
    if (recv_response(&resp)) return 1;

    printf("Users and sessions:\n%s\n", resp.data);
    return 0;
}

/* ═══════════════════════════════════════════════
   /quit
   ═══════════════════════════════════════════════ */
static int quit(void)
{
    if (logged_in) logout();
    printf("Goodbye.\n");
    exit(0);
}

/* ═══════════════════════════════════════════════
   Send plain text as a MESSAGE to current session
   ═══════════════════════════════════════════════ */
static int send_message(const char *text)
{
    if (!logged_in)    { printf("Not logged in.\n"); return 1; }
    if (!is_in_session){ printf("Not in a session.\n"); return 1; }

    send_through(client_sock, MESSAGE, cur_name, cur_session, text);
    return 0;
}

/* ═══════════════════════════════════════════════
   Process one line of user input from stdin
   ═══════════════════════════════════════════════ */
static void handle_stdin(void)
{
    char command[MAX_COMMAND_LEN];
    char session_id[MAX_SESSION_ID];
    char name[MAX_NAME];
    char pass[MAX_DATA];
    char server_ip[64];
    char server_port[16];

    /* Read first token (the command) */
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
        /* Not a command — treat as chat text.
           Read rest of the line and prepend the first word. */
        if (!logged_in) {
            printf("Not logged in.\n");
            /* consume rest of line */
            char discard[MAX_DATA];
            fgets(discard, sizeof discard, stdin);
            return;
        }
        char msg_buf[MAX_DATA];
        strncpy(msg_buf, command, MAX_DATA - 1);
        int offset = strlen(msg_buf);
        /* read the rest of the line */
        fgets(msg_buf + offset, MAX_DATA - offset, stdin);
        /* strip trailing newline */
        msg_buf[strcspn(msg_buf, "\n")] = '\0';
        send_message(msg_buf);
    }
}

/* ═══════════════════════════════════════════════
   Handle one incoming packet from the server
   ═══════════════════════════════════════════════ */
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
        print_message(&m);
        break;
    case QU_ACK:
        printf("Users and sessions:\n%s\n", m.data);
        break;
    case JN_ACK:
        strncpy(cur_session, m.session_id[0] ? m.session_id : m.data,
                MAX_SESSION_ID - 1);
        is_in_session = 1;
        printf("Joined session: %s\n", cur_session);
        break;
    case JN_NAK:
        printf("Could not join session: %s\n", m.data);
        break;
    case NS_ACK:
        printf("Session created: %s\n", m.data);
        break;
    default:
        printf("[Server packet type %d]: %s\n", m.type, m.data);
        break;
    }
    fflush(stdout);
}

/* ═══════════════════════════════════════════════
   Main – select() loop
   ═══════════════════════════════════════════════ */
int main(void)
{
    printf("ECE361 Text Conferencing Client\n");
    printf("Commands: /login <id> <pass> <ip> <port>\n");
    printf("          /logout  /joinsession <id>  /leavesession\n");
    printf("          /createsession <id>  /list  /quit\n\n");

    fd_set fds;

    for (;;) {
        FD_ZERO(&fds);
        FD_SET(fileno(stdin), &fds);

        if (client_sock > 0) {
            FD_SET(client_sock, &fds);
            select(client_sock + 1, &fds, NULL, NULL, NULL);
        } else {
            select(fileno(stdin) + 1, &fds, NULL, NULL, NULL);
        }

        /* Incoming data from the server */
        if (client_sock > 0 && FD_ISSET(client_sock, &fds)) {
            handle_server();
        }

        /* User typed something */
        if (FD_ISSET(fileno(stdin), &fds)) {
            handle_stdin();
        }
    }

    return 0;
}

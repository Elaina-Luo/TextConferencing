/*
 * server.c - ECE361 Text Conferencing Lab - Section 1
 *
 * Usage: ./server <TCP port number>
 *
 * Wire format matches client.c exactly:
 *   - Messages serialized as text: "type:size:source:session_id:data\0"
 *   - Fixed BUF_SIZE buffer per send/recv
 *   - message_t enum values start at 0 (LOGIN=0, LO_ACK=1, ...)
 *   - MAX_NAME=32, MAX_DATA=512, MAX_SESSION_ID=32
 *
 * Uses select() for synchronous I/O multiplexing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* ═══════════════════════════════════════════════════════════════════
   Constants  –  must match client.c exactly
   ═══════════════════════════════════════════════════════════════════ */
#define MAX_NAME        32
#define MAX_DATA        512
#define MAX_SESSION_ID  32
#define BUF_SIZE        620   /* matches client: large enough for full serialized message */

#define MAX_CLIENTS     64
#define MAX_SESSIONS    32
#define BACKLOG         10

/* ═══════════════════════════════════════════════════════════════════
   Packet type codes  –  enum starting at 0, matches client.c exactly
   ═══════════════════════════════════════════════════════════════════ */
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

/* ═══════════════════════════════════════════════════════════════════
   Message struct  –  matches client.c exactly (includes session_id)
   ═══════════════════════════════════════════════════════════════════ */
struct message {
    unsigned int type;
    unsigned int size;
    char         source[MAX_NAME];
    char         session_id[MAX_SESSION_ID];
    char         data[MAX_DATA];
};

/* ═══════════════════════════════════════════════════════════════════
   Serialization / Deserialization  –  "type:size:source:session_id:data"
   Matches client.c's message_to_string / parse_message exactly.
   ═══════════════════════════════════════════════════════════════════ */
static void message_to_string(const struct message *m, char *dest)
{
    memset(dest, 0, BUF_SIZE);
    snprintf(dest, BUF_SIZE, "%d:%d:%s:%s:%s",
             m->type, m->size, m->source, m->session_id, m->data);
}

static void parse_message(const char *src, struct message *m)
{
    memset(m, 0, sizeof *m);

    char tmp[BUF_SIZE];
    strncpy(tmp, src, BUF_SIZE - 1);

    char *tok;

    tok = strtok(tmp, ":");
    if (!tok) return;
    m->type = (unsigned int)atoi(tok);

    tok = strtok(NULL, ":");
    if (!tok) return;
    m->size = (unsigned int)atoi(tok);

    tok = strtok(NULL, ":");
    if (!tok) return;
    strncpy(m->source, tok, MAX_NAME - 1);

    tok = strtok(NULL, ":");
    if (!tok) return;
    strncpy(m->session_id, tok, MAX_SESSION_ID - 1);

    /* data may contain ':', so take the rest of the original string directly */
    const char *p = src;
    int colons = 0;
    while (*p && colons < 4) {
        if (*p == ':') colons++;
        p++;
    }
    strncpy(m->data, p, MAX_DATA - 1);
}

/* ═══════════════════════════════════════════════════════════════════
   Send / Receive helpers
   ═══════════════════════════════════════════════════════════════════ */

/* Serialize and send one message to fd. Returns 0 on success, -1 on error. */
static int send_msg(int fd, const struct message *m)
{
    char buf[BUF_SIZE];
    message_to_string(m, buf);
    if (send(fd, buf, BUF_SIZE, 0) == -1) {
        perror("send");
        return -1;
    }
    return 0;
}

/* Receive and deserialize one message from fd.
   Returns bytes read (>0) on success, 0 if connection closed, -1 on error. */
static int recv_msg(int fd, struct message *m)
{
    char buf[BUF_SIZE];
    memset(buf, 0, sizeof buf);
    int n = recv(fd, buf, BUF_SIZE - 1, 0);
    if (n <= 0) return n;
    buf[n] = '\0';
    parse_message(buf, m);
    return n;
}

/* Convenience: build and send a response in one call */
static void respond(int fd, message_t type,
                    const char *session_id, const char *data)
{
    struct message resp;
    memset(&resp, 0, sizeof resp);
    resp.type = (unsigned int)type;
    strncpy(resp.source,     "server",     MAX_NAME       - 1);
    strncpy(resp.session_id, session_id,   MAX_SESSION_ID - 1);
    strncpy(resp.data,       data,         MAX_DATA       - 1);
    resp.size = (unsigned int)strlen(resp.data);
    send_msg(fd, &resp);
}

/* ═══════════════════════════════════════════════════════════════════
   Hard-coded user database
   ═══════════════════════════════════════════════════════════════════ */
typedef struct { char id[MAX_NAME]; char password[MAX_NAME]; } UserRecord;

static UserRecord user_db[] = {
    { "jill",  "eW94dsol" },
    { "jack",  "432wlFd"  },
    { "alice", "pass123"  },
    { "bob",   "qwerty"   },
    { "carol", "hello99"  },
};
static const int USER_DB_SIZE = (int)(sizeof user_db / sizeof user_db[0]);

static int check_credentials(const char *id, const char *pw)
{
    for (int i = 0; i < USER_DB_SIZE; i++)
        if (strcmp(user_db[i].id, id) == 0 &&
            strcmp(user_db[i].password, pw) == 0)
            return 1;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
   Connected-client table
   ═══════════════════════════════════════════════════════════════════ */
typedef struct {
    int  fd;                        /* -1 = empty slot          */
    char id[MAX_NAME];
    char session_id[MAX_SESSION_ID]; /* "" = not in any session  */
    char ip[INET6_ADDRSTRLEN];
    int  port;
} Client;

static Client clients[MAX_CLIENTS];

static Client *find_client_by_fd(int fd)
{
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].fd == fd) return &clients[i];
    return NULL;
}

static Client *find_client_by_id(const char *id)
{
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].fd != -1 && strcmp(clients[i].id, id) == 0)
            return &clients[i];
    return NULL;
}

static Client *alloc_client_slot(void)
{
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].fd == -1) return &clients[i];
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════
   Session table
   ═══════════════════════════════════════════════════════════════════ */
typedef struct {
    char name[MAX_SESSION_ID];  /* "" = unused slot */
} Session;

static Session sessions[MAX_SESSIONS];

static Session *find_session(const char *name)
{
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (sessions[i].name[0] != '\0' &&
            strcmp(sessions[i].name, name) == 0)
            return &sessions[i];
    return NULL;
}

static Session *alloc_session_slot(void)
{
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (sessions[i].name[0] == '\0') return &sessions[i];
    return NULL;
}

/* Delete a session if no clients remain in it */
static void maybe_delete_session(const char *name)
{
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].fd != -1 &&
            strcmp(clients[i].session_id, name) == 0)
            return; /* still has members */

    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (strcmp(sessions[i].name, name) == 0) {
            memset(sessions[i].name, 0, sizeof sessions[i].name);
            printf("[server] Session '%s' deleted (no members left).\n", name);
            return;
        }
    }
}

/* Multicast a message to every client in a session */
static void broadcast(const char *session_id, struct message *msg)
{
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].fd != -1 &&
            strcmp(clients[i].session_id, session_id) == 0)
            send_msg(clients[i].fd, msg);
}

/* ═══════════════════════════════════════════════════════════════════
   Disconnect / cleanup
   ═══════════════════════════════════════════════════════════════════ */
static void disconnect_client(int fd, fd_set *master, int *fd_max)
{
    Client *c = find_client_by_fd(fd);
    if (!c) return;

    printf("[server] '%s' (fd=%d) disconnected.\n",
           c->id[0] ? c->id : "(unknown)", fd);

    if (c->session_id[0] != '\0')
        maybe_delete_session(c->session_id);

    FD_CLR(fd, master);
    if (fd == *fd_max)
        while (*fd_max > 0 && !FD_ISSET(*fd_max, master))
            (*fd_max)--;

    close(fd);
    memset(c, 0, sizeof *c);
    c->fd = -1;
}

/* ═══════════════════════════════════════════════════════════════════
   Message handlers
   ═══════════════════════════════════════════════════════════════════ */

/* LOGIN */
static void handle_login(int fd, struct message *msg,
                          fd_set *master, int *fd_max)
{
    const char *id = msg->source;
    const char *pw = msg->data;

    if (find_client_by_id(id)) {
        char reason[MAX_DATA];
        snprintf(reason, sizeof reason, "ID '%s' is already logged in.", id);
        respond(fd, LO_NAK, "", reason);
        printf("[server] LOGIN denied '%s': already connected.\n", id);
        return;
    }

    if (!check_credentials(id, pw)) {
        respond(fd, LO_NAK, "", "Invalid ID or password.");
        printf("[server] LOGIN denied '%s': bad credentials.\n", id);
        return;
    }

    /* Register (slot was pre-allocated on accept) */
    Client *c = find_client_by_fd(fd);
    if (!c) {
        respond(fd, LO_NAK, "", "Server error: no slot for fd.");
        return;
    }
    strncpy(c->id, id, MAX_NAME - 1);

    respond(fd, LO_ACK, "", "");
    printf("[server] '%s' logged in.\n", id);

    (void)master; (void)fd_max; /* unused here, kept for signature symmetry */
}

/* EXIT */
static void handle_exit(int fd, fd_set *master, int *fd_max)
{
    disconnect_client(fd, master, fd_max);
}

/* JOIN */
static void handle_join(int fd, struct message *msg)
{
    Client *c = find_client_by_fd(fd);
    const char *sess = msg->session_id;  /* client puts session ID here */

    if (!c || c->id[0] == '\0') {
        char nak[MAX_DATA];
        snprintf(nak, sizeof nak, "%s,Not logged in.", sess);
        respond(fd, JN_NAK, sess, nak);
        return;
    }
    if (c->session_id[0] != '\0') {
        char nak[MAX_DATA];
        snprintf(nak, sizeof nak, "%s,Already in session '%s'.",
                 sess, c->session_id);
        respond(fd, JN_NAK, sess, nak);
        return;
    }
    if (!find_session(sess)) {
        char nak[MAX_DATA];
        snprintf(nak, sizeof nak, "%s,Session does not exist.", sess);
        respond(fd, JN_NAK, sess, nak);
        return;
    }

    strncpy(c->session_id, sess, MAX_SESSION_ID - 1);
    respond(fd, JN_ACK, sess, sess);
    printf("[server] '%s' joined session '%s'.\n", c->id, sess);
}

/* LEAVE_SESS */
static void handle_leave_sess(int fd)
{
    Client *c = find_client_by_fd(fd);
    if (!c || c->session_id[0] == '\0') {
        printf("[server] LEAVE_SESS from fd=%d but not in a session.\n", fd);
        return;
    }
    char old[MAX_SESSION_ID];
    strncpy(old, c->session_id, MAX_SESSION_ID - 1);
    memset(c->session_id, 0, sizeof c->session_id);
    printf("[server] '%s' left session '%s'.\n", c->id, old);
    maybe_delete_session(old);
}

/* NEW_SESS */
static void handle_new_sess(int fd, struct message *msg)
{
    Client *c = find_client_by_fd(fd);
    const char *sess = msg->session_id;  /* client puts session ID here */

    if (!c || c->id[0] == '\0') {
        char nak[MAX_DATA];
        snprintf(nak, sizeof nak, "%s,Not logged in.", sess);
        respond(fd, JN_NAK, sess, nak);
        return;
    }
    if (c->session_id[0] != '\0') {
        char nak[MAX_DATA];
        snprintf(nak, sizeof nak, "%s,Already in session '%s'.",
                 sess, c->session_id);
        respond(fd, JN_NAK, sess, nak);
        return;
    }
    if (find_session(sess)) {
        char nak[MAX_DATA];
        snprintf(nak, sizeof nak, "%s,Session already exists.", sess);
        respond(fd, JN_NAK, sess, nak);
        return;
    }

    Session *s = alloc_session_slot();
    if (!s) {
        char nak[MAX_DATA];
        snprintf(nak, sizeof nak, "%s,Max sessions reached.", sess);
        respond(fd, JN_NAK, sess, nak);
        return;
    }
    strncpy(s->name, sess, MAX_SESSION_ID - 1);
    strncpy(c->session_id, sess, MAX_SESSION_ID - 1);

    respond(fd, NS_ACK, sess, sess);
    printf("[server] '%s' created session '%s'.\n", c->id, sess);
}

/* MESSAGE  –  multicast to all session members */
static void handle_message(int fd, struct message *msg)
{
    Client *c = find_client_by_fd(fd);
    if (!c || c->id[0] == '\0') return;
    if (c->session_id[0] == '\0') {
        printf("[server] MESSAGE from '%s' not in a session – ignored.\n",
               c->id);
        return;
    }
    broadcast(c->session_id, msg);
}

/* QUERY */
static void handle_query(int fd)
{
    char buf[MAX_DATA];
    int  off = 0;

    off += snprintf(buf + off, sizeof buf - off, "Users: ");
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].fd != -1 && clients[i].id[0] != '\0')
            off += snprintf(buf + off, sizeof buf - off,
                            "%s ", clients[i].id);

    off += snprintf(buf + off, sizeof buf - off, "\nSessions: ");
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (sessions[i].name[0] != '\0')
            off += snprintf(buf + off, sizeof buf - off,
                            "%s ", sessions[i].name);

    respond(fd, QU_ACK, "", buf);
}

/* ═══════════════════════════════════════════════════════════════════
   Dispatch one incoming packet from an existing client fd
   ═══════════════════════════════════════════════════════════════════ */
static void dispatch(int fd, fd_set *master, int *fd_max)
{
    struct message msg;
    int n = recv_msg(fd, &msg);

    if (n == 0) {
        /* peer closed connection cleanly */
        disconnect_client(fd, master, fd_max);
        return;
    }
    if (n < 0) {
        fprintf(stderr, "[server] recv error fd=%d, disconnecting.\n", fd);
        disconnect_client(fd, master, fd_max);
        return;
    }

    switch ((message_t)msg.type) {
        case LOGIN:      handle_login(fd, &msg, master, fd_max); break;
        case EXIT:       handle_exit(fd, master, fd_max);        break;
        case JOIN:       handle_join(fd, &msg);                  break;
        case LEAVE_SESS: handle_leave_sess(fd);                  break;
        case NEW_SESS:   handle_new_sess(fd, &msg);              break;
        case MESSAGE:    handle_message(fd, &msg);               break;
        case QUERY:      handle_query(fd);                       break;
        default:
            printf("[server] Unknown type %u from fd=%d.\n", msg.type, fd);
    }
}

/* ═══════════════════════════════════════════════════════════════════
   main
   ═══════════════════════════════════════════════════════════════════ */
int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    const char *port = argv[1];

    /* Initialise tables */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        memset(&clients[i], 0, sizeof clients[i]);
        clients[i].fd = -1;
    }
    memset(sessions, 0, sizeof sessions);

    /* ── Create listener socket ───────────────────────────────────── */
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    int rv = getaddrinfo(NULL, port, &hints, &res);
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(EXIT_FAILURE);
    }

    int listener = -1;
    for (p = res; p != NULL; p = p->ai_next) {
        listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener < 0) continue;

        int yes = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

        if (bind(listener, p->ai_addr, p->ai_addrlen) < 0) {
            close(listener);
            listener = -1;
            continue;
        }
        break;
    }
    freeaddrinfo(res);

    if (listener < 0) {
        fprintf(stderr, "[server] Failed to bind on port %s\n", port);
        exit(EXIT_FAILURE);
    }
    if (listen(listener, BACKLOG) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    printf("[server] Listening on port %s ...\n", port);

    /* ── select() loop ────────────────────────────────────────────── */
    fd_set master, rfds;
    FD_ZERO(&master);
    FD_SET(listener, &master);
    int fd_max = listener;

    for (;;) {
        rfds = master;
        if (select(fd_max + 1, &rfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            perror("select");
            exit(EXIT_FAILURE);
        }

        for (int fd = 0; fd <= fd_max; fd++) {
            if (!FD_ISSET(fd, &rfds)) continue;

            if (fd == listener) {
                /* ── Accept new connection ────────────────────────── */
                struct sockaddr_storage addr;
                socklen_t addrlen = sizeof addr;
                int new_fd = accept(listener,
                                    (struct sockaddr *)&addr, &addrlen);
                if (new_fd < 0) { perror("accept"); continue; }

                Client *slot = alloc_client_slot();
                if (!slot) {
                    fprintf(stderr,
                            "[server] Max clients reached, rejecting.\n");
                    close(new_fd);
                    continue;
                }

                slot->fd = new_fd;

                /* Record peer IP / port */
                void *addr_in;
                if (addr.ss_family == AF_INET) {
                    struct sockaddr_in *s4 = (struct sockaddr_in *)&addr;
                    addr_in    = &s4->sin_addr;
                    slot->port = ntohs(s4->sin_port);
                } else {
                    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&addr;
                    addr_in    = &s6->sin6_addr;
                    slot->port = ntohs(s6->sin6_port);
                }
                inet_ntop(addr.ss_family, addr_in, slot->ip, sizeof slot->ip);

                FD_SET(new_fd, &master);
                if (new_fd > fd_max) fd_max = new_fd;

                printf("[server] New connection from %s:%d (fd=%d).\n",
                       slot->ip, slot->port, new_fd);

            } else {
                /* ── Existing client sent something ──────────────── */
                dispatch(fd, &master, &fd_max);
            }
        }
    }

    close(listener);
    return 0;
}

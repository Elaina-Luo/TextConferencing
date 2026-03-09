/*
 * server.c - ECE361 Text Conferencing Lab
 *
 * Usage: ./server <TCP port number>
 *
 * Wire format: "type:size:source:data"  (4 fields, 3 colons)
 * Exact struct from lab spec — no session_id field.
 * session ID is carried in the data field where needed.
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
   Constants — must match client.c exactly
   ═══════════════════════════════════════════════════════════════════ */
#define MAX_NAME     32
#define MAX_DATA     512
#define BUF_SIZE     580
#define MAX_CLIENTS  64
#define MAX_SESSIONS 32
#define BACKLOG      10

/* ═══════════════════════════════════════════════════════════════════
   Packet type codes — must match client.c exactly
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
   Exact struct from lab spec — 4 fields only, no session_id
   data carries different things depending on packet type:
     LOGIN    → password
     JOIN     → session ID to join
     JN_ACK   → session ID that was joined
     JN_NAK   → reason for failure
     NEW_SESS → session ID to create
     NS_ACK   → session ID that was created
     MESSAGE  → chat text
     QU_ACK   → list of users and sessions
   ═══════════════════════════════════════════════════════════════════ */
struct message {
    unsigned int  type;
    unsigned int  size;
    unsigned char source[MAX_NAME];
    unsigned char data[MAX_DATA];
};

/* ═══════════════════════════════════════════════════════════════════
   Serialization / Deserialization — "type:size:source:data"
   Must match client.c's message_to_string / parse_message exactly.
   ═══════════════════════════════════════════════════════════════════ */
static int message_to_string(const struct message *m, char *dest)
{
    memset(dest, 0, BUF_SIZE);
    // write type:size:source: prefix
    int prefix_len = snprintf(dest, BUF_SIZE, "%d:%d:%s:", m->type, m->size, (char *)m->source);
    // copy data raw — may contain colons (e.g. chat text)
    memcpy(dest + prefix_len, m->data, m->size);
    return prefix_len + m->size; 
}

static void parse_message(const char *src, struct message *m)
{
    memset(m, 0, sizeof *m);

    char tmp[BUF_SIZE];
    strncpy(tmp, src, BUF_SIZE - 1);

    char *tok;

    // type
    tok = strtok(tmp, ":");
    if (!tok) return;
    m->type = (unsigned int)atoi(tok);

    // size
    tok = strtok(NULL, ":");
    if (!tok) return;
    m->size = (unsigned int)atoi(tok);

    // source
    tok = strtok(NULL, ":");
    if (!tok) return;
    strncpy((char *)m->source, tok, MAX_NAME - 1);

    // data — may contain ':', skip past 3 colons in original string
    const char *p = src;
    int colons = 0;
    while (*p && colons < 3) {
        if (*p == ':') colons++;
        p++;
    }
    memcpy(m->data, p, m->size);
}

/* ═══════════════════════════════════════════════════════════════════
   Send / Receive helpers
   ═══════════════════════════════════════════════════════════════════ */

// Serialize and send one message to fd
static int send_msg(int fd, const struct message *m)
{
    char buf[BUF_SIZE]; 
    int len = message_to_string(m, buf);
    if (send(fd, buf, len, 0) == -1) {
        perror("send");
        return -1;
    }
    return 0;
}

// Receive and deserialize one message from fd
// Returns bytes read (>0) on success, 0 if closed, -1 on error
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

// Build and send a response in one call
// source is always "server", data carries the payload
static void respond(int fd, message_t type, const char *data)
{
    struct message resp;
    memset(&resp, 0, sizeof resp);
    resp.type = (unsigned int)type;
    strncpy((char *)resp.source, "server", MAX_NAME - 1);
    strncpy((char *)resp.data,   data,     MAX_DATA - 1);
    resp.size = (unsigned int)strlen((char *)resp.data);
    send_msg(fd, &resp);
}

/* ═══════════════════════════════════════════════════════════════════
   Hard-coded user database — add more users here as needed
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

// Returns 1 if id+password match a record, 0 otherwise
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
   Each slot tracks one logged-in client.
   fd=-1 means the slot is empty.
   session="" means the client is not in any session.
   ═══════════════════════════════════════════════════════════════════ */
typedef struct {
    int  fd;
    char id[MAX_NAME];
    char session[MAX_NAME]; // current session, "" = none
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
   Each slot is one active session.
   name="" means the slot is empty.
   ═══════════════════════════════════════════════════════════════════ */
typedef struct {
    char name[MAX_NAME]; // "" = unused slot
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

// Delete a session if no clients remain in it
static void maybe_delete_session(const char *name)
{
    // check if anyone is still in the session
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].fd != -1 &&
            strcmp(clients[i].session, name) == 0)
            return; // still has members, keep it

    // no members left — delete it
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (strcmp(sessions[i].name, name) == 0) {
            memset(sessions[i].name, 0, sizeof sessions[i].name);
            printf("[server] Session '%s' deleted (empty).\n", name);
            return;
        }
    }
}

// Multicast a message to every client in a session
static void broadcast(const char *session, struct message *msg)
{
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].fd != -1 &&
            strcmp(clients[i].session, session) == 0)
            send_msg(clients[i].fd, msg);
}

/* ═══════════════════════════════════════════════════════════════════
   Disconnect / cleanup one client
   ═══════════════════════════════════════════════════════════════════ */
static void disconnect_client(int fd, fd_set *master, int *fd_max)
{
    Client *c = find_client_by_fd(fd);
    if (!c) return;

    printf("[server] '%s' (fd=%d) disconnected.\n",
           c->id[0] ? c->id : "(unknown)", fd);

    // if client was in a session, maybe delete it
    if (c->session[0] != '\0')
        maybe_delete_session(c->session);

    FD_CLR(fd, master);
    if (fd == *fd_max)
        while (*fd_max > 0 && !FD_ISSET(*fd_max, master))
            (*fd_max)--;

    close(fd);
    memset(c, 0, sizeof *c);
    c->fd = -1;
}

/* ═══════════════════════════════════════════════════════════════════
   Message handlers — one per packet type
   ═══════════════════════════════════════════════════════════════════ */

// LOGIN — source=client_id, data=password
static void handle_login(int fd, struct message *msg,
                          fd_set *master, int *fd_max)
{
    const char *id = (char *)msg->source;
    const char *pw = (char *)msg->data;

    // reject if this ID is already logged in
    if (find_client_by_id(id)) {
        char reason[MAX_DATA];
        snprintf(reason, sizeof reason, "ID '%s' is already logged in.", id);
        respond(fd, LO_NAK, reason);
        printf("[server] LOGIN denied '%s': already connected.\n", id);
        return;
    }

    // reject if credentials don't match
    if (!check_credentials(id, pw)) {
        respond(fd, LO_NAK, "Invalid ID or password.");
        printf("[server] LOGIN denied '%s': bad credentials.\n", id);
        return;
    }

    // register the client in the slot that was pre-allocated on accept
    Client *c = find_client_by_fd(fd);
    if (!c) {
        respond(fd, LO_NAK, "Server error: no slot for fd.");
        return;
    }
    strncpy(c->id, id, MAX_NAME - 1);

    respond(fd, LO_ACK, "");
    printf("[server] '%s' logged in.\n", id);

    (void)master; (void)fd_max;
}

// EXIT — client is logging out
static void handle_exit(int fd, fd_set *master, int *fd_max)
{
    disconnect_client(fd, master, fd_max);
}

// JOIN — data = session ID to join
static void handle_join(int fd, struct message *msg)
{
    Client *c = find_client_by_fd(fd);
    const char *sess = (char *)msg->data; // session ID is in data field

    if (!c || c->id[0] == '\0') {
        respond(fd, JN_NAK, "Not logged in.");
        return;
    }
    if (c->session[0] != '\0') {
        char nak[MAX_DATA];
        snprintf(nak, sizeof nak, "Already in session '%s'.", c->session);
        respond(fd, JN_NAK, nak);
        return;
    }
    if (!find_session(sess)) {
        respond(fd, JN_NAK, "Session does not exist.");
        return;
    }

    strncpy(c->session, sess, MAX_NAME - 1);
    respond(fd, JN_ACK, sess); // data = session ID so client knows which one
    printf("[server] '%s' joined session '%s'.\n", c->id, sess);
}

// LEAVE_SESS — client leaves their current session
static void handle_leave_sess(int fd)
{
    Client *c = find_client_by_fd(fd);
    if (!c || c->session[0] == '\0') {
        printf("[server] LEAVE_SESS from fd=%d but not in a session.\n", fd);
        return;
    }

    char old[MAX_NAME];
    strncpy(old, c->session, MAX_NAME - 1);
    memset(c->session, 0, sizeof c->session);
    printf("[server] '%s' left session '%s'.\n", c->id, old);
    maybe_delete_session(old);
}

// NEW_SESS — data = session ID to create
static void handle_new_sess(int fd, struct message *msg)
{
    Client *c = find_client_by_fd(fd);
    const char *sess = (char *)msg->data; // session ID is in data field

    if (!c || c->id[0] == '\0') {
        respond(fd, JN_NAK, "Not logged in.");
        return;
    }
    if (c->session[0] != '\0') {
        char nak[MAX_DATA];
        snprintf(nak, sizeof nak, "Already in session '%s'.", c->session);
        respond(fd, JN_NAK, nak);
        return;
    }
    if (find_session(sess)) {
        respond(fd, JN_NAK, "Session already exists.");
        return;
    }

    Session *s = alloc_session_slot();
    if (!s) {
        respond(fd, JN_NAK, "Server has reached max sessions.");
        return;
    }

    strncpy(s->name,    sess, MAX_NAME - 1);
    strncpy(c->session, sess, MAX_NAME - 1);

    respond(fd, NS_ACK, sess); // data = session ID so client knows which one
    printf("[server] '%s' created session '%s'.\n", c->id, sess);
}

// MESSAGE — broadcast chat text to all members of sender's session
static void handle_message(int fd, struct message *msg)
{
    Client *c = find_client_by_fd(fd);
    if (!c || c->id[0] == '\0') return;
    if (c->session[0] == '\0') {
        printf("[server] MESSAGE from '%s' not in a session — ignored.\n", c->id);
        return;
    }

    // tag the source field with sender's ID so receivers know who sent it
    strncpy((char *)msg->source, c->id, MAX_NAME - 1);
    broadcast(c->session, msg);
}

// QUERY — respond with list of all logged-in users and active sessions
static void handle_query(int fd)
{
    char buf[MAX_DATA];
    int  off = 0;

    off += snprintf(buf + off, sizeof buf - off, "Users: ");
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].fd != -1 && clients[i].id[0] != '\0')
            off += snprintf(buf + off, sizeof buf - off, "%s ", clients[i].id);

    off += snprintf(buf + off, sizeof buf - off, "\nSessions: ");
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (sessions[i].name[0] != '\0')
            off += snprintf(buf + off, sizeof buf - off, "%s ", sessions[i].name);

    respond(fd, QU_ACK, buf);
}

/* ═══════════════════════════════════════════════════════════════════
   Dispatch one incoming packet from a client fd
   ═══════════════════════════════════════════════════════════════════ */
static void dispatch(int fd, fd_set *master, int *fd_max)
{
    struct message msg;
    int n = recv_msg(fd, &msg);

    if (n == 0) {
        // peer closed connection cleanly
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
            printf("[server] Unknown packet type %u from fd=%d.\n", msg.type, fd);
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

    // initialise client and session tables
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
    hints.ai_flags    = AI_PASSIVE; // bind to all interfaces

    int rv = getaddrinfo(NULL, port, &hints, &res);
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(EXIT_FAILURE);
    }

    int listener = -1;
    for (p = res; p != NULL; p = p->ai_next) {
        listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener < 0) continue;

        // avoid "address already in use" error after restart
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
        rfds = master; // select() modifies the set so use a copy each iteration
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
                int new_fd = accept(listener, (struct sockaddr *)&addr, &addrlen);
                if (new_fd < 0) { perror("accept"); continue; }

                // pre-allocate a client slot so we can store the fd immediately
                Client *slot = alloc_client_slot();
                if (!slot) {
                    fprintf(stderr, "[server] Max clients reached, rejecting fd=%d.\n", new_fd);
                    close(new_fd);
                    continue;
                }
                slot->fd = new_fd;

                // record peer IP and port for logging
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
/*
 * server.c - ECE361 Text Conferencing Lab - Section 1
 *
 * Usage: ./server <TCP port number>
 *
 * The server acts as both a conference session router and a database.
 * It uses select() for synchronous I/O multiplexing to handle
 * multiple clients simultaneously without threads.
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

/* ─── Constants ─────────────────────────────────────────────────── */
#define MAX_NAME     100
#define MAX_DATA     4096
#define MAX_CLIENTS  64
#define MAX_SESSIONS 32
#define BACKLOG      10

/* ─── Message Types ─────────────────────────────────────────────── */
#define LOGIN       1
#define LO_ACK      2
#define LO_NAK      3
#define EXIT        4
#define JOIN        5
#define JN_ACK      6
#define JN_NAK      7
#define LEAVE_SESS  8
#define NEW_SESS    9
#define NS_ACK      10
#define MESSAGE     11
#define QUERY       12
#define QU_ACK      13

/* ─── Message Structure ──────────────────────────────────────────── */
struct message {
    unsigned int  type;
    unsigned int  size;
    unsigned char source[MAX_NAME];
    unsigned char data[MAX_DATA];
};

/* ─── Hard-coded user database ───────────────────────────────────── */
typedef struct {
    char id[MAX_NAME];
    char password[MAX_NAME];
} UserRecord;

static UserRecord user_db[] = {
    { "jill",  "eW94dsol" },
    { "jack",  "432wlFd"  },
    { "alice", "pass123"  },
    { "bob",   "qwerty"   },
    { "carol", "hello99"  },
};
static const int USER_DB_SIZE = sizeof(user_db) / sizeof(user_db[0]);

/* ─── Connected client table ─────────────────────────────────────── */
typedef struct {
    int  fd;                    /* socket file descriptor, -1 = empty slot */
    char id[MAX_NAME];          /* client identifier                        */
    char session_id[MAX_NAME];  /* current session, empty string = none     */
    char ip[INET6_ADDRSTRLEN];  /* IP address string                        */
    int  port;                  /* port number                              */
} Client;

static Client clients[MAX_CLIENTS];
static int    num_clients = 0;  /* number of currently connected clients    */

/* ─── Session table ─────────────────────────────────────────────── */
typedef struct {
    char name[MAX_NAME];        /* session ID, empty string = unused slot   */
} Session;

static Session sessions[MAX_SESSIONS];

/* ─── Utility: send a full message struct to a socket ───────────── */
/*
 * We prefix every message with a 4-byte network-order length so that
 * the receiver can reconstruct message boundaries over TCP's byte stream.
 */
static int send_message(int fd, struct message *msg)
{
    /* Total payload size */
    uint32_t payload_len = sizeof(struct message);
    uint32_t net_len     = htonl(payload_len);

    /* Send length prefix */
    if (send(fd, &net_len, sizeof(net_len), 0) < 0) {
        perror("send (length prefix)");
        return -1;
    }
    /* Send message body */
    size_t  total_sent = 0;
    uint8_t *buf       = (uint8_t *)msg;
    while (total_sent < payload_len) {
        ssize_t n = send(fd, buf + total_sent, payload_len - total_sent, 0);
        if (n <= 0) {
            perror("send (body)");
            return -1;
        }
        total_sent += n;
    }
    return 0;
}

/* ─── Utility: receive a full message struct from a socket ──────── */
static int recv_message(int fd, struct message *msg)
{
    /* Read 4-byte length prefix */
    uint32_t net_len;
    ssize_t  n = recv(fd, &net_len, sizeof(net_len), MSG_WAITALL);
    if (n == 0)  return 0;   /* connection closed */
    if (n < 0) { perror("recv (length prefix)"); return -1; }

    uint32_t payload_len = ntohl(net_len);
    if (payload_len != sizeof(struct message)) {
        fprintf(stderr, "recv_message: unexpected payload size %u\n", payload_len);
        return -1;
    }

    /* Read message body */
    size_t  total_recv = 0;
    uint8_t *buf       = (uint8_t *)msg;
    while (total_recv < payload_len) {
        n = recv(fd, buf + total_recv, payload_len - total_recv, 0);
        if (n == 0)  return 0;
        if (n < 0) { perror("recv (body)"); return -1; }
        total_recv += n;
    }
    return (int)total_recv;
}

/* ─── Utility: find client slot by fd ───────────────────────────── */
static Client *find_client_by_fd(int fd)
{
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].fd == fd) return &clients[i];
    return NULL;
}

/* ─── Utility: find client slot by ID ───────────────────────────── */
static Client *find_client_by_id(const char *id)
{
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].fd != -1 && strcmp(clients[i].id, id) == 0)
            return &clients[i];
    return NULL;
}

/* ─── Utility: find a free client slot ──────────────────────────── */
static Client *alloc_client_slot(void)
{
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].fd == -1) return &clients[i];
    return NULL;
}

/* ─── Utility: find session by name ─────────────────────────────── */
static Session *find_session(const char *name)
{
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (strlen(sessions[i].name) > 0 &&
            strcmp(sessions[i].name, name) == 0)
            return &sessions[i];
    return NULL;
}

/* ─── Utility: find free session slot ───────────────────────────── */
static Session *alloc_session_slot(void)
{
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (strlen(sessions[i].name) == 0) return &sessions[i];
    return NULL;
}

/* ─── Utility: delete a session if no clients remain in it ──────── */
static void maybe_delete_session(const char *name)
{
    /* Check if anyone is still in this session */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].fd != -1 &&
            strcmp(clients[i].session_id, name) == 0)
            return;  /* still occupied */
    }
    /* Remove session */
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (strcmp(sessions[i].name, name) == 0) {
            memset(sessions[i].name, 0, sizeof(sessions[i].name));
            printf("[server] Session '%s' deleted (empty).\n", name);
            return;
        }
    }
}

/* ─── Utility: multicast MESSAGE to all clients in a session ─────── */
static void broadcast_to_session(const char *session_id, struct message *msg)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].fd != -1 &&
            strcmp(clients[i].session_id, session_id) == 0) {
            if (send_message(clients[i].fd, msg) < 0)
                fprintf(stderr, "[server] Failed to forward to %s\n",
                        clients[i].id);
        }
    }
}

/* ─── Utility: look up password in user_db ───────────────────────── */
static int check_credentials(const char *id, const char *password)
{
    for (int i = 0; i < USER_DB_SIZE; i++)
        if (strcmp(user_db[i].id, id) == 0 &&
            strcmp(user_db[i].password, password) == 0)
            return 1;
    return 0;
}

/* ─── Disconnect / cleanup a client ─────────────────────────────── */
static void disconnect_client(int fd, fd_set *master_fds, int *fd_max)
{
    Client *c = find_client_by_fd(fd);
    if (!c) return;

    printf("[server] Client '%s' (fd=%d) disconnected.\n",
           strlen(c->id) ? c->id : "(unknown)", fd);

    /* Leave session if in one */
    if (strlen(c->session_id) > 0)
        maybe_delete_session(c->session_id);

    /* Remove from master set */
    FD_CLR(fd, master_fds);
    if (fd == *fd_max) {
        while (*fd_max > 0 && !FD_ISSET(*fd_max, master_fds))
            (*fd_max)--;
    }

    close(fd);

    /* Clear slot */
    memset(c, 0, sizeof(Client));
    c->fd = -1;
    num_clients--;
}

/* ─── Handle LOGIN ──────────────────────────────────────────────── */
static void handle_login(int fd, struct message *msg,
                         fd_set *master_fds, int *fd_max)
{
    struct message resp;
    memset(&resp, 0, sizeof(resp));

    char *id  = (char *)msg->source;
    char *pw  = (char *)msg->data;

    /* Check if ID already connected */
    if (find_client_by_id(id)) {
        resp.type = LO_NAK;
        snprintf((char *)resp.data, MAX_DATA,
                 "ID '%s' is already logged in.", id);
        resp.size = (unsigned int)strlen((char *)resp.data);
        strncpy((char *)resp.source, "server", MAX_NAME - 1);
        send_message(fd, &resp);
        printf("[server] LOGIN denied for '%s': already connected.\n", id);
        return;
    }

    /* Validate credentials */
    if (!check_credentials(id, pw)) {
        resp.type = LO_NAK;
        snprintf((char *)resp.data, MAX_DATA,
                 "Invalid ID or password.");
        resp.size = (unsigned int)strlen((char *)resp.data);
        strncpy((char *)resp.source, "server", MAX_NAME - 1);
        send_message(fd, &resp);
        printf("[server] LOGIN denied for '%s': bad credentials.\n", id);
        return;
    }

    /* Register client */
    Client *c = find_client_by_fd(fd);
    if (!c) {
        /* fd was accepted but slot not yet assigned – find free slot */
        c = alloc_client_slot();
        if (!c) {
            resp.type = LO_NAK;
            snprintf((char *)resp.data, MAX_DATA, "Server full.");
            resp.size = (unsigned int)strlen((char *)resp.data);
            strncpy((char *)resp.source, "server", MAX_NAME - 1);
            send_message(fd, &resp);
            return;
        }
        c->fd = fd;
    }
    strncpy(c->id, id, MAX_NAME - 1);
    memset(c->session_id, 0, sizeof(c->session_id));
    num_clients++;

    resp.type = LO_ACK;
    resp.size = 0;
    strncpy((char *)resp.source, "server", MAX_NAME - 1);
    send_message(fd, &resp);
    printf("[server] '%s' logged in successfully.\n", id);
}

/* ─── Handle EXIT ────────────────────────────────────────────────── */
static void handle_exit(int fd, fd_set *master_fds, int *fd_max)
{
    disconnect_client(fd, master_fds, fd_max);
}

/* ─── Handle JOIN ────────────────────────────────────────────────── */
static void handle_join(int fd, struct message *msg)
{
    struct message resp;
    memset(&resp, 0, sizeof(resp));
    strncpy((char *)resp.source, "server", MAX_NAME - 1);

    Client *c = find_client_by_fd(fd);
    if (!c || strlen(c->id) == 0) {
        /* Not logged in */
        resp.type = JN_NAK;
        snprintf((char *)resp.data, MAX_DATA,
                 "%s,Not logged in.", (char *)msg->data);
        resp.size = (unsigned int)strlen((char *)resp.data);
        send_message(fd, &resp);
        return;
    }

    char *sess_id = (char *)msg->data;

    /* Already in a session? */
    if (strlen(c->session_id) > 0) {
        resp.type = JN_NAK;
        snprintf((char *)resp.data, MAX_DATA,
                 "%s,Already in session '%s'. Leave first.",
                 sess_id, c->session_id);
        resp.size = (unsigned int)strlen((char *)resp.data);
        send_message(fd, &resp);
        return;
    }

    /* Does session exist? */
    Session *s = find_session(sess_id);
    if (!s) {
        resp.type = JN_NAK;
        snprintf((char *)resp.data, MAX_DATA,
                 "%s,Session does not exist.", sess_id);
        resp.size = (unsigned int)strlen((char *)resp.data);
        send_message(fd, &resp);
        return;
    }

    /* Join */
    strncpy(c->session_id, sess_id, MAX_NAME - 1);
    resp.type = JN_ACK;
    strncpy((char *)resp.data, sess_id, MAX_DATA - 1);
    resp.size = (unsigned int)strlen(sess_id);
    send_message(fd, &resp);
    printf("[server] '%s' joined session '%s'.\n", c->id, sess_id);
}

/* ─── Handle LEAVE_SESS ─────────────────────────────────────────── */
static void handle_leave_sess(int fd)
{
    Client *c = find_client_by_fd(fd);
    if (!c || strlen(c->session_id) == 0) {
        printf("[server] LEAVE_SESS from fd=%d but not in a session.\n", fd);
        return;
    }

    char old_sess[MAX_NAME];
    strncpy(old_sess, c->session_id, MAX_NAME - 1);
    memset(c->session_id, 0, sizeof(c->session_id));

    printf("[server] '%s' left session '%s'.\n", c->id, old_sess);
    maybe_delete_session(old_sess);
}

/* ─── Handle NEW_SESS ───────────────────────────────────────────── */
static void handle_new_sess(int fd, struct message *msg)
{
    struct message resp;
    memset(&resp, 0, sizeof(resp));
    strncpy((char *)resp.source, "server", MAX_NAME - 1);

    Client *c = find_client_by_fd(fd);
    if (!c || strlen(c->id) == 0) {
        resp.type = JN_NAK;
        snprintf((char *)resp.data, MAX_DATA,
                 "%s,Not logged in.", (char *)msg->data);
        resp.size = (unsigned int)strlen((char *)resp.data);
        send_message(fd, &resp);
        return;
    }

    char *sess_id = (char *)msg->data;

    /* Already in a session? */
    if (strlen(c->session_id) > 0) {
        resp.type = JN_NAK;
        snprintf((char *)resp.data, MAX_DATA,
                 "%s,Already in session '%s'. Leave first.",
                 sess_id, c->session_id);
        resp.size = (unsigned int)strlen((char *)resp.data);
        send_message(fd, &resp);
        return;
    }

    /* Session name already taken? */
    if (find_session(sess_id)) {
        resp.type = JN_NAK;
        snprintf((char *)resp.data, MAX_DATA,
                 "%s,Session already exists.", sess_id);
        resp.size = (unsigned int)strlen((char *)resp.data);
        send_message(fd, &resp);
        return;
    }

    /* Allocate session */
    Session *s = alloc_session_slot();
    if (!s) {
        resp.type = JN_NAK;
        snprintf((char *)resp.data, MAX_DATA,
                 "%s,Maximum sessions reached.", sess_id);
        resp.size = (unsigned int)strlen((char *)resp.data);
        send_message(fd, &resp);
        return;
    }
    strncpy(s->name, sess_id, MAX_NAME - 1);

    /* Join the creator into the session */
    strncpy(c->session_id, sess_id, MAX_NAME - 1);

    resp.type = NS_ACK;
    strncpy((char *)resp.data, sess_id, MAX_DATA - 1);
    resp.size = (unsigned int)strlen(sess_id);
    send_message(fd, &resp);
    printf("[server] '%s' created and joined session '%s'.\n",
           c->id, sess_id);
}

/* ─── Handle MESSAGE ────────────────────────────────────────────── */
static void handle_message(int fd, struct message *msg)
{
    Client *c = find_client_by_fd(fd);
    if (!c || strlen(c->id) == 0) return;

    if (strlen(c->session_id) == 0) {
        printf("[server] MESSAGE from '%s' who is not in a session – ignored.\n",
               c->id);
        return;
    }

    /* Forward to all clients in the same session (including sender) */
    broadcast_to_session(c->session_id, msg);
}

/* ─── Handle QUERY ──────────────────────────────────────────────── */
static void handle_query(int fd)
{
    struct message resp;
    memset(&resp, 0, sizeof(resp));
    resp.type = QU_ACK;
    strncpy((char *)resp.source, "server", MAX_NAME - 1);

    /* Build list: "Users: u1 u2 ... \nSessions: s1 s2 ..." */
    char buf[MAX_DATA];
    int  offset = 0;

    offset += snprintf(buf + offset, sizeof(buf) - offset, "Users: ");
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].fd != -1 && strlen(clients[i].id) > 0) {
            offset += snprintf(buf + offset, sizeof(buf) - offset,
                               "%s ", clients[i].id);
        }
    }

    offset += snprintf(buf + offset, sizeof(buf) - offset, "\nSessions: ");
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (strlen(sessions[i].name) > 0) {
            offset += snprintf(buf + offset, sizeof(buf) - offset,
                               "%s ", sessions[i].name);
        }
    }

    strncpy((char *)resp.data, buf, MAX_DATA - 1);
    resp.size = (unsigned int)strlen(buf);
    send_message(fd, &resp);
}

/* ─── Dispatch incoming message from an existing client ─────────── */
static void handle_client_message(int fd, fd_set *master_fds, int *fd_max)
{
    struct message msg;
    memset(&msg, 0, sizeof(msg));

    int n = recv_message(fd, &msg);
    if (n == 0) {
        /* Connection closed cleanly */
        disconnect_client(fd, master_fds, fd_max);
        return;
    }
    if (n < 0) {
        fprintf(stderr, "[server] recv error on fd=%d, disconnecting.\n", fd);
        disconnect_client(fd, master_fds, fd_max);
        return;
    }

    switch (msg.type) {
        case LOGIN:      handle_login(fd, &msg, master_fds, fd_max); break;
        case EXIT:       handle_exit(fd, master_fds, fd_max);        break;
        case JOIN:       handle_join(fd, &msg);                      break;
        case LEAVE_SESS: handle_leave_sess(fd);                      break;
        case NEW_SESS:   handle_new_sess(fd, &msg);                  break;
        case MESSAGE:    handle_message(fd, &msg);                   break;
        case QUERY:      handle_query(fd);                           break;
        default:
            printf("[server] Unknown message type %u from fd=%d.\n",
                   msg.type, fd);
    }
}

/* ─── main ──────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *port_str = argv[1];

    /* Initialise client table */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        memset(&clients[i], 0, sizeof(Client));
        clients[i].fd = -1;
    }
    /* Initialise session table */
    memset(sessions, 0, sizeof(sessions));

    /* ── Set up listening socket ─────────────────────────────────── */
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;   /* IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;  /* use local IP */

    int rv = getaddrinfo(NULL, port_str, &hints, &res);
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(EXIT_FAILURE);
    }

    int listener_fd = -1;
    for (p = res; p != NULL; p = p->ai_next) {
        listener_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener_fd < 0) continue;

        /* Allow address reuse to avoid "port in use" after restart */
        int yes = 1;
        setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        if (bind(listener_fd, p->ai_addr, p->ai_addrlen) < 0) {
            close(listener_fd);
            continue;
        }
        break;
    }
    freeaddrinfo(res);

    if (p == NULL) {
        fprintf(stderr, "[server] Failed to bind to port %s.\n", port_str);
        exit(EXIT_FAILURE);
    }

    if (listen(listener_fd, BACKLOG) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    printf("[server] Listening on port %s ...\n", port_str);

    /* ── select() main loop ──────────────────────────────────────── */
    fd_set master_fds;   /* all active FDs            */
    fd_set read_fds;     /* working copy for select() */
    FD_ZERO(&master_fds);
    FD_ZERO(&read_fds);

    FD_SET(listener_fd, &master_fds);
    int fd_max = listener_fd;

    while (1) {
        read_fds = master_fds;   /* select() modifies the set, so copy each time */

        if (select(fd_max + 1, &read_fds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;  /* interrupted by signal, retry */
            perror("select");
            exit(EXIT_FAILURE);
        }

        /* Iterate over all possible FDs */
        for (int fd = 0; fd <= fd_max; fd++) {
            if (!FD_ISSET(fd, &read_fds)) continue;

            if (fd == listener_fd) {
                /* ── New incoming connection ──────────────────────── */
                struct sockaddr_storage peer_addr;
                socklen_t peer_addrlen = sizeof(peer_addr);
                int new_fd = accept(listener_fd,
                                    (struct sockaddr *)&peer_addr,
                                    &peer_addrlen);
                if (new_fd < 0) {
                    perror("accept");
                    continue;
                }

                /* Check capacity */
                Client *slot = alloc_client_slot();
                if (!slot) {
                    fprintf(stderr,
                            "[server] Max clients reached, rejecting fd=%d.\n",
                            new_fd);
                    close(new_fd);
                    continue;
                }

                /* Pre-register slot with fd (ID filled in upon LOGIN) */
                slot->fd = new_fd;

                /* Store peer IP and port */
                void *addr_ptr;
                if (peer_addr.ss_family == AF_INET) {
                    struct sockaddr_in *s = (struct sockaddr_in *)&peer_addr;
                    addr_ptr   = &s->sin_addr;
                    slot->port = ntohs(s->sin_port);
                } else {
                    struct sockaddr_in6 *s = (struct sockaddr_in6 *)&peer_addr;
                    addr_ptr   = &s->sin6_addr;
                    slot->port = ntohs(s->sin6_port);
                }
                inet_ntop(peer_addr.ss_family, addr_ptr,
                          slot->ip, sizeof(slot->ip));

                FD_SET(new_fd, &master_fds);
                if (new_fd > fd_max) fd_max = new_fd;

                printf("[server] New connection from %s:%d (fd=%d).\n",
                       slot->ip, slot->port, new_fd);

            } else {
                /* ── Data from existing client ────────────────────── */
                handle_client_message(fd, &master_fds, &fd_max);
            }
        }
    }

    close(listener_fd);
    return 0;
}

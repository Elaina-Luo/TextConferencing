#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_NAME        32
#define MAX_DATA        512
#define BUF_SIZE        580
#define MAX_CLIENTS     100
#define MAX_SESSIONS    100

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
    QU_ACK,
    KICK,       
    GIVE_ADMIN  
} message_t;

struct message {
    unsigned int  type;
    unsigned int  size;
    unsigned char source[MAX_NAME];
    unsigned char data[MAX_DATA];
};

static int message_to_string(const struct message *m, char *dest)
{
    memset(dest, 0, BUF_SIZE);
    int prefix_len = snprintf(dest, BUF_SIZE, "%d:%d:%s:", m->type, m->size, (char *)m->source);
    memcpy(dest + prefix_len, m->data, m->size);
    return prefix_len + m->size;
}

static void parse_message(const char *src, struct message *m)
{
    memset(m, 0, sizeof *m);

    char tmp[BUF_SIZE];
    memset(tmp, 0, sizeof tmp);
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
    strncpy((char *)m->source, tok, MAX_NAME - 1);

    /* data = everything after the 3rd colon (may contain ':') */
    const char *p = src;
    int colons = 0;
    while (*p && colons < 3) {
        if (*p == ':') colons++;
        p++;
    }
    memcpy(m->data, p, m->size);
}

static int send_message_struct(int sock, const struct message *m)
{
    char buf[BUF_SIZE];
    int len = message_to_string(m, buf);
    int n = send(sock, buf, len, 0);
    if (n <= 0) {
        return -1;
    }
    return 0;
}

static int send_packet(int sock, message_t type,
                       const char *source,
                       const char *data)
{
    struct message m;
    memset(&m, 0, sizeof m);
    m.type = type;

    if (source) strncpy((char *)m.source, source, MAX_NAME - 1);
    if (data)   strncpy((char *)m.data,   data,   MAX_DATA - 1);

    m.size = (unsigned int)strlen((char *)m.data);

    return send_message_struct(sock, &m);
}


typedef struct {
    char id[MAX_NAME];
    char password[MAX_DATA];
} credential_t;

static credential_t credentials[] = {
    {"jill",  "eW94dsol"},
    {"jack",  "432wlFd"},
    {"alice", "alice123"},
    {"bob",   "bob123"},
    {"grace", "grace123"},
    {"jenny", "jenny123"}
};

static const int NUM_CREDENTIALS =
    (int)(sizeof(credentials) / sizeof(credentials[0]));

/*Server state*/
typedef struct {
    int    active;
    int    sockfd;
    char   id[MAX_NAME];
    char   session_id[MAX_NAME];  /* current session, "" = none */
    int    logged_in;
} client_info_t;

typedef struct {
    int  active;
    char session_id[MAX_NAME];
    char admin_id[MAX_NAME];      
} session_info_t;

static client_info_t  clients[MAX_CLIENTS];
static session_info_t sessions[MAX_SESSIONS];

/*Helpers: lookup / management*/
static int find_client_index_by_sock(int sockfd)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].sockfd == sockfd)
            return i;
    }
    return -1;
}

static int find_client_index_by_id(const char *id)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].logged_in &&
            strcmp(clients[i].id, id) == 0)
            return i;
    }
    return -1;
}

static int add_client(int sockfd)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) {
            memset(&clients[i], 0, sizeof(clients[i]));
            clients[i].active      = 1;
            clients[i].sockfd      = sockfd;
            return i;
        }
    }
    return -1;
}

static void remove_client(int idx)
{
    if (idx < 0 || idx >= MAX_CLIENTS) return;
    memset(&clients[idx], 0, sizeof(clients[idx]));
}

static int verify_credentials(const char *id, const char *password)
{
    for (int i = 0; i < NUM_CREDENTIALS; i++) {
        if (strcmp(credentials[i].id, id) == 0 &&
            strcmp(credentials[i].password, password) == 0)
            return 1;
    }
    return 0;
}

static int find_session_index(const char *session_id)
{
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].active &&
            strcmp(sessions[i].session_id, session_id) == 0)
            return i;
    }
    return -1;
}

static int create_session_if_needed(const char *session_id)
{
    int idx = find_session_index(session_id);
    if (idx != -1) return idx;

    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].active) {
            memset(&sessions[i], 0, sizeof(sessions[i]));
            sessions[i].active = 1;
            strncpy(sessions[i].session_id, session_id, MAX_NAME - 1);
            return i;
        }
    }
    return -1;
}

static int session_has_members(const char *session_id)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].logged_in &&
            strcmp(clients[i].session_id, session_id) == 0)
            return 1;
    }
    return 0;
}

static void delete_session_if_empty(const char *session_id)
{
    if (session_id == NULL || session_id[0] == '\0') return;

    if (session_has_members(session_id)) return;

    int sidx = find_session_index(session_id);
    if (sidx != -1) {
        memset(&sessions[sidx], 0, sizeof(sessions[sidx]));
    }
}

static void leave_current_session(int client_idx)
{
    if (client_idx < 0 || client_idx >= MAX_CLIENTS) return;
    if (!clients[client_idx].active) return;

    char old_session[MAX_NAME];
    memset(old_session, 0, sizeof old_session);
    strncpy(old_session, clients[client_idx].session_id, MAX_NAME - 1);

    memset(clients[client_idx].session_id, 0, sizeof(clients[client_idx].session_id));

    // if leaving client was admin, transfer admin to next member
    int sidx = find_session_index(old_session);
    if (sidx != -1 &&
        strcmp(sessions[sidx].admin_id, clients[client_idx].id) == 0) {
        int transferred = 0;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active && clients[i].logged_in &&
                strcmp(clients[i].session_id, old_session) == 0 &&
                i != client_idx) {
                strncpy(sessions[sidx].admin_id, clients[i].id, MAX_NAME - 1);
                // notify new admin
                send_packet(clients[i].sockfd, GIVE_ADMIN, "server", old_session);
                printf("[server] Admin of '%s' transferred to '%s' (old admin left)\n",
                       old_session, clients[i].id);
                transferred = 1;
                break;
            }
        }
        if (!transferred)
            memset(sessions[sidx].admin_id, 0, MAX_NAME);
    }

    delete_session_if_empty(old_session);
}

static void broadcast_to_session(const char *session_id, const struct message *m)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].logged_in &&
            strcmp(clients[i].session_id, session_id) == 0) {
            send_message_struct(clients[i].sockfd, m);
        }
    }
}

static void build_query_response(char *out, size_t out_size)
{
    size_t used = 0;
    int n = snprintf(out, out_size, "Online users:\n");
    if (n < 0) return;
    used = (size_t)n;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].logged_in) {
            const char *sess =
                (clients[i].session_id[0] ? clients[i].session_id : "(none)");
            n = snprintf(out + used, out_size - used,
                         "  %s  [session: %s]\n", clients[i].id, sess);
            if (n < 0 || (size_t)n >= out_size - used) return;
            used += (size_t)n;
        }
    }

    n = snprintf(out + used, out_size - used, "Sessions:\n");
    if (n < 0 || (size_t)n >= out_size - used) return;
    used += (size_t)n;

    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].active) {
            // Section 2: show admin next to each session
            n = snprintf(out + used, out_size - used,
                         "  %s  [admin: %s]\n",
                         sessions[i].session_id,
                         sessions[i].admin_id[0] ? sessions[i].admin_id : "(none)");
            if (n < 0 || (size_t)n >= out_size - used) return;
            used += (size_t)n;
        }
    }
}

/*Request handlers*/
static void handle_login_req(int sockfd, const struct message *req)
{
    int cidx = find_client_index_by_sock(sockfd);
    if (cidx == -1) return;

    if (clients[cidx].logged_in) {
        send_packet(sockfd, LO_NAK, "server", "Already logged in on this socket");
        return;
    }

    if (!verify_credentials((char *)req->source, (char *)req->data)) {
        send_packet(sockfd, LO_NAK, "server", "Invalid ID or password");
        return;
    }

    if (find_client_index_by_id((char *)req->source) != -1) {
        send_packet(sockfd, LO_NAK, "server", "User already logged in");
        return;
    }

    clients[cidx].logged_in   = 1;
    strncpy(clients[cidx].id, (char *)req->source, MAX_NAME - 1);

    send_packet(sockfd, LO_ACK, "server", "");
    printf("User logged in: %s (sock %d)\n", clients[cidx].id, sockfd);
}

static void handle_join_req(int sockfd, const struct message *req)
{
    int cidx = find_client_index_by_sock(sockfd);
    if (cidx == -1) return;

    /* session ID is in data field */
    const char *sess = (char *)req->data;

    if (!clients[cidx].logged_in) {
        send_packet(sockfd, JN_NAK, "server", "Please login first");
        return;
    }

    if (clients[cidx].session_id[0] != '\0') {
        send_packet(sockfd, JN_NAK, "server", "Already in a session");
        return;
    }

    int sidx = find_session_index(sess);
    if (sidx == -1) {
        send_packet(sockfd, JN_NAK, "server", "Session does not exist");
        return;
    }

    strncpy(clients[cidx].session_id, sess, MAX_NAME - 1);
    /* send session ID back in data so client knows which session was joined */
    send_packet(sockfd, JN_ACK, "server", sess);
    printf("%s joined session %s\n", clients[cidx].id, sess);
}

static void handle_new_sess_req(int sockfd, const struct message *req)
{
    int cidx = find_client_index_by_sock(sockfd);
    if (cidx == -1) return;

    /* session ID is in data field */
    const char *sess = (char *)req->data;

    if (!clients[cidx].logged_in) {
        send_packet(sockfd, JN_NAK, "server", "Please login first");
        return;
    }

    if (clients[cidx].session_id[0] != '\0') {
        send_packet(sockfd, JN_NAK, "server", "Already in a session");
        return;
    }

    if (find_session_index(sess) != -1) {
        send_packet(sockfd, JN_NAK, "server", "Session already exists");
        return;
    }

    int sidx = create_session_if_needed(sess);
    if (sidx == -1) {
        send_packet(sockfd, JN_NAK, "server", "Server session table full");
        return;
    }

    strncpy(clients[cidx].session_id, sess, MAX_NAME - 1);
    // creator becomes admin
    strncpy(sessions[sidx].admin_id, clients[cidx].id, MAX_NAME - 1);

    /* send session ID back in data so client knows which session was created */
    send_packet(sockfd, NS_ACK, "server", sess);
    printf("%s created session %s (admin: %s)\n",
           clients[cidx].id, sess, clients[cidx].id);
}

static void handle_leave_req(int sockfd)
{
    int cidx = find_client_index_by_sock(sockfd);
    if (cidx == -1) return;
    if (!clients[cidx].logged_in) return;

    if (clients[cidx].session_id[0] != '\0') {
        printf("%s left session %s\n", clients[cidx].id, clients[cidx].session_id);
        leave_current_session(cidx);
    }
}

static void handle_message_req(int sockfd, const struct message *req)
{
    int cidx = find_client_index_by_sock(sockfd);
    if (cidx == -1) return;

    if (!clients[cidx].logged_in) return;
    if (clients[cidx].session_id[0] == '\0') return;

    struct message out;
    memset(&out, 0, sizeof out);
    out.type = MESSAGE;
    out.size = (unsigned int)strlen((char *)req->data);
    strncpy((char *)out.source, clients[cidx].id,   MAX_NAME - 1);
    strncpy((char *)out.data,   (char *)req->data,   MAX_DATA - 1);

    broadcast_to_session(clients[cidx].session_id, &out);
}

static void handle_query_req(int sockfd)
{
    char listbuf[MAX_DATA];
    memset(listbuf, 0, sizeof listbuf);

    build_query_response(listbuf, sizeof listbuf);
    send_packet(sockfd, QU_ACK, "server", listbuf);
}

// kick handler — admin only, removes target from session
static void handle_kick_req(int sockfd, const struct message *req)
{
    int cidx = find_client_index_by_sock(sockfd);
    if (cidx == -1) return;
    if (!clients[cidx].logged_in) return;
    if (clients[cidx].session_id[0] == '\0') {
        send_packet(sockfd, JN_NAK, "server", "You are not in a session");
        return;
    }

    // verify sender is admin
    int sidx = find_session_index(clients[cidx].session_id);
    if (sidx == -1 ||
        strcmp(sessions[sidx].admin_id, clients[cidx].id) != 0) {
        send_packet(sockfd, JN_NAK, "server", "You are not the admin");
        return;
    }

    const char *target_id = (char *)req->data;
    int tidx = find_client_index_by_id(target_id);
    if (tidx == -1) {
        send_packet(sockfd, JN_NAK, "server", "Target user not found");
        return;
    }
    if (strcmp(clients[tidx].session_id, clients[cidx].session_id) != 0) {
        send_packet(sockfd, JN_NAK, "server", "Target is not in your session");
        return;
    }

    // notify kicked client — data = reason
    char reason[MAX_DATA];
    snprintf(reason, sizeof reason, "Kicked by admin %s", clients[cidx].id);
    send_packet(clients[tidx].sockfd, KICK, "server", reason);

    // remove target from session
    memset(clients[tidx].session_id, 0, sizeof(clients[tidx].session_id));
    printf("[server] %s kicked %s from session %s\n",
           clients[cidx].id, target_id, sessions[sidx].session_id);
    delete_session_if_empty(sessions[sidx].session_id);
}

// give_admin handler — transfers admin role to another client
static void handle_give_admin_req(int sockfd, const struct message *req)
{
    int cidx = find_client_index_by_sock(sockfd);
    if (cidx == -1) return;
    if (!clients[cidx].logged_in) return;
    if (clients[cidx].session_id[0] == '\0') {
        send_packet(sockfd, JN_NAK, "server", "You are not in a session");
        return;
    }

    // verify sender is admin
    int sidx = find_session_index(clients[cidx].session_id);
    if (sidx == -1 ||
        strcmp(sessions[sidx].admin_id, clients[cidx].id) != 0) {
        send_packet(sockfd, JN_NAK, "server", "You are not the admin");
        return;
    }

    const char *target_id = (char *)req->data;
    int tidx = find_client_index_by_id(target_id);
    if (tidx == -1) {
        send_packet(sockfd, JN_NAK, "server", "Target user not found");
        return;
    }
    if (strcmp(clients[tidx].session_id, clients[cidx].session_id) != 0) {
        send_packet(sockfd, JN_NAK, "server", "Target is not in your session");
        return;
    }

    // transfer admin
    strncpy(sessions[sidx].admin_id, target_id, MAX_NAME - 1);
    // notify new admin — data = session name so client knows which session
    send_packet(clients[tidx].sockfd, GIVE_ADMIN, "server",
                clients[cidx].session_id);
    printf("[server] Admin of '%s' transferred from '%s' to '%s'\n",
           sessions[sidx].session_id, clients[cidx].id, target_id);
}

static void disconnect_client(int sockfd, fd_set *master)
{
    int cidx = find_client_index_by_sock(sockfd);

    if (cidx != -1) {
        if (clients[cidx].logged_in) {
            printf("Disconnecting user %s (sock %d)\n", clients[cidx].id, sockfd);
        } else {
            printf("Disconnecting anonymous client (sock %d)\n", sockfd);
        }

        if (clients[cidx].session_id[0] != '\0') {
            leave_current_session(cidx);
        }
        remove_client(cidx);
    }

    close(sockfd);
    FD_CLR(sockfd, master);
}

/*Network setup*/
static int create_listener(const char *port)
{
    struct addrinfo hints, *servinfo, *p;
    int yes = 1;
    int listener = -1;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC; //IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener == -1)
            continue;

        if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) == -1) {
            close(listener);
            listener = -1;
            continue;
        }

        if (bind(listener, p->ai_addr, p->ai_addrlen) == -1) {
            close(listener);
            listener = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL || listener == -1) {
        fprintf(stderr, "Failed to bind to port %s\n", port);
        return -1;
    }

    if (listen(listener, 10) == -1) {
        perror("listen");
        close(listener);
        return -1;
    }

    return listener;
}


int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <TCP port>\n", argv[0]);
        return 1;
    }

    int listener = create_listener(argv[1]);
    if (listener == -1) {
        return 1;
    }

    printf("ECE361 Text Conferencing Server listening on port %s\n", argv[1]);

    fd_set master, read_fds;
    FD_ZERO(&master);
    FD_ZERO(&read_fds);

    FD_SET(listener, &master);
    int fdmax = listener;

    for (;;) {
        read_fds = master;

        if (select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select");
            break;
        }

        for (int i = 0; i <= fdmax; i++) {
            if (!FD_ISSET(i, &read_fds))
                continue;

            if (i == listener) {
                /* new incoming connection */
                struct sockaddr_storage remoteaddr;
                socklen_t addrlen = sizeof remoteaddr;
                int newfd = accept(listener, (struct sockaddr *)&remoteaddr, &addrlen);
                if (newfd == -1) {
                    perror("accept");
                    continue;
                }

                int idx = add_client(newfd);
                if (idx == -1) {
                    fprintf(stderr, "Too many clients; rejecting socket %d\n", newfd);
                    close(newfd);
                    continue;
                }

                FD_SET(newfd, &master);
                if (newfd > fdmax) fdmax = newfd;

                printf("New connection accepted on socket %d\n", newfd);
            } else {
                /* request from an existing client */
                char buf[BUF_SIZE];
                memset(buf, 0, sizeof buf);

                /* single recv call — avoids blocking if client sends less than BUF_SIZE */
                int n = recv(i, buf, BUF_SIZE - 1, 0);

                if (n <= 0) {
                    if (n == 0)
                        printf("Socket %d closed connection\n", i);
                    else
                        perror("recv");

                    disconnect_client(i, &master);
                    continue;
                }

                buf[n] = '\0';

                struct message req;
                parse_message(buf, &req);

                switch (req.type) {
                    case LOGIN:
                        handle_login_req(i, &req);
                        break;

                    case EXIT:
                        disconnect_client(i, &master);
                        break;

                    case JOIN:
                        handle_join_req(i, &req);
                        break;

                    case LEAVE_SESS:
                        handle_leave_req(i);
                        break;

                    case NEW_SESS:
                        handle_new_sess_req(i, &req);
                        break;

                    case MESSAGE:
                        handle_message_req(i, &req);
                        break;

                    case QUERY:
                        handle_query_req(i);
                        break;
                    case KICK:
                        handle_kick_req(i, &req);
                        break;

                    case GIVE_ADMIN:
                        handle_give_admin_req(i, &req);
                        break;

                    default:
                        printf("Unknown packet type %u from socket %d\n", req.type, i);
                        break;
                }
            }
        }
    }

    close(listener);
    return 0;
}
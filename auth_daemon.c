#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <ctype.h>
//I add this words.
#define errExit(msg)  do { perror(msg); exit(EXIT_FAILURE); } while (0)

#include "database.h"

#define SOCKET_PATH "/tmp/auth_daemon.sock"
#define BUF_SIZE 256
#define MAX_CLIENTS 10
#define USERNAME_MAX 50
#define HASH_MAX 65
#define MIN_USERNAME_LEN 1
#define MIN_HASH_LEN 64

struct Client {
    int fd;
    char buf[BUF_SIZE];
    size_t buf_len;
};

static volatile sig_atomic_t stop_flag = 0;

static void term_handler(int sig) {
    (void)sig;
    stop_flag = 1;
}

static void skeleton_daemon()
{
    pid_t pid;

    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    if (setsid() < 0) exit(EXIT_FAILURE);

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    signal(SIGTERM, term_handler);
    signal(SIGINT, term_handler);
    signal(SIGPIPE, SIG_IGN);

    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    umask(0);
    chdir("/");

    int x;
    for (x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        close(x);
    }
}

static int is_valid_sha256_hash(const char* str) {
    if (strlen(str) != MIN_HASH_LEN) return 0;

    for (int i = 0; i < MIN_HASH_LEN; i++) {
        if (!isxdigit(str[i])) return 0;
    }
    return 1;
}

static int is_valid_username(const char* str) {
    int len = strlen(str);
    if (len < MIN_USERNAME_LEN || len >= USERNAME_MAX) return 0;

    for (int i = 0; i < len; i++) {
        if (!isalnum(str[i]) && str[i] != '_' && str[i] != '-' &&
            str[i] != '@' && str[i] != '.') {
            return 0;
        }
    }
    return 1;
}

static void process_auth_request(struct Client* client)
{
    char username[USERNAME_MAX];
    char password_hash[HASH_MAX];
    char response[BUF_SIZE];
    int auth_result;

    char* colon = strchr(client->buf, ':');
    if (colon == NULL) {
        strcpy(response, "ERROR:bad_format\n");
        goto send_response;
    }

    *colon = '\0';
    size_t username_len = strlen(client->buf);

    if (username_len == 0) {
        strcpy(response, "ERROR:empty_username\n");
        goto send_response;
    }

    if (username_len >= USERNAME_MAX) {
        strcpy(response, "ERROR:username_too_long\n");
        goto send_response;
    }

    if (!is_valid_username(client->buf)) {
        strcpy(response, "ERROR:invalid_username\n");
        goto send_response;
    }

    strncpy(username, client->buf, sizeof(username) - 1);
    username[sizeof(username) - 1] = '\0';

    char* hash_start = colon + 1;
    char* newline = strchr(hash_start, '\n');
    if (newline == NULL) {
        strcpy(response, "ERROR:no_newline\n");
        goto send_response;
    }

    size_t hash_len = newline - hash_start;

    if (hash_len == 0) {
        strcpy(response, "ERROR:empty_hash\n");
        goto send_response;
    }

    if (hash_len >= HASH_MAX) {
        strcpy(response, "ERROR:hash_too_long\n");
        goto send_response;
    }

    if (hash_len < MIN_HASH_LEN) {
        strcpy(response, "ERROR:hash_too_short\n");
        goto send_response;
    }

    strncpy(password_hash, hash_start, hash_len);
    password_hash[hash_len] = '\0';

    if (!is_valid_sha256_hash(password_hash)) {
        strcpy(response, "ERROR:invalid_hash_format\n");
        goto send_response;
    }

    PGconn *conn = db_connect();
    if (!conn) {
        strcpy(response, "ERROR:db_connection\n");
        goto send_response;
    }

    const char *check_user_query = "SELECT id FROM users WHERE username = $1";
    const char *check_user_params[1] = { username };

    PGresult *user_res = PQexecParams(conn, check_user_query, 1, NULL, check_user_params, NULL, NULL, 0);

    if (PQresultStatus(user_res) != PGRES_TUPLES_OK) {
        PQclear(user_res);
        strcpy(response, "ERROR:db_query\n");
        goto send_response;
    }

    if (PQntuples(user_res) == 0) {
        PQclear(user_res);
        strcpy(response, "USER_NOT_FOUND\n");
        goto send_response;
    }

    PQclear(user_res);

    auth_result = db_check_credentials(username, password_hash);

    if (auth_result) {
        strcpy(response, "SUCCESS\n");
    }
    else {
        strcpy(response, "INVALID_PASSWORD\n");
    }

send_response:
    send(client->fd, response, strlen(response), 0);

    client->buf_len = 0;
    memset(client->buf, 0, sizeof(client->buf));
}

static void run_daemon()
{
    int server_fd, rc;
    socklen_t len;
    struct sockaddr_un self;
    struct Client clients[MAX_CLIENTS];
    struct pollfd pfds[MAX_CLIENTS + 1];

    memset(&self, 0, sizeof(self));
    memset(clients, 0, sizeof(clients));

    for (int i = 0; i < MAX_CLIENTS; i++) {
        pfds[i].fd = -1;
        pfds[i].events = 0;
        clients[i].fd = -1;
    }

    len = sizeof(self);

    unlink(SOCKET_PATH);
    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
        errExit("socket");

    self.sun_family = AF_UNIX;
    strcpy(self.sun_path, SOCKET_PATH);

    if ((rc = bind(server_fd, (struct sockaddr*)&self, len)) == -1)
        errExit("bind");

    if ((listen(server_fd, 10)) == -1)
        errExit("listen");

    fcntl(server_fd, F_SETFL, fcntl(server_fd, F_GETFL) | O_NONBLOCK);

    pfds[MAX_CLIENTS].fd = server_fd;
    pfds[MAX_CLIENTS].events = POLLIN;

    while (!stop_flag) {
        int ready = poll(pfds, MAX_CLIENTS + 1, 1000);

        if (ready == -1) {
            if (errno == EINTR) continue;
            errExit("poll");
        }

        if (ready == 0) continue;

        if (pfds[MAX_CLIENTS].revents & POLLIN) {
            int client_fd;
            struct sockaddr_un peer_addr;
            socklen_t peer_len = sizeof(peer_addr);

            client_fd = accept(server_fd, (struct sockaddr*)&peer_addr, &peer_len);
            if (client_fd == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                errExit("accept");
            }

            int slot = -1;
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].fd == -1) {
                    slot = i;
                    break;
                }
            }

            if (slot != -1) {
                clients[slot].fd = client_fd;
                clients[slot].buf_len = 0;
                memset(clients[slot].buf, 0, sizeof(clients[slot].buf));

                fcntl(client_fd, F_SETFL, fcntl(client_fd, F_GETFL) | O_NONBLOCK);
                pfds[slot].fd = client_fd;
                pfds[slot].events = POLLIN;
            }
            else {
                close(client_fd);
            }
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (pfds[i].fd == -1) continue;

            if (pfds[i].revents & (POLLERR | POLLHUP)) {
                close(clients[i].fd);
                clients[i].fd = -1;
                pfds[i].fd = -1;
                continue;
            }

            if (pfds[i].revents & POLLIN) {
                ssize_t bytes_read = recv(clients[i].fd,
                    clients[i].buf + clients[i].buf_len,
                    sizeof(clients[i].buf) - clients[i].buf_len - 1,
                    0);

                if (bytes_read > 0) {
                    clients[i].buf_len += bytes_read;
                    clients[i].buf[clients[i].buf_len] = '\0';

                    if (strchr(clients[i].buf, '\n') != NULL) {
                        process_auth_request(&clients[i]);
                    }
                }
                else if (bytes_read == 0) {
                    close(clients[i].fd);
                    clients[i].fd = -1;
                    pfds[i].fd = -1;
                }
                else if (bytes_read == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    close(clients[i].fd);
                    clients[i].fd = -1;
                    pfds[i].fd = -1;
                }
            }
        }
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].fd != -1) close(clients[i].fd);
    }

    close(server_fd);
    unlink(SOCKET_PATH);
}

int main(void)
{
    skeleton_daemon();
    run_daemon();
    return EXIT_SUCCESS;
}

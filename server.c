#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <sys/stat.h>   
#include <sys/mman.h>   
#include <fcntl.h>    
#define GET "GET"
#define POST "POST"
#define HTTPS_HEADER "HTTP/1.0 200 OK\r\nContent-Type: text/html;charset=utf-8\r\n"
#define ERR404 "HTTP/1.1 404 Not Found\r\nContent-Type: text/html;charset=utf-8\r\n"
#define WROOT "./html"
#define INDEX "/index.html"
#define H404 "/h404.html"

#define BUFFER_SIZE 4096
#define SERVER_PORT 8443

#define MAX_USERNAME 64
#define MAX_PASSWORD 64
#define UNIX_SOCKET_PATH "/tmp/auth_daemon.sock"

void errExit(const char* msg);
int create_server_socket(int port);
SSL_CTX* create_ssl_context();
void configure_ssl_context(SSL_CTX* ctx);
void handle_client(int client_sock, SSL_CTX* ctx);
int parse_auth_data(const char* post_data, char* username, char* password);
void sha256_hash(const char* input, char* output);

void errExit(const char* msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void sha256_hash(const char* input, char* output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input, strlen(input), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + i * 2, "%02x", hash[i]);
    }
    output[SHA256_DIGEST_LENGTH * 2] = '\0';
}

int create_server_socket(int port) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) errExit("socket");

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(server_sock);
        errExit("bind");
    }

    if (listen(server_sock, 10) < 0) {
        close(server_sock);
        errExit("listen");
    }

    return server_sock;
}

SSL_CTX* create_ssl_context() {
    const SSL_METHOD* method = TLS_server_method();
    if (!method) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "Unable to create SSL context\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_ssl_context(SSL_CTX* ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load certificate\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Failed to load private key\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match certificate!\n");
        exit(EXIT_FAILURE);
    }

    printf("SSL certificate loaded successfully\n");
}

int parse_auth_data(const char* post_data, char* username, char* password) {
    char user_field[32], pass_field[32];

    if (sscanf(post_data, "%31[^=]=%63[^&]&%31[^=]=%63s",
        user_field, username,
        pass_field, password) != 4) {
        printf("Error parsing POST data: %s\n", post_data);
        return 0;
    }

    if (strcmp(user_field, "username") != 0 ||
        strcmp(pass_field, "password") != 0) {
        printf("Invalid field names in POST data\n");
        return 0;
    }

    for (char* p = username; *p; p++) if (*p == '+') *p = ' ';
    for (char* p = password; *p; p++) if (*p == '+') *p = ' ';

    printf("Parsing successful: user='%s', pass='%s'\n", username, password);
    return 1;
}

void handle_auth_request(SSL* ssl, char* post_data) {
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    char response[BUFFER_SIZE];

    printf("Authentication attempt\n");

    if (!parse_auth_data(post_data, username, password)) {
        snprintf(response, sizeof(response),
            "HTTP/1.1 400 Bad Request\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Content-Length: 55\r\n\r\n"
            "<h1>Data error</h1><a href='/'>Back</a>");
        SSL_write(ssl, response, strlen(response));
        return;
    }

    int sock;
    struct sockaddr_un addr;
    char request[256];
    char daemon_response[32];
    char password_hash[65];

    sha256_hash(password, password_hash);
    snprintf(request, sizeof(request), "%s:%s\n", username, password_hash);

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("[server] socket");
        goto auth_error;
    }

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, UNIX_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        printf("[server] Cannot connect to auth daemon\n");
        close(sock);
        goto auth_error;
    }

    ssize_t sent_bytes = send(sock, request, strlen(request), 0);
    if (sent_bytes == -1) {
        perror("[server] send to auth daemon");
        close(sock);
        goto auth_error;
    }

    memset(daemon_response, 0, sizeof(daemon_response));
    ssize_t bytes = recv(sock, daemon_response, sizeof(daemon_response) - 1, 0);
    close(sock);

    if (bytes > 0) {
        daemon_response[bytes] = '\0';
        if (strcmp(daemon_response, "SUCCESS\n") == 0) {
            snprintf(response, sizeof(response),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "Content-Length: 45\r\n\r\n"
                "<h1>Login successful!</h1><a href='/'>Home</a>");
        }
        else if (strcmp(daemon_response, "INVALID_PASSWORD\n") == 0) {
            snprintf(response, sizeof(response),
                "HTTP/1.1 401 Unauthorized\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "Content-Length: 65\r\n\r\n"
                "<h1>Invalid password</h1><p>Password is incorrect</p><a href='/'>Back</a>");
        }
        else if (strcmp(daemon_response, "USER_NOT_FOUND\n") == 0) {
            snprintf(response, sizeof(response),
                "HTTP/1.1 401 Unauthorized\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "Content-Length: 85\r\n\r\n"
                "<h1>User not found</h1><p>User '%s' does not exist</p><a href='/'>Back</a>", username);
        }
        else {
            snprintf(response, sizeof(response),
                "HTTP/1.1 401 Unauthorized\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                "Content-Length: 55\r\n\r\n"
                "<h1>Authentication failed</h1><a href='/'>Back</a>");
        }
    }
    else {
        goto auth_error;
    }

    SSL_write(ssl, response, strlen(response));
    return;

auth_error:
    snprintf(response, sizeof(response),
        "HTTP/1.1 401 Unauthorized\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: 55\r\n\r\n"
        "<h1>Authentication error</h1><a href='/'>Back</a>");
    SSL_write(ssl, response, strlen(response));
}

void serve_static_file(SSL* ssl, const char* path) {
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "%s%s", WROOT, path);

    struct stat fs;
    if (stat(full_path, &fs) < 0) {
        char error_path[512];
        snprintf(error_path, sizeof(error_path), "%s%s", WROOT, H404);

        int fd = open(error_path, O_RDONLY);
        if (fd >= 0 && stat(error_path, &fs) == 0) {
            char headers[512];
            snprintf(headers, sizeof(headers),
                "%sContent-Length: %ld\r\n\r\n", ERR404, fs.st_size);

            SSL_write(ssl, headers, strlen(headers));
            void* fmap = mmap(NULL, fs.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
            if (fmap != (void*)-1) {
                SSL_write(ssl, fmap, fs.st_size);
                munmap(fmap, fs.st_size);
            }
            close(fd);
        }
        return;
    }

    int fd = open(full_path, O_RDONLY);
    if (fd >= 0) {
        char headers[512];
        snprintf(headers, sizeof(headers),
            "%sContent-Length: %ld\r\n\r\n", HTTPS_HEADER, fs.st_size);

        SSL_write(ssl, headers, strlen(headers));
        void* fmap = mmap(NULL, fs.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (fmap != (void*)-1) {
            SSL_write(ssl, fmap, fs.st_size);
            munmap(fmap, fs.st_size);
        }
        close(fd);
        printf("File sent: %s (%ld bytes)\n", path, fs.st_size);
    }
}

void handle_client(int client_sock, SSL_CTX* ctx) {
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_sock);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_sock);
        return;
    }

    char buffer[BUFFER_SIZE];
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        SSL_free(ssl);
        close(client_sock);
        return;
    }
    buffer[bytes] = '\0';

    char method[16], path[256];
    if (sscanf(buffer, "%15s %255s", method, path) != 2) {
        SSL_free(ssl);
        close(client_sock);
        return;
    }

    printf("%s %s\n", method, path);

    if (strcmp(method, GET) == 0) {
        if (strcmp(path, "/") == 0) {
            serve_static_file(ssl, INDEX);
        }
        else {
            serve_static_file(ssl, path);
        }
    }
    else if (strcmp(method, POST) == 0 && strcmp(path, "/auth") == 0) {
        char* body = strstr(buffer, "\r\n\r\n");
        if (body) {
            body += 4;
            handle_auth_request(ssl, body);
        }
        else {
            char response[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
            SSL_write(ssl, response, strlen(response));
        }
    }
    else {
        char response[] = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
        SSL_write(ssl, response, strlen(response));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

int main() {
    printf("Starting HTTPS server (port %d)\n", SERVER_PORT);
    printf("HTML directory: %s\n", WROOT);
    printf("SSL certificate: server.crt\n");
    printf("SSL private key: server.key\n");
    printf("Auth daemon socket: %s\n", UNIX_SOCKET_PATH);
    printf("Open: https://localhost:%d\n", SERVER_PORT);
    printf("\n");

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX* ctx = create_ssl_context();
    configure_ssl_context(ctx);

    int server_sock = create_server_socket(SERVER_PORT);
    printf("Server ready for HTTPS connections\n\n");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);

        if (client_sock >= 0) {
            printf("New connection from %s\n", inet_ntoa(client_addr.sin_addr));
            handle_client(client_sock, ctx);
            close(client_sock);
            printf("Connection closed\n\n");
        }
    }

    SSL_CTX_free(ctx);
    close(server_sock);
    return 0;
}

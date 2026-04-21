#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
#include "parse.h"
#define LISO_PORT 9999
#define BUF_SIZE 4096
#define MAX_HEADER_SIZE 8192
#define INITIAL_CONN_BUF_SIZE 8192
#define STATIC_ROOT "static_site"

int sock = -1, client_sock = -1;
char buf[BUF_SIZE];

/* 在缓冲区中查找一个完整 HTTP 请求头的结束位置（\r\n\r\n） */
static int find_request_end(const char *data, int len) {
    if (data == NULL || len < 4) {
        return -1;
    }
    for (int i = 0; i <= len - 4; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n' &&
            data[i + 2] == '\r' && data[i + 3] == '\n') {
            return i + 4;
        }
    }
    return -1;
}

/* 只做 ASCII 大小写无关比较，避免为了查请求头引入哈希表或额外库 */
static int ascii_tolower(int ch) {
    if (ch >= 'A' && ch <= 'Z') {
        return ch + ('a' - 'A');
    }
    return ch;
}

/* 判断一行头部名是否等于指定名称，例如 Content-Length */
static int header_name_equals(const char *start, int len, const char *name) {
    int name_len = (int)strlen(name);

    if (len != name_len) {
        return 0;
    }
    for (int i = 0; i < len; i++) {
        if (ascii_tolower((unsigned char)start[i]) != ascii_tolower((unsigned char)name[i])) {
            return 0;
        }
    }
    return 1;
}

/*
 * 从已经完整接收的请求头中解析 Content-Length。
 * 返回 0 表示解析成功，-1 表示 Content-Length 格式错误。
 */
static int get_content_length_from_header(const char *data, int header_len, size_t *content_length) {
    int pos = 0;

    if (data == NULL || content_length == NULL || header_len < 0) {
        return -1;
    }

    *content_length = 0;

    /* 跳过请求行 */
    while (pos + 1 < header_len && !(data[pos] == '\r' && data[pos + 1] == '\n')) {
        pos++;
    }
    if (pos + 1 >= header_len) {
        return -1;
    }
    pos += 2;

    while (pos + 1 < header_len) {
        int line_start = pos;
        int colon = -1;
        int line_end = -1;

        if (data[pos] == '\r' && data[pos + 1] == '\n') {
            break;
        }

        while (pos + 1 < header_len && !(data[pos] == '\r' && data[pos + 1] == '\n')) {
            if (data[pos] == ':' && colon < 0) {
                colon = pos;
            }
            pos++;
        }
        if (pos + 1 >= header_len) {
            return -1;
        }
        line_end = pos;
        pos += 2;

        if (colon < 0) {
            continue;
        }

        int name_end = colon;
        while (name_end > line_start &&
               (data[name_end - 1] == ' ' || data[name_end - 1] == '\t')) {
            name_end--;
        }

        if (header_name_equals(data + line_start, name_end - line_start, "Content-Length")) {
            size_t value = 0;
            int value_pos = colon + 1;

            while (value_pos < line_end &&
                   (data[value_pos] == ' ' || data[value_pos] == '\t')) {
                value_pos++;
            }
            if (value_pos >= line_end) {
                return -1;
            }

            for (; value_pos < line_end; value_pos++) {
                if (data[value_pos] < '0' || data[value_pos] > '9') {
                    while (value_pos < line_end &&
                           (data[value_pos] == ' ' || data[value_pos] == '\t')) {
                        value_pos++;
                    }
                    if (value_pos == line_end) {
                        *content_length = value;
                        return 0;
                    }
                    return -1;
                }
                value = value * 10 + (size_t)(data[value_pos] - '0');
            }

            *content_length = value;
            return 0;
        }
    }

    return 0;
}

/*
 * 仅基于请求行做快速分类：
 * 1 = 支持的方法(GET/HEAD/POST)
 * 0 = 请求行格式错误
 * -1 = 方法存在但未实现（应返回 501）
 */
static int classify_request_line(const char *data, int len) {
    if (data == NULL || len <= 0) {
        return 0;
    }

    int line_end = -1;
    for (int i = 0; i < len - 1; i++) {
        if (data[i] == '\r' && data[i + 1] == '\n') {
            line_end = i;
            break;
        }
    }
    if (line_end <= 0 || line_end >= 512) {
        return 0;
    }

    char line[512];
    memcpy(line, data, (size_t)line_end);
    line[line_end] = '\0';

    char method[64], uri[4096], version[64];
    if (sscanf(line, "%63s %4095s %63s", method, uri, version) != 3) {
        return 0;
    }
    if (strncmp(version, "HTTP/", 5) != 0) {
        return 0;
    }

    if (strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0 || strcmp(method, "POST") == 0) {
        return 1;
    }

    return -1;
}

/* 确保把 len 字节全部发送出去，避免大文件一次 send 发送不完整 */
static int send_all(int fd, const void *data, size_t len) {
    const char *p = (const char *)data;
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n <= 0) {
            return -1;
        }
        sent += (size_t)n;
    }

    return 0;
}

/* 根据状态码生成最小错误响应，便于 400/403/404/500/501/505 统一返回 */
static int build_error_response(int status_code, char **out) {
    const char *response = NULL;

    switch (status_code) {
        case 400:
            response = "HTTP/1.1 400 Bad Request\r\n\r\n";
            break;
        case 403:
            response = "HTTP/1.1 403 Forbidden\r\n\r\n";
            break;
        case 404:
            response = "HTTP/1.1 404 Not Found\r\n\r\n";
            break;
        case 500:
            response = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
            break;
        case 501:
            response = "HTTP/1.1 501 Not Implemented\r\n\r\n";
            break;
        case 505:
            response = "HTTP/1.1 505 HTTP Version not supported\r\n\r\n";
            break;
        default:
            response = "HTTP/1.1 400 Bad Request\r\n\r\n";
            break;
    }

    size_t len = strlen(response);
    *out = (char *)malloc(len);
    if (*out == NULL) {
        return -1;
    }
    memcpy(*out, response, len);
    return (int)len;
}

/* 将磁盘文件相关 errno 转换为 HTTP 状态码 */
static int file_errno_to_status(int err) {
    if (err == ENOENT || err == ENOTDIR) {
        return 404;
    }
    if (err == EACCES || err == EPERM) {
        return 403;
    }
    return 500;
}

/* 根据文件扩展名推断 Content-Type，覆盖本实验静态站点会用到的类型 */
static const char *guess_mime_type(const char *path) {
    const char *ext = strrchr(path, '.');

    if (ext == NULL) {
        return "application/octet-stream";
    }
    if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0) {
        return "text/html";
    }
    if (strcmp(ext, ".css") == 0) {
        return "text/css";
    }
    if (strcmp(ext, ".png") == 0) {
        return "image/png";
    }
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) {
        return "image/jpeg";
    }
    if (strcmp(ext, ".gif") == 0) {
        return "image/gif";
    }
    if (strcmp(ext, ".txt") == 0) {
        return "text/plain";
    }

    return "application/octet-stream";
}

/* 将 URI 安全地映射到 static_site 目录，防止 ../ 路径穿越 */
static int build_static_path(const char *uri, char *path, size_t path_size) {
    char clean_uri[4096];
    size_t uri_len = 0;

    if (uri == NULL || path == NULL || path_size == 0 || uri[0] != '/') {
        return -1;
    }
    if (strstr(uri, "..") != NULL || strchr(uri, '\\') != NULL) {
        return -1;
    }

    /* 去掉查询串：/index.html?a=1 按 /index.html 处理 */
    while (uri[uri_len] != '\0' && uri[uri_len] != '?' && uri_len < sizeof(clean_uri) - 1) {
        clean_uri[uri_len] = uri[uri_len];
        uri_len++;
    }
    clean_uri[uri_len] = '\0';

    /* 访问根路径时返回默认首页 */
    if (strcmp(clean_uri, "/") == 0) {
        return snprintf(path, path_size, "%s/index.html", STATIC_ROOT) < (int)path_size ? 0 : -1;
    }

    return snprintf(path, path_size, "%s%s", STATIC_ROOT, clean_uri) < (int)path_size ? 0 : -1;
}

/*
 * 根据解析后的 Request 构造完整响应：
 * GET/HEAD 返回静态文件响应，POST 原样 echo 完整请求，其余错误返回标准状态码。
 * 由于图片等静态文件可能超过 4096 字节，这里动态分配 out，调用方负责 free。
 */
static int build_encapsulated_request(const Request *request,
                                      const char *raw_request,
                                      size_t raw_request_len,
                                      char **out) {
    if (request == NULL || out == NULL) {
        return -1;
    }

    *out = NULL;

    /* 第二阶段只支持 HTTP/1.1，其他 HTTP 版本返回 505 */
    if (strcmp(request->http_version, "HTTP/1.1") != 0) {
        return build_error_response(505, out);
    }

    /* GET/HEAD：从 static_site 中读取静态文件并构造 HTTP 响应 */
    if (strcmp(request->http_method, "GET") == 0 || strcmp(request->http_method, "HEAD") == 0) {
        char path[4096];
        struct stat st;
        int is_head = strcmp(request->http_method, "HEAD") == 0;

        if (build_static_path(request->http_uri, path, sizeof(path)) != 0) {
            return build_error_response(400, out);
        }
        if (stat(path, &st) != 0) {
            /* stat 失败时区分不存在、权限不足和其他磁盘/路径错误 */
            int status = file_errno_to_status(errno);
            return build_error_response(status, out);
        }
        if (!S_ISREG(st.st_mode) || st.st_size < 0) {
            /* 目录、设备文件等都不是本实验要服务的普通静态文件 */
            return build_error_response(404, out);
        }

        const char *mime = guess_mime_type(path);
        char header[1024];
        int header_len = snprintf(header, sizeof(header),
                                  "HTTP/1.1 200 OK\r\n"
                                  "Server: Liso/1.0\r\n"
                                  "Content-Length: %ld\r\n"
                                  "Content-Type: %s\r\n"
                                  "Connection: keep-alive\r\n"
                                  "\r\n",
                                  (long)st.st_size, mime);
        if (header_len < 0 || (size_t)header_len >= sizeof(header)) {
            return -1;
        }

        size_t body_len = is_head ? 0 : (size_t)st.st_size;
        size_t total_len = (size_t)header_len + body_len;
        *out = (char *)malloc(total_len);
        if (*out == NULL) {
            return build_error_response(500, out);
        }
        memcpy(*out, header, (size_t)header_len);

        /* HEAD 只返回响应头，不能把文件正文发给客户端 */
        if (is_head) {
            return header_len;
        }

        FILE *fp = fopen(path, "rb");
        if (fp == NULL) {
            /* fopen 失败时同样区分权限、文件消失和其他 IO 错误 */
            int status = file_errno_to_status(errno);
            free(*out);
            *out = NULL;
            return build_error_response(status, out);
        }

        size_t read_len = fread(*out + header_len, 1, body_len, fp);
        int read_failed = ferror(fp);
        fclose(fp);
        if (read_len != body_len) {
            /* fread 短读或底层 IO 错误都说明磁盘读取失败，返回 500 而不是静默断连 */
            (void)read_failed;
            free(*out);
            *out = NULL;
            return build_error_response(500, out);
        }

        return (int)total_len;
    }

    /* POST：按实验要求 echo 返回。这里直接返回原始请求，包含请求体 body。 */
    if (strcmp(request->http_method, "POST") == 0) {
        if (raw_request == NULL || raw_request_len == 0) {
            return -1;
        }
        *out = (char *)malloc(raw_request_len);
        if (*out == NULL) {
            return -1;
        }
        memcpy(*out, raw_request, raw_request_len);
        return (int)raw_request_len;
    }

    /* 理论上 classify_request_line 已经拦截未知方法，这里兜底返回 501 */
    return build_error_response(501, out);
}

int close_socket(int sock) {
    if (close(sock)) {
        fprintf(stderr, "Failed closing socket.\n");
        return 1;
    }
    return 0;
}
void handle_signal(const int sig) {
    if (sock != -1) {
        fprintf(stderr, "\nReceived signal %d. Closing socket.\n", sig);
        close_socket(sock);
    }
    exit(0);
}
void handle_sigpipe(const int sig) 
{
    if (sock != -1) {
        return;
    }
    exit(0);
}
int main(int argc, char *argv[]) {
    /* register signal handler */
    /* process termination signals */
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGSEGV, handle_signal);
    signal(SIGABRT, handle_signal);
    signal(SIGQUIT, handle_signal);
    signal(SIGTSTP, handle_signal);
    signal(SIGFPE, handle_signal);
    signal(SIGHUP, handle_signal);
    /* normal I/O event */
    signal(SIGPIPE, handle_sigpipe);
    socklen_t cli_size;
    struct sockaddr_in addr, cli_addr;
    fprintf(stdout, "----- Liso Server -----\n");

    /* all networked programs must create a socket */
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "Failed creating socket.\n");
        return EXIT_FAILURE;
    }
    /* set socket SO_REUSEADDR | SO_REUSEPORT */
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        fprintf(stderr, "Failed setting socket options.\n");
        return EXIT_FAILURE;
    }

    addr.sin_family = AF_INET; // ipv4
    addr.sin_port = htons(LISO_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* servers bind sockets to ports---notify the OS they accept connections */
    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr))) {
        close_socket(sock);
        fprintf(stderr, "Failed binding socket.\n");
        return EXIT_FAILURE;
    }

    if (listen(sock, 5)) {
        close_socket(sock);
        fprintf(stderr, "Error listening on socket.\n");
        return EXIT_FAILURE;
    }

    /* finally, loop waiting for input and then write it back */

    while (1) {
        /* listen for new connection */
        cli_size = sizeof(cli_addr);
        fprintf(stdout,"Waiting for connection...\n");
        client_sock = accept(sock, (struct sockaddr *) &cli_addr, &cli_size);
        if (client_sock == -1)
        {
            fprintf(stderr, "Error accepting connection.\n");
            close_socket(sock);
            return EXIT_FAILURE;
        }
        fprintf(stdout,"New connection from %s:%d\n",inet_ntoa(cli_addr.sin_addr),ntohs(cli_addr.sin_port));
        char *conn_buf = (char *)malloc(INITIAL_CONN_BUF_SIZE);
        size_t conn_cap = INITIAL_CONN_BUF_SIZE;
        size_t conn_len = 0;
        int close_connection = 0;

        if (conn_buf == NULL) {
            close_socket(client_sock);
            continue;
        }

        while(1){

            int readret = recv(client_sock, buf, BUF_SIZE, 0);
            if (readret < 0) {
                break;
            }
            if (readret == 0) {
                /* 对端关闭连接时若仍有残缺报文，按格式错误处理 */
                if (conn_len > 0) {
                    const char *bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
                    send(client_sock, bad_request, strlen(bad_request), 0);
                }
                break;
            }

            if (conn_len + (size_t)readret > conn_cap) {
                size_t need = conn_len + (size_t)readret;
                size_t new_cap = conn_cap;
                char *new_buf = NULL;

                /* 缓冲区只表示连接内暂存数据，不再把 body 大于 8192 当成头部错误 */
                while (new_cap < need) {
                    if (new_cap > (size_t)INT_MAX / 2) {
                        new_cap = need;
                        break;
                    }
                    new_cap *= 2;
                }

                new_buf = (char *)realloc(conn_buf, new_cap);
                if (new_buf == NULL) {
                    const char *bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
                    send(client_sock, bad_request, strlen(bad_request), 0);
                    break;
                }
                conn_buf = new_buf;
                conn_cap = new_cap;
            }

            memcpy(conn_buf + conn_len, buf, (size_t)readret);
            conn_len += (size_t)readret;
            fprintf(stdout,"Received (total %zu bytes in conn buffer):\n%.*s\n",
                    conn_len, (int)(conn_len > (size_t)INT_MAX ? (size_t)INT_MAX : conn_len), conn_buf);

            /* 关键逻辑：同一次 recv 中可能包含多个请求，循环逐个切分处理 */
            while (1) {
                int header_len = find_request_end(conn_buf, (int)conn_len);
                size_t content_length = 0;
                size_t full_req_len = 0;

                if (header_len < 0) {
                    /* 只在请求头尚未结束且已经超过 8192 字节时返回 400 */
                    if (conn_len > MAX_HEADER_SIZE) {
                        const char *bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
                        send(client_sock, bad_request, strlen(bad_request), 0);
                        conn_len = 0;
                        close_connection = 1;
                    }
                    break;
                }

                /* 头部长度超过 8192 字节才算本条要求中的 header too large */
                if (header_len > MAX_HEADER_SIZE ||
                    get_content_length_from_header(conn_buf, header_len, &content_length) != 0) {
                    const char *bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
                    send(client_sock, bad_request, strlen(bad_request), 0);
                    conn_len = 0;
                    close_connection = 1;
                    break;
                }

                if (content_length > (size_t)INT_MAX || (size_t)header_len > (size_t)INT_MAX - content_length) {
                    const char *bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
                    send(client_sock, bad_request, strlen(bad_request), 0);
                    conn_len = 0;
                    close_connection = 1;
                    break;
                }

                full_req_len = (size_t)header_len + content_length;
                if (full_req_len > conn_len) {
                    /* 请求头已经完整，但 body 还没收完，继续 recv */
                    break;
                }

                int request_type = classify_request_line(conn_buf, header_len);
                if (request_type == 0) {
                    const char *bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
                    if (send(client_sock, bad_request, strlen(bad_request), 0) < 0) {
                        conn_len = 0;
                        break;
                    }
                } else if (request_type == -1) {
                    const char *not_impl = "HTTP/1.1 501 Not Implemented\r\n\r\n";
                    if (send(client_sock, not_impl, strlen(not_impl), 0) < 0) {
                        conn_len = 0;
                        break;
                    }
                } else {
                    Request *request = parse(conn_buf, header_len, client_sock);
                    if (request == NULL) {
                        const char *bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
                        if (send(client_sock, bad_request, strlen(bad_request), 0) < 0) {
                            conn_len = 0;
                            break;
                        }
                        if (full_req_len < conn_len) {
                            memmove(conn_buf, conn_buf + full_req_len, conn_len - full_req_len);
                        }
                        conn_len -= full_req_len;
                        continue;
                    }

                    char *response = NULL;
                    int response_len = -1;

                    response_len = build_encapsulated_request(request, conn_buf, full_req_len, &response);

                    if (response_len <= 0 || response == NULL ||
                        send_all(client_sock, response, (size_t)response_len) < 0) {
                        free(response);
                        free(request->headers);
                        free(request);
                        conn_len = 0;
                        break;
                    }

                    fprintf(stdout,"Send response for method: %s\n", request->http_method);
                    free(response);
                    free(request->headers);
                    free(request);
                }

                /* 丢弃已处理请求，继续解析剩余字节 */
                if (full_req_len < conn_len) {
                    memmove(conn_buf, conn_buf + full_req_len, conn_len - full_req_len);
                }
                conn_len -= full_req_len;
            }

            if (close_connection) {
                break;
            }

            /* when client is closing the connection：
                FIN of client carrys empty，so recv() return 0
                ACK of server only carrys response data, so send() return 11
                ACK of client carrys empty, so recv() return 0
                Then server finishes closing the connection, recv() and send() return -1 */
        }
        free(conn_buf);
        /* client closes the connection. server free resources and listen again */
        if (close_socket(client_sock))
        {
            close_socket(sock);
            fprintf(stderr, "Error closing client socket.\n");
            return EXIT_FAILURE;
        }
        fprintf(stdout,"Closed connection from %s:%d\n",inet_ntoa(cli_addr.sin_addr),ntohs(cli_addr.sin_port));
    }
    close_socket(sock);
    return EXIT_SUCCESS;
}

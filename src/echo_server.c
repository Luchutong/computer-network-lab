#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include "parse.h"
#define ECHO_PORT 9999
#define BUF_SIZE 4096

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

/*把 parse 产生的结构化请求 Request，重新拼装成一段完整的 HTTP 请求文本，写入调用方提供的输出缓冲区。
 *封装函数
 */
static int build_encapsulated_request(const Request *request, char *out, size_t out_size) {
    
    if (request == NULL || out == NULL || out_size == 0) {
        return -1;
    }
    //写入缓存
    int written = snprintf(out, out_size, "%s %s %s\r\n",
                           request->http_method,
                           request->http_uri,
                           request->http_version);
    if (written < 0 || (size_t) written >= out_size) {
        return -1;
    }

    size_t offset = (size_t) written;
    //写入请求体，并用offset偏移量来记录已经写入的字节数，确保不会越界
    for (int i = 0; i < request->header_count; i++) {
        written = snprintf(out + offset, out_size - offset, "%s: %s\r\n",
                           request->headers[i].header_name,
                           request->headers[i].header_value);
        if (written < 0 || (size_t) written >= out_size - offset) {
            return -1;
        }
        offset += (size_t) written;
    }

    written = snprintf(out + offset, out_size - offset, "\r\n");
    if (written < 0 || (size_t) written >= out_size - offset) {
        return -1;
    }
    //返回总的字节数
    return (int) (offset + (size_t) written);
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
    fprintf(stdout, "----- Echo Server -----\n");

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
    addr.sin_port = htons(ECHO_PORT);
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
        char conn_buf[BUF_SIZE * 2];
        int conn_len = 0;

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

            if (conn_len + readret > (int)sizeof(conn_buf)) {
                /* 缓冲区不足说明本次消息无法形成可处理请求，直接返回 400 */
                const char *bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
                send(client_sock, bad_request, strlen(bad_request), 0);
                break;
            }

            memcpy(conn_buf + conn_len, buf, (size_t)readret);
            conn_len += readret;
            fprintf(stdout,"Received (total %d bytes in conn buffer):\n%.*s\n", conn_len, conn_len, conn_buf);

            /* 关键逻辑：同一次 recv 中可能包含多个请求，循环逐个切分处理 */
            while (1) {
                int req_len = find_request_end(conn_buf, conn_len);
                if (req_len < 0) {
                    break;
                }

                int request_type = classify_request_line(conn_buf, req_len);
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
                    Request *request = parse(conn_buf, req_len, client_sock);
                    if (request == NULL) {
                        const char *bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
                        if (send(client_sock, bad_request, strlen(bad_request), 0) < 0) {
                            conn_len = 0;
                            break;
                        }
                        if (req_len < conn_len) {
                            memmove(conn_buf, conn_buf + req_len, (size_t)(conn_len - req_len));
                        }
                        conn_len -= req_len;
                        continue;
                    }

                    char response[BUF_SIZE];
                    int response_len = -1;

                    response_len = build_encapsulated_request(request, response, sizeof(response));

                    if (response_len <= 0 || send(client_sock, response, (size_t)response_len, 0) < 0) {
                        free(request->headers);
                        free(request);
                        conn_len = 0;
                        break;
                    }

                    fprintf(stdout,"Send response for method: %s\n", request->http_method);
                    free(request->headers);
                    free(request);
                }

                /* 丢弃已处理请求，继续解析剩余字节 */
                if (req_len < conn_len) {
                    memmove(conn_buf, conn_buf + req_len, (size_t)(conn_len - req_len));
                }
                conn_len -= req_len;
            }

            /* when client is closing the connection：
                FIN of client carrys empty，so recv() return 0
                ACK of server only carrys"(echo back)", so send() return 11
                ACK of client carrys empty, so recv() return 0
                Then server finishes closing the connection, recv() and send() return -1 */
        }
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

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
        while(1){
            
            memset(buf, 0, BUF_SIZE);
            int readret = recv(client_sock, buf, BUF_SIZE, 0);
            if (readret <= 0) break;
            fprintf(stdout,"Received (total %d bytes):\n%.*s\n",readret,readret,buf);

            Request *request = parse(buf, readret, client_sock);
            if (request == NULL) {
                const char *bad_request = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
                send(client_sock, bad_request, strlen(bad_request), 0);
                break;
            }

            char response[BUF_SIZE];
            int response_len = -1;
            if (strcmp(request->http_method, "GET") == 0 ||
                strcmp(request->http_method, "HEAD") == 0 ||
                strcmp(request->http_method, "POST") == 0) {
                response_len = build_encapsulated_request(request, response, sizeof(response));
            } else {
                response_len = snprintf(response, sizeof(response),
                                        "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n");
            }
            
            if (response_len <= 0 || send(client_sock, response, (size_t) response_len, 0) < 0) {
                free(request->headers);
                free(request);
                break;
            }

            fprintf(stdout,"Send encapsulated response for method: %s\n", request->http_method);
            free(request->headers);
            free(request);
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

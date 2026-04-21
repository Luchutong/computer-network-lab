/******************************************************************************
* liso_client.c                                                               *
*                                                                             *
* Description: This file contains the C source code for an echo client.  The  *
*              client connects to an arbitrary <host,port> and sends input    *
*              from stdin.                                                    *
*                                                                             *
* Authors: Athula Balachandran <abalacha@cs.cmu.edu>,                         *
*          Wolf Richter <wolf@cs.cmu.edu>                                     *
*                                                                             *
*******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/time.h>

#define LISO_PORT 9999
#define BUF_SIZE 4096

/* 从文件或标准输入中读取完整请求内容，调用方负责 free(*out) */
static int read_request(FILE *input, char **out, size_t *out_len)
{
    size_t capacity = BUF_SIZE;
    size_t len = 0;
    char *data = malloc(capacity);

    if (data == NULL) {
        return -1;
    }

    while (1) {
        if (len == capacity) {
            size_t new_capacity = capacity * 2;
            char *new_data = realloc(data, new_capacity);
            if (new_data == NULL) {
                free(data);
                return -1;
            }
            data = new_data;
            capacity = new_capacity;
        }

        size_t n = fread(data + len, 1, capacity - len, input);
        len += n;

        if (n == 0) {
            if (ferror(input)) {
                free(data);
                return -1;
            }
            break;
        }
    }

    *out = data;
    *out_len = len;
    return 0;
}

/* 确保完整发送请求，避免一次 send 只发送了部分字节 */
static int send_all(int sock, const char *data, size_t len)
{
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(sock, data + sent, len - sent, 0);
        if (n <= 0) {
            return -1;
        }
        sent += (size_t)n;
    }

    return 0;
}

int main(int argc, char* argv[])
{
    if (argc != 3 && argc != 4)
    {
        fprintf(stderr, "usage: %s <server-ip> <port> [request-file]\n", argv[0]);
        return EXIT_FAILURE;
    }

    char buf[BUF_SIZE];
    FILE *input = stdin;
    char *msg = NULL;
    size_t total_to_send = 0;
        
    int status, sock;
    struct addrinfo hints;
	memset(&hints, 0, sizeof(struct addrinfo));
    struct addrinfo *servinfo; //will point to the results
    hints.ai_family = AF_INET;  //IPv4
    hints.ai_socktype = SOCK_STREAM; //TCP stream sockets
    hints.ai_flags = AI_PASSIVE; //fill in my IP for me

    if ((status = getaddrinfo(argv[1], argv[2], &hints, &servinfo)) != 0) 
    {
        fprintf(stderr, "getaddrinfo error: %s \n", gai_strerror(status));
        return EXIT_FAILURE;
    }

    if((sock = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol)) == -1)
    {
        fprintf(stderr, "Socket failed");
        return EXIT_FAILURE;
    }
    
    if (connect (sock, servinfo->ai_addr, servinfo->ai_addrlen) == -1)
    {
        fprintf(stderr, "Connect");
        return EXIT_FAILURE;
    }

    /* 第三个参数存在时，从请求文件读取；否则保持原行为，从 stdin 读取 */
    if (argc == 4) {
        input = fopen(argv[3], "rb");
        if (input == NULL) {
            fprintf(stderr, "Failed opening request file: %s\n", argv[3]);
            freeaddrinfo(servinfo);
            close(sock);
            return EXIT_FAILURE;
        }
    }

    if (read_request(input, &msg, &total_to_send) != 0) {
        fprintf(stderr, "Failed reading request.\n");
        if (input != stdin) {
            fclose(input);
        }
        freeaddrinfo(servinfo);
        close(sock);
        return EXIT_FAILURE;
    }
    if (input != stdin) {
        fclose(input);
    }

    int bytes_received;
    fprintf(stdout, "Sending %.*s", (int)total_to_send, msg);
    if (send_all(sock, msg, total_to_send) != 0) {
        fprintf(stderr, "Send failed.\n");
        free(msg);
        freeaddrinfo(servinfo);
        close(sock);
        return EXIT_FAILURE;
    }

    /*
     * HTTP/1.1 默认长连接，服务端可能不会主动断开。
     * 设置接收超时，让客户端在一小段时间内收完响应后自行退出。
     */
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    fprintf(stdout, "Received ");
    while ((bytes_received = recv(sock, buf, BUF_SIZE, 0)) > 0)
    {
        fwrite(buf, 1, (size_t)bytes_received, stdout);
    }

    free(msg);
    freeaddrinfo(servinfo);
    close(sock);    
    return EXIT_SUCCESS;
}

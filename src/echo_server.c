#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <limits.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include "parse.h"
#define LISO_PORT 9999
#define BUF_SIZE 4096
#define MAX_HEADER_SIZE 8192
#define INITIAL_CONN_BUF_SIZE 8192
#define MAX_CLIENTS 1024
#define STATIC_ROOT "static_site"
#define LOG_DIR "logs"
#define ACCESS_LOG_PATH "logs/access.log"
#define ERROR_LOG_PATH "logs/error.log"
#define RESPONSE_400 "HTTP/1.1 400 Bad Request\r\n\r\n"
#define RESPONSE_403 "HTTP/1.1 403 Forbidden\r\n\r\n"
#define RESPONSE_404 "HTTP/1.1 404 Not Found\r\n\r\n"
#define RESPONSE_500 "HTTP/1.1 500 Internal Server Error\r\n\r\n"
#define RESPONSE_501 "HTTP/1.1 501 Not Implemented\r\n\r\n"
#define RESPONSE_505 "HTTP/1.1 505 HTTP Version not supported\r\n\r\n"

int sock = -1;

typedef enum {
    PIPELINE_NEED_MORE = 0,
    PIPELINE_READY,
    PIPELINE_BAD_REQUEST,
    PIPELINE_FATAL_ERROR
} PipelineStatus;

typedef struct {
    int header_len;
    size_t content_length;
    size_t full_len;
} PipelineRequestSlice;

typedef struct {
    int fd;
    int active;
    struct sockaddr_in addr;
    char *conn_buf;
    size_t conn_len;
    size_t conn_cap;
} ClientConn;

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

/* 判断 HTTP 版本字段是否是 HTTP/<数字>.<数字> 的合法形态 */
static int http_version_has_valid_shape(const char *version) {
    int pos = 5;
    int major_digits = 0;
    int minor_digits = 0;

    if (version == NULL || strncmp(version, "HTTP/", 5) != 0) {
        return 0;
    }

    while (version[pos] >= '0' && version[pos] <= '9') {
        major_digits++;
        pos++;
    }
    if (major_digits == 0 || version[pos] != '.') {
        return 0;
    }
    pos++;

    while (version[pos] >= '0' && version[pos] <= '9') {
        minor_digits++;
        pos++;
    }

    return minor_digits > 0 && version[pos] == '\0';
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
 * 从连接缓冲区头部提取一条 pipeline 请求的边界。
 * 第三阶段的关键是：每次只处理缓冲区最前面的一条请求，响应后再消费它，
 * 这样天然保证 HTTP pipelining 的响应顺序与请求顺序一致。
 */
static PipelineStatus extract_pipeline_request(const char *data,
                                               size_t data_len,
                                               PipelineRequestSlice *slice) {
    int header_len;
    size_t content_length = 0;

    if (data == NULL || slice == NULL) {
        return PIPELINE_FATAL_ERROR;
    }
    memset(slice, 0, sizeof(*slice));

    /*
     * find_request_end() 使用 int 长度。正常测试不会接近 INT_MAX；
     * 如果真的超过，说明缓冲区已经不可控，直接按致命错误关闭连接。
     */
    if (data_len > (size_t)INT_MAX) {
        return PIPELINE_FATAL_ERROR;
    }

    header_len = find_request_end(data, (int)data_len);
    if (header_len < 0) {
        /*
         * 请求头还没收完整时不能处理；但如果头部已经超过 8192 字节，
         * 无法可靠找到下一条请求起点，只能返回 400 后关闭当前连接。
         */
        if (data_len > MAX_HEADER_SIZE) {
            return PIPELINE_FATAL_ERROR;
        }
        return PIPELINE_NEED_MORE;
    }

    slice->header_len = header_len;
    slice->full_len = (size_t)header_len;

    /*
     * 已经找到 \r\n\r\n 时，即使当前请求头非法，也至少能消费这段头部。
     * 这样中间某条请求出错时，后续 pipeline 请求仍有机会被继续解析。
     */
    if (header_len > MAX_HEADER_SIZE ||
        get_content_length_from_header(data, header_len, &content_length) != 0) {
        return PIPELINE_BAD_REQUEST;
    }

    if (content_length > (size_t)INT_MAX ||
        (size_t)header_len > (size_t)INT_MAX - content_length) {
        return PIPELINE_BAD_REQUEST;
    }

    slice->content_length = content_length;
    slice->full_len = (size_t)header_len + content_length;
    if (slice->full_len > data_len) {
        /* 请求头完整但 POST body 还没收完，继续等待 recv()。 */
        return PIPELINE_NEED_MORE;
    }

    return PIPELINE_READY;
}

/* 消费已经处理完的一条请求，把后续 pipeline 请求移动到缓冲区开头 */
static void discard_consumed_bytes(char *data, size_t *data_len, size_t consume_len) {
    if (data == NULL || data_len == NULL || consume_len == 0) {
        return;
    }

    if (consume_len >= *data_len) {
        *data_len = 0;
        return;
    }

    memmove(data, data + consume_len, *data_len - consume_len);
    *data_len -= consume_len;
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
    if (data[0] == ' ' || data[0] == '\t') {
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
    int consumed = 0;

    if (sscanf(line, "%63s %4095s %63s %n", method, uri, version, &consumed) != 3) {
        return 0;
    }
    /* 请求行只能有 method、uri、version 三段，多余字段属于格式错误 */
    if (consumed != line_end) {
        return 0;
    }
    if (!http_version_has_valid_shape(version)) {
        return 0;
    }

    if (strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0 || strcmp(method, "POST") == 0) {
        return 1;
    }

    return -1;
}

/* 释放原始解析器创建的 Request，集中处理可减少错误分支里的重复代码 */
static void free_request(Request *request) {
    if (request == NULL) {
        return;
    }
    free(request->headers);
    free(request);
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

/* 启动时创建日志目录；目录已存在不是错误 */
static void init_logs(void) {
    if (mkdir(LOG_DIR, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "Failed creating log directory: %s\n", strerror(errno));
    }
}

/* Apache Error Log 风格时间，例如 Wed Apr 22 12:34:56 2026 */
static void format_error_time(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm tm_now;

    localtime_r(&now, &tm_now);
    strftime(buf, size, "%a %b %d %H:%M:%S %Y", &tm_now);
}

/* Apache Common Log Format 时间，例如 22/Apr/2026:12:34:56 +0800 */
static void format_access_time(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm tm_now;

    localtime_r(&now, &tm_now);
    strftime(buf, size, "%d/%b/%Y:%H:%M:%S %z", &tm_now);
}

/* 记录服务器错误：格式近似 Apache Error Log */
static void log_error_message(const char *fmt, ...) {
    FILE *fp = fopen(ERROR_LOG_PATH, "a");
    char time_buf[64];
    va_list args;

    if (fp == NULL) {
        return;
    }

    format_error_time(time_buf, sizeof(time_buf));
    fprintf(fp, "[%s] [error] ", time_buf);

    va_start(args, fmt);
    vfprintf(fp, fmt, args);
    va_end(args);

    fprintf(fp, "\n");
    fclose(fp);
}

/* 从原始请求头中取出请求行，用于 access.log 的 "%r" 字段 */
static void extract_request_line(const char *data, int len, char *out, size_t out_size) {
    size_t i = 0;

    if (out == NULL || out_size == 0) {
        return;
    }
    out[0] = '\0';

    if (data == NULL || len <= 0) {
        snprintf(out, out_size, "-");
        return;
    }

    while (i + 1 < (size_t)len && i < out_size - 1) {
        if (data[i] == '\r' && data[i + 1] == '\n') {
            break;
        }
        out[i] = data[i];
        i++;
    }
    out[i] = '\0';

    if (out[0] == '\0') {
        snprintf(out, out_size, "-");
    }
}

/* 客户端关闭时若缓冲区只剩空白行，说明不是新请求，不应额外记一次 400 */
static int buffer_is_only_blank(const char *data, size_t len) {
    if (data == NULL) {
        return 1;
    }

    for (size_t i = 0; i < len; i++) {
        if (data[i] != '\r' && data[i] != '\n' &&
            data[i] != ' ' && data[i] != '\t') {
            return 0;
        }
    }
    return 1;
}

/* 记录访问日志：Common Log Format，即 host ident user [time] "request" status bytes */
static void log_access_request(const struct sockaddr_in *cli_addr,
                               const char *request_line,
                               int status_code,
                               size_t bytes_sent) {
    FILE *fp = fopen(ACCESS_LOG_PATH, "a");
    char ip[INET_ADDRSTRLEN];
    char time_buf[64];
    const char *line = request_line;

    if (fp == NULL) {
        return;
    }

    if (cli_addr == NULL ||
        inet_ntop(AF_INET, &cli_addr->sin_addr, ip, sizeof(ip)) == NULL) {
        snprintf(ip, sizeof(ip), "0.0.0.0");
    }
    if (line == NULL || line[0] == '\0') {
        line = "-";
    }

    format_access_time(time_buf, sizeof(time_buf));
    fprintf(fp, "%s - - [%s] \"%s\" %d %zu\n",
            ip, time_buf, line, status_code, bytes_sent);
    fclose(fp);
}

/* 从 HTTP 响应状态行中提取状态码；POST echo 没有状态行时按成功处理 */
static int response_status_code(const char *response, int response_len) {
    int status_code = 200;
    int line_len = 0;
    char status_line[128];

    if (response == NULL || response_len <= 0 || strncmp(response, "HTTP/", 5) != 0) {
        return 200;
    }

    /*
     * response 可能是“响应头 + 二进制正文”的缓冲区，并不保证以 '\0' 结尾。
     * 先只复制状态行，再用 sscanf 解析，避免 pipeline 下连续响应时越界读取。
     */
    while (line_len < response_len &&
           line_len < (int)sizeof(status_line) - 1 &&
           !(response[line_len] == '\r' &&
             line_len + 1 < response_len &&
             response[line_len + 1] == '\n')) {
        status_line[line_len] = response[line_len];
        line_len++;
    }
    status_line[line_len] = '\0';

    if (sscanf(status_line, "HTTP/%*s %d", &status_code) == 1) {
        return status_code;
    }

    return 200;
}

/* Common Log Format 的 bytes 字段按响应体长度记录，不包含响应头 */
static size_t response_body_bytes(const char *response, int response_len) {
    int header_len;

    if (response == NULL || response_len <= 0) {
        return 0;
    }
    if (strncmp(response, "HTTP/", 5) != 0) {
        return (size_t)response_len;
    }

    header_len = find_request_end(response, response_len);
    if (header_len < 0 || header_len > response_len) {
        return 0;
    }

    return (size_t)(response_len - header_len);
}

/* HTTP/1.1 请求必须带 Host 头，头名大小写不敏感 */
static int request_has_host_header(const Request *request) {
    if (request == NULL) {
        return 0;
    }

    for (int i = 0; i < request->header_count; i++) {
        int name_len = (int)strlen(request->headers[i].header_name);
        if (header_name_equals(request->headers[i].header_name, name_len, "Host")) {
            return 1;
        }
    }

    return 0;
}

/* 根据状态码生成最小错误响应，便于 400/403/404/500/501/505 统一返回 */
static int build_error_response(int status_code, char **out) {
    const char *response = NULL;

    switch (status_code) {
        case 400:
            response = RESPONSE_400;
            break;
        case 403:
            response = RESPONSE_403;
            break;
        case 404:
            response = RESPONSE_404;
            break;
        case 500:
            response = RESPONSE_500;
            break;
        case 501:
            response = RESPONSE_501;
            break;
        case 505:
            response = RESPONSE_505;
            break;
        default:
            response = RESPONSE_400;
            break;
    }

    size_t len = strlen(response);
    *out = (char *)malloc(len + 1);
    if (*out == NULL) {
        return -1;
    }
    memcpy(*out, response, len);
    (*out)[len] = '\0';
    return (int)len;
}

/* 统一发送错误响应，保证 pipeline 中的每个错误响应也不会因为短写而丢字节 */
static int send_error_response(int fd, int status_code) {
    char *response = NULL;
    int response_len = build_error_response(status_code, &response);
    int ret = 0;

    if (response_len <= 0 || response == NULL) {
        return -1;
    }

    ret = send_all(fd, response, (size_t)response_len);
    free(response);

    return ret == 0 ? response_len : -1;
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

/* 将 URI 安全地映射到 static_site 目录，防止 ../ 路径穿越；-2 表示非法路径 */
static int build_static_path(const char *uri, char *path, size_t path_size) {
    char clean_uri[4096];
    size_t uri_len = 0;

    if (uri == NULL || path == NULL || path_size == 0 || uri[0] != '/') {
        return -1;
    }
    if (strstr(uri, "..") != NULL || strchr(uri, '\\') != NULL) {
        return -2;
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

    /*
     * 第四阶段性能测试常用 ApacheBench，其默认请求为 HTTP/1.0。
     * 这里兼容 HTTP/1.0 和 HTTP/1.1；其它形态合法但不支持的版本仍返回 505。
     */
    if (strcmp(request->http_version, "HTTP/1.1") != 0 &&
        strcmp(request->http_version, "HTTP/1.0") != 0) {
        return build_error_response(505, out);
    }

    /* HTTP/1.1 要求必须出现 Host 头；HTTP/1.0 兼容模式下不强制该字段 */
    if (strcmp(request->http_version, "HTTP/1.1") == 0 &&
        !request_has_host_header(request)) {
        log_error_message("HTTP/1.1 request missing Host header");
        return build_error_response(400, out);
    }

    /* GET/HEAD：从 static_site 中读取静态文件并构造 HTTP 响应 */
    if (strcmp(request->http_method, "GET") == 0 || strcmp(request->http_method, "HEAD") == 0) {
        char path[4096];
        struct stat st;
        int is_head = strcmp(request->http_method, "HEAD") == 0;
        int is_http10 = strcmp(request->http_version, "HTTP/1.0") == 0;
        const char *connection_value = is_http10 ? "close" : "keep-alive";

        int path_result = build_static_path(request->http_uri, path, sizeof(path));
        if (path_result != 0) {
            log_error_message("invalid static path for uri \"%s\"", request->http_uri);
            return build_error_response(path_result == -2 ? 404 : 400, out);
        }
        if (stat(path, &st) != 0) {
            /* stat 失败时区分不存在、权限不足和其他磁盘/路径错误 */
            log_error_message("stat() failed for \"%s\": %s", path, strerror(errno));
            int status = file_errno_to_status(errno);
            return build_error_response(status, out);
        }
        if (!S_ISREG(st.st_mode) || st.st_size < 0) {
            /* 目录、设备文件等都不是本实验要服务的普通静态文件 */
            log_error_message("\"%s\" is not a readable regular file", path);
            return build_error_response(404, out);
        }

        const char *mime = guess_mime_type(path);
        char header[1024];
        int header_len = snprintf(header, sizeof(header),
                                  "%s 200 OK\r\n"
                                  "Server: Liso/1.0\r\n"
                                  "Content-Length: %ld\r\n"
                                  "Content-Type: %s\r\n"
                                  "Connection: %s\r\n"
                                  "\r\n",
                                  request->http_version,
                                  (long)st.st_size,
                                  mime,
                                  connection_value);
        if (header_len < 0 || (size_t)header_len >= sizeof(header)) {
            return -1;
        }

        size_t body_len = is_head ? 0 : (size_t)st.st_size;
        size_t total_len = (size_t)header_len + body_len;
        *out = (char *)malloc(total_len);
        if (*out == NULL) {
            log_error_message("malloc() failed while building response for \"%s\"", path);
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
            log_error_message("fopen() failed for \"%s\": %s", path, strerror(errno));
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
            log_error_message("fread() failed for \"%s\": expected %zu bytes, got %zu, ferror=%d",
                              path, body_len, read_len, read_failed);
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
            log_error_message("malloc() failed while echoing POST request");
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

/* 初始化客户端连接表；第四阶段要求最多支持 1024 个连接槽位 */
static void init_clients(ClientConn clients[], int count) {
    for (int i = 0; i < count; i++) {
        clients[i].fd = -1;
        clients[i].active = 0;
        clients[i].conn_buf = NULL;
        clients[i].conn_len = 0;
        clients[i].conn_cap = 0;
        memset(&clients[i].addr, 0, sizeof(clients[i].addr));
    }
}

/* 关闭并清理单个客户端；只释放该客户端资源，不影响其它并发连接 */
static void close_client(ClientConn *client) {
    if (client == NULL || !client->active) {
        return;
    }

    if (client->fd != -1 && close_socket(client->fd) != 0) {
        log_error_message("close() failed for client fd %d", client->fd);
    }

    free(client->conn_buf);
    client->fd = -1;
    client->active = 0;
    client->conn_buf = NULL;
    client->conn_len = 0;
    client->conn_cap = 0;
    memset(&client->addr, 0, sizeof(client->addr));
}

/* 为新 accept 的 socket 分配连接槽位和独立缓冲区 */
static int add_client(ClientConn clients[],
                      int count,
                      int fd,
                      const struct sockaddr_in *addr) {
    if (fd < 0 || fd >= FD_SETSIZE) {
        log_error_message("rejecting client fd %d because it exceeds FD_SETSIZE", fd);
        return -1;
    }

    for (int i = 0; i < count; i++) {
        if (!clients[i].active) {
            clients[i].conn_buf = (char *)malloc(INITIAL_CONN_BUF_SIZE);
            if (clients[i].conn_buf == NULL) {
                log_error_message("malloc() failed while creating client buffer");
                return -1;
            }
            clients[i].fd = fd;
            clients[i].active = 1;
            clients[i].conn_len = 0;
            clients[i].conn_cap = INITIAL_CONN_BUF_SIZE;
            if (addr != NULL) {
                clients[i].addr = *addr;
            } else {
                memset(&clients[i].addr, 0, sizeof(clients[i].addr));
            }
            return 0;
        }
    }

    log_error_message("too many active clients, rejecting fd %d", fd);
    return -1;
}

/* 追加 recv 到的数据；每个客户端有自己的缓冲区，因此半包不会阻塞其他客户端 */
static int append_client_data(ClientConn *client, const char *data, size_t len) {
    size_t need;
    size_t new_cap;
    char *new_buf = NULL;

    if (client == NULL || data == NULL || len == 0) {
        return 0;
    }

    need = client->conn_len + len;
    if (need > client->conn_cap) {
        new_cap = client->conn_cap;
        while (new_cap < need) {
            if (new_cap > (size_t)INT_MAX / 2) {
                new_cap = need;
                break;
            }
            new_cap *= 2;
        }

        new_buf = (char *)realloc(client->conn_buf, new_cap);
        if (new_buf == NULL) {
            char request_line[512];
            extract_request_line(client->conn_buf,
                                 client->conn_len > (size_t)INT_MAX ? INT_MAX : (int)client->conn_len,
                                 request_line,
                                 sizeof(request_line));
            log_error_message("realloc() failed while growing client buffer to %zu bytes", new_cap);
            if (send_error_response(client->fd, 400) > 0) {
                log_access_request(&client->addr, request_line, 400, 0);
            }
            return -1;
        }
        client->conn_buf = new_buf;
        client->conn_cap = new_cap;
    }

    memcpy(client->conn_buf + client->conn_len, data, len);
    client->conn_len += len;
    return 0;
}

/* 处理单个客户端缓冲区中的完整请求，保持第三阶段 pipeline 顺序语义 */
static int process_client_buffer(ClientConn *client) {
    if (client == NULL || !client->active) {
        return -1;
    }

    while (1) {
        PipelineRequestSlice slice;
        PipelineStatus pipeline_status =
            extract_pipeline_request(client->conn_buf, client->conn_len, &slice);
        char request_line[512];

        if (pipeline_status == PIPELINE_NEED_MORE) {
            return 0;
        }

        if (pipeline_status == PIPELINE_FATAL_ERROR) {
            int line_len = client->conn_len > (size_t)INT_MAX ? INT_MAX : (int)client->conn_len;
            extract_request_line(client->conn_buf, line_len, request_line, sizeof(request_line));
            log_error_message("cannot recover pipeline boundary; request header is larger than %d bytes",
                              MAX_HEADER_SIZE);
            if (send_error_response(client->fd, 400) > 0) {
                log_access_request(&client->addr, request_line, 400, 0);
            }
            client->conn_len = 0;
            return -1;
        }

        extract_request_line(client->conn_buf, slice.header_len, request_line, sizeof(request_line));

        if (pipeline_status == PIPELINE_BAD_REQUEST) {
            /*
             * 已经定位到当前错误请求的头部边界，返回 400 后只丢弃它；
             * 当前客户端继续保留，其他客户端也不会被这个错误请求影响。
             */
            log_error_message("bad pipeline request header, consuming %zu bytes", slice.full_len);
            if (send_error_response(client->fd, 400) < 0) {
                log_error_message("send_all() failed while returning 400: %s", strerror(errno));
                client->conn_len = 0;
                return -1;
            }
            log_access_request(&client->addr, request_line, 400, 0);
            discard_consumed_bytes(client->conn_buf, &client->conn_len, slice.full_len);
            continue;
        }

        int request_type = classify_request_line(client->conn_buf, slice.header_len);
        if (request_type == 0) {
            if (send_error_response(client->fd, 400) < 0) {
                log_error_message("send_all() failed while returning 400: %s", strerror(errno));
                client->conn_len = 0;
                return -1;
            }
            log_access_request(&client->addr, request_line, 400, 0);
        } else if (request_type == -1) {
            if (send_error_response(client->fd, 501) < 0) {
                log_error_message("send_all() failed while returning 501: %s", strerror(errno));
                client->conn_len = 0;
                return -1;
            }
            log_access_request(&client->addr, request_line, 501, 0);
        } else {
            Request *request = parse(client->conn_buf, slice.header_len, client->fd);
            int close_after_response = 0;
            if (request == NULL) {
                if (send_error_response(client->fd, 400) < 0) {
                    log_error_message("send_all() failed after parse error: %s", strerror(errno));
                    client->conn_len = 0;
                    return -1;
                }
                log_access_request(&client->addr, request_line, 400, 0);
                discard_consumed_bytes(client->conn_buf, &client->conn_len, slice.full_len);
                continue;
            }
            /*
             * HTTP/1.0 默认不具备 HTTP/1.1 的持久连接语义。
             * 响应发送完成后主动关闭该客户端，可兼容 ab 等 HTTP/1.0 工具。
             */
            close_after_response = strcmp(request->http_version, "HTTP/1.0") == 0;

            char *response = NULL;
            int response_len =
                build_encapsulated_request(request, client->conn_buf, slice.full_len, &response);

            if (response_len <= 0 || response == NULL ||
                send_all(client->fd, response, (size_t)response_len) < 0) {
                log_error_message("send_all() failed for \"%s\": %s",
                                  request_line,
                                  strerror(errno));
                free(response);
                free_request(request);
                client->conn_len = 0;
                return -1;
            }

            log_access_request(&client->addr,
                               request_line,
                               response_status_code(response, response_len),
                               response_body_bytes(response, response_len));
            free(response);
            free_request(request);

            if (close_after_response) {
                client->conn_len = 0;
                return -1;
            }
        }

        /* 丢弃已处理请求，继续解析该客户端缓冲区中的后续 pipeline 请求 */
        discard_consumed_bytes(client->conn_buf, &client->conn_len, slice.full_len);
    }
}

/* select 通知某客户端可读时调用：读取数据并处理该客户端自己的缓冲区 */
static int handle_client_read(ClientConn *client) {
    char read_buf[BUF_SIZE];
    ssize_t readret;

    if (client == NULL || !client->active) {
        return -1;
    }

    readret = recv(client->fd, read_buf, sizeof(read_buf), 0);
    if (readret < 0) {
        if (errno == EINTR) {
            return 0;
        }
        log_error_message("recv() failed from %s:%d: %s",
                          inet_ntoa(client->addr.sin_addr),
                          ntohs(client->addr.sin_port),
                          strerror(errno));
        return -1;
    }

    if (readret == 0) {
        /* 对端关闭连接时若仍有残缺报文，按格式错误处理后清理该客户端 */
        if (client->conn_len > 0 && !buffer_is_only_blank(client->conn_buf, client->conn_len)) {
            char request_line[512];
            extract_request_line(client->conn_buf,
                                 client->conn_len > (size_t)INT_MAX ? INT_MAX : (int)client->conn_len,
                                 request_line,
                                 sizeof(request_line));
            if (send_error_response(client->fd, 400) > 0) {
                log_access_request(&client->addr, request_line, 400, 0);
            }
        }
        return -1;
    }

    if (append_client_data(client, read_buf, (size_t)readret) != 0) {
        return -1;
    }

    return process_client_buffer(client);
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
    struct sockaddr_in addr;
    ClientConn clients[MAX_CLIENTS];
    init_logs();
    init_clients(clients, MAX_CLIENTS);
    /* 评测脚本只检查网络响应，服务端标准输出保持安静可避免长流水线测试阻塞。 */

    /* all networked programs must create a socket */
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        log_error_message("socket() failed: %s", strerror(errno));
        fprintf(stderr, "Failed creating socket.\n");
        return EXIT_FAILURE;
    }
    /* set socket SO_REUSEADDR | SO_REUSEPORT */
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        log_error_message("setsockopt() failed: %s", strerror(errno));
        fprintf(stderr, "Failed setting socket options.\n");
        return EXIT_FAILURE;
    }

    addr.sin_family = AF_INET; // ipv4
    addr.sin_port = htons(LISO_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    /* servers bind sockets to ports---notify the OS they accept connections */
    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr))) {
        log_error_message("bind() failed on port %d: %s", LISO_PORT, strerror(errno));
        close_socket(sock);
        fprintf(stderr, "Failed binding socket.\n");
        return EXIT_FAILURE;
    }

    if (listen(sock, MAX_CLIENTS)) {
        log_error_message("listen() failed: %s", strerror(errno));
        close_socket(sock);
        fprintf(stderr, "Error listening on socket.\n");
        return EXIT_FAILURE;
    }

    /*
     * 第四阶段主循环：使用 select() 同时等待监听 socket 和所有客户端 socket。
     * 这样某个客户端发送半个请求后暂停时，服务器仍能继续处理其它客户端。
     */
    while (1) {
        fd_set read_fds;
        int max_fd = sock;
        int ready;

        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].active) {
                FD_SET(clients[i].fd, &read_fds);
                if (clients[i].fd > max_fd) {
                    max_fd = clients[i].fd;
                }
            }
        }

        ready = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            log_error_message("select() failed: %s", strerror(errno));
            break;
        }

        if (FD_ISSET(sock, &read_fds)) {
            struct sockaddr_in cli_addr;
            socklen_t cli_size = sizeof(cli_addr);
            int new_client = accept(sock, (struct sockaddr *) &cli_addr, &cli_size);

            if (new_client == -1) {
                log_error_message("accept() failed: %s", strerror(errno));
            } else if (add_client(clients, MAX_CLIENTS, new_client, &cli_addr) != 0) {
                close_socket(new_client);
            }

            if (--ready <= 0) {
                continue;
            }
        }

        for (int i = 0; i < MAX_CLIENTS && ready > 0; i++) {
            if (!clients[i].active || !FD_ISSET(clients[i].fd, &read_fds)) {
                continue;
            }

            ready--;
            if (handle_client_read(&clients[i]) != 0) {
                close_client(&clients[i]);
            }
        }
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active) {
            close_client(&clients[i]);
        }
    }
    close_socket(sock);
    return EXIT_SUCCESS;
}

#include "parse.h"

/* flex 词法分析器保存了全局扫描状态；长连接多次 parse 前后必须显式重置。 */
extern int yylex_destroy(void);

/**
* Given a char buffer returns the parsed request headers
*/
Request *parse(const char *buffer, const int size, int socketFd) {
    //Different states in the state machine
    enum {
        STATE_START = 0, STATE_CR, STATE_CRLF, STATE_CRLFCR, STATE_CRLFCRLF
    };

    int i = 0;
    size_t offset = 0;
    char parse_buf[8192] = {0};

    // FSM to parse the request
    // expect for this regular expression:
    // .*(\r\n\r\n)
    // represent end of the http header part
    int state = STATE_START;
    while (state != STATE_CRLFCRLF) {
        char expected = 0;

        // when reach the end of the buffer, break
        if (i == size)
            break;

        const char ch = buffer[i++];
        parse_buf[offset++] = ch;

        switch (state) {
            case STATE_START:
            case STATE_CRLF:
                expected = '\r';
                break;
            case STATE_CR:
            case STATE_CRLFCR:
                expected = '\n';
                break;
            default:
                state = STATE_START;
                continue;
        }

        if (ch == expected)
            state++;
        else
            state = STATE_START;
    }

    //Valid End State
    if (state == STATE_CRLFCRLF) {
        Request *request = malloc(sizeof(Request));
        if (request == NULL) {
            return NULL;
        }
        request->header_count = 0;
        request->headers = (Request_header *) malloc(sizeof(Request_header) * 1);
        if (request->headers == NULL) {
            free(request);
            return NULL;
        }
        set_parsing_options(parse_buf, i, request);

        if (yyparse() == SUCCESS) {
            yylex_destroy();
            return request;
        }

        /*
         * yyparse() 失败时不能把 flex 的 EOF/缓冲区状态留给下一条请求。
         * 第三阶段 pipeline 会在同一进程内连续解析很多请求，若不清理，
         * 后续合法 GET/HEAD 可能被前一次解析状态污染并误判为 400。
         */
        yylex_destroy();
        free(request->headers);
        free(request);
    }

    return NULL;
}

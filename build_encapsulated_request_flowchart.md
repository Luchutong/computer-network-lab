# build_encapsulated_request 流程图

该流程图描述 `echo_server.c` 中 `build_encapsulated_request` 的执行路径，用于将结构化 `Request` 重新封装为 HTTP 请求文本。

```mermaid
flowchart LR
A[开始: 输入 request, out, out_size] --> B{参数有效? request!=NULL 且 out!=NULL 且 out_size>0}
B -- 否 --> Z1[返回 -1]
B -- 是 --> C[写入请求行 METHOD URI VERSION CRLF]
C --> D{written < 0 或 written >= out_size ?}
D -- 是 --> Z1
D -- 否 --> E[offset = written]
E --> F[遍历每个请求头]
F --> G[写入一行 Name: Value CRLF 到 out+offset]
G --> H{written < 0 或 written >= out_size-offset ?}
H -- 是 --> Z1
H -- 否 --> I[offset += written]
I --> J{还有下一个请求头?}
J -- 是 --> G
J -- 否 --> K[写入头结束空行 CRLF]
K --> L{written < 0 或 written >= out_size-offset ?}
L -- 是 --> Z1
L -- 否 --> M[返回 offset + written]
```

## 说明

1. 函数先做参数校验，任何空指针或非法缓冲区直接失败。
2. 请求行、请求头、结束空行均通过 `snprintf` 逐段写入。
3. `offset` 表示已写入长度，`out_size - offset` 表示剩余空间。
4. 任一步骤出现错误或截断，函数立即返回 `-1`。
5. 成功时返回总字节数，用于后续 `send()` 发送。

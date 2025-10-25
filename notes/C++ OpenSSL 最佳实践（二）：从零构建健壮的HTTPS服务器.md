在系列的第一篇文章《告别C风格，构建健壮的HTTPS客户端》中，我们探讨了如何运用现代C++特性（如RAII和异常处理）来封装OpenSSL，创建一个安全、可移植的HTTPS客户端。现在，我们将视角转换，应用同样的原则来构建通信的另一端——一个HTTPS服务器。

构建服务器比客户端稍微复杂一些，因为它需要处理更多的配置，例如加载服务器证书和私钥，并管理监听和接受客户端连接的生命周期。本文将引导你完成这个过程，最终创建一个能够处理简单HTTPS请求的基础服务器。我们将继续沿用上一篇文章中建立的最佳实践，确保代码的健壮性和可维护性。

## 准备工作：生成自签名证书

一个HTTPS服务器需要两样东西来向客户端证明自己的身份：一个**SSL证书**和一个与之配对的**私钥**。在生产环境中，证书通常由受信任的证书颁发机构（CA）签发。但在开发和测试阶段，我们可以自己生成一个“自签名”证书。

打开你的终端，使用OpenSSL命令行工具执行以下命令：

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"
```

这个命令会生成两个文件：
*   `key.pem`: 你的服务器私钥。**请务必妥善保管，切勿泄露。**
*   `cert.pem`: 你的服务器证书。客户端将通过它来验证你的服务器身份。

`nodes`参数表示不加密私钥文件，这样在启动服务器时就不需要输入密码。`-subj "/CN=localhost"`将证书的通用名（Common Name）设置为`localhost`，这在本地测试时非常有用。

## 最终代码示例

和上一篇文章一样，我们先展示将要构建的最终代码。这个服务器会监听4433端口，等待客户端连接，接收一个简单的HTTP请求，然后发送一个固定的HTTP响应。**此版本已修复原始版本中的关键逻辑错误**。

<!-- filename: examples/server.cpp -->

```cpp
// 编译命令:
// Linux/macOS: g++ examples/server.cpp -o ssl_server -lssl -lcrypto
// Windows (MSVC): cl examples\server.cpp /I"C:\path\to\openssl\include" /link /libpath:"C:\path\to\openssl\lib" libssl.lib libcrypto.lib crypt32.lib ws2_32.lib
//
// 运行前，请确保 cert.pem 和 key.pem 文件与可执行文件在同一目录下。
//
// 本代码演示了如何构建一个基础的、单线程的、阻塞式的HTTPS服务器。
// 它沿用了第一篇文章中的现代C++实践，并纠正了原始版本中的BIO链处理错误。

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <array>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#if defined(_WIN32)
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#endif

// --- 复用上一篇文章中的RAII包装器和异常类 ---

struct SSL_CTX_deleter {
    void operator()(SSL_CTX* ctx) const { if (ctx) SSL_CTX_free(ctx); }
};
using unique_SSL_CTX = std::unique_ptr<SSL_CTX, SSL_CTX_deleter>;

struct BIO_deleter {
    void operator()(BIO* bio) const { if (bio) BIO_free_all(bio); }
};
using unique_BIO = std::unique_ptr<BIO, BIO_deleter>;

class OpenSSLException : public std::runtime_error {
public:
    explicit OpenSSLException(const std::string& msg) : std::runtime_error(msg) {
        std::array <char, 256> err_buf;
        unsigned long err_code;
        std::string err_string = msg + "\nOpenSSL Errors:\n";
        while ((err_code = ERR_get_error()) != 0) {
            ERR_error_string_n(err_code, err_buf.data(), err_buf.size());
            err_string += std::string(err_buf.data()) + "\n";
        }
        ERR_clear_error();
        // 在实际应用中，你可能希望将这些详细信息记录到日志文件。
        std::cerr << err_string;
    }
};

// --- OpenSSL全局初始化与清理 ---

struct OpenSSLInitializer {
    OpenSSLInitializer() {
        OPENSSL_init_ssl(0, nullptr);
#if defined(_WIN32)
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
#endif
    }
    ~OpenSSLInitializer() {
#if defined(_WIN32)
        WSACleanup();
#endif
        OPENSSL_cleanup();
    }
};


// --- 服务器端上下文创建与配置 ---

unique_SSL_CTX create_server_context() {
    const SSL_METHOD* method = TLS_server_method();
    if (!method) {
        throw OpenSSLException("Failed to get TLS server method");
    }

    unique_SSL_CTX ctx(SSL_CTX_new(method));
    if (!ctx) {
        throw OpenSSLException("Failed to create SSL_CTX");
    }

    // 同样，设置最低协议版本以增强安全性
    if (!SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION)) {
        throw OpenSSLException("Failed to set minimum TLS version");
    }

    // 加载服务器证书
    if (SSL_CTX_use_certificate_file(ctx.get(), "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        throw OpenSSLException("Failed to load certificate file");
    }

    // 加载服务器私钥
    if (SSL_CTX_use_PrivateKey_file(ctx.get(), "key.pem", SSL_FILETYPE_PEM) <= 0) {
        throw OpenSSLException("Failed to load private key file");
    }

    // 检查私钥是否与证书匹配
    if (!SSL_CTX_check_private_key(ctx.get())) {
        throw OpenSSLException("Private key does not match the public certificate");
    }

    std::cout << "Server context created and configured successfully.\n";
    return ctx;
}

// --- 服务器主逻辑 (已纠正) ---

void run_server(const unique_SSL_CTX& ctx) {
    // 创建一个 "accept" BIO，监听指定端口
    unique_BIO accept_bio(BIO_new_accept("4433"));
    if (!accept_bio) {
        throw OpenSSLException("Failed to create accept BIO");
    }

    // 设置BIO进行监听。这一步是必需的。
    if (BIO_do_accept(accept_bio.get()) <= 0) {
        throw OpenSSLException("Failed to bind/listen on port 4433");
    }
    std::cout << "Server listening on port 4433...\n";

    while (true) {
        std::cout << "Waiting for a connection...\n";

        // 等待客户端连接。这会阻塞直到有新连接进来。
        if (BIO_do_accept(accept_bio.get()) <= 0) {
            std::cerr << "Error accepting connection.\n";
            ERR_print_errors_fp(stderr);
            continue;
        }

        // BIO_do_accept 执行成功后，一个新的连接 BIO 被创建并链接在 accept_bio 的内部。
        // 我们需要用 BIO_pop 将其“弹出”以独立处理。它是一个原始的套接字BIO。
        BIO* client_socket_bio = BIO_pop(accept_bio.get());

        // **纠正部分开始**
        // 1. 创建一个 SSL BIO 过滤器
        BIO* ssl_filter_bio = BIO_new_ssl(ctx.get(), 0); // 0 = server mode
        if (!ssl_filter_bio) {
            BIO_free(client_socket_bio); // 清理弹出的BIO
            throw OpenSSLException("Failed to create SSL BIO");
        }

        // 2. 将 SSL BIO 压入套接字 BIO 之上，形成BIO链
        // ssl_filter_bio 现在是链的头部，它拥有了 client_socket_bio
        BIO_push(ssl_filter_bio, client_socket_bio);
        
        // 3. 使用 unique_BIO 管理整个BIO链的生命周期
        unique_BIO client_chain_bio(ssl_filter_bio);

        // 4. 在链的头部执行TLS握手 (相当于 SSL_accept)
        if (BIO_do_handshake(client_chain_bio.get()) <= 0) {
            std::cerr << "SSL handshake failed.\n";
            ERR_print_errors_fp(stderr);
            continue; // 继续等待下一个连接
        }
        std::cout << "SSL handshake successful with a client.\n";
        // **纠正部分结束**

        // 读取客户端请求 (简单实现)
        std::vector<char> buffer(4096);
        int len = BIO_read(client_chain_bio.get(), buffer.data(), buffer.size() - 1);
        if (len > 0) {
            buffer[len] = '\0';
            std::cout << "Received request:\n---\n" << buffer.data() << "---\n";

            // 发送一个简单的HTTP响应
            std::string response = "HTTP/1.1 200 OK\r\n"
                                 "Content-Type: text/html\r\n"
                                 "Content-Length: 45\r\n"
                                 "Connection: close\r\n\r\n"
                                 "<html><body><h1>Hello from OpenSSL!</h1></body></html>";

            BIO_write(client_chain_bio.get(), response.c_str(), response.length());
        } else if (len == 0) {
             std::cout << "Client closed the connection.\n";
        } else {
             std::cerr << "Failed to read from client.\n";
             ERR_print_errors_fp(stderr);
        }
        
        // client_chain_bio 的 unique_ptr 析构时会自动调用 BIO_free_all,
        // 它会释放整个BIO链，包括 SSL BIO 和底层的套接字 BIO，从而关闭连接。
    }
}

// --- 主入口点 ---

int main() {
    // 使用一个对象来管理OpenSSL和Winsock的初始化与清理
    OpenSSLInitializer initializer;

    try {
        unique_SSL_CTX ctx = create_server_context();
        run_server(ctx);
    } catch (const std::exception& e) {
        std::cerr << "Critical Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
```

## 服务器端核心概念解析（已更新）

与客户端类似，服务器端也围绕着`SSL_CTX`, `BIO`和`SSL`对象。然而，它们的配置和使用方式有所不同。

### 1. `SSL_CTX`：服务器的配置模板

*   **它是什么？**：服务器端的`SSL_CTX`同样是配置模板，但它包含的是服务器特定的信息。最重要的区别是，它必须加载**服务器的证书和私钥**。
*   **关键函数与用法**：
    *   `TLS_server_method()`: 获取用于创建服务器端`SSL_CTX`的方法结构体。
    *   `SSL_CTX_use_certificate_file(ctx, "cert.pem", ...)`: 从文件加载服务器证书。这个证书将会在TLS握手期间发送给客户端。
    *   `SSL_CTX_use_privatekey_file(ctx, "key.pem", ...)`: 从文件加载与证书配对的私钥。私钥用于解密客户端发来的信息以及在握手中签名，以证明服务器确实拥有该证书。
    *   `SSL_CTX_check_private_key(ctx)`: 这是一个**至关重要的安全检查**。它验证加载的私钥是否确实与证书匹配。如果二者不匹配，任何TLS握手都将失败。

### 2. `BIO`：监听、链接与通信的I/O抽象

*   **它是什么？**：在服务器端，我们使用一个`accept BIO`来处理监听，并为每个接入的连接**动态构建一个BIO链**来进行安全通信。
*   **为何使用？**：这种模型将网络I/O的不同层面（监听、TCP连接、TLS加密）清晰地分离开。`accept BIO`封装了底层的`bind/listen/accept`，而我们手动构建的`SSL BIO -> Socket BIO`链则优雅地将加密层叠加在TCP连接之上。
*   **关键函数与用法（已更新）**：
    *   `BIO_new_accept("port")`: 创建特殊的`accept BIO`用于监听端口。
    *   `BIO_do_accept(bio)`: 第一次调用时绑定并监听端口。后续调用则会阻塞，直到接受一个新连接。
    *   `BIO_pop(accept_bio)`: 当新连接到达时，此函数会从`accept_bio`中**弹出一个代表底层TCP连接的原始套接字BIO**。
    *   `BIO_new_ssl(ctx, 0)`: **这是修正后的关键**。我们为每个连接创建一个新的`SSL BIO`作为过滤器。第二个参数`0`表示将其配置为**服务器模式**。
    *   `BIO_push(ssl_bio, socket_bio)`: 将SSL过滤器`ssl_bio`**压入**到原始的`socket_bio`之上。这会创建一个链，`ssl_bio`成为链的头部。`ssl_bio`现在“拥有”了`socket_bio`。
    *   `BIO_do_handshake(chain_head_bio)`: 在整个BIO链的头部调用此函数，它会驱动底层的`SSL_accept()`来完成TLS握手。
    *   `BIO_read/write(chain_head_bio, ...)`: 握手成功后，所有I/O操作都在链的头部进行。数据写入时会自动加密，读取时会自动解密。

### 3. `SSL`：隐式管理的连接实例

*   **它是什么？**：`SSL`对象代表一个具体的TLS连接。在**我们修正后的代码中，这个`SSL`对象是作为`SSL BIO`的一部分被隐式创建和管理的**。
*   **为何使用？**：通过使用`BIO_new_ssl`，我们将`SSL`对象的创建和生命周期管理委托给了`SSL BIO`。这简化了我们的代码，因为我们不再需要手动创建`SSL`对象（`SSL_new`）、将其与`SSL_CTX`关联（`SSL_set_SSL_CTX`）或直接调用`SSL_accept`。所有这些操作都在BIO层级内部被优雅地处理了。
*   **调用顺序总结（已更新）**：`SSL_CTX` (加载证书和密钥) -> `BIO_new_accept` -> `BIO_do_accept` (监听) -> **循环开始** -> `BIO_do_accept` (等待连接) -> `BIO_pop` (获取套接字BIO) -> `BIO_new_ssl` (创建SSL过滤器) -> `BIO_push` (构建链) -> **`BIO_do_handshake`** (在链上执行握手) -> `BIO_read/write` (在链上通信) -> `unique_BIO`析构 (自动清理整个链) -> **循环结束**。

## C++最佳实践回顾

我们在这个服务器示例中继续坚持了上一篇文章中建立的原则，并且修正后的代码更加体现了BIO链的正确用法：

1.  **RAII驱动的资源管理**: `unique_BIO`现在管理着整个BIO链的头部。当`client_chain_bio`离开作用域时，其析构函数会调用`BIO_free_all`，它会递归地释放链中的所有BIO（SSL BIO和Socket BIO），从而干净利落地关闭连接。
2.  **通过异常进行错误处理**: 所有的OpenSSL函数调用都被检查，任何失败都会抛出`OpenSSLException`。
3.  **封装初始化与清理**: `OpenSSLInitializer`结构体确保了全局状态的正确管理。

## 如何测试服务器

1.  **编译并运行服务器**：
    ```bash
    g++ server.cpp -o ssl_server -lssl -lcrypto
    ./ssl_server
    ```
    你应该会看到服务器输出 "Server listening on port 4433..."。

2.  **使用`curl`进行测试（推荐）**：
    `curl`是测试HTTPS服务器的最佳工具之一，因为它能提供详细的反馈。
    ```bash
    # 使用 -k 或 --insecure 选项来跳过对我们自签名证书的验证
    curl -v -k https://localhost:4433
    ```
    *   `-v` (verbose) 选项会显示详细的连接和TLS握手信息，非常有助于调试。
    *   `-k` 允许连接到使用“不受信任”证书（如我们的自签名证书）的服务器。

    如果一切顺利，`curl`会输出 `<html><body><h1>Hello from OpenSSL!</h1></body></html>`，同时你的服务器终端会打印出接收到的HTTP请求。

3.  **使用第一篇文章的客户端**：
    如果您想用第一篇文章中的客户端来测试，请注意：**原始客户端代码硬编码连接到端口443**。您需要对其进行简单修改：
    在客户端的 `secure_connect` 函数中，找到以下行：
    `std::string host_with_port = hostname + ":443";`
    将其修改为：
    `std::string host_with_port = hostname + ":4433";`
    修改并重新编译后，客户端 `ssl_example` 就可以连接到我们的服务器了。它应该会报告证书验证失败（因为证书是自签名的），但这恰恰证明了TLS握手是成功的！

## 结论与展望

通过本文，我们成功地将现代C++的最佳实践应用到了OpenSSL的服务器端编程中，并且深入理解了使用BIO链来构建安全通信的正确方法。我们学会了如何配置服务器上下文、加载证书私钥、以及如何动态地为每个客户端连接构建和管理一个完整的I/O处理链。

至此，你已经拥有了构建基本TLS通信渠道两端（客户端和服务器）的完整知识。在本系列的后续文章中，我们可以探索更高级的主题，例如：

*   **双向认证（mTLS）**：不仅服务器要验证客户端，客户端也要验证服务器身份。
*   **非阻塞I/O**：将OpenSSL与`select`, `poll`, `epoll`或Boost.Asio等事件驱动模型集成，构建高性能、可扩展的服务器。
*   **证书管理与验证**：深入探讨证书链、吊销列表（CRL）和在线证书状态协议（OCSP）。

敬请期待！
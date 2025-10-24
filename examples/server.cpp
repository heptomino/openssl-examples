// 编译命令:
// Linux/macOS: g++ server.cpp -o ssl_server -lssl -lcrypto
// Windows (MSVC): cl server.cpp /I"C:\path\to\openssl\include" /link /libpath:"C:\path\to\openssl\lib" libssl.lib libcrypto.lib crypt32.lib ws2_32.lib
//
// 运行前，请确保 cert.pem 和 key.pem 文件与可执行文件在同一目录下。
//
// 本代码演示了如何构建一个基础的、单线程的、阻塞式的HTTPS服务器。
// 它沿用了第一篇文章中的现代C++实践。

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

// --- 服务器主逻辑 ---

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
            // 在这个简单的服务器中，我们忽略接受连接时的错误，继续等待下一个
            std::cerr << "Error accepting connection.\n";
            ERR_print_errors_fp(stderr);
            continue;
        }

        // BIO_do_accept 执行成功后，一个新的连接 BIO 被创建并链接在 accept_bio 的内部。
        // 我们需要用 BIO_pop 将其“弹出”以独立处理。
        unique_BIO client_bio(BIO_pop(accept_bio.get()));

        // 为这个新连接设置 SSL 对象
        SSL* ssl = nullptr;
        BIO_get_ssl(client_bio.get(), &ssl);
        if (!ssl) {
            throw OpenSSLException("Failed to get SSL from client BIO");
        }
        SSL_set_SSL_CTX(ssl, ctx.get());

        // 执行TLS握手
        if (SSL_accept(ssl) <= 0) {
            std::cerr << "SSL handshake failed.\n";
            ERR_print_errors_fp(stderr);
            continue; // 继续等待下一个连接
        }
        std::cout << "SSL handshake successful with a client.\n";

        // 读取客户端请求 (简单实现)
        std::vector<char> buffer(4096);
        int len = BIO_read(client_bio.get(), buffer.data(), buffer.size() - 1);
        if (len > 0) {
            buffer[len] = '\0';
            std::cout << "Received request:\n---\n" << buffer.data() << "---\n";

            // 发送一个简单的HTTP响应
            std::string response = "HTTP/1.1 200 OK\r\n"
                                 "Content-Type: text/html\r\n"
                                 "Content-Length: 45\r\n"
                                 "Connection: close\r\n\r\n"
                                 "<html><body><h1>Hello from OpenSSL!</h1></body></html>";

            BIO_write(client_bio.get(), response.c_str(), response.length());
        } else {
             std::cerr << "Failed to read from client.\n";
        }
        
        // BIO_free_all (通过 unique_BIO) 会自动关闭连接
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

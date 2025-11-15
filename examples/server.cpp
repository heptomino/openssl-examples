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
#include <atomic>
#include <csignal>
#include <thread>
#include <chrono>
#include <fstream>
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

// 全局控制与日志
static std::atomic<bool> g_should_stop{false};
static std::ofstream g_log;

static void log_info(const std::string &msg) {
    if (g_log.is_open()) {
        g_log << "[INFO] " << msg << std::endl;
        g_log.flush();
    }
    std::cout << msg << std::endl;
}

static void log_error(const std::string &msg) {
    if (g_log.is_open()) {
        g_log << "[ERROR] " << msg << std::endl;
        g_log.flush();
    }
    std::cerr << msg << std::endl;
}

static void signal_handler(int /*signum*/) {
    g_should_stop.store(true);
}

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

    // 从配置目录加载服务器证书与私钥。优先使用环境变量 OPENSSL_CERT_DIR。
    const char* cert_dir_env = std::getenv("OPENSSL_CERT_DIR");
    std::string cert_dir = cert_dir_env ? std::string(cert_dir_env) : std::string("certs");
    std::string cert_path = cert_dir + "/cert.pem";
    std::string key_path = cert_dir + "/key.pem";

    // 加载服务器证书
    if (SSL_CTX_use_certificate_file(ctx.get(), cert_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        throw OpenSSLException("Failed to load certificate file: " + cert_path);
    }

    // 加载服务器私钥
    if (SSL_CTX_use_PrivateKey_file(ctx.get(), key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        throw OpenSSLException("Failed to load private key file: " + key_path);
    }

    // 检查私钥是否与证书匹配
    if (!SSL_CTX_check_private_key(ctx.get())) {
        throw OpenSSLException("Private key does not match the public certificate");
    }

    log_info("Server context created and configured successfully.");
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
    log_info("Server listening on port 4433...");

    // 将 accept BIO 设置为非阻塞，以便我们在信号触发时可以优雅退出
    BIO_set_nbio(accept_bio.get(), 1);

    while (!g_should_stop.load()) {
        log_info("Waiting for a connection...");

        // 等待客户端连接。这会阻塞直到有新连接进来。
        int accept_ret = BIO_do_accept(accept_bio.get());
        if (accept_ret <= 0) {
            if (BIO_should_retry(accept_bio.get())) {
                // 非阻塞且暂无连接，稍作等待并检查中断信号
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
            log_error("Error accepting connection.");
            ERR_print_errors_fp(stderr);
            continue;
        }

        // BIO_do_accept 执行成功后，一个新的连接 BIO 被创建并链接在 accept_bio 的内部。
        // 我们需要用 BIO_pop 将其“弹出”以独立处理。它是一个原始的套接字BIO。
        BIO* client_socket_bio = BIO_pop(accept_bio.get());
        if (!client_socket_bio) {
            log_error("Failed to pop client socket BIO.");
            continue;
        }

        // 1. 创建一个 SSL BIO 过滤器
        BIO* ssl_filter_bio = BIO_new_ssl(ctx.get(), 0); // 0 = server mode
        if (!ssl_filter_bio) {
            BIO_free(client_socket_bio);
            log_error("Failed to create SSL BIO.");
            continue;
        }

        // 2. 将 SSL BIO 压入套接字 BIO 之上，形成BIO链
        BIO_push(ssl_filter_bio, client_socket_bio);

        // 3. 使用 unique_BIO 管理整个BIO链的生命周期
        unique_BIO client_chain_bio(ssl_filter_bio);

        // 4. 在链的头部执行TLS握手 (相当于 SSL_accept)
        // 在非阻塞 BIO 上循环执行握手，直到成功或出现不可恢复错误
        bool hs_failed = false;
        while (true) {
            int hs_ret = BIO_do_handshake(client_chain_bio.get());
            if (hs_ret == 1) {
                log_info("SSL handshake successful with a client.");
                break;
            }
            if (hs_ret <= 0) {
                if (BIO_should_retry(client_chain_bio.get())) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }
                log_error("SSL handshake failed.");
                ERR_print_errors_fp(stderr);
                hs_failed = true;
                break;
            }
        }
        if (hs_failed) {
            // 让 unique_BIO 在离开当前作用域时自动清理链
            continue; // 继续等待下一个连接
        }

        // 读取客户端请求 (简单实现)
        std::vector<char> buffer(4096);
        int len = BIO_read(client_chain_bio.get(), buffer.data(), buffer.size() - 1);
        if (len > 0) {
            buffer[len] = '\0';
            log_info(std::string("Received request:\n---\n") + buffer.data() + "---");

            // 发送一个简单的HTTP响应（动态计算 Content-Length，避免与正文长度不符）
            std::string body = "<html><body><h1>Hello from OpenSSL!</h1></body></html>";
            std::string response = "HTTP/1.1 200 OK\r\n"
                                 "Content-Type: text/html\r\n"
                                 "Content-Length: " + std::to_string(body.size()) + "\r\n"
                                 "Connection: close\r\n\r\n" + body;

            // 循环写入，确保发送所有字节（处理 BIO_should_retry）
            size_t total = response.size();
            size_t written = 0;
            const char* data = response.c_str();
            while (written < total) {
                int w = BIO_write(client_chain_bio.get(), data + written, (int)(total - written));
                if (w > 0) {
                    written += (size_t)w;
                } else if (BIO_should_retry(client_chain_bio.get())) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                } else {
                    log_error("BIO_write failed while sending response.");
                    ERR_print_errors_fp(stderr);
                    break;
                }
            }
            log_info("Response sent (bytes=" + std::to_string(written) + ").");
        } else if (len == 0) {
            log_info("Client closed the connection.");
        } else {
            log_error("Failed to read from client.");
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

    // 注册信号处理器以便优雅退出
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // 打开日志目录（可由 OPENSSL_LOG_DIR 环境变量覆盖）
    const char* log_dir_env = std::getenv("OPENSSL_LOG_DIR");
    std::string log_dir = log_dir_env ? std::string(log_dir_env) : std::string("logs");
    // 确保日志目录存在（简单方式）
    std::string mkdir_cmd = std::string("mkdir -p ") + log_dir;
    (void)system(mkdir_cmd.c_str());
    g_log.open(log_dir + "/server.log", std::ios::app);

    try {
        unique_SSL_CTX ctx = create_server_context();
        run_server(ctx);
    } catch (const std::exception& e) {
        log_error(std::string("Critical Error: ") + e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

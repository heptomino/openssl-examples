// 编译命令:
// Linux/macOS: g++ main.cpp -o ssl_example -lssl -lcrypto
// Windows (MSVC): cl main.cpp /I"C:\path\to\openssl\include" /link /libpath:"C:\path\to\openssl\lib" libssl.lib libcrypto.lib crypt32.lib ws2_32.lib
//
// 本代码演示了如何配置OpenSSL以使用系统的默认信任库。
// 它通过现代C++实践（RAII、异常处理）进行了增强，并支持Linux、macOS和Windows。

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

// --- RAII Wrappers for OpenSSL ---

struct SSL_CTX_deleter {
    void operator()(SSL_CTX* ctx) const { if (ctx) SSL_CTX_free(ctx); }
};
using unique_SSL_CTX = std::unique_ptr<SSL_CTX, SSL_CTX_deleter>;

struct BIO_deleter {
    void operator()(BIO* bio) const { if (bio) BIO_free_all(bio); }
};
using unique_BIO = std::unique_ptr<BIO, BIO_deleter>;

// --- Custom Exception for Errors ---

class OpenSSLException : public std::runtime_error {
public:
    explicit OpenSSLException(const std::string& msg) : std::runtime_error(msg) {
        char err_buf[256];
        unsigned long err_code;
        std::string err_string = msg + "\nOpenSSL Errors:\n";
        while ((err_code = ERR_get_error()) != 0) {
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            err_string += std::string(err_buf) + "\n";
        }
        // 重置错误状态以防影响其他操作
        ERR_clear_error();
        // C++17 'what()' is const, so we can't change it. This is a common workaround.
        // For simplicity, we print here, though in a real app you might log it.
        std::cerr << err_string;
    }
};

// --- OpenSSL Initialization and Global Cleanup ---

void init_openssl() {
    OPENSSL_init_ssl(0, NULL);
}

void cleanup_openssl() {
    OPENSSL_cleanup();
}

// --- Context Creation and Configuration ---

unique_SSL_CTX create_context() {
    const SSL_METHOD* method = TLS_client_method();
    if (!method) {
        throw OpenSSLException("Failed to get TLS client method");
    }

    unique_SSL_CTX ctx(SSL_CTX_new(method));
    if (!ctx) {
        throw OpenSSLException("Failed to create SSL_CTX");
    }

    // 强制最低 TLS1.2，禁用不安全算法
    if (!SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION)) {
        throw OpenSSLException("Failed to set minimum TLS version");
    }
    SSL_CTX_set_options(ctx.get(), SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

    return ctx;
}

void configure_truststore(SSL_CTX* ctx) {
#if defined(_WIN32)
    HCERTSTORE hStore = CertOpenSystemStore(0, "ROOT");
    if (!hStore) {
        throw OpenSSLException("Failed to open Windows root certificate store");
    }

    X509_STORE* store = SSL_CTX_get_cert_store(ctx);
    PCCERT_CONTEXT pContext = nullptr;

    while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != nullptr) {
        const unsigned char* cert_der = pContext->pbCertEncoded;
        X509* x509 = d2i_X509(nullptr, &cert_der, pContext->cbCertEncoded);
        if (x509) {
            X509_STORE_add_cert(store, x509);
            X509_free(x509);
        }
    }

    CertCloseStore(hStore, 0);

#else // For Linux, macOS, and other Unix-like systems
    // SSL_CTX_set_default_verify_paths is the most portable way
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        throw OpenSSLException("Failed to load default system trust store");
    }
#endif
    
    // 启用证书验证
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
}

// --- Main Connection Logic ---

void secure_connect(const std::string& hostname) {
    unique_SSL_CTX ctx = create_context();
    configure_truststore(ctx.get());

    unique_BIO bio(BIO_new_ssl_connect(ctx.get()));
    if (!bio) {
        throw OpenSSLException("Failed to create BIO");
    }

    SSL* ssl = nullptr;
    BIO_get_ssl(bio.get(), &ssl);
    if (!ssl) {
        throw OpenSSLException("Failed to get SSL from BIO");
    }

    // 设置 SNI 和主机名验证（在握手前）
    SSL_set_tlsext_host_name(ssl, hostname.c_str());
    if (!SSL_set1_host(ssl, hostname.c_str())) {
        throw OpenSSLException("Failed to set expected host name");
    }
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    std::string host_with_port = hostname + ":443";
    BIO_set_conn_hostname(bio.get(), host_with_port.c_str());

    // 尝试连接
    if (BIO_do_connect(bio.get()) <= 0) {
        throw OpenSSLException("Failed to connect to " + hostname);
    }

    // 验证证书
    long verify_flag = SSL_get_verify_result(ssl);
    if (verify_flag != X509_V_OK) {
        const char* err_str = X509_verify_cert_error_string(verify_flag);
        throw OpenSSLException("Certificate verification failed: " + std::string(err_str));
    }
    std::cout << "Certificate verification successful.\n\n";

    // 发送 HTTPS 请求
    std::string request = "GET / HTTP/1.1\r\nHost: " + hostname + "\r\nConnection: close\r\n\r\n";
    if (BIO_write(bio.get(), request.c_str(), request.length()) <= 0) {
        throw OpenSSLException("Failed to write HTTP request");
    }

    // 读取响应
    std::vector<char> response_buffer(4096);
    int len;
    while ((len = BIO_read(bio.get(), response_buffer.data(), response_buffer.size())) > 0) {
        std::cout.write(response_buffer.data(), len);
    }
    std::cout << std::endl;
}

// --- Main Entry Point ---

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <hostname>\n";
        return EXIT_FAILURE;
    }

    init_openssl();
    // 确保程序退出时调用全局清理函数
    atexit(cleanup_openssl);

    try {
        std::string hostname = argv[1];
        std::cout << "Connecting to " << hostname << "...\n";
        secure_connect(hostname);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
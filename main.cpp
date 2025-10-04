// compilation: g++ main.cpp -o ssl_example -lssl -lcrypto
// This code demonstrates how to configure OpenSSL to use the system's default truststore
// on different platforms (Linux, macOS, Windows) using C++17.

#include <stdio.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>

#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#elif defined(__APPLE__)
#include <Security/Security.h>
#endif

#define BufferSize 4096

void report_error(const char* msg)
{
    std::cerr << msg << std::endl;
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

void init_openssl()
{
    OPENSSL_init_ssl(0, NULL);
}

void cleanup_openssl(SSL_CTX* ctx, BIO* bio)
{
    // EVP_cleanup();
    SSL_CTX_free(ctx);
    BIO_free_all(bio);
    // 全局清理（在程序退出时调用一次）
    OPENSSL_cleanup();
}

SSL_CTX* create_context()
{
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    /* 强制最低 TLS1.2，禁用不安全算法 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);
    return ctx;
}

void configure_truststore(SSL_CTX* ctx)
{
#if defined(__linux__)
    if (!SSL_CTX_load_verify_locations(ctx,
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/certs")) {
        /* 回退到默认路径（如果可用） */
        if (!SSL_CTX_set_default_verify_paths(ctx)) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }
#elif defined(__APPLE__)
    if (!SSL_CTX_load_verify_locations(ctx,
        "/opt/homebrew/etc/openssl@3/cert.pem", nullptr)) {
        if (!SSL_CTX_set_default_verify_paths(ctx)) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }
#endif
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}

void secure_connect(const char* hostname)
{
    char name[BufferSize];
    char request[BufferSize];
    char response[BufferSize];

    SSL_CTX* ctx = create_context();

    configure_truststore(ctx); // <-- 已移到这里

    BIO* bio = BIO_new_ssl_connect(ctx);
    if (!bio) {
        report_error("Failed to create BIO");
    }

    SSL* ssl = nullptr;

    /* link bio channel, SSL session, and server endpoint */
    snprintf(name, sizeof(name), "%s:%s", hostname, "https");
    BIO_get_ssl(bio, &ssl);
    if (!ssl) {
        cleanup_openssl(ctx, bio);
        report_error("Failed to get SSL from BIO");
    }
    /* 设置 SNI 和主机名验证（在握手前） */
    SSL_set_tlsext_host_name(ssl, hostname);
    if (!SSL_set1_host(ssl, hostname)) {
        cleanup_openssl(ctx, bio);
        report_error("Failed to set expected host name");
    }
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, name);

    /* attempt to connect */
    if (BIO_do_connect(bio) <= 0) {
        cleanup_openssl(ctx, bio);
        report_error("Failed to connect");
    }

    /* verify the certificate */
    long verify_flag = SSL_get_verify_result(ssl);
    if (verify_flag != X509_V_OK) {
        std::cerr << "Certificate verification failed: " << verify_flag << "\n";
        cleanup_openssl(ctx, bio);
        return;
    }

    /* 发送 HTTPS 请求 */
    snprintf(request, sizeof(request),
             "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
             hostname);
    BIO_write(bio, request, strlen(request));

    /* 读取响应 */
    int len = 0;
    while ((len = BIO_read(bio, response, sizeof(response))) > 0) {
        std::cout.write(response, len);
    }

    cleanup_openssl(ctx, bio);
}

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <hostname>\n";
        return EXIT_FAILURE;
    }

    init_openssl();

    const char* hostname = argv[1];
    std::cout << "Connecting to " << hostname << "...\n";
    secure_connect(hostname);

    return 0;
}
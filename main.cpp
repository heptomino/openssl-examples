#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>

#if defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#elif defined(__APPLE__)
#include <Security/Security.h>
#endif

void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX* create_context()
{
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_truststore(SSL_CTX* ctx)
{
#if defined(__linux__)
    // Linux: 使用系统 CA 路径
    if (!SSL_CTX_load_verify_locations(ctx,
        "/etc/ssl/certs/ca-certificates.crt",  // Debian/Ubuntu
        "/etc/ssl/certs")) {
        // 也可尝试 RHEL/CentOS 的路径: /etc/pki/tls/certs/ca-bundle.crt
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

#elif defined(__APPLE__)
    // macOS: 使用系统 Keychain
    // OpenSSL 本身不会自动读取 Keychain，需要应用层导入
    // 简化方式：使用 SecureTransport 或手动导出 CA 到 PEM 再加载
    // 这里给出一个常见做法：加载 Homebrew 安装的 OpenSSL truststore
    if (!SSL_CTX_load_verify_locations(ctx,
        "/opt/homebrew/etc/openssl@3/cert.pem", nullptr)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

#elif defined(_WIN32)
    // Windows: 使用系统证书存储
    HCERTSTORE hStore = CertOpenSystemStore(0, "ROOT");
    if (!hStore) {
        std::cerr << "Failed to open Windows ROOT store\n";
        exit(EXIT_FAILURE);
    }

    PCCERT_CONTEXT pContext = nullptr;
    while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != nullptr) {
        const unsigned char* encoded = pContext->pbCertEncoded;
        X509* x509 = d2i_X509(NULL, &encoded, pContext->cbCertEncoded);
        if (x509) {
            X509_STORE* store = SSL_CTX_get_cert_store(ctx);
            X509_STORE_add_cert(store, x509);
            X509_free(x509);
        }
    }
    CertCloseStore(hStore, 0);

#else
    #error "Unsupported platform"
#endif

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}

int main()
{
    init_openssl();
    SSL_CTX* ctx = create_context();

    configure_truststore(ctx);

    // 这里可以添加更多的 SSL/TLS 配置，例如设置证书、私钥等

    // 清理
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
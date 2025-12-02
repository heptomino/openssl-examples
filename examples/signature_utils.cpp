// 编译命令:
// Linux/macOS: g++ examples/signature_utils.cpp -o signature_demo -lssl -lcrypto
// Windows (MSVC): cl examples\signature_utils.cpp /I"C:\path\to\openssl\include" /link /libpath:"C:\path\to\openssl\lib" libssl.lib libcrypto.lib

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>

// --- 基础类型与 RAII ---

using Bytes = std::vector<uint8_t>;

// EVP_PKEY 是 OpenSSL 中通用的密钥容器，可存放 RSA、ECC 等多种密钥
struct EVP_PKEY_deleter {
    void operator()(EVP_PKEY* pkey) const { EVP_PKEY_free(pkey); }
};
using unique_EVP_PKEY = std::unique_ptr<EVP_PKEY, EVP_PKEY_deleter>;

// EVP_MD_CTX 是摘要和签名的上下文
struct EVP_MD_CTX_deleter {
    void operator()(EVP_MD_CTX* ctx) const { EVP_MD_CTX_free(ctx); }
};
using unique_EVP_MD_CTX = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_deleter>;

// --- 异常处理 ---

class CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string& msg) : std::runtime_error(msg) {
        // 实际项目中应在此处提取 OpenSSL 错误堆栈
    }
};

// --- 签名与验签核心类 ---

class SignatureManager {
public:
    enum class KeyType { RSA, ECC };

    /**
     * @brief 生成密钥对 (仅用于演示，实际生产中密钥通常从文件加载)
     */
    static unique_EVP_PKEY generate_key(KeyType type) {
        unique_EVP_PKEY pkey(nullptr);

        if (type == KeyType::RSA) {
            int bits = 2048;
            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_BITS, &bits),
                OSSL_PARAM_END
            };
            EVP_PKEY* p = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", params);
            if (!p) throw CryptoException("EVP_PKEY_Q_keygen(RSA) failed");
            pkey.reset(p);

        } else {
            char group_name[] = "prime256v1"; // NIST P-256
            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0),
                OSSL_PARAM_END
            };
            EVP_PKEY* p = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", params);
            if (!p) throw CryptoException("EVP_PKEY_Q_keygen(EC) failed");
            pkey.reset(p);
        }
        return pkey;
    }

    /**
     * @brief 对数据进行签名
     * @param private_key 私钥
     * @param data 待签名的数据
     * @return 签名产生的字节流
     */
    static Bytes sign(EVP_PKEY* private_key, const Bytes& data) {
        if (!private_key) throw CryptoException("Invalid private key");

        unique_EVP_MD_CTX ctx(EVP_MD_CTX_new());
        if (!ctx) throw CryptoException("Failed to create MD context");

        // 初始化签名操作，使用 SHA-256 作为摘要算法
        // EVP_DigestSignInit 能够根据 PKEY 类型自动选择正确的签名算法 (RSA 或 ECDSA)
        if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, private_key) <= 0) {
            throw CryptoException("DigestSignInit failed");
        }

        // 像计算哈希一样传入数据
        if (EVP_DigestSignUpdate(ctx.get(), data.data(), data.size()) <= 0) {
            throw CryptoException("DigestSignUpdate failed");
        }

        // 获取签名长度
        size_t sig_len = 0;
        if (EVP_DigestSignFinal(ctx.get(), nullptr, &sig_len) <= 0) {
            throw CryptoException("DigestSignFinal (get length) failed");
        }

        // 获取签名内容
        Bytes signature(sig_len);
        if (EVP_DigestSignFinal(ctx.get(), signature.data(), &sig_len) <= 0) {
            throw CryptoException("DigestSignFinal (get signature) failed");
        }
        
        // 某些算法生成的长度可能小于预估的最大长度，调整大小
        signature.resize(sig_len);
        return signature;
    }

    /**
     * @brief 验证签名
     * @param public_key 公钥 (可以是包含私钥的 PKEY 对象，因为私钥对象包含公钥信息)
     * @param data 原始数据
     * @param signature 待验证的签名
     * @return true 验证成功, false 验证失败
     */
    static bool verify(EVP_PKEY* public_key, const Bytes& data, const Bytes& signature) {
        if (!public_key) throw CryptoException("Invalid public key");

        unique_EVP_MD_CTX ctx(EVP_MD_CTX_new());
        if (!ctx) throw CryptoException("Failed to create MD context");

        // 初始化验签操作
        if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, public_key) <= 0) {
            throw CryptoException("DigestVerifyInit failed");
        }

        if (EVP_DigestVerifyUpdate(ctx.get(), data.data(), data.size()) <= 0) {
            throw CryptoException("DigestVerifyUpdate failed");
        }

        // 执行验证
        // 返回 1 表示成功，0 表示签名无效，负值表示错误
        int ret = EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size());
        if (ret < 0) {
            throw CryptoException("DigestVerifyFinal encountered an error");
        }

        return ret == 1;
    }

    // 辅助：打印 Bytes 为 Hex
    static void print_hex(const std::string& label, const Bytes& data) {
        std::cout << label << " (" << data.size() << " bytes): ";
        for (auto b : data) printf("%02x", b);
        std::cout << std::endl;
    }
};

// --- 主程序演示 ---

int main() {
    try {
        std::string message_str = "This is a critical system update v1.0.1";
        Bytes data(message_str.begin(), message_str.end());

        std::cout << "Original Data: " << message_str << "\n\n";

        // --- 场景 1: 使用 RSA 进行签名 ---
        {
            std::cout << "--- Testing RSA Signature ---\n";
            auto rsa_key = SignatureManager::generate_key(SignatureManager::KeyType::RSA);
            
            // 1. 签名
            Bytes signature = SignatureManager::sign(rsa_key.get(), data);
            SignatureManager::print_hex("RSA Signature", signature);

            // 2. 验签 (成功)
            bool valid = SignatureManager::verify(rsa_key.get(), data, signature);
            std::cout << "Verification Result: " << (valid ? "PASSED" : "FAILED") << "\n";

            // 3. 验签 (篡改数据)
            Bytes tampered_data = data;
            tampered_data[0] = 't'; // 'T' -> 't'
            bool tampered_valid = SignatureManager::verify(rsa_key.get(), tampered_data, signature);
            std::cout << "Tampered Data Verification: " << (tampered_valid ? "PASSED" : "FAILED") << "\n";
        }

        std::cout << "\n";

        // --- 场景 2: 使用 ECC (ECDSA) 进行签名 ---
        {
            std::cout << "--- Testing ECDSA (P-256) Signature ---\n";
            auto ec_key = SignatureManager::generate_key(SignatureManager::KeyType::ECC);

            // 1. 签名
            // 注意：ECDSA 的签名通常比 RSA 短得多
            Bytes signature = SignatureManager::sign(ec_key.get(), data);
            SignatureManager::print_hex("ECDSA Signature", signature);

            // 2. 验签
            bool valid = SignatureManager::verify(ec_key.get(), data, signature);
            std::cout << "Verification Result: " << (valid ? "PASSED" : "FAILED") << "\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
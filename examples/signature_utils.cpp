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
        EVP_PKEY_CTX* ctx = nullptr; // 不需要手动释放，由 EVP_PKEY_new_... 管理或栈分配不适用

        if (type == KeyType::RSA) {
            // 生成 2048 位 RSA 密钥
            EVP_PKEY* p = EVP_PKEY_new(); // 创建空对象
            if (!p) throw CryptoException("Failed to create EVP_PKEY");
            pkey.reset(p);
            
            // 旧式生成方法已弃用，使用 EVP_PKEY_Q_keygen (OpenSSL 3.0+) 或 EVP_RSA_gen (OpenSSL 1.1+)
            // 这里为了演示通用性，展示更底层的 PKEY_CTX 流程：
            EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
            if (!kctx) throw CryptoException("EVP_PKEY_CTX_new_id failed");
            
            if (EVP_PKEY_keygen_init(kctx) <= 0 ||
                EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0 ||
                EVP_PKEY_keygen(kctx, &p) <= 0) {
                EVP_PKEY_CTX_free(kctx);
                throw CryptoException("RSA Key generation failed");
            }
            EVP_PKEY_CTX_free(kctx);
            // 注意：EVP_PKEY_keygen 将生成的密钥赋值给了 p，我们需要重置智能指针接管它
            pkey.release(); // 释放旧的空指针所有权
            pkey.reset(p);  // 接管新的
            
        } else {
            // 生成 ECC 密钥 (使用 prime256v1 / NIST P-256 曲线)
            // 这是一个现代且高效的选择
            EVP_PKEY* p = nullptr;
            EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
            if (!kctx) throw CryptoException("EVP_PKEY_CTX_new_id failed");

            if (EVP_PKEY_keygen_init(kctx) <= 0 ||
                EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1) <= 0 ||
                EVP_PKEY_keygen(kctx, &p) <= 0) {
                EVP_PKEY_CTX_free(kctx);
                throw CryptoException("ECC Key generation failed");
            }
            EVP_PKEY_CTX_free(kctx);
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
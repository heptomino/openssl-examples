// 编译命令:
// Linux/macOS: g++ examples/crypto_utils.cpp -o aes_gcm -lssl -lcrypto
// Windows (MSVC): cl examples\crypto_utils.cpp /I"C:\path\to\openssl\include" /link /libpath:"C:\path\to\openssl\lib" libssl.lib libcrypto.lib

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <array>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// --- 基础类型定义 ---
// 使用 uint8_t vector 处理二进制数据是 C++ 的最佳实践，比 char* 更安全
using Bytes = std::vector<uint8_t>;

// --- RAII Wrappers ---
// EVP_CIPHER_CTX 是 OpenSSL 加密操作的核心上下文
struct EVP_CIPHER_CTX_deleter {
    void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); }
};
using unique_EVP_CIPHER_CTX = std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_deleter>;

// --- 异常处理 ---
class CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string& msg) : std::runtime_error(msg) {
        // 在实际应用中，这里可以抓取 ERR_get_error() 堆栈
    }
};

// --- AES-GCM 加密工具类 ---
class AesGcm {
public:
    // AES-256 需要 32 字节的密钥
    static constexpr size_t KEY_SIZE = 32;
    // GCM 推荐 IV 长度为 12 字节 (96 bits)
    static constexpr size_t IV_SIZE = 12;
    // GCM 默认 Tag 长度为 16 字节 (128 bits)
    static constexpr size_t TAG_SIZE = 16;

    /**
     * @brief 加密数据
     * @param plaintext 原始数据
     * @param key 32字节密钥
     * @param aad 附加认证数据(可选)，不加密但参与完整性校验
     * @return 包含 IV + Ciphertext + Tag 的组合数据
     */
    static Bytes encrypt(const Bytes& plaintext, const Bytes& key, const Bytes& aad = {}) {
        if (key.size() != KEY_SIZE) {
            throw CryptoException("Invalid key size. Must be 32 bytes for AES-256.");
        }

        // 1. 生成随机 IV
        Bytes iv(IV_SIZE);
        if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
            throw CryptoException("Failed to generate random IV.");
        }

        // 2. 创建并初始化上下文
        unique_EVP_CIPHER_CTX ctx(EVP_CIPHER_CTX_new());
        if (!ctx) throw CryptoException("Failed to create EVP_CIPHER_CTX");

        // 初始化加密操作，指定 AES-256-GCM
        if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            throw CryptoException("EVP_EncryptInit_ex failed");
        }

        // 设置 IV 长度 (默认为12，显式设置是个好习惯)
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(IV_SIZE), nullptr) != 1) {
            throw CryptoException("Failed to set IV length");
        }

        // 传入 Key 和 IV
        if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
            throw CryptoException("Failed to set Key and IV");
        }

        // 3. 处理 AAD (附加认证数据)
        // 这部分数据不会被加密，但会被计算进 Tag 中，防止元数据被篡改
        int outlen;
        if (!aad.empty()) {
            if (EVP_EncryptUpdate(ctx.get(), nullptr, &outlen, aad.data(), static_cast<int>(aad.size())) != 1) {
                throw CryptoException("Failed to set AAD");
            }
        }

        // 4. 加密数据
        // 输出缓冲区大小至少要等于输入大小 (对于 GCM，通常是一样的)
        Bytes ciphertext(plaintext.size());
        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &outlen, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
            throw CryptoException("Encryption failed during Update");
        }
        int total_len = outlen;

        // 5. 结束加密 (GCM 模式下这一步通常不输出数据，但必须调用以计算 Tag)
        if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + outlen, &outlen) != 1) {
            throw CryptoException("Encryption failed during Final");
        }
        total_len += outlen;
        ciphertext.resize(total_len); // 调整为实际大小

        // 6. 获取 Tag (这是验证数据完整性的关键)
        Bytes tag(TAG_SIZE);
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(TAG_SIZE), tag.data()) != 1) {
            throw CryptoException("Failed to get Tag");
        }

        // 7. 打包结果: IV + Ciphertext + Tag
        Bytes result;
        result.reserve(iv.size() + ciphertext.size() + tag.size());
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());
        result.insert(result.end(), tag.begin(), tag.end());

        return result;
    }

    /**
     * @brief 解密数据
     * @param packed_data 包含 IV + Ciphertext + Tag 的组合数据
     * @param key 32字节密钥
     * @param aad 附加认证数据(必须与加密时一致)
     * @return 解密后的原始数据
     */
    static Bytes decrypt(const Bytes& packed_data, const Bytes& key, const Bytes& aad = {}) {
        if (key.size() != KEY_SIZE) {
            throw CryptoException("Invalid key size.");
        }
        if (packed_data.size() < IV_SIZE + TAG_SIZE) {
            throw CryptoException("Invalid data format: too short.");
        }

        // 1. 拆包: 提取 IV, Ciphertext, Tag
        Bytes iv(packed_data.begin(), packed_data.begin() + IV_SIZE);
        Bytes tag(packed_data.end() - TAG_SIZE, packed_data.end());
        Bytes ciphertext(packed_data.begin() + IV_SIZE, packed_data.end() - TAG_SIZE);

        // 2. 创建并初始化上下文
        unique_EVP_CIPHER_CTX ctx(EVP_CIPHER_CTX_new());
        if (!ctx) throw CryptoException("Failed to create EVP_CIPHER_CTX");

        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            throw CryptoException("EVP_DecryptInit_ex failed");
        }

        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(IV_SIZE), nullptr) != 1) {
            throw CryptoException("Failed to set IV length");
        }

        if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
            throw CryptoException("Failed to set Key and IV");
        }

        // 3. 处理 AAD
        int outlen;
        if (!aad.empty()) {
            if (EVP_DecryptUpdate(ctx.get(), nullptr, &outlen, aad.data(), static_cast<int>(aad.size())) != 1) {
                throw CryptoException("Failed to set AAD");
            }
        }

        // 4. 解密数据
        Bytes plaintext(ciphertext.size());
        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outlen, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
            throw CryptoException("Decryption failed during Update");
        }
        int total_len = outlen;

        // 5. 设置期望的 Tag (这是 GCM 解密最关键的一步！)
        // 在 Final 之前，必须告诉 OpenSSL 应该匹配哪个 Tag
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(TAG_SIZE), tag.data()) != 1) {
            throw CryptoException("Failed to set expected Tag");
        }

        // 6. 结束解密并验证 Tag
        // 如果 Tag 不匹配，EVP_DecryptFinal_ex 将返回 0（失败）。
        // 这意味着数据被篡改或密钥错误。
        if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + outlen, &outlen) <= 0) {
            // 为了安全，这里不应返回任何部分解密的数据
            throw CryptoException("Authentication failed! Integrity check error (Tag mismatch).");
        }
        total_len += outlen;
        plaintext.resize(total_len);

        return plaintext;
    }

    // 辅助函数：将 Bytes 转为 Hex 字符串方便打印
    static std::string to_hex(const Bytes& data) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (uint8_t b : data) ss << std::setw(2) << (int)b;
        return ss.str();
    }
    
    // 辅助函数：从字符串创建 Bytes
    static Bytes from_string(const std::string& s) {
        return Bytes(s.begin(), s.end());
    }
    
    // 辅助函数：将 Bytes 转回字符串
    static std::string to_string(const Bytes& b) {
        return std::string(b.begin(), b.end());
    }
};

int main() {
    try {
        // 模拟一个 32 字节的密钥 (实际应用中应从安全的 KDF 或 Key Vault 获取)
        Bytes key(32, 0xAB); 
        
        std::string original_text = "Hello, this is a secret message secured by AES-GCM!";
        std::string aad_text = "header-info-v1"; // 假设这是协议头，不加密但需防篡改

        std::cout << "Original: " << original_text << "\n";
        
        // 1. 加密
        Bytes encrypted = AesGcm::encrypt(
            AesGcm::from_string(original_text), 
            key, 
            AesGcm::from_string(aad_text)
        );
        
        std::cout << "Encrypted (Hex): " << AesGcm::to_hex(encrypted) << "\n";
        std::cout << "Total size: " << encrypted.size() << " bytes\n";

        // 2. 解密
        Bytes decrypted = AesGcm::decrypt(
            encrypted, 
            key, 
            AesGcm::from_string(aad_text)
        );

        std::cout << "Decrypted: " << AesGcm::to_string(decrypted) << "\n";

        // 3. 演示篡改检测
        std::cout << "\n--- Tamper Test ---\n";
        encrypted[encrypted.size() - 1] ^= 0x01; // 修改 Tag 的最后一个字节
        try {
            AesGcm::decrypt(encrypted, key, AesGcm::from_string(aad_text));
        } catch (const std::exception& e) {
            std::cout << "Caught expected error: " << e.what() << "\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
# C++ OpenSSL 最佳实践（三）：拒绝ECB，使用 AES-GCM 打造现代加密工具类

在前两篇文章中，我们构建了安全的通信管道（HTTPS 客户端与服务端）。但如果你的需求不仅仅是传输数据，而是要将敏感数据（如用户配置、本地数据库文件、或者身份令牌）**存储**在磁盘上呢？

很多开发者在这一步会犯严重的错误：直接调用底层的 `AES_encrypt` 函数，或者错误地选择了 ECB 模式，甚至忘记了对加密数据进行完整性校验（MAC）。

本篇文章将带你回到密码学的原点。我们将使用 OpenSSL 推荐的高层 **EVP (Envelope)** 接口，结合现代 C++，封装一个基于 **AES-256-GCM** 的加密工具类。GCM（Galois/Counter Mode）是一种 **AEAD（带认证的加密）** 模式，它能同时保证数据的**机密性**（别人看不懂）和**完整性**（没人篡改过）。

## 最终代码示例

这是一个生产级可用的 AES-GCM 封装类。它展示了如何安全地生成随机 IV（初始化向量），处理认证标签（Tag），并使用 `std::vector<uint8_t>` 来安全地处理二进制数据。

<!-- filename: examples/crypto_utils.cpp -->

```cpp
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
```

# OpenSSL 核心概念解析：EVP 与 AES-GCM

在这一篇中，我们离开了 `SSL_` 前缀的函数，进入了 `EVP_` (Envelope) 的领域。

### 1. `EVP_CIPHER_CTX`：通用的加密上下文

*   **它是什么？**：就像 `SSL_CTX` 管理 TLS 配置一样，`EVP_CIPHER_CTX` 维护着一次对称加密操作的状态。它记录了当前的算法（AES-GCM）、密钥、IV、部分处理的数据块以及内部缓冲区。
*   **为什么需要它？**：OpenSSL 支持数十种加密算法（AES, ChaCha20, Camellia等）。`EVP` 提供了一个统一的高层接口。你只需要将 `EVP_aes_256_gcm()` 传给上下文，剩下的代码对于所有算法几乎都是通用的。这比直接调用底层的 `AES_encrypt` 要安全得多，因为底层 API 容易误用（例如容易搞错填充）。

### 2. AES-GCM：认证加密的黄金标准

在代码中，我们选择了 `EVP_aes_256_gcm()`。这不仅仅是因为它“强”，而是因为它解决了两个问题：
1.  **机密性 (Confidentiality)**：使用 AES 算法加密，别人看不懂。
2.  **完整性 (Integrity)**：使用 GCM 模式生成 **Tag**（认证标签）。

**Tag 的重要性**：
在传统的 CBC 模式中，如果攻击者篡改了密文的某一位，解密出来可能是一堆乱码，但程序可能会继续处理这些乱码，导致崩溃或逻辑漏洞。而在 GCM 模式下，解密函数 `EVP_DecryptFinal_ex` 会自动校验 Tag。**如果密文被修改过哪怕一个比特，校验都会失败，解密操作会返回错误。**

### 3. AAD (Associated Authenticated Data)

你会在代码中看到 `aad` 参数。这是一种很酷的功能。
*   **场景**：假设你加密了一个网络包，包头包含“协议版本”和“目标IP”，包体是加密数据。
*   **问题**：攻击者不能修改包体（因为有加密），但他可以修改包头的“目标IP”，把包转发给别人。
*   **解决**：你可以把包头作为 AAD 传入。AAD **不会被加密**（它是明文），但它**参与 Tag 的计算**。解密时，如果 AAD 不匹配，解密也会失败。这确保了元数据和加密数据的绑定关系。

## C++ 最佳实践深度解析

### 1. 二进制数据类型的选择：`std::vector<uint8_t>`

**问题**：在 C 语言和旧式 C++ 代码中，我们习惯用 `char*` 或 `std::string` 来存储二进制数据（密钥、密文）。
**风险**：`char` 在不同平台上可能有符号也可能无符号。更糟糕的是，`std::string` 语义上是用来存文本的，使用它存二进制数据容易让人误解，且在该字符串被打印或处理时可能因为 `\0` 截断或编码问题导致数据损坏。
**最佳实践**：使用 `std::vector<uint8_t>`（本例中别名为 `Bytes`）。
*   它语义明确：这是一串字节，不是文本。
*   它内存连续：可以直接传给 OpenSSL 的 C API（使用 `.data()`）。
*   它能自动管理内存大小。

### 2. 避免“重用 IV”的灾难

在 AES-GCM 中，**IV (Initialization Vector) 绝对不能重复**。如果同一个 Key 和同一个 IV 被使用了两次，攻击者可以利用异或性质直接破解出明文。
**代码策略**：
*   我们的 `encrypt` 函数内部调用 `RAND_bytes` **强制生成新的随机 IV**。
*   我们将 IV 直接拼接到密文的前面 (`IV + Ciphertext + Tag`)。IV 不需要保密，只需要唯一，所以随密文一起传输是标准的做法。

### 3. 正确的 Tag 处理流程

OpenSSL 的 GCM API 在加密和解密时对 Tag 的处理是不对称的，这是新手最容易掉坑的地方：
*   **加密时**：Tag 是在 `EVP_EncryptFinal_ex` 之后生成的。你需要调用 `EVP_CIPHER_CTX_ctrl` + `EVP_CTRL_GCM_GET_TAG` 来**获取**它。
*   **解密时**：你必须在调用 `EVP_DecryptFinal_ex` **之前**，调用 `EVP_CIPHER_CTX_ctrl` + `EVP_CTRL_GCM_SET_TAG` 来**设置**期望的 Tag。如果 Final 阶段发现计算出的 Tag 与设置的不一致，它会报错。

### 4. 异常安全 (Exception Safety)

我们在 `encrypt/decrypt` 函数中使用了 RAII (`unique_EVP_CIPHER_CTX`)。如果在加密过程中抛出异常（比如内存不足，或者 OpenSSL 内部错误），`unique_ptr` 会确保 `EVP_CIPHER_CTX_free` 被自动调用。
如果没有 RAII，一旦中间步骤抛出异常，这个 Context 就会泄漏，长此以往会导致内存耗尽。

## 结论

通过封装 OpenSSL 的 EVP 接口，我们不仅获得了一个易于使用的 C++ 加密类，更重要的是我们屏蔽了底层密码学的复杂性和陷阱。我们强制使用了随机 IV，强制进行了 Tag 校验，并使用了类型安全的容器。

现在，你已经掌握了如何在 C++ 中安全地“锁住”你的数据。无论是在本地存储配置文件，还是设计自定义的加密协议，这个 `AesGcm` 类都是一个坚实的基石。
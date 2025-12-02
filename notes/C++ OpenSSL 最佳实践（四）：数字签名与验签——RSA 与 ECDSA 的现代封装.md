# C++ OpenSSL 最佳实践（四）：数字签名与验签——RSA 与 ECDSA 的现代封装

在上一篇文章中，我们利用 AES-GCM 构建了一个坚固的加密工具，确保了数据**不被偷看**（机密性）。但在网络安全的世界里，还有另一个同样关键的问题：**信任**。

试想以下场景：
*   **软件更新**：客户端下载了一个固件包，如何确保它是由官方发布的，而不是被黑客植入后门的恶意版本？
*   **API 鉴权**：服务器收到一个请求，如何确信它真的来自合法的用户，而不是被中间人篡改过的伪造请求？
*   **区块链交易**：如何证明这笔转账确实是由账户持有者发起的？

加密无法解决这些问题（因为黑客也可以加密恶意数据）。我们需要的是**数字签名**。就像古代信件上的火漆印章或支票上的手写签名一样，数字签名能证明数据的**来源**（Origin）和**完整性**（Integrity）。

本篇文章将带你深入 OpenSSL 的非对称密码学领域。我们将封装一套通用的签名与验签工具，支持经典的 **RSA** 和现代高效的 **ECDSA**（椭圆曲线），并继续贯彻我们的现代 C++ 设计哲学。

## 最终代码示例

这是一个高度封装的 `SignatureManager` 类。它屏蔽了 OpenSSL 底层复杂的 `EVP` 状态机，提供了一个简洁的接口来执行签名和验证。代码中同时演示了如何生成和使用 RSA 与 ECC（椭圆曲线）密钥对。

<!-- filename: examples/signature_utils.cpp -->

```cpp
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
```

## OpenSSL 核心概念解析

在非对称加密和签名领域，OpenSSL 提供了两套 API：一套是特定于算法的（如 `RSA_sign`、`ECDSA_sign`），另一套是通用的 EVP 接口。**最佳实践是永远使用 EVP 接口**。

### 1. `EVP_PKEY`：万能钥匙容器

*   **它是什么？**：`EVP_PKEY` 是一个抽象的容器，它可以持有 RSA 密钥、DSA 密钥、ECC（椭圆曲线）密钥，甚至是最新的 Ed25519 密钥。
*   **为什么需要它？**：它实现了“算法无关性”。在我们的代码中，`sign` 和 `verify` 函数接受 `EVP_PKEY*` 指针。这意味着同一套代码可以用于验证 RSA 签名，也可以用于验证 ECDSA 签名。你只需要在加载或生成密钥时指定算法即可，无需修改业务逻辑。

### 2. `EVP_DigestSign` 与 `EVP_DigestVerify`

*   **流程**：签名的本质是：`Hash(数据) -> 使用私钥加密 Hash`。
*   **EVP 的封装**：OpenSSL 的 `EVP_DigestSign*` 系列函数将“哈希”和“非对称加密”这两个步骤封装在了一个 Pipeline 中。
    1.  `Init`：设置哈希算法（如 SHA-256）和密钥。
    2.  `Update`：像计算普通哈希一样，分块传入大文件或数据流。
    3.  `Final`：OpenSSL 内部完成最后的数据哈希计算，并自动调用对应算法（RSA 或 ECDSA）的底层签名逻辑输出结果。

这种设计不仅简化了调用，还避免了开发者手动计算 Hash 然后错误地调用底层签名函数的风险（例如，RSA 签名对 Padding 方式非常敏感，EVP 接口会自动处理这些细节）。

## C++ 最佳实践深度解析

### 1. 算法敏捷性 (Algorithm Agility)

在现代安全工程中，"Hard-coding"（硬编码）具体的算法是一种反模式。虽然我们的示例为了演示方便硬编码了 SHA-256，但在 `EVP_PKEY` 的设计支持下，我们可以轻松地更换底层的非对称算法。

观察 `generate_key` 函数中的 `RSA` 和 `ECC` 分支。虽然生成过程不同，但它们最后都产生了一个 `EVP_PKEY` 对象。一旦有了这个对象，后续的 `sign` 和 `verify` 函数对于两种算法是**完全复用**的。这使得你的程序在未来需要从 RSA 迁移到更高效的 ECC 时，只需更改密钥加载部分的代码。

### 2. RSA vs ECDSA：该选哪个？

在实际应用中，你经常面临这个选择。

*   **RSA (Rivest–Shamir–Adleman)**：
    *   **优点**：历史悠久，兼容性极好（几乎所有系统都支持）。**验签速度极快**（这对于客户端验证服务端证书非常有利）。
    *   **缺点**：密钥很大（2048位是底线），签名后的数据也很大（256字节）。生成密钥慢。
    *   **适用场景**：传统的 Web 证书、旧系统兼容、注重验签性能的场景。

*   **ECDSA (Elliptic Curve Digital Signature Algorithm)**：
    *   **优点**：**效率极高**。256 位的 ECC 密钥提供的安全性相当于 3072 位的 RSA 密钥。签名产生的数据非常小（约 64-72 字节），生成密钥和签名速度都很快。
    *   **缺点**：验签操作涉及复杂的点乘运算，比 RSA 验签稍慢（但在现代 CPU 上差异已不明显）。实现复杂，对随机数生成器的质量要求极高（随机数不好会导致私钥泄露）。
    *   **适用场景**：移动设备、区块链、带宽受限的 IoT 设备、现代微服务通信。

**建议**：对于新系统，**优先选择 ECC (如 P-256 或 Ed25519)**。它更节省带宽和存储空间。

### 3. 正确处理 OpenSSL 的“两步调用”

在 `sign` 函数中，你会注意到 `EVP_DigestSignFinal` 被调用了两次：

```cpp
// 第一次调用：传 nullptr，获取所需的缓冲区大小
EVP_DigestSignFinal(ctx.get(), nullptr, &sig_len);

// 调整缓冲区大小
signature.resize(sig_len);

// 第二次调用：传缓冲区，写入实际数据
EVP_DigestSignFinal(ctx.get(), signature.data(), &sig_len);
```

这是 C 语言 API 的经典模式。**不要硬编码签名长度**（例如不要假设 RSA-2048 的签名永远是 256 字节，或者 ECC 的签名永远是 72 字节）。总是让 OpenSSL 告诉你它需要多少空间，这样你的代码才能健壮地适应不同的密钥长度和算法。

### 4. 验证的返回值陷阱

`EVP_DigestVerifyFinal` 的返回值非常容易让人混淆，需要特别注意：

*   **`1`**：验证**成功**。签名有效。
*   **`0`**：验证**失败**。签名格式正确，但与数据不匹配（数据被篡改或密钥错误）。
*   **`< 0`**：**程序错误**。比如内存不足、配置错误等。

在 C++ 代码中，我们必须区分“验证失败”和“程序出错”。如果是程序出错，应该抛出异常；如果是验证失败，应该返回 `false`。切勿简单地用 `if (EVP_DigestVerifyFinal(...))` 来判断，因为负数在 C++ if 中也会被视为 true！**必须显式检查 `== 1`**。

## 总结

通过封装 `EVP_PKEY` 和 `EVP_Digest*` 系列函数，我们获得了一个强大且灵活的签名工具类。它不仅支持 RSA 和 ECDSA 的无缝切换，还利用 RAII 和 C++ 异常机制规避了 OpenSSL 底层 API 常见的内存泄漏和错误检查遗漏问题。

至此，我们的工具箱里已经有了：
1.  **HTTPS 客户端/服务端**：建立安全通道。
2.  **AES-GCM**：保护静态数据的机密性。
3.  **Digital Signature**：保护数据的完整性与真实性。

这三者构成了现代网络安全开发的基石。在下一篇文章中，我们将挑战更高阶的话题：如何将这些同步的操作变为**非阻塞（Non-blocking）**，以构建高性能的异步网络应用。
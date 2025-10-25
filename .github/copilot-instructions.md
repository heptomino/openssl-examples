## 快速目标
帮助自动化编码代理（Copilot / AI agents）快速上手本仓库：理解项目目的、关键文件、构建/运行步骤、以及特有的编码约定与调试技巧。

## 大体架构（为何这样组织）
- 本仓库包含两个示例程序：一个 TLS 客户端（`examples/client.cpp`）和一个 TLS 服务器示例（`examples/server.cpp`，示例/文章在 `C++ OpenSSL 最佳实践（二）...md` 中）。
- 设计目标：使用现代 C++（RAII + exceptions）封装 OpenSSL，简化资源管理并避免裸指针/手动释放。
- 通信模型：客户端使用 `BIO_new_ssl_connect`（在 `examples/client.cpp`），服务器使用 `BIO_new_accept` + 为每连接构建 `SSL BIO -> socket BIO` 链（参见文章 md 中的 `BIO_push` / `BIO_do_handshake` 示例）。

## 关键文件一览
 - `examples/client.cpp` — TLS 客户端示例，展示如何加载系统信任库（`SSL_CTX_set_default_verify_paths` / Windows 使用 CertOpenSystemStore）、SNI 设置、主机名验证以及 `BIO_new_ssl_connect` 使用。
 - `examples/server.cpp` — TLS 服务器（文章同时给出完整示例），监听 `4433`，加载 `cert.pem`/`key.pem`，为每个接入连接构建 SSL BIO 链并执行握手。
- `cert.pem`, `key.pem` — 自签名证书/私钥（开发测试），必须与可执行文件同目录或在 server 运行前指定正确路径。
- `C++ OpenSSL 最佳实践（二）...md` — 设计说明与逐行解释（重要的行为和修正被记录在这里，可作为实现依据）。

## 快速构建与运行（最常用的开发工作流）
- 构建客户端：
  `g++ main.cpp -o ssl_example -lssl -lcrypto`
- 构建服务器：
  `g++ server.cpp -o ssl_server -lssl -lcrypto`
- 运行服务器（默认示例监听 4433）：
  `./ssl_server`
  运行前确保 `cert.pem` 与 `key.pem` 在当前目录。
- 测试（在另一终端）：
  `curl -v -k https://localhost:4433`  # `-k` 跳过自签名证书验证

## 项目特有约定与模式（对 AI 很重要）
- 错误处理：本项目通过抛出 `OpenSSLException`（继承自 `std::runtime_error`）来传播 OpenSSL 层的错误，并在构造器中打印由 `ERR_get_error()` 收集的详情。修改行为时保持异常语义一致。
- 资源管理：使用自定义删除器和 `std::unique_ptr` 封装 OpenSSL 资源（例如 `unique_SSL_CTX`, `unique_BIO`）。不要替换为裸指针释放；请保留 RAII 风格。
- BIO 链约定（关键）：服务器端流程为 `accept BIO` -> `BIO_do_accept` -> `BIO_pop`（得到 socket BIO）-> `BIO_new_ssl(ctx, 0)`（server-mode）-> `BIO_push(ssl_bio, socket_bio)` -> `BIO_do_handshake(chain_head)` -> `BIO_read/write(chain_head)`。这段逻辑在文章 md 中有完整示例，是实现时必须遵守的顺序。
- 网络端口：示例服务器使用 `4433`（非默认 `443`），客户端 `examples/client.cpp` 默认连接 `:443` —— 如果用客户端测试本地服务器，请把 `host_with_port` 改为 `hostname + ":4433"`（文章中有示例说明）。

## 平台与集成要点
- Windows 特殊处理：`main.cpp` 和示例中包含 Windows 证书导入（`CertOpenSystemStore`）和 Winsock 初始化（`WSAStartup`/`WSACleanup`）；修改或在 CI 中使用这些代码时请考虑条件编译宏 `#if defined(_WIN32)`。
- 依赖：系统上需安装 OpenSSL 开发库（头文件与 lib）。在 linux/macOS 下用 `-lssl -lcrypto` 链接。

## 调试与常见问题（工程化提示）
- 握手失败：查看程序 stderr（`ERR_print_errors_fp(stderr)` 或 `OpenSSLException` 输出），并用 `curl -v` 检查客户端握手日志。
- 证书验证失败（客户端）：如果使用自签名证书，连接测试请使用 `curl -k`，或把自签名证书加入系统受信任根（仅在受控测试环境）。
- 端口占用：如果 `BIO_do_accept` 在绑定时失败，检查是否已有进程占用 4433（`ss -ltnp | grep 4433`）。

## 示例新增与迭代工作流（重要）

当你从外部粘贴一篇新文章（包含完整代码示例）到仓库的 `notes/` 目录时，遵循以下最小流程可以让 AI 代理快速将文章变为可运行示例并修正文中/代码中的问题：

1. 把文章放到 `notes/<slug>.md`（`<slug>` 使用短小的 ASCII 字符，如 `best-practice-3`）。
2. 确保文章中包含完整的可编译代码块，使用 fenced code block 并指定语言：

  ```cpp
  // 这里是一段完整的 C++ 程序
  ```

3. 约定：把对应的源文件放在 `examples/`（推荐）或仓库根目录，并采用 `<slug>.cpp` 命名。例如：`examples/best-practice-3.cpp`。
4. 编译步骤（在 Linux/macOS）：

  ```bash
  mkdir -p examples
  # 假设你已把代码保存为 examples/best-practice-3.cpp
  g++ examples/best-practice-3.cpp -o examples/best-practice-3 -lssl -lcrypto
  ```

5. 运行与验证：使用与文章一致的运行命令（示例见每篇文章顶部的注释），并用 `curl -v` 等工具验证网络行为（若适用）。
6. 迭代原则（AI 代理应该自动执行或建议）：
  - 优先在不改动原文章叙述的前提下修复可编译错误（头文件、命名、API 更改）。
  - 对 API 的错误使用（例如 BIO 链顺序）在代码注释中写明修正理由，并在文章中更新对应段落（保留原文并追加注释）。
  - 运行时错误（握手失败、证书问题）优先通过增强日志（`ERR_print_errors_fp` / 抛出 `OpenSSLException`）来定位，再在文章中说明复现与解决步骤。

7. 可选：我可以为仓库添加一个小脚本 `tools/extract_and_build.sh` 来自动从 `notes/<slug>.md` 提取第一个 ```cpp ``` 代码块并保存为 `examples/<slug>.cpp`，然后编译并运行基本 smoke test——如果你想我可以实现并加入 CI。

   - 说明：脚本并不严格依赖文件名格式为 `<slug>.md`。它会按以下优先级决定输出文件名：
     1. 文章中的第一个 H1（`# Title`），sanitize（ASCII、小写、非字母数字替换为 `-`）后作为文件名。
     2. 若没有 H1，则使用 Markdown 的文件名（去掉扩展名）作为输出名。
     3. 输出始终写入 `examples/` 目录（默认），并可通过脚本参数覆盖。
     - 覆盖文件名：你也可以在代码块前显式指定输出文件名，格式为 HTML 注释：

       ```
       <!-- filename: examples/my_example.cpp -->
       ```

       如果注释中包含目录（例如 `examples/`），脚本会把该路径作为仓库相对路径写入；否则脚本会把文件写入 `examples/` 目录。

   - 使用示例：
     ```bash
     # 提取并编译 notes/ 下所有 md，输出到 examples/
     tools/extract_and_build.sh

     # 不编译，只提取（将第三个参数设为 0）
     tools/extract_and_build.sh notes examples 0
     ```

## 修改与贡献规则（针对 AI 编辑）
- 保留 RAII + 异常风格。若新增函数/类，请使用相同的资源封装方式（`unique_*` typedef + custom deleter）。
- 若调整握手或 BIO 相关逻辑，务必在注释中指出引用的文章段落或原始实现行号，避免误用 `BIO_pop`/`BIO_push` 的顺序。

---
如果这份指南有遗漏（例如你想让我把 `server.cpp` 具体函数内的注释转成更详细的 inline TODOs，或需要添加 CI 构建脚本/测试），告诉我需要补充的点，我会迭代更新这份文件。

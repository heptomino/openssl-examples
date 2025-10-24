# OpenSSL Examples (现代 C++ 最佳实践)

一组面向教学的示例，展示如何在现代 C++ 中安全且可维护地使用 OpenSSL（RAII、异常、BIO/SSL API 的正确用法）。

目录结构（重要文件）
- `main.cpp` — 最佳实践（一）：TLS 客户端示例
- `server.cpp` — 最佳实践（二）：TLS 服务器示例（监听 4433）
- `notes/` — 存放每篇文章的草稿与最终文档（文章应包含完整的代码示例）
- `examples/` — （推荐）存放从文章抽取并可编译的源代码示例（如果不存在，可创建）

快速开始

1. 编译客户端：

```bash
g++ main.cpp -o ssl_example -lssl -lcrypto
```

2. 编译服务器：

```bash
g++ server.cpp -o ssl_server -lssl -lcrypto
```

3. 运行服务器（确保 `cert.pem` 与 `key.pem` 在当前目录）：

```bash
./ssl_server
```

4. 测试（在另一终端）：

```bash
curl -v -k https://localhost:4433
```

新增示例（建议工作流）

1. 把文章（包含完整代码）保存到 `notes/<slug>.md`。
2. 在文章中用 ```cpp 标注完整可编译的代码块。
3. 将代码块另存为 `examples/<slug>.cpp`，或放在仓库根目录并以 `<slug>.cpp` 命名。
4. 编译并运行（见上面命令）。

如果你愿意，我可以：
- 为你实现 `tools/extract_and_build.sh`，自动从 `notes/<slug>.md` 提取第一个 `cpp` 代码块并编译为 `examples/<slug>`，并把它加入到一个简单的 GitHub Actions CI（只做快速构建和 smoke test）。

贡献者指南（对 AI 代理）
- 保持 RAII + 异常风格（使用 `unique_*` typedefs 和自定义释放器）。
- 任何对 BIO 链或握手流程的修正，需在代码注释中说明原因并在文章中更新相关段落。

许可证

本仓库示例用于教学目的，请在实际生产使用前进行安全审计并替换示例证书。

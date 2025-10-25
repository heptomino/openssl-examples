# OpenSSL Examples (现代 C++ 最佳实践)

一组面向教学的示例，展示如何在现代 C++ 中安全且可维护地使用 OpenSSL（RAII、异常、以及正确的 BIO/SSL 使用模式）。

仓库布局（重要目录）
- `examples/` — 可编译的示例源（客户端/服务器示例）。
- `notes/` — 教学文章与逐行说明。通常把文章放在这里并从中抽取示例代码。
- `certs/` — 本地证书目录（开发/测试用）。*注意：私钥不应提交到远程仓库，已有项目请参照下文处理。*
- `bin/` — 编译产物（可执行二进制）。
- `logs/` — 运行时日志和 PID 文件（runtime-generated）。
- `tools/` — 启动/辅助脚本（例如 `tools/run_server.sh`）。

快速开始（推荐流程）

1. 构建（使用仓库 Makefile）：

```bash
make
```

这会把 `examples/server.cpp` 编译为 `bin/server`（链接 `-lssl -lcrypto`）。

2. 启动服务器（推荐使用 helper）：

```bash
./tools/run_server.sh start
```

该脚本会把 stdout/stderr 重定向到 `logs/server.out`，并把 PID 写到 `logs/server.pid`。服务器默认使用 `certs/cert.pem` 和 `certs/key.pem`，监听端口 `4433`。

3. 测试（另一终端）：

```bash
curl -v -k https://localhost:4433
```

可用的环境覆盖（可选）
- `OPENSSL_CERT_DIR` — 指定证书/私钥目录（默认 `certs/`）。
- `OPENSSL_LOG_DIR`  — 指定日志目录（默认 `logs/`）。

例如：

```bash
OPENSSL_CERT_DIR=/path/to/mycerts OPENSSL_LOG_DIR=/tmp/mylogs ./tools/run_server.sh start
```

安全与版本控制建议
- `certs/` 目录用于本地测试，但**不要**把私钥提交到远程仓库。仓库已包含 `.gitignore`，忽略 `certs/*.pem`、`logs/`、`bin/` 等运行时文件。
- 如果仓库中已有敏感文件（例如 `certs/key.pem`），建议把它们从 Git 索引中移除但保留在磁盘：

```bash
git rm --cached certs/key.pem certs/cert.pem
git commit -m "Remove local certs from index; keep them locally and add to .gitignore"
```

示例设计原则
- 本仓库示例聚焦于 OpenSSL 的正确用法（资源管理、BIO链、握手流程），而不是实现完整的生产级 HTTP 服务器。
- 我们优先保持示例简短、可读，并在必要时添加最小的健壮性改进（例如日志、优雅退出、可靠写入）。

进一步改进（可选）
- 添加 CI（GitHub Actions）以在每次 PR 中编译示例并运行 smoke tests。
- 将证书处理与示例解耦，提供一个 `tools/generate_dev_certs.sh` 来在本地生成测试证书（仅用于开发）。

贡献者指南（对 AI 代理）
- 保持 RAII + 异常风格（使用 `unique_*` typedefs 和自定义删除器）。
- 对 BIO 链或握手流程的任何修正，应在代码注释和对应 `notes/` 文档中说明原因。

许可证

本仓库示例用于教学目的，请在实际生产使用前进行安全审计并替换示例证书。

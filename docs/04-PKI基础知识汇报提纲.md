# PKI 基础知识汇报提纲

## 1. 背景与目标

- 为什么需要 PKI：身份认证、数据保密、完整性、不可否认。
- 本次任务目标：自建 CA、签发证书、实现浏览器双向 SSL（mTLS）；演示环境为 **Windows、无 Docker、单人单机**。

## 2. 核心概念

- X.509 证书结构（Subject、Issuer、SAN、KU、EKU、有效期）。
- 证书链与信任锚（Root → Intermediate → 终端实体）。
- CRL 与 OCSP 的差异及使用场景。
- **CDP / AIA**：叶子证书中如何指向 CRL 与 CA 签发者信息；本仓库通过本机 HTTP `/repo/` 做最小「证书仓库」演示。

## 3. 技术方案

- 两级 CA 架构设计与安全收益（Root 离线思路、Intermediate 在线签发）。
- 证书签发策略（server/client 分模板，`openssl-intermediate.cnf` 中 EKU、SAN、CDP/AIA）。
- mTLS 在 TLS 握手中的验证流程（服务端校验客户端证书链、可选 CRL）。
- **可选组件**：FastAPI Web 控制台（Python 编排 + OpenSSL）、公开 `/repo/` 分发链与 CRL、`audit.jsonl` 模拟管理员侧留痕。
- **严格口径补充**：区分 TLS1.2（教材常见 RSA 叙述）与 TLS1.2/1.3（现代 (EC)DHE）握手路径。
- **双链路补充**：Intl（国际算法）与 GM（国密算法）双专区并行，接口前缀分别为 `/api/intl/*`、`/api/gm/*`。

## 4. 实施过程

- 环境准备：OpenSSL、Python 与 `web/` 虚拟环境（见 `web/README.md`）。
- 现场从零：`docs/02-执行手册.md` **第 4 节** 环境清零（Web「0. 演示重置」）→ **第 7 节** Web 按钮完成初始化与建 CA、签发、校验。
- Root/Intermediate 构建与链路校验；服务端/客户端证书签发与浏览器导入 P12。
- Web 控制台已支持按钮触发全部核心 Python 工作流，适合单人单机演示（减少命令行输入）。
- 新增 `TLS 握手观测` 按钮：输出 `tls-observe-*.log`，用于讲解 TCP/TLS 分层、证书认证、吊销拒绝和 TLS1.2/1.3 差异。
- 新增 GM 专区：输出 `artifacts/logs/gm/*`，与 Intl 日志隔离，支持并行对比讲解。
- **mTLS 联调**：以 `openssl s_server` 为主路径（本机 `https://localhost:8443/`）；`configs/nginx/mtls.conf` 为可选参考（非演示必需）。

## 5. 实验结果

- 成功用例：合法客户端证书访问成功；可选展示 `http://127.0.0.1:8765/repo/` 可访问链与 CRL。
- 失败用例：无证书、吊销证书（`s_server` 启用 `-CRL` 与 `-crl_check`）被拒绝。
- 证据：`artifacts/logs/verify-*.log`、浏览器与终端截图、可选 `audit.jsonl`。

## 6. 问题与改进

- 常见问题：SAN 缺失、证书链不完整、CRL 未加载、CDP 端口与 Web 不一致、系统时间漂移。
- 改进方向：自动化续期、OCSP、HSM、分环境证书策略、独立 RA 与强鉴权。

## 7. 结论

- 已完成任务二考核项：CA、签发、mTLS、吊销与验证；并可选展示 **HTTP 仓库 + 审计** 以说明 PKI 组件分工。
- 方案具备可复现、可演示、可扩展特性；详细操作见 [02-执行手册.md](02-执行手册.md)。

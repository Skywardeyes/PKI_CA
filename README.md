# PKI_CA 任务二落地实现

本仓库用于完成培训计划中的任务二：自建 CA、签发证书、完成浏览器双向 SSL 认证并输出汇报材料。环境约定：**Windows、无 Docker、可选 Web 控制台（单人单机演示友好）**。Web 控制台由 **Python 原生编排** 直接调用 OpenSSL，**运行时不再依赖** `powershell -File scripts/*.ps1`。
术语口径（管理员 / 终端用户 / Web 控制台 / HTTP 证书仓库 / 业务 mTLS 服务）统一见 [docs/02-执行手册.md](docs/02-执行手册.md) **§2.1**。

## 快速开始（统一 Web 控制台）

在仓库根目录启动 Python Web 控制台：

```powershell
cd D:\Github\PKI_CA\web
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

浏览器打开 `http://127.0.0.1:8765/`，按按钮执行：
- `0. 演示重置`
- `1. 初始化目录`
- `2. 构建 Root / Intermediate`
- `3. 签发服务端 + 客户端`
- `4. 校验证书链`

浏览器 mTLS：先按 [docs/02-执行手册.md](docs/02-执行手册.md) **第 9、10 节** 启动业务 mTLS 服务（`openssl s_server`）后访问 `https://localhost:8443/`。

## Web PKI 控制台

控制台现已提供 **双专区双链路**：
- Intl 国际算法专区：`/api/intl/*`
- GM 国密算法专区：`/api/gm/*`

两条链路均提供重置、初始化、建 CA、签发、校验、吊销、mTLS、TLS 观测能力；并同时提供 TLS1.2 与 TLS1.3 按钮（GM 的 TLS1.3 握手失败会严格返回 API 失败）。HTTP 证书仓库 `/repo/`（含 `/repo/gm/*`）、审计日志、API 响应结构见 [web/README.md](web/README.md)。

## 目录说明

- `ca/`：OpenSSL CA 配置（含 CDP/AIA 的 `openssl-intermediate.cnf`）
- `gm/`：国密链路运行目录（GM CA/Server/Client 产物）
- `scripts/`：历史对照用 PowerShell 脚本（**Web 运行时不再调用**；编排见 `web/app/services/pki_workflow.py`）
- `web/`：Web 控制台（FastAPI + 静态页）
- `configs/nginx/`：可选的本机 Nginx mTLS 参考配置
- `docs/`：实施标准、**执行手册（含验证矩阵与现场演示时间轴）**、汇报提纲等
- `artifacts/`：验证日志、审计等证据输出（默认不入库）

## 文档索引

| 文档 | 用途 |
|------|------|
| [docs/01-任务二实施标准.md](docs/01-任务二实施标准.md) | 命名、策略、安全与交付基线 |
| [docs/02-执行手册.md](docs/02-执行手册.md) | **主文档**：环境清零、分步命令、Web/CDP、mTLS、吊销、验收、**验证矩阵（§16）**、**演示时间轴（§17）** |
| [docs/04-PKI基础知识汇报提纲.md](docs/04-PKI基础知识汇报提纲.md) | 汇报结构（已与当前实现同步） |
| [web/README.md](web/README.md) | Web 安装、令牌、`/repo/` 与审计 API |
| [培训计划-陆宇涵 姚壬爔.md](培训计划-陆宇涵%20姚壬爔.md) | 原培训计划（任务来源） |

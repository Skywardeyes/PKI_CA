# Web PKI 控制台

在浏览器中触发与 PowerShell 脚本等价的操作（初始化、建 CA、签发、验证、吊销），并下载 `p12` / CA 链文件。

## 依赖

- Python 3.10+
- 本机已安装 **OpenSSL**、**PowerShell**，且仓库根目录下 `scripts/*.ps1` 可正常运行

## 安装与启动

在仓库根目录执行：

```powershell
cd D:\Github\PKI_CA\web
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

启动（仅本机）：

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

浏览器打开：`http://127.0.0.1:8765/`

## HTTP 证书仓库（CDP / AIA，公开只读）

与 [ca/openssl-intermediate.cnf](../ca/openssl-intermediate.cnf) 中叶子证书的 **CDP、AIA（caIssuers）** URI 对应（默认 `http://127.0.0.1:8765/repo/...`）：

- `http://127.0.0.1:8765/repo/` — 索引页
- `http://127.0.0.1:8765/repo/ca-chain.cert.pem`
- `http://127.0.0.1:8765/repo/intermediate.crl.pem`

**无需** `X-Admin-Token` 即可访问（与生产 PKI 中 CRL/链通常公开分发一致）。

## 审计日志

- 控制台触发的 `init` / `build-ca` / `issue` / `verify` / `revoke` 会追加写入仓库根下 `artifacts/logs/audit.jsonl`（每行一条 JSON）。
- `GET /api/audit/tail?n=50`：若已设置 `PKI_WEB_TOKEN`，须带 `X-Admin-Token`；未设置时允许直接读取（便于单人本机演示）。

## 安全建议

- 默认只监听 `127.0.0.1`；若需局域网访问，请自行评估并改用 `--host 0.0.0.0` 且务必设置令牌。
- 设置环境变量 `PKI_WEB_TOKEN` 后，**写操作类 API**、**受控下载**（`/api/download/...`）、**状态与审计读取**需携带相同值的 `X-Admin-Token`（页面可填写并保存到浏览器）。**`/repo/` 下链与 CRL** 仍为公开只读。

```powershell
$env:PKI_WEB_TOKEN = "请改为强随机字符串"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

## 与命令行的关系

Web 控制台是对现有 `scripts/*.ps1` 的封装；浏览器 **mTLS 演示** 仍按 `docs/02-执行手册.md` 使用 `openssl s_server` 与本机 HTTPS。

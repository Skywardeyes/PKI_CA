# Web PKI 控制台（唯一操作入口）

本项目推荐只通过本页面完成操作，不再手工逐条执行脚本命令。  
术语口径（Web 控制台、HTTP 证书仓库、业务 mTLS 服务等）与 [docs/02-执行手册.md](../docs/02-执行手册.md) **§2.1** 保持一致。

## 5 分钟上手

### 1) 安装依赖（首次）

```powershell
cd D:\Github\PKI_CA\web
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2) 启动控制台

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

浏览器打开：`http://127.0.0.1:8765/`

### 3) 按钮执行顺序（推荐）

1. `0. 演示重置`
2. `1. 初始化目录`
3. `2. 构建 Root / Intermediate CA`
4. `3. 签发服务端 + 客户端证书`
5. `4. 校验证书链`
6. （可选）`5. 吊销客户端证书`
7. （可选）`6. 一键 mTLS 验证`

## 按钮与脚本映射

- `0. 演示重置` -> `00-reset-demo.ps1`
- `1. 初始化目录` -> `00-init-structure.ps1`
- `2. 构建 Root / Intermediate` -> `01-build-ca.ps1`
- `3. 签发` -> `02-issue-certs.ps1`
- `4. 校验` -> `04-verify.ps1`
- `5. 吊销` -> `03-revoke-client.ps1`
- `6. 一键 mTLS 验证` -> `05-mtls-validate.ps1`（会触发吊销流程）

## mTLS 浏览器演示（与控制台配合）

控制台负责证书生命周期（重置/建 CA/签发/吊销/校验），  
业务双向 TLS 演示仍使用 `openssl s_server` 并访问 `https://localhost:8443/`（详见 `docs/02-执行手册.md` 第 9、10 节）。

## HTTP 证书仓库（CDP / AIA，公开只读）

与 [ca/openssl-intermediate.cnf](../ca/openssl-intermediate.cnf) 中叶子证书的 **CDP、AIA（caIssuers）** URI 对应（默认 `http://127.0.0.1:8765/repo/...`）：

- `http://127.0.0.1:8765/repo/` — 索引页
- `http://127.0.0.1:8765/repo/ca-chain.cert.pem`
- `http://127.0.0.1:8765/repo/intermediate.crl.pem`

**无需** `X-Admin-Token` 即可访问（与生产 PKI 中 CRL/链通常公开分发一致）。

## 审计日志

- 控制台触发的 `init` / `build-ca` / `issue` / `verify` / `revoke` 会追加写入仓库根下 `artifacts/logs/audit.jsonl`（每行一条 JSON）。
- 还会记录 `reset-demo`、`mtls-validate` 两类动作。
- `GET /api/audit/tail?n=50`：若已设置 `PKI_WEB_TOKEN`，须带 `X-Admin-Token`；未设置时允许直接读取（便于单人本机演示）。

## API 响应结构（统一）

除下载接口（直接返回文件）外，JSON API 统一返回：

```json
{
  "ok": true,
  "code": "STATUS_OK",
  "message": "status fetched",
  "data": {},
  "logs": {}
}
```

- `ok`：是否成功
- `code`：机器可读状态码（如 `SCRIPT_OK` / `SCRIPT_FAILED`）
- `message`：人类可读说明
- `data`：业务数据
- `logs`：脚本输出（`stdout` / `stderr`）

## 安全建议

- 默认只监听 `127.0.0.1`；若需局域网访问，请自行评估并改用 `--host 0.0.0.0` 且务必设置令牌。
- 设置环境变量 `PKI_WEB_TOKEN` 后，**写操作类 API**、**受控下载**（`/api/download/...`）、**状态与审计读取**需携带相同值的 `X-Admin-Token`（页面可填写并保存到浏览器）。**`/repo/` 下链与 CRL** 仍为公开只读。

```powershell
$env:PKI_WEB_TOKEN = "请改为强随机字符串"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

## 依赖

- Python 3.10+
- 本机已安装 **OpenSSL**、**PowerShell**（PowerShell 由 Web 后端调用脚本引擎使用）

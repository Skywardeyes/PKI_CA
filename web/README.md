# Web PKI 控制台（唯一操作入口）

本项目推荐只通过本页面完成操作，不再依赖逐条命令行执行 PKI 步骤。  
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

Intl（国际链路）：
1. `0. 演示重置`
2. `1. 初始化目录`
3. `2. 构建 Root / Intermediate CA`
4. `3. 签发服务端 + 客户端证书`
5. `4. 校验证书链`
6. （可选）`5. 吊销客户端证书`
7. （可选）`6. 一键 mTLS 验证（TLS1.2）`
8. （可选）`7. TLS 握手观测（TLS1.2）`
9. （可选）`8. 一键 mTLS 验证（TLS1.3）`
10. （可选）`9. TLS 握手观测（TLS1.3）`

GM（国密链路）：
1. 先点 `检测国密能力`
2. `0. 演示重置`
3. `1. 初始化目录`
4. `2. 构建 GM Root / Intermediate CA`
5. `3. 签发 GM 服务端 + 客户端证书`
6. `4. 校验 GM 证书链`
7. （可选）`5/6/7/8/9` 吊销、TLS1.2/TLS1.3 mTLS、TLS1.2/TLS1.3 观测

## 按钮与 Python 工作流映射

后端按 profile 拆分：
- Intl：`web/app/services/pki_workflow.py`，API 前缀 `/api/intl/*`
- GM：`web/app/services/pki_workflow_gm.py`，API 前缀 `/api/gm/*`

Intl 映射：

- `0. 演示重置` → `reset_demo()`（清理生成物并 `init_structure()`）
- `1. 初始化目录` → `init_structure()`
- `2. 构建 Root / Intermediate` → `build_ca()`
- `3. 签发` → `issue()`（服务端按需签发 + 客户端 + P12）
- `4. 校验` → `verify()`
- `5. 吊销` → `revoke()`（吊销 + `gencrl`）
- `6. 一键 mTLS 验证（TLS1.2）` → `mtls_validate(tls_version="tls1_2")`
- `7. TLS 握手观测（TLS1.2）` → `tls_observe(tls_version="tls1_2")`
- `8. 一键 mTLS 验证（TLS1.3）` → `mtls_validate(tls_version="tls1_3")`
- `9. TLS 握手观测（TLS1.3）` → `tls_observe(tls_version="tls1_3")`

GM 映射：
- `0~9` 与 Intl 同语义，调用 `PKIWorkflowGM` 的同名能力
- GM 的 TLS1.3 路径采用**严格判定**：任一握手失败即返回 `ok=false` 与 `OPENSSL_FAILED`
- 运行产物隔离在 `gm/` 与 `artifacts/logs/gm/`

仓库中 `scripts/*.ps1` 仅作手工对照或培训材料，不参与 Web 控制台执行链。

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
- 还会记录 `reset-demo`、`mtls-validate`、`tls-observe` 三类动作；并新增 `profile` 字段（`intl` / `gm`）。
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
- `code`：机器可读状态码（如 `WORKFLOW_OK` / `OPENSSL_FAILED` / `STATE_INVALID`）
- `message`：人类可读说明
- `data`：业务数据
- `logs`：OpenSSL / 工作流输出（`stdout` / `stderr`）
- `data.steps`：执行阶段列表（便于前端展示）
- `data.duration_ms`：耗时（毫秒）
- `data.artifacts`：关键日志文件列表（如 `artifacts/logs/tls-observe-*.log`）
- `data.profile`：链路标识（`intl` / `gm`）

## TLS 严格口径（新增）

- `tls_observe(tls_version=...)` 会按版本产出日志，TLS1.2 与 TLS1.3 文件互不覆盖：
  - Intl：`artifacts/logs/tls-observe-tls12-*.log` 与 `artifacts/logs/tls-observe-tls13-*.log`
  - GM：`artifacts/logs/gm/tls-observe-tls12-*.log` 与 `artifacts/logs/gm/tls-observe-tls13-*.log`
- 课堂讲解建议：
  - TCP 三次握手与 TLS 握手分层描述
  - TLS1.2（RSA 教材路径）与 TLS1.2/1.3（(EC)DHE）分开说明
  - 用 `tls-observe-tls12-no-cert.log`、`tls-observe-tls12-revoked.log` 说明认证失败与吊销拒绝
  - GM TLS1.3 若环境握手不支持会直接返回失败（这是预期行为）

## 安全建议

- 默认只监听 `127.0.0.1`；若需局域网访问，请自行评估并改用 `--host 0.0.0.0` 且务必设置令牌。
- 设置环境变量 `PKI_WEB_TOKEN` 后，**写操作类 API**、**受控下载**（`/api/download/...`）、**状态与审计读取**需携带相同值的 `X-Admin-Token`（页面可填写并保存到浏览器）。**`/repo/` 下链与 CRL** 仍为公开只读。

```powershell
$env:PKI_WEB_TOKEN = "请改为强随机字符串"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

## 依赖

- Python 3.10+
- 本机已安装 **OpenSSL**（`openssl` 在 `PATH` 中可用）

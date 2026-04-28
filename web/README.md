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
4. `3. 签发服务端证书`
5. `4. 签发客户端证书`
6. `5. 校验证书链`
7. （可选）`6. 吊销服务端证书`
8. （可选）`6+. 校验服务端吊销状态`
9. （可选）`7. 吊销客户端证书`
10. （可选）`启动 Intl s_server` / `关闭 Intl s_server`（免手输 `openssl s_server`）

GM（国密链路）：
1. 先点 `检测国密能力`
2. `0. 演示重置`
3. `1. 初始化目录`
4. `2. 构建 GM Root / Intermediate CA`
5. `3. 签发 GM 服务端证书`
6. `4. 签发 GM 客户端证书`
7. `5. 校验 GM 证书链`
8. （可选）`6. 吊销 GM 服务端证书`
9. （可选）`6+. 校验 GM 服务端吊销状态`
10. （可选）`7. 吊销 GM 客户端证书`
11. （可选）`启动 GM s_server` / `关闭 GM s_server`

说明：GM 链路命令会在运行时自动优先使用 `gmssl`，若本机未安装 `gmssl` 则自动回退到 `openssl`，无需额外配置环境变量。

## 按钮与 Python 工作流映射

后端按 profile 拆分：
- Intl：`web/app/services/pki_workflow.py`，API 前缀 `/api/intl/*`
- GM：`web/app/services/pki_workflow_gm.py`，API 前缀 `/api/gm/*`

Intl 映射：

- `0. 演示重置` → `reset_demo()`（清理生成物并 `init_structure()`）
- `1. 初始化目录` → `init_structure()`
- `2. 构建 Root / Intermediate` → `build_ca()`（会额外导出 `ca/root/certs/ca.cert.p12` 与 `ca/intermediate/certs/intermediate.cert.p12`，用于浏览器导入受信任证书）
- `3. 签发服务端` → `issue_server()`
- `4. 签发客户端` → `issue_client(client_name, p12_password)`
- `5. 校验` → `verify()`
- `6. 吊销服务端` → `revoke_server()`（吊销 + `gencrl`）
- `6+. 校验服务端吊销状态` → `POST /api/intl/server-revocation-check`（封装 `openssl verify -CAfile ... -CRLfile ... -crl_check server/server.cert.pem`）
- `7. 吊销客户端` → `revoke_client(client_name)`（吊销 + `gencrl`）
- `启动 Intl s_server`（页面按钮）→ `POST /api/intl/browser-mtls/start`
- `关闭 Intl s_server`（页面按钮）→ `POST /api/intl/browser-mtls/stop`
- `GET /api/intl/browser-mtls/status` 仍用于顶部状态标志自动刷新（每 5 秒）
- `POST /api/intl/browser-mtls/start`（等价封装 `openssl s_server ... -CRL ... -crl_check`）
- `POST /api/intl/browser-mtls/stop`
- 若 CRL 文件不存在，`start` 会先自动执行一次 `gencrl`，因此可在执行完 `0~5` 后直接启动，无需先点吊销按钮。

GM 映射：
- `0. 演示重置` → `reset_demo()`
- `1. 初始化目录` → `init_structure()`
- `2. 构建 GM Root / Intermediate` → `build_ca()`（会额外导出 `gm/ca/root/certs/ca.cert.p12` 与 `gm/ca/intermediate/certs/intermediate.cert.p12`）
- `3. 签发 GM 服务端` → `issue_server()`
- `4. 签发 GM 客户端` → `issue_client(client_name, p12_password)`
- `5. 校验 GM 证书链` → `verify()`
- `6. 吊销 GM 服务端` → `revoke_server()`（吊销 + `gencrl`）
- `6+. 校验 GM 服务端吊销状态` → `POST /api/gm/server-revocation-check`（封装 `openssl verify -CAfile ... -CRLfile ... -crl_check gm/server/server.cert.pem`）
- `7. 吊销 GM 客户端` → `revoke_client(client_name)`（吊销 + `gencrl`）
- `启动 GM s_server`（页面按钮）→ `POST /api/gm/browser-mtls/start`
- `关闭 GM s_server`（页面按钮）→ `POST /api/gm/browser-mtls/stop`
- `GET /api/gm/browser-mtls/status` 仍用于顶部状态标志自动刷新（每 5 秒）
- `POST /api/gm/browser-mtls/start`
- `POST /api/gm/browser-mtls/stop`
- 若 GM CRL 文件不存在，`start` 会先自动执行一次 `gencrl`。
- 运行产物隔离在 `gm/` 与 `artifacts/logs/gm/`

仓库中 `scripts/*.ps1` 仅作手工对照或历史材料，不参与 Web 控制台执行链。

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
- 还会记录 `reset-demo`，并新增 `profile` 字段（`intl` / `gm`）。
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
- `data.artifacts`：关键日志文件列表
- `data.profile`：链路标识（`intl` / `gm`）

## 控制台结果展示（新增）

- `Intl` 与 `GM` 两个分区都保留原有 `<pre>` 日志窗口，用于查看 `stdout/stderr/raw` 全量输出。
- 在输出区工具栏与 `<pre>` 之间新增“结果摘要卡片”，展示：
  - `SUCCESS/FAILED` 状态
  - `profile`（`intl` / `gm`）
  - `code`、`action`、`duration_ms`
  - `steps` 与 `artifacts` 全量内容
- 当 `steps` 或 `artifacts` 较长时，卡片内对应字段会出现滚动条，可查看全部条目，不再折叠为 `...(+N)` 简写。
- 颜色语义：
  - 成功为绿色、失败为红色
  - `intl` 使用蓝色标签、`gm` 使用绿色标签
- 点击“清空”会同时清空摘要卡片和日志窗口内容。

## 全局 s_server 状态标志（新增）

- 顶部导航区域新增两组全局状态标志：
  - `Intl s_server: 运行中(8443)` / `Intl s_server: 未运行`
  - `GM s_server: 运行中(9443)` / `GM s_server: 未运行`
- 状态标志默认每 5 秒自动刷新一次，分别调用：
  - `GET /api/intl/browser-mtls/status`
  - `GET /api/gm/browser-mtls/status`
- 若设置了 `PKI_WEB_TOKEN` 但未填写令牌，状态标志会显示 `无权限(需令牌)`。
- OpenSSL 控制按钮已上移到概览区（全局入口），可直接启动/关闭 Intl 与 GM 的浏览器 mTLS 服务。

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

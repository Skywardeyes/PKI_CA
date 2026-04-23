# PKI_CA 任务二落地实现

本仓库用于完成培训计划中的任务二：自建 CA、签发证书、完成浏览器双向 SSL 认证并输出汇报材料。

## 快速开始
在仓库根目录打开 **Windows PowerShell**，执行（路径按本机修改）：

```powershell
cd D:\Github\PKI_CA

powershell -ExecutionPolicy Bypass -File .\scripts\00-init-structure.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\01-build-ca.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\02-issue-certs.ps1 -ClientName trainee -P12Password "ChangeMe!2026"
powershell -ExecutionPolicy Bypass -File .\scripts\04-verify.ps1 -ClientName trainee
```

已安装 PowerShell 7 时，可将 `powershell` 换成 `pwsh`，参数不变。

访问：`https://localhost:8443/`（按 `docs/02-执行手册.md` 启动 `openssl s_server` 后）

## Web PKI 控制台（可选）

在浏览器中点击完成初始化、建 CA、签发、验证、吊销与下载，说明见 [web/README.md](web/README.md)。

```powershell
cd D:\Github\PKI_CA\web
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

浏览器打开 `http://127.0.0.1:8765/`。

## 目录说明
- `ca/`：OpenSSL CA 配置
- `scripts/`：自动化执行脚本
- `web/`：Web 控制台（FastAPI + 静态页）
- `configs/nginx/`：Nginx mTLS 配置
- `docs/`：标准、手册、验证矩阵、汇报提纲、演示脚本
- `artifacts/`：验证日志等证据输出

## 关键文档
- `docs/01-任务二实施标准.md`
- `docs/02-执行手册.md`
- `docs/03-验证矩阵.md`
- `docs/04-PKI基础知识汇报提纲.md`
- `docs/05-现场演示脚本.md`

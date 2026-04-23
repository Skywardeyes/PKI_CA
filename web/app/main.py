"""
Web PKI 控制台：通过 HTTP 调用仓库根目录下的 PowerShell 脚本，完成 CA 初始化、签发与验证。
默认仅绑定 127.0.0.1；可选环境变量 PKI_WEB_TOKEN 要求请求头 X-Admin-Token。
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS = REPO_ROOT / "scripts"
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
AUDIT_LOG = REPO_ROOT / "artifacts" / "logs" / "audit.jsonl"
CRL_PUBLISH_PATH = REPO_ROOT / "ca" / "intermediate" / "crl" / "intermediate.crl.pem"
CHAIN_PUBLISH_PATH = REPO_ROOT / "ca" / "intermediate" / "certs" / "ca-chain.cert.pem"

SAFE_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")


def _require_token(x_admin_token: str | None, query_token: str | None = None) -> None:
    expected = os.environ.get("PKI_WEB_TOKEN", "").strip()
    if not expected:
        return
    got = (x_admin_token or query_token or "").strip()
    if got != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing admin token")


def _run_ps1(
    script: str,
    args: list[str] | None = None,
    timeout: int = 600,
) -> dict:
    path = SCRIPTS / script
    if not path.is_file():
        raise HTTPException(status_code=500, detail=f"Script not found: {script}")
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(path),
    ]
    if args:
        cmd.extend(args)
    try:
        p = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "returncode": -1,
            "stdout": "",
            "stderr": "Command timed out",
        }
    return {
        "ok": p.returncode == 0,
        "returncode": p.returncode,
        "stdout": p.stdout or "",
        "stderr": p.stderr or "",
    }


def _validate_client_name(name: str) -> str:
    if not SAFE_NAME.match(name):
        raise HTTPException(
            status_code=400,
            detail="clientName must match [a-zA-Z0-9][a-zA-Z0-9_-]{0,63}",
        )
    return name


def _append_audit(
    action: str,
    result: dict,
    *,
    client_name: str | None = None,
    reason: str | None = None,
) -> None:
    """Append one JSON line to audit log (P2). Failures to write are ignored so API still returns script output."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "ok": result.get("ok"),
        "returncode": result.get("returncode"),
        "client_name": client_name,
        "reason": (reason or "")[:500] or None,
    }
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _require_token_for_audit_read(
    x_admin_token: str | None,
    admin_token: str | None,
) -> None:
    """When PKI_WEB_TOKEN is set, audit tail requires the same token; otherwise open for solo demo."""
    _require_token(x_admin_token, admin_token)


app = FastAPI(title="PKI Web Console", version="1.0.0")

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def index():
    index_html = STATIC_DIR / "index.html"
    if not index_html.is_file():
        return JSONResponse({"detail": "static/index.html missing"}, status_code=500)
    return FileResponse(index_html)


@app.get("/api/health")
def health():
    return {"status": "ok", "repo_root": str(REPO_ROOT)}


@app.get("/repo/intermediate.crl.pem")
def repo_crl():
    """Public CRL distribution (CDP target). No admin token."""
    if not CRL_PUBLISH_PATH.is_file():
        raise HTTPException(status_code=404, detail="CRL not found")
    return FileResponse(
        CRL_PUBLISH_PATH,
        filename="intermediate.crl.pem",
        media_type="application/pkix-crl",
    )


@app.get("/repo/ca-chain.cert.pem")
def repo_ca_chain():
    """Public CA chain (AIA caIssuers target). No admin token."""
    if not CHAIN_PUBLISH_PATH.is_file():
        raise HTTPException(status_code=404, detail="ca-chain not found")
    return FileResponse(
        CHAIN_PUBLISH_PATH,
        filename="ca-chain.cert.pem",
        media_type="application/x-pem-file",
    )


@app.get("/repo/", response_class=HTMLResponse)
def repo_index():
    """Minimal HTML index for solo demo (Repository narrative)."""
    return HTMLResponse(
        """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"/><title>PKI Repository</title></head>
<body>
<h1>演示用证书仓库（HTTP）</h1>
<p>叶子证书中的 CDP / AIA 指向本页资源（单人单机、无 Docker）。URI 与 <code>ca/openssl-intermediate.cnf</code> 中端口一致（默认 8765）。</p>
<ul>
<li><a href="/repo/ca-chain.cert.pem">ca-chain.cert.pem</a>（CAIssuers）</li>
<li><a href="/repo/intermediate.crl.pem">intermediate.crl.pem</a>（CRL）</li>
</ul>
<p><a href="/">返回控制台</a></p>
</body></html>"""
    )


@app.get("/api/status")
def status(
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
    admin_token: str | None = Query(default=None, description="与 X-Admin-Token 二选一（仅 GET 便捷）"),
):
    _require_token(x_admin_token, admin_token)
    chain = REPO_ROOT / "ca/intermediate/certs/ca-chain.cert.pem"
    root_ca = REPO_ROOT / "ca/root/certs/ca.cert.pem"
    inter = REPO_ROOT / "ca/intermediate/certs/intermediate.cert.pem"
    server_cert = REPO_ROOT / "server/server.cert.pem"
    p12_files = sorted(REPO_ROOT.glob("client/*.p12"))
    return {
        "repo_root": str(REPO_ROOT),
        "has_root_ca": root_ca.is_file(),
        "has_intermediate_cert": inter.is_file(),
        "has_ca_chain": chain.is_file(),
        "has_server_cert": server_cert.is_file(),
        "client_p12": [p.name for p in p12_files],
    }


class IssueBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    client_name: str = Field(alias="clientName", default="trainee")
    p12_password: str = Field(alias="p12Password", default="ChangeMe!2026")
    reason: str | None = Field(default=None, max_length=500)


class ClientNameBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    client_name: str = Field(alias="clientName", default="trainee")
    reason: str | None = Field(default=None, max_length=500)


@app.post("/api/init")
def api_init(x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    out = _run_ps1("00-init-structure.ps1")
    _append_audit("init", out)
    return out


@app.post("/api/build-ca")
def api_build_ca(x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    out = _run_ps1("01-build-ca.ps1", timeout=900)
    _append_audit("build-ca", out)
    return out


@app.post("/api/issue")
def api_issue(body: IssueBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    out = _run_ps1(
        "02-issue-certs.ps1",
        ["-ClientName", cn, "-P12Password", body.p12_password],
        timeout=900,
    )
    _append_audit("issue", out, client_name=cn, reason=body.reason)
    return out


@app.post("/api/verify")
def api_verify(body: ClientNameBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    out = _run_ps1("04-verify.ps1", ["-ClientName", cn])
    _append_audit("verify", out, client_name=cn, reason=body.reason)
    return out


@app.post("/api/revoke")
def api_revoke(body: ClientNameBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    out = _run_ps1("03-revoke-client.ps1", ["-ClientName", cn])
    _append_audit("revoke", out, client_name=cn, reason=body.reason)
    return out


@app.get("/api/audit/tail")
def audit_tail(
    n: int = Query(50, ge=1, le=500),
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
    admin_token: str | None = Query(default=None),
):
    """Last n audit lines. If PKI_WEB_TOKEN is set, requires admin token (same as other APIs)."""
    if os.environ.get("PKI_WEB_TOKEN", "").strip():
        _require_token_for_audit_read(x_admin_token, admin_token)
    if not AUDIT_LOG.is_file():
        return {"lines": [], "path": str(AUDIT_LOG)}
    try:
        raw = AUDIT_LOG.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"lines": [], "path": str(AUDIT_LOG)}
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    tail = lines[-n:]
    parsed = []
    for ln in tail:
        try:
            parsed.append(json.loads(ln))
        except json.JSONDecodeError:
            parsed.append({"raw": ln})
    return {"path": str(AUDIT_LOG), "count": len(parsed), "entries": parsed}


@app.get("/api/download/p12/{client_name}")
def download_p12(
    client_name: str,
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
    admin_token: str | None = Query(default=None),
):
    _require_token(x_admin_token, admin_token)
    cn = _validate_client_name(client_name)
    path = REPO_ROOT / "client" / f"client-{cn}.p12"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="P12 not found")
    return FileResponse(
        path,
        filename=path.name,
        media_type="application/x-pkcs12",
    )


@app.get("/api/download/ca-chain")
def download_ca_chain(
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
    admin_token: str | None = Query(default=None),
):
    _require_token(x_admin_token, admin_token)
    path = REPO_ROOT / "ca/intermediate/certs/ca-chain.cert.pem"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="ca-chain not found")
    return FileResponse(path, filename="ca-chain.cert.pem", media_type="application/x-pem-file")

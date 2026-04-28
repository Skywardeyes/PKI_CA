"""
Web PKI 控制台：通过 HTTP 调用 Python 原生工作流，使用 OpenSSL 完成 CA 初始化、签发与验证。
默认仅绑定 127.0.0.1；可选环境变量 PKI_WEB_TOKEN 要求请求头 X-Admin-Token。
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from .services import AuditService, PKIWorkflow, PKIWorkflowGM, WorkflowResult

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
AUDIT_LOG = REPO_ROOT / "artifacts" / "logs" / "audit.jsonl"
CRL_PUBLISH_PATH = REPO_ROOT / "ca" / "intermediate" / "crl" / "intermediate.crl.pem"
CHAIN_PUBLISH_PATH = REPO_ROOT / "ca" / "intermediate" / "certs" / "ca-chain.cert.pem"
GM_CRL_PUBLISH_PATH = REPO_ROOT / "gm" / "ca" / "intermediate" / "crl" / "intermediate.crl.pem"
GM_CHAIN_PUBLISH_PATH = REPO_ROOT / "gm" / "ca" / "intermediate" / "certs" / "ca-chain.cert.pem"
GM_CRYPTO_BIN = "gmssl" if shutil.which("gmssl") else "openssl"

SAFE_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")


def _require_token(x_admin_token: str | None, query_token: str | None = None) -> None:
    expected = os.environ.get("PKI_WEB_TOKEN", "").strip()
    if not expected:
        return
    got = (x_admin_token or query_token or "").strip()
    if got != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing admin token")


workflow = PKIWorkflow(REPO_ROOT)
workflow_gm = PKIWorkflowGM(REPO_ROOT)
audit_service = AuditService(AUDIT_LOG)
INTL_BROWSER_MTLS_PROC: subprocess.Popen[str] | None = None
GM_BROWSER_MTLS_PROC: subprocess.Popen[str] | None = None


def _intl_browser_mtls_log_paths() -> tuple[Path, Path]:
    logs_dir = REPO_ROOT / "artifacts" / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    return logs_dir / "browser-mtls-server.log", logs_dir / "browser-mtls-server.err.log"


def _intl_browser_mtls_status() -> dict:
    global INTL_BROWSER_MTLS_PROC
    running = False
    pid: int | None = None
    if INTL_BROWSER_MTLS_PROC is not None:
        if INTL_BROWSER_MTLS_PROC.poll() is None:
            running = True
            pid = int(INTL_BROWSER_MTLS_PROC.pid)
        else:
            INTL_BROWSER_MTLS_PROC = None
    return {
        "running": running,
        "pid": pid,
        "port": 8443,
        "log_file": "artifacts/logs/browser-mtls-server.log",
        "err_log_file": "artifacts/logs/browser-mtls-server.err.log",
    }


def _gm_browser_mtls_log_paths() -> tuple[Path, Path]:
    logs_dir = REPO_ROOT / "artifacts" / "logs" / "gm"
    logs_dir.mkdir(parents=True, exist_ok=True)
    return logs_dir / "browser-mtls-server.log", logs_dir / "browser-mtls-server.err.log"


def _gm_browser_mtls_status() -> dict:
    global GM_BROWSER_MTLS_PROC
    running = False
    pid: int | None = None
    if GM_BROWSER_MTLS_PROC is not None:
        if GM_BROWSER_MTLS_PROC.poll() is None:
            running = True
            pid = int(GM_BROWSER_MTLS_PROC.pid)
        else:
            GM_BROWSER_MTLS_PROC = None
    return {
        "running": running,
        "pid": pid,
        "port": 9443,
        "log_file": "artifacts/logs/gm/browser-mtls-server.log",
        "err_log_file": "artifacts/logs/gm/browser-mtls-server.err.log",
    }


def _api_response(
    *,
    ok: bool,
    code: str,
    message: str,
    data: dict | list | None = None,
    logs: dict | None = None,
) -> dict:
    return {
        "ok": ok,
        "code": code,
        "message": message,
        "data": data if data is not None else {},
        "logs": logs if logs is not None else {},
    }


def _result_to_response(
    *,
    profile: str,
    action: str,
    result: WorkflowResult,
    client_name: str | None = None,
    reason: str | None = None,
) -> dict:
    audit_service.append(
        action,
        ok=result.ok,
        code=result.code,
        profile=profile,
        client_name=client_name,
        reason=reason,
    )
    return _api_response(
        ok=result.ok,
        code=result.code,
        message=result.message,
        data={
            "profile": profile,
            "action": action,
            "returncode": result.returncode,
            "clientName": client_name,
            "steps": result.steps,
            "duration_ms": result.duration_ms,
            "artifacts": result.artifacts or [],
        },
        logs={
            "stdout": result.stdout,
            "stderr": result.stderr,
        },
    )


def _validate_client_name(name: str) -> str:
    if not SAFE_NAME.match(name):
        raise HTTPException(
            status_code=400,
            detail="clientName must match [a-zA-Z0-9][a-zA-Z0-9_-]{0,63}",
        )
    return name


def _require_token_for_audit_read(
    x_admin_token: str | None,
    admin_token: str | None,
) -> None:
    """When PKI_WEB_TOKEN is set, audit tail requires the same token; otherwise open for solo demo."""
    _require_token(x_admin_token, admin_token)


def _server_revocation_check(profile: str, reason: str | None = None) -> dict:
    if profile == "gm":
        server_cert = REPO_ROOT / "gm/server/server.cert.pem"
        chain_cert = REPO_ROOT / "gm/ca/intermediate/certs/ca-chain.cert.pem"
        crl_file = REPO_ROOT / "gm/ca/intermediate/crl/intermediate.crl.pem"
    else:
        server_cert = REPO_ROOT / "server/server.cert.pem"
        chain_cert = REPO_ROOT / "ca/intermediate/certs/ca-chain.cert.pem"
        crl_file = REPO_ROOT / "ca/intermediate/crl/intermediate.crl.pem"

    missing = [
        str(p.relative_to(REPO_ROOT)).replace("\\", "/")
        for p in (server_cert, chain_cert, crl_file)
        if not p.is_file()
    ]
    action = "server-revocation-check"
    if missing:
        audit_service.append(action, ok=False, code="STATE_INVALID", profile=profile, reason=reason)
        return _api_response(
            ok=False,
            code="STATE_INVALID",
            message=f"{profile} server revocation check failed",
            data={
                "profile": profile,
                "action": action,
                "steps": ["check-required-files"],
                "duration_ms": 0,
                "artifacts": [],
                "missing_files": missing,
            },
            logs={"stderr": "Required files missing. Run build/issue/revoke flow first."},
        )

    bin_name = GM_CRYPTO_BIN if profile == "gm" else "openssl"
    cmd = [
        bin_name,
        "verify",
        "-CAfile",
        str(chain_cert.relative_to(REPO_ROOT)).replace("\\", "/"),
        "-CRLfile",
        str(crl_file.relative_to(REPO_ROOT)).replace("\\", "/"),
        "-crl_check",
        str(server_cert.relative_to(REPO_ROOT)).replace("\\", "/"),
    ]
    start = time.monotonic()
    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    duration_ms = int((time.monotonic() - start) * 1000)
    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    combined = f"{stdout}\n{stderr}".lower()
    is_revoked = "certificate revoked" in combined
    if proc.returncode == 0:
        ok = True
        code = "CERT_VALID"
        message = f"{profile} server certificate is valid (not revoked by current CRL)"
    elif is_revoked:
        ok = False
        code = "CERT_REVOKED"
        message = f"{profile} server certificate is revoked by current CRL"
    else:
        ok = False
        code = "OPENSSL_FAILED"
        message = f"{profile} server revocation check failed"

    audit_service.append(action, ok=ok, code=code, profile=profile, reason=reason)
    return _api_response(
        ok=ok,
        code=code,
        message=message,
        data={
            "profile": profile,
            "action": action,
            "returncode": proc.returncode,
            "steps": ["verify-server-cert-with-crl"],
            "duration_ms": duration_ms,
            "artifacts": [],
            "revoked": is_revoked,
            "command": " ".join(cmd),
        },
        logs={"stdout": stdout, "stderr": stderr},
    )


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
    return _api_response(
        ok=True,
        code="HEALTH_OK",
        message="service is healthy",
        data={"repo_root": str(REPO_ROOT)},
    )


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


@app.get("/repo/gm/intermediate.crl.pem")
def repo_gm_crl():
    if not GM_CRL_PUBLISH_PATH.is_file():
        raise HTTPException(status_code=404, detail="gm CRL not found")
    return FileResponse(
        GM_CRL_PUBLISH_PATH,
        filename="intermediate.crl.pem",
        media_type="application/pkix-crl",
    )


@app.get("/repo/gm/ca-chain.cert.pem")
def repo_gm_ca_chain():
    if not GM_CHAIN_PUBLISH_PATH.is_file():
        raise HTTPException(status_code=404, detail="gm ca-chain not found")
    return FileResponse(
        GM_CHAIN_PUBLISH_PATH,
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
    return _api_response(
        ok=True,
        code="STATUS_OK",
        message="status fetched",
        data={
            "repo_root": str(REPO_ROOT),
            "has_root_ca": root_ca.is_file(),
            "has_intermediate_cert": inter.is_file(),
            "has_ca_chain": chain.is_file(),
            "has_server_cert": server_cert.is_file(),
            "client_p12": [p.name for p in p12_files],
        },
    )


@app.get("/api/intl/status")
def intl_status(
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
    admin_token: str | None = Query(default=None, description="与 X-Admin-Token 二选一（仅 GET 便捷）"),
):
    return status(x_admin_token=x_admin_token, admin_token=admin_token)


@app.get("/api/gm/status")
def gm_status(
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
    admin_token: str | None = Query(default=None, description="与 X-Admin-Token 二选一（仅 GET 便捷）"),
):
    _require_token(x_admin_token, admin_token)
    chain = REPO_ROOT / "gm/ca/intermediate/certs/ca-chain.cert.pem"
    root_ca = REPO_ROOT / "gm/ca/root/certs/ca.cert.pem"
    inter = REPO_ROOT / "gm/ca/intermediate/certs/intermediate.cert.pem"
    server_cert = REPO_ROOT / "gm/server/server.cert.pem"
    p12_files = sorted((REPO_ROOT / "gm/client").glob("*.p12")) if (REPO_ROOT / "gm/client").exists() else []
    return _api_response(
        ok=True,
        code="STATUS_OK",
        message="gm status fetched",
        data={
            "profile": "gm",
            "repo_root": str(REPO_ROOT),
            "has_root_ca": root_ca.is_file(),
            "has_intermediate_cert": inter.is_file(),
            "has_ca_chain": chain.is_file(),
            "has_server_cert": server_cert.is_file(),
            "client_p12": [p.name for p in p12_files],
        },
    )


class IssueBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    client_name: str = Field(alias="clientName", default="trainee")
    p12_password: str = Field(alias="p12Password", default="123456")
    reason: str | None = Field(default=None, max_length=500)


class ClientNameBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    client_name: str = Field(alias="clientName", default="trainee")
    reason: str | None = Field(default=None, max_length=500)


class ResetBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    keep_web_cache: bool = Field(alias="keepWebCache", default=False)
    reason: str | None = Field(default=None, max_length=500)


class ReasonBody(BaseModel):
    reason: str | None = Field(default=None, max_length=500)


@app.get("/api/intl/browser-mtls/status")
def api_intl_browser_mtls_status(
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
):
    _require_token(x_admin_token)
    return _api_response(
        ok=True,
        code="STATUS_OK",
        message="intl browser mTLS status fetched",
        data={"profile": "intl", **_intl_browser_mtls_status()},
    )


@app.post("/api/intl/browser-mtls/start")
def api_intl_browser_mtls_start(
    body: ReasonBody,
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
):
    _require_token(x_admin_token)
    global INTL_BROWSER_MTLS_PROC
    status = _intl_browser_mtls_status()
    if status["running"]:
        return _api_response(
            ok=True,
            code="STATE_OK",
            message="intl browser mTLS server already running",
            data={"profile": "intl", **status},
        )
    required = [
        REPO_ROOT / "server/server.cert.pem",
        REPO_ROOT / "server/server.key.pem",
        REPO_ROOT / "ca/intermediate/certs/ca-chain.cert.pem",
    ]
    missing = [str(p.relative_to(REPO_ROOT)).replace("\\", "/") for p in required if not p.is_file()]
    if missing:
        audit_service.append("browser-mtls-start", ok=False, code="STATE_INVALID", profile="intl", reason=body.reason)
        return _api_response(
            ok=False,
            code="STATE_INVALID",
            message="intl browser mTLS start failed",
            data={"profile": "intl", "missing_files": missing},
            logs={"stderr": "Required files missing. Run build/issue-server/issue-client first to prepare cert/key/chain."},
        )
    crl_path = REPO_ROOT / "ca/intermediate/crl/intermediate.crl.pem"
    if not crl_path.is_file():
        gen = subprocess.run(
            ["openssl", "ca", "-config", "ca/openssl-intermediate.cnf", "-gencrl", "-out", "ca/intermediate/crl/intermediate.crl.pem"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        if gen.returncode != 0:
            audit_service.append("browser-mtls-start", ok=False, code="OPENSSL_FAILED", profile="intl", reason=body.reason)
            return _api_response(
                ok=False,
                code="OPENSSL_FAILED",
                message="intl browser mTLS start failed",
                data={"profile": "intl"},
                logs={"stdout": gen.stdout or "", "stderr": (gen.stderr or "failed to generate CRL").strip()},
            )
    out_log, err_log = _intl_browser_mtls_log_paths()
    cmd = [
        "openssl",
        "s_server",
        "-accept",
        "8443",
        "-www",
        "-cert",
        "server/server.cert.pem",
        "-key",
        "server/server.key.pem",
        "-CAfile",
        "ca/intermediate/certs/ca-chain.cert.pem",
        "-Verify",
        "1",
        "-verify_return_error",
        "-CRL",
        "ca/intermediate/crl/intermediate.crl.pem",
        "-crl_check",
    ]
    with out_log.open("w", encoding="utf-8") as out_fp, err_log.open("w", encoding="utf-8") as err_fp:
        INTL_BROWSER_MTLS_PROC = subprocess.Popen(cmd, cwd=str(REPO_ROOT), stdout=out_fp, stderr=err_fp, text=True)
    status = _intl_browser_mtls_status()
    audit_service.append("browser-mtls-start", ok=True, code="WORKFLOW_OK", profile="intl", reason=body.reason)
    return _api_response(
        ok=True,
        code="WORKFLOW_OK",
        message="intl browser mTLS server started",
        data={"profile": "intl", **status},
    )


@app.post("/api/intl/browser-mtls/stop")
def api_intl_browser_mtls_stop(
    body: ReasonBody,
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
):
    _require_token(x_admin_token)
    global INTL_BROWSER_MTLS_PROC
    status_before = _intl_browser_mtls_status()
    if not status_before["running"]:
        return _api_response(
            ok=True,
            code="STATE_OK",
            message="intl browser mTLS server already stopped",
            data={"profile": "intl", **status_before},
        )
    if INTL_BROWSER_MTLS_PROC is not None and INTL_BROWSER_MTLS_PROC.poll() is None:
        INTL_BROWSER_MTLS_PROC.terminate()
        try:
            INTL_BROWSER_MTLS_PROC.wait(timeout=5)
        except subprocess.TimeoutExpired:
            INTL_BROWSER_MTLS_PROC.kill()
    INTL_BROWSER_MTLS_PROC = None
    audit_service.append("browser-mtls-stop", ok=True, code="WORKFLOW_OK", profile="intl", reason=body.reason)
    return _api_response(
        ok=True,
        code="WORKFLOW_OK",
        message="intl browser mTLS server stopped",
        data={"profile": "intl", **_intl_browser_mtls_status()},
    )


@app.get("/api/gm/browser-mtls/status")
def api_gm_browser_mtls_status(
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
):
    _require_token(x_admin_token)
    return _api_response(
        ok=True,
        code="STATUS_OK",
        message="gm browser mTLS status fetched",
        data={"profile": "gm", **_gm_browser_mtls_status()},
    )


@app.post("/api/gm/browser-mtls/start")
def api_gm_browser_mtls_start(
    body: ReasonBody,
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
):
    _require_token(x_admin_token)
    global GM_BROWSER_MTLS_PROC
    status = _gm_browser_mtls_status()
    if status["running"]:
        return _api_response(
            ok=True,
            code="STATE_OK",
            message="gm browser mTLS server already running",
            data={"profile": "gm", **status},
        )
    required = [
        REPO_ROOT / "gm/server/server.cert.pem",
        REPO_ROOT / "gm/server/server.key.pem",
        REPO_ROOT / "gm/ca/intermediate/certs/ca-chain.cert.pem",
    ]
    missing = [str(p.relative_to(REPO_ROOT)).replace("\\", "/") for p in required if not p.is_file()]
    if missing:
        audit_service.append("browser-mtls-start", ok=False, code="STATE_INVALID", profile="gm", reason=body.reason)
        return _api_response(
            ok=False,
            code="STATE_INVALID",
            message="gm browser mTLS start failed",
            data={"profile": "gm", "missing_files": missing},
            logs={"stderr": "Required GM files missing. Run build/issue-server/issue-client first to prepare cert/key/chain."},
        )
    gm_crl_path = REPO_ROOT / "gm/ca/intermediate/crl/intermediate.crl.pem"
    if not gm_crl_path.is_file():
        gen = subprocess.run(
            [GM_CRYPTO_BIN, "ca", "-config", "gm/ca/openssl-intermediate-gm.cnf", "-gencrl", "-out", "gm/ca/intermediate/crl/intermediate.crl.pem"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        if gen.returncode != 0:
            audit_service.append("browser-mtls-start", ok=False, code="OPENSSL_FAILED", profile="gm", reason=body.reason)
            return _api_response(
                ok=False,
                code="OPENSSL_FAILED",
                message="gm browser mTLS start failed",
                data={"profile": "gm"},
                logs={"stdout": gen.stdout or "", "stderr": (gen.stderr or "failed to generate GM CRL").strip()},
            )
    out_log, err_log = _gm_browser_mtls_log_paths()
    cmd = [
        GM_CRYPTO_BIN,
        "s_server",
        "-accept",
        "9443",
        "-www",
        "-cert",
        "gm/server/server.cert.pem",
        "-key",
        "gm/server/server.key.pem",
        "-CAfile",
        "gm/ca/intermediate/certs/ca-chain.cert.pem",
        "-Verify",
        "1",
        "-verify_return_error",
        "-CRL",
        "gm/ca/intermediate/crl/intermediate.crl.pem",
        "-crl_check",
    ]
    with out_log.open("w", encoding="utf-8") as out_fp, err_log.open("w", encoding="utf-8") as err_fp:
        GM_BROWSER_MTLS_PROC = subprocess.Popen(cmd, cwd=str(REPO_ROOT), stdout=out_fp, stderr=err_fp, text=True)
    status = _gm_browser_mtls_status()
    audit_service.append("browser-mtls-start", ok=True, code="WORKFLOW_OK", profile="gm", reason=body.reason)
    return _api_response(
        ok=True,
        code="WORKFLOW_OK",
        message="gm browser mTLS server started",
        data={"profile": "gm", **status},
    )


@app.post("/api/gm/browser-mtls/stop")
def api_gm_browser_mtls_stop(
    body: ReasonBody,
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
):
    _require_token(x_admin_token)
    global GM_BROWSER_MTLS_PROC
    status_before = _gm_browser_mtls_status()
    if not status_before["running"]:
        return _api_response(
            ok=True,
            code="STATE_OK",
            message="gm browser mTLS server already stopped",
            data={"profile": "gm", **status_before},
        )
    if GM_BROWSER_MTLS_PROC is not None and GM_BROWSER_MTLS_PROC.poll() is None:
        GM_BROWSER_MTLS_PROC.terminate()
        try:
            GM_BROWSER_MTLS_PROC.wait(timeout=5)
        except subprocess.TimeoutExpired:
            GM_BROWSER_MTLS_PROC.kill()
    GM_BROWSER_MTLS_PROC = None
    audit_service.append("browser-mtls-stop", ok=True, code="WORKFLOW_OK", profile="gm", reason=body.reason)
    return _api_response(
        ok=True,
        code="WORKFLOW_OK",
        message="gm browser mTLS server stopped",
        data={"profile": "gm", **_gm_browser_mtls_status()},
    )


@app.post("/api/init")
@app.post("/api/intl/init")
def api_init(x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    result = workflow.init_structure()
    return _result_to_response(profile="intl", action="init", result=result)


@app.post("/api/build-ca")
@app.post("/api/intl/build-ca")
def api_build_ca(x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    result = workflow.build_ca()
    return _result_to_response(profile="intl", action="build-ca", result=result)


@app.post("/api/issue-server")
@app.post("/api/intl/issue-server")
def api_issue_server(body: ReasonBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    result = workflow.issue_server()
    return _result_to_response(profile="intl", action="issue-server", result=result, reason=body.reason)


@app.post("/api/issue-client")
@app.post("/api/intl/issue-client")
def api_issue_client(body: IssueBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow.issue_client(client_name=cn, p12_password=body.p12_password)
    return _result_to_response(profile="intl", action="issue-client", result=result, client_name=cn, reason=body.reason)


@app.post("/api/verify")
@app.post("/api/intl/verify")
def api_verify(body: ClientNameBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow.verify(client_name=cn)
    return _result_to_response(profile="intl", action="verify", result=result, client_name=cn, reason=body.reason)


@app.post("/api/revoke-server")
@app.post("/api/intl/revoke-server")
def api_revoke_server(body: ReasonBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    result = workflow.revoke_server()
    return _result_to_response(profile="intl", action="revoke-server", result=result, reason=body.reason)


@app.post("/api/revoke-client")
@app.post("/api/intl/revoke-client")
def api_revoke_client(body: ClientNameBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow.revoke_client(client_name=cn)
    return _result_to_response(profile="intl", action="revoke-client", result=result, client_name=cn, reason=body.reason)


@app.post("/api/intl/server-revocation-check")
def api_intl_server_revocation_check(body: ReasonBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    return _server_revocation_check(profile="intl", reason=body.reason)


@app.post("/api/reset-demo")
@app.post("/api/intl/reset-demo")
def api_reset_demo(body: ResetBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    """Reset generated runtime artifacts and re-create clean baseline folders."""
    _require_token(x_admin_token)
    global INTL_BROWSER_MTLS_PROC
    if INTL_BROWSER_MTLS_PROC is not None and INTL_BROWSER_MTLS_PROC.poll() is None:
        INTL_BROWSER_MTLS_PROC.terminate()
        try:
            INTL_BROWSER_MTLS_PROC.wait(timeout=5)
        except subprocess.TimeoutExpired:
            INTL_BROWSER_MTLS_PROC.kill()
    INTL_BROWSER_MTLS_PROC = None
    result = workflow.reset_demo(keep_web_cache=body.keep_web_cache)
    return _result_to_response(profile="intl", action="reset-demo", result=result, reason=body.reason)


@app.get("/api/gm/capability")
def api_gm_capability(x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    result = workflow_gm.capability_check()
    return _result_to_response(profile="gm", action="capability", result=result)


@app.post("/api/gm/init")
def api_gm_init(x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    result = workflow_gm.init_structure()
    return _result_to_response(profile="gm", action="init", result=result)


@app.post("/api/gm/build-ca")
def api_gm_build_ca(x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    result = workflow_gm.build_ca()
    return _result_to_response(profile="gm", action="build-ca", result=result)


@app.post("/api/gm/issue-server")
def api_gm_issue_server(body: ReasonBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    result = workflow_gm.issue_server()
    return _result_to_response(profile="gm", action="issue-server", result=result, reason=body.reason)


@app.post("/api/gm/issue-client")
def api_gm_issue_client(body: IssueBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow_gm.issue_client(client_name=cn, p12_password=body.p12_password)
    return _result_to_response(profile="gm", action="issue-client", result=result, client_name=cn, reason=body.reason)


@app.post("/api/gm/verify")
def api_gm_verify(body: ClientNameBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow_gm.verify(client_name=cn)
    return _result_to_response(profile="gm", action="verify", result=result, client_name=cn, reason=body.reason)


@app.post("/api/gm/revoke-server")
def api_gm_revoke_server(body: ReasonBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    result = workflow_gm.revoke_server()
    return _result_to_response(profile="gm", action="revoke-server", result=result, reason=body.reason)


@app.post("/api/gm/revoke-client")
def api_gm_revoke_client(body: ClientNameBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow_gm.revoke_client(client_name=cn)
    return _result_to_response(profile="gm", action="revoke-client", result=result, client_name=cn, reason=body.reason)


@app.post("/api/gm/server-revocation-check")
def api_gm_server_revocation_check(body: ReasonBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    return _server_revocation_check(profile="gm", reason=body.reason)


@app.post("/api/gm/reset-demo")
def api_gm_reset_demo(body: ResetBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    global GM_BROWSER_MTLS_PROC
    if GM_BROWSER_MTLS_PROC is not None and GM_BROWSER_MTLS_PROC.poll() is None:
        GM_BROWSER_MTLS_PROC.terminate()
        try:
            GM_BROWSER_MTLS_PROC.wait(timeout=5)
        except subprocess.TimeoutExpired:
            GM_BROWSER_MTLS_PROC.kill()
    GM_BROWSER_MTLS_PROC = None
    result = workflow_gm.reset_demo(keep_web_cache=body.keep_web_cache)
    return _result_to_response(profile="gm", action="reset-demo", result=result, reason=body.reason)


@app.get("/api/audit/tail")
def audit_tail(
    n: int = Query(50, ge=1, le=500),
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
    admin_token: str | None = Query(default=None),
):
    """Last n audit lines. If PKI_WEB_TOKEN is set, requires admin token (same as other APIs)."""
    if os.environ.get("PKI_WEB_TOKEN", "").strip():
        _require_token_for_audit_read(x_admin_token, admin_token)
    result = audit_service.tail(n)
    return _api_response(
        ok=result.ok,
        code=result.code,
        message=result.message,
        data={"path": str(AUDIT_LOG), "count": len(result.entries), "entries": result.entries},
    )


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


@app.get("/api/gm/download/p12/{client_name}")
def download_gm_p12(
    client_name: str,
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
    admin_token: str | None = Query(default=None),
):
    _require_token(x_admin_token, admin_token)
    cn = _validate_client_name(client_name)
    path = REPO_ROOT / "gm" / "client" / f"client-{cn}.p12"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="gm P12 not found")
    return FileResponse(
        path,
        filename=path.name,
        media_type="application/x-pkcs12",
    )


@app.get("/api/gm/download/ca-chain")
def download_gm_ca_chain(
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
    admin_token: str | None = Query(default=None),
):
    _require_token(x_admin_token, admin_token)
    path = REPO_ROOT / "gm/ca/intermediate/certs/ca-chain.cert.pem"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="gm ca-chain not found")
    return FileResponse(path, filename="gm-ca-chain.cert.pem", media_type="application/x-pem-file")

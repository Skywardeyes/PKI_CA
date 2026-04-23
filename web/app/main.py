"""
Web PKI 控制台：通过 HTTP 调用 Python 原生工作流，使用 OpenSSL 完成 CA 初始化、签发与验证。
默认仅绑定 127.0.0.1；可选环境变量 PKI_WEB_TOKEN 要求请求头 X-Admin-Token。
"""

from __future__ import annotations

import os
import re
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
    p12_password: str = Field(alias="p12Password", default="ChangeMe!2026")
    reason: str | None = Field(default=None, max_length=500)


class ClientNameBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    client_name: str = Field(alias="clientName", default="trainee")
    reason: str | None = Field(default=None, max_length=500)


class ResetBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    keep_web_cache: bool = Field(alias="keepWebCache", default=False)
    reason: str | None = Field(default=None, max_length=500)


class TLSObserveBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    client_name: str = Field(alias="clientName", default="trainee")
    reason: str | None = Field(default=None, max_length=500)


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


@app.post("/api/issue")
@app.post("/api/intl/issue")
def api_issue(body: IssueBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow.issue(client_name=cn, p12_password=body.p12_password)
    return _result_to_response(profile="intl", action="issue", result=result, client_name=cn, reason=body.reason)


@app.post("/api/verify")
@app.post("/api/intl/verify")
def api_verify(body: ClientNameBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow.verify(client_name=cn)
    return _result_to_response(profile="intl", action="verify", result=result, client_name=cn, reason=body.reason)


@app.post("/api/revoke")
@app.post("/api/intl/revoke")
def api_revoke(body: ClientNameBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow.revoke(client_name=cn)
    return _result_to_response(profile="intl", action="revoke", result=result, client_name=cn, reason=body.reason)


@app.post("/api/reset-demo")
@app.post("/api/intl/reset-demo")
def api_reset_demo(body: ResetBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    """Reset generated runtime artifacts and re-create clean baseline folders."""
    _require_token(x_admin_token)
    result = workflow.reset_demo(keep_web_cache=body.keep_web_cache)
    return _result_to_response(profile="intl", action="reset-demo", result=result, reason=body.reason)


@app.post("/api/mtls-validate")
@app.post("/api/intl/mtls-validate")
def api_mtls_validate(body: ClientNameBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    """
    Run full local mTLS validation helper (includes revoke flow).
    This is for demo/testing and may revoke the selected client certificate.
    """
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow.mtls_validate(client_name=cn, tls_version="tls1_2")
    return _result_to_response(profile="intl", action="mtls-validate", result=result, client_name=cn, reason=body.reason)


@app.post("/api/intl/mtls-validate-tls13")
def api_mtls_validate_tls13(body: ClientNameBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow.mtls_validate(client_name=cn, tls_version="tls1_3")
    return _result_to_response(profile="intl", action="mtls-validate-tls13", result=result, client_name=cn, reason=body.reason)


@app.post("/api/tls-observe")
@app.post("/api/intl/tls-observe")
def api_tls_observe(body: TLSObserveBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    """
    Run strict TLS handshake observation:
    - TLS1.2 with client cert
    - TLS1.2 without client cert
    - TLS1.3 with client cert
    - revoke + CRL refresh + TLS1.2 with revoked cert
    """
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow.tls_observe(client_name=cn, tls_version="tls1_2")
    return _result_to_response(profile="intl", action="tls-observe", result=result, client_name=cn, reason=body.reason)


@app.post("/api/intl/tls-observe-tls13")
def api_tls_observe_tls13(body: TLSObserveBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow.tls_observe(client_name=cn, tls_version="tls1_3")
    return _result_to_response(profile="intl", action="tls-observe-tls13", result=result, client_name=cn, reason=body.reason)


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


@app.post("/api/gm/issue")
def api_gm_issue(body: IssueBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow_gm.issue(client_name=cn, p12_password=body.p12_password)
    return _result_to_response(profile="gm", action="issue", result=result, client_name=cn, reason=body.reason)


@app.post("/api/gm/verify")
def api_gm_verify(body: ClientNameBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow_gm.verify(client_name=cn)
    return _result_to_response(profile="gm", action="verify", result=result, client_name=cn, reason=body.reason)


@app.post("/api/gm/revoke")
def api_gm_revoke(body: ClientNameBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow_gm.revoke(client_name=cn)
    return _result_to_response(profile="gm", action="revoke", result=result, client_name=cn, reason=body.reason)


@app.post("/api/gm/reset-demo")
def api_gm_reset_demo(body: ResetBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    result = workflow_gm.reset_demo(keep_web_cache=body.keep_web_cache)
    return _result_to_response(profile="gm", action="reset-demo", result=result, reason=body.reason)


@app.post("/api/gm/mtls-validate")
def api_gm_mtls_validate(body: ClientNameBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow_gm.mtls_validate(client_name=cn, tls_version="tls1_2")
    return _result_to_response(profile="gm", action="mtls-validate", result=result, client_name=cn, reason=body.reason)


@app.post("/api/gm/mtls-validate-tls13")
def api_gm_mtls_validate_tls13(body: ClientNameBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow_gm.mtls_validate(client_name=cn, tls_version="tls1_3")
    return _result_to_response(profile="gm", action="mtls-validate-tls13", result=result, client_name=cn, reason=body.reason)


@app.post("/api/gm/tls-observe")
def api_gm_tls_observe(body: TLSObserveBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow_gm.tls_observe(client_name=cn, tls_version="tls1_2")
    return _result_to_response(profile="gm", action="tls-observe", result=result, client_name=cn, reason=body.reason)


@app.post("/api/gm/tls-observe-tls13")
def api_gm_tls_observe_tls13(body: TLSObserveBody, x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    _require_token(x_admin_token)
    cn = _validate_client_name(body.client_name)
    result = workflow_gm.tls_observe(client_name=cn, tls_version="tls1_3")
    return _result_to_response(profile="gm", action="tls-observe-tls13", result=result, client_name=cn, reason=body.reason)


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

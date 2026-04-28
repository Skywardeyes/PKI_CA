from __future__ import annotations

import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from .openssl_runner import OpenSSLRunner


@dataclass
class WorkflowResult:
    ok: bool
    code: str
    message: str
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    steps: list[str]
    artifacts: list[str] | None = None


class PKIWorkflow:
    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root
        self.runner = OpenSSLRunner(repo_root)
        self.root_ca_cfg = "ca/openssl-root.cnf"
        self.inter_ca_cfg = "ca/openssl-intermediate.cnf"

    def _join_logs(self, chunks: list[tuple[str, str]]) -> tuple[str, str]:
        return (
            "\n".join(part for part, _ in chunks if part).strip(),
            "\n".join(part for _, part in chunks if part).strip(),
        )

    def _run_checked(self, command: list[str], *, timeout: int, logs: list[tuple[str, str]], steps: list[str], step: str) -> tuple[bool, int]:
        result = self.runner.run(command, timeout=timeout)
        logs.append((result.stdout, result.stderr))
        steps.append(step)
        if not result.ok:
            return False, result.returncode
        return True, 0

    def _is_already_revoked(self, text: str) -> bool:
        lower = text.lower()
        return "already revoked" in lower or "error:already revoked" in lower

    def init_structure(self) -> WorkflowResult:
        start = time.perf_counter()
        dirs = [
            "ca/root/certs",
            "ca/root/crl",
            "ca/root/newcerts",
            "ca/root/private",
            "ca/root/csr",
            "ca/intermediate/certs",
            "ca/intermediate/crl",
            "ca/intermediate/newcerts",
            "ca/intermediate/private",
            "ca/intermediate/csr",
            "server",
            "client",
            "artifacts/logs",
        ]
        for d in dirs:
            (self.repo_root / d).mkdir(parents=True, exist_ok=True)
        defaults = {
            "ca/root/index.txt": "",
            "ca/intermediate/index.txt": "",
            "ca/root/serial": "1000",
            "ca/intermediate/serial": "2000",
            "ca/intermediate/crlnumber": "2000",
        }
        for rel, value in defaults.items():
            p = self.repo_root / rel
            if not p.exists():
                p.write_text(value, encoding="ascii")
        duration_ms = int((time.perf_counter() - start) * 1000)
        return WorkflowResult(
            ok=True,
            code="WORKFLOW_OK",
            message="init succeeded",
            returncode=0,
            stdout="PKI directory initialization completed.",
            stderr="",
            duration_ms=duration_ms,
            steps=["init:prepare-dirs", "init:seed-index-serial"],
        )

    def reset_demo(self, *, keep_web_cache: bool) -> WorkflowResult:
        start = time.perf_counter()
        removed: list[str] = []
        for rel in ["ca/root", "ca/intermediate", "server", "client", "artifacts"]:
            p = self.repo_root / rel
            if p.exists():
                shutil.rmtree(p, ignore_errors=False)
                removed.append(rel)
        if not keep_web_cache:
            pycache = self.repo_root / "web/app/__pycache__"
            if pycache.exists():
                shutil.rmtree(pycache, ignore_errors=False)
                removed.append("web/app/__pycache__")
        init_result = self.init_structure()
        if not init_result.ok:
            return init_result
        duration_ms = int((time.perf_counter() - start) * 1000)
        lines = [f"Removed: {item}" for item in removed]
        lines.append(init_result.stdout)
        lines.append("Demo reset completed.")
        return WorkflowResult(
            ok=True,
            code="WORKFLOW_OK",
            message="reset-demo succeeded",
            returncode=0,
            stdout="\n".join(lines),
            stderr="",
            duration_ms=duration_ms,
            steps=["reset:cleanup", "reset:re-init"],
        )

    def build_ca(self) -> WorkflowResult:
        start = time.perf_counter()
        logs: list[tuple[str, str]] = []
        steps: list[str] = []
        commands = [
            (["openssl", "genrsa", "-out", "ca/root/private/ca.key.pem", "4096"], "build-ca:root-keygen"),
            ([
                "openssl", "req", "-config", self.root_ca_cfg, "-key", "ca/root/private/ca.key.pem", "-new", "-x509",
                "-days", "3650", "-sha256", "-extensions", "v3_ca",
                "-subj", "/C=CN/ST=Shanghai/O=Koal/OU=Training/CN=Koal Root CA",
                "-out", "ca/root/certs/ca.cert.pem",
            ], "build-ca:root-self-sign"),
            (["openssl", "genrsa", "-out", "ca/intermediate/private/intermediate.key.pem", "4096"], "build-ca:intermediate-keygen"),
            ([
                "openssl", "req", "-config", self.inter_ca_cfg, "-new", "-sha256",
                "-key", "ca/intermediate/private/intermediate.key.pem",
                "-subj", "/C=CN/ST=Shanghai/O=Koal/OU=Training/CN=Koal Intermediate CA",
                "-out", "ca/intermediate/csr/intermediate.csr.pem",
            ], "build-ca:intermediate-csr"),
            ([
                "openssl", "ca", "-batch", "-config", self.root_ca_cfg, "-extensions", "v3_ca", "-days", "1825",
                "-notext", "-md", "sha256", "-in", "ca/intermediate/csr/intermediate.csr.pem",
                "-out", "ca/intermediate/certs/intermediate.cert.pem",
            ], "build-ca:issue-intermediate"),
            (["openssl", "verify", "-CAfile", "ca/root/certs/ca.cert.pem", "ca/intermediate/certs/intermediate.cert.pem"], "build-ca:verify-chain"),
            ([
                "openssl", "pkcs12", "-export", "-nokeys",
                "-in", "ca/root/certs/ca.cert.pem",
                "-out", "ca/root/certs/ca.cert.p12",
                "-password", "pass:123456",
            ], "build-ca:export-root-p12"),
            ([
                "openssl", "pkcs12", "-export", "-nokeys",
                "-in", "ca/intermediate/certs/intermediate.cert.pem",
                "-certfile", "ca/root/certs/ca.cert.pem",
                "-out", "ca/intermediate/certs/intermediate.cert.p12",
                "-password", "pass:123456",
            ], "build-ca:export-intermediate-p12"),
        ]
        for cmd, step in commands:
            ok, rc = self._run_checked(cmd, timeout=900, logs=logs, steps=steps, step=step)
            if not ok:
                stdout, stderr = self._join_logs(logs)
                return WorkflowResult(False, "OPENSSL_FAILED", "build-ca failed", rc, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)
        chain_file = self.repo_root / "ca/intermediate/certs/ca-chain.cert.pem"
        inter = (self.repo_root / "ca/intermediate/certs/intermediate.cert.pem").read_text(encoding="utf-8")
        root = (self.repo_root / "ca/root/certs/ca.cert.pem").read_text(encoding="utf-8")
        chain_file.write_text(f"{inter}{root}", encoding="ascii")
        steps.append("build-ca:write-chain")
        stdout, stderr = self._join_logs(logs)
        stdout = (
            stdout
            + "\nRoot/Intermediate CA build completed."
            + "\nCA P12 files (cert-only):"
            + "\n- ca/root/certs/ca.cert.p12"
            + "\n- ca/intermediate/certs/intermediate.cert.p12"
            + "\nP12 password: 123456"
        ).strip()
        return WorkflowResult(True, "WORKFLOW_OK", "build-ca succeeded", 0, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)

    def issue_server(self) -> WorkflowResult:
        start = time.perf_counter()
        logs: list[tuple[str, str]] = []
        steps: list[str] = []
        commands: list[tuple[list[str], str]] = [
            (["openssl", "genrsa", "-out", "server/server.key.pem", "2048"], "issue-server:keygen"),
            ([
                "openssl", "req", "-config", self.inter_ca_cfg, "-new", "-sha256", "-key", "server/server.key.pem",
                "-subj", "/C=CN/ST=Shanghai/O=Koal/OU=PKI/CN=localhost", "-out", "ca/intermediate/csr/server.csr.pem",
            ], "issue-server:csr"),
            ([
                "openssl", "ca", "-batch", "-config", self.inter_ca_cfg, "-extensions", "server_cert", "-days", "825",
                "-notext", "-md", "sha256", "-in", "ca/intermediate/csr/server.csr.pem", "-out", "server/server.cert.pem",
            ], "issue-server:sign"),
        ]
        for cmd, step in commands:
            ok, rc = self._run_checked(cmd, timeout=900, logs=logs, steps=steps, step=step)
            if not ok:
                stdout, stderr = self._join_logs(logs)
                return WorkflowResult(False, "OPENSSL_FAILED", "issue-server failed", rc, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)
        stdout, stderr = self._join_logs(logs)
        stdout = (stdout + "\nServer certificate issued.").strip()
        return WorkflowResult(True, "WORKFLOW_OK", "issue-server succeeded", 0, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)

    def issue_client(self, *, client_name: str, p12_password: str) -> WorkflowResult:
        start = time.perf_counter()
        logs: list[tuple[str, str]] = []
        steps: list[str] = []
        commands: list[tuple[list[str], str]] = [
            (["openssl", "genrsa", "-out", f"client/client-{client_name}.key.pem", "2048"], "issue:client-keygen"),
            ([
                "openssl", "req", "-config", self.inter_ca_cfg, "-new", "-sha256", "-key", f"client/client-{client_name}.key.pem",
                "-subj", f"/C=CN/ST=Shanghai/O=Koal/OU=PKI/CN={client_name}", "-out", f"ca/intermediate/csr/client-{client_name}.csr.pem",
            ], "issue:client-csr"),
            ([
                "openssl", "ca", "-batch", "-config", self.inter_ca_cfg, "-extensions", "usr_cert", "-days", "825",
                "-notext", "-md", "sha256", "-in", f"ca/intermediate/csr/client-{client_name}.csr.pem", "-out", f"client/client-{client_name}.cert.pem",
            ], "issue:client-sign"),
            ([
                "openssl", "pkcs12", "-export",
                "-inkey", f"client/client-{client_name}.key.pem",
                "-in", f"client/client-{client_name}.cert.pem",
                "-certfile", "ca/intermediate/certs/ca-chain.cert.pem",
                "-out", f"client/client-{client_name}.p12",
                "-password", f"pass:{p12_password}",
            ], "issue:export-p12"),
        ]
        for cmd, step in commands:
            ok, rc = self._run_checked(cmd, timeout=900, logs=logs, steps=steps, step=step)
            if not ok:
                stdout, stderr = self._join_logs(logs)
                return WorkflowResult(False, "OPENSSL_FAILED", "issue-client failed", rc, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)
        stdout, stderr = self._join_logs(logs)
        stdout = (stdout + f"\nClient certificate issued.\nClient P12 file: client/client-{client_name}.p12").strip()
        return WorkflowResult(True, "WORKFLOW_OK", "issue-client succeeded", 0, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)

    def revoke_server(self) -> WorkflowResult:
        start = time.perf_counter()
        cert_rel = "server/server.cert.pem"
        cert_path = self.repo_root / cert_rel
        if not cert_path.exists():
            return WorkflowResult(False, "STATE_INVALID", "revoke-server failed", 2, "", f"Server certificate not found: {cert_rel}", int((time.perf_counter() - start) * 1000), ["revoke-server:precheck"])
        logs: list[tuple[str, str]] = []
        steps: list[str] = []
        for cmd, step in [
            (["openssl", "ca", "-config", self.inter_ca_cfg, "-revoke", cert_rel], "revoke-server:mark-revoked"),
            (["openssl", "ca", "-config", self.inter_ca_cfg, "-gencrl", "-out", "ca/intermediate/crl/intermediate.crl.pem"], "revoke-server:gen-crl"),
        ]:
            ok, rc = self._run_checked(cmd, timeout=600, logs=logs, steps=steps, step=step)
            if not ok:
                stdout, stderr = self._join_logs(logs)
                return WorkflowResult(False, "OPENSSL_FAILED", "revoke-server failed", rc, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)
        stdout, stderr = self._join_logs(logs)
        stdout = (stdout + "\nServer certificate revoked and CRL generated.").strip()
        return WorkflowResult(True, "WORKFLOW_OK", "revoke-server succeeded", 0, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)

    def revoke_client(self, *, client_name: str) -> WorkflowResult:
        start = time.perf_counter()
        cert_rel = f"client/client-{client_name}.cert.pem"
        cert_path = self.repo_root / cert_rel
        if not cert_path.exists():
            return WorkflowResult(False, "STATE_INVALID", "revoke-client failed", 2, "", f"Client certificate not found: {cert_rel}", int((time.perf_counter() - start) * 1000), ["revoke-client:precheck"])
        logs: list[tuple[str, str]] = []
        steps: list[str] = []
        for cmd, step in [
            (["openssl", "ca", "-config", self.inter_ca_cfg, "-revoke", cert_rel], "revoke-client:mark-revoked"),
            (["openssl", "ca", "-config", self.inter_ca_cfg, "-gencrl", "-out", "ca/intermediate/crl/intermediate.crl.pem"], "revoke-client:gen-crl"),
        ]:
            ok, rc = self._run_checked(cmd, timeout=600, logs=logs, steps=steps, step=step)
            if not ok:
                stdout, stderr = self._join_logs(logs)
                return WorkflowResult(False, "OPENSSL_FAILED", "revoke-client failed", rc, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)
        stdout, stderr = self._join_logs(logs)
        stdout = (stdout + "\nClient certificate revoked and CRL generated.").strip()
        return WorkflowResult(True, "WORKFLOW_OK", "revoke-client succeeded", 0, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)

    def verify(self, *, client_name: str) -> WorkflowResult:
        start = time.perf_counter()
        logs_dir = self.repo_root / "artifacts/logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        tasks = [
            (["openssl", "verify", "-CAfile", "ca/root/certs/ca.cert.pem", "ca/intermediate/certs/intermediate.cert.pem"], logs_dir / "verify-chain.log", "verify:chain"),
            (["openssl", "verify", "-CAfile", "ca/intermediate/certs/ca-chain.cert.pem", "server/server.cert.pem"], logs_dir / "verify-server.log", "verify:server"),
            (["openssl", "verify", "-CAfile", "ca/intermediate/certs/ca-chain.cert.pem", f"client/client-{client_name}.cert.pem"], logs_dir / "verify-client.log", "verify:client"),
        ]
        logs: list[tuple[str, str]] = []
        steps: list[str] = []
        for cmd, outfile, step in tasks:
            result = self.runner.run(cmd, timeout=600)
            combined = (result.stdout + ("\n" if result.stdout and result.stderr else "") + result.stderr).strip()
            outfile.write_text(combined + ("\n" if combined else ""), encoding="utf-8")
            logs.append((result.stdout, result.stderr))
            steps.append(step)
            if not result.ok:
                stdout, stderr = self._join_logs(logs)
                return WorkflowResult(False, "OPENSSL_FAILED", "verify failed", result.returncode, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)
        stdout, stderr = self._join_logs(logs)
        stdout = (stdout + "\nCertificate chain verification logs written to artifacts/logs.").strip()
        return WorkflowResult(True, "WORKFLOW_OK", "verify succeeded", 0, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)

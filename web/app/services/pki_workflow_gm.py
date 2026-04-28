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


class PKIWorkflowGM:
    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root
        self.runner = OpenSSLRunner(repo_root)
        self.gm_bin = "gmssl" if shutil.which("gmssl") else "openssl"
        self.gm_root_cfg = "gm/ca/openssl-root-gm.cnf"
        self.gm_inter_cfg = "gm/ca/openssl-intermediate-gm.cnf"

    def _gm_cmd(self, command: list[str]) -> list[str]:
        if command and command[0] == "openssl":
            return [self.gm_bin, *command[1:]]
        return command

    def _join_logs(self, chunks: list[tuple[str, str]]) -> tuple[str, str]:
        return (
            "\n".join(part for part, _ in chunks if part).strip(),
            "\n".join(part for _, part in chunks if part).strip(),
        )

    def _run_checked(self, command: list[str], *, timeout: int, logs: list[tuple[str, str]], steps: list[str], step: str) -> tuple[bool, int]:
        result = self.runner.run(self._gm_cmd(command), timeout=timeout)
        logs.append((result.stdout, result.stderr))
        steps.append(step)
        if not result.ok:
            return False, result.returncode
        return True, 0

    def _write_gm_configs(self) -> None:
        root_tpl = (self.repo_root / "ca/openssl-root.cnf").read_text(encoding="utf-8")
        inter_tpl = (self.repo_root / "ca/openssl-intermediate.cnf").read_text(encoding="utf-8")
        root_cfg = root_tpl.replace("./ca/root", "./gm/ca/root").replace("default_md        = sha256", "default_md        = sm3")
        inter_cfg = (
            inter_tpl.replace("./ca/intermediate", "./gm/ca/intermediate")
            .replace("default_md        = sha256", "default_md        = sm3")
            .replace("default_md          = sha256", "default_md          = sm3")
            .replace("/repo/intermediate.crl.pem", "/repo/gm/intermediate.crl.pem")
            .replace("/repo/ca-chain.cert.pem", "/repo/gm/ca-chain.cert.pem")
        )
        gm_ca = self.repo_root / "gm/ca"
        gm_ca.mkdir(parents=True, exist_ok=True)
        (gm_ca / "openssl-root-gm.cnf").write_text(root_cfg, encoding="utf-8")
        (gm_ca / "openssl-intermediate-gm.cnf").write_text(inter_cfg, encoding="utf-8")

    def capability_check(self) -> WorkflowResult:
        start = time.perf_counter()
        checks = [
            ("sm2", ["openssl", "list", "-public-key-algorithms"]),
            ("sm3", ["openssl", "list", "-digest-algorithms"]),
            ("sm4", ["openssl", "list", "-cipher-algorithms"]),
        ]
        logs: list[tuple[str, str]] = []
        missing: list[str] = []
        for name, cmd in checks:
            r = self.runner.run(self._gm_cmd(cmd), timeout=60)
            logs.append((r.stdout, r.stderr))
            if name.upper() not in (r.stdout or "").upper() and name.upper() not in (r.stderr or "").upper():
                missing.append(name.upper())
        stdout, stderr = self._join_logs(logs)
        if missing:
            return WorkflowResult(
                False,
                "STATE_INVALID",
                "gm capability check failed",
                2,
                stdout,
                f"Missing algorithms: {', '.join(missing)}\n{stderr}",
                int((time.perf_counter() - start) * 1000),
                ["gm:capability-check"],
                [],
            )
        return WorkflowResult(
            True,
            "WORKFLOW_OK",
            "gm capability check succeeded",
            0,
            stdout,
            stderr,
            int((time.perf_counter() - start) * 1000),
            ["gm:capability-check"],
            [],
        )

    def init_structure(self) -> WorkflowResult:
        start = time.perf_counter()
        dirs = [
            "gm/ca/root/certs",
            "gm/ca/root/crl",
            "gm/ca/root/newcerts",
            "gm/ca/root/private",
            "gm/ca/root/csr",
            "gm/ca/intermediate/certs",
            "gm/ca/intermediate/crl",
            "gm/ca/intermediate/newcerts",
            "gm/ca/intermediate/private",
            "gm/ca/intermediate/csr",
            "gm/server",
            "gm/client",
            "artifacts/logs/gm",
        ]
        for d in dirs:
            (self.repo_root / d).mkdir(parents=True, exist_ok=True)
        defaults = {
            "gm/ca/root/index.txt": "",
            "gm/ca/intermediate/index.txt": "",
            "gm/ca/root/serial": "1000",
            "gm/ca/intermediate/serial": "2000",
            "gm/ca/intermediate/crlnumber": "2000",
        }
        for rel, value in defaults.items():
            p = self.repo_root / rel
            if not p.exists():
                p.write_text(value, encoding="ascii")
        self._write_gm_configs()
        return WorkflowResult(
            True,
            "WORKFLOW_OK",
            "gm init succeeded",
            0,
            "GM PKI directory initialization completed.",
            "",
            int((time.perf_counter() - start) * 1000),
            ["gm:init:prepare-dirs", "gm:init:seed-db", "gm:init:write-configs"],
            [],
        )

    def reset_demo(self, *, keep_web_cache: bool) -> WorkflowResult:
        start = time.perf_counter()
        removed: list[str] = []
        for rel in ["gm/ca", "gm/server", "gm/client", "artifacts/logs/gm"]:
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
        lines = [f"Removed: {item}" for item in removed] + [init_result.stdout, "GM demo reset completed."]
        return WorkflowResult(
            init_result.ok,
            init_result.code,
            "gm reset-demo succeeded" if init_result.ok else "gm reset-demo failed",
            init_result.returncode,
            "\n".join(lines),
            init_result.stderr,
            int((time.perf_counter() - start) * 1000),
            ["gm:reset:cleanup", "gm:reset:re-init"],
            [],
        )

    def build_ca(self) -> WorkflowResult:
        start = time.perf_counter()
        logs: list[tuple[str, str]] = []
        steps: list[str] = []
        pre = self.capability_check()
        if not pre.ok:
            return pre
        cmds = [
            (["openssl", "ecparam", "-name", "SM2", "-genkey", "-out", "gm/ca/root/private/ca.key.pem"], "gm:build-ca:root-keygen"),
            (
                [
                    "openssl",
                    "req",
                    "-config",
                    self.gm_root_cfg,
                    "-key",
                    "gm/ca/root/private/ca.key.pem",
                    "-new",
                    "-x509",
                    "-days",
                    "3650",
                    "-sm3",
                    "-extensions",
                    "v3_ca",
                    "-subj",
                    "/C=CN/ST=Shanghai/O=Koal/OU=Training/CN=Koal GM Root CA",
                    "-out",
                    "gm/ca/root/certs/ca.cert.pem",
                ],
                "gm:build-ca:root-self-sign",
            ),
            (["openssl", "ecparam", "-name", "SM2", "-genkey", "-out", "gm/ca/intermediate/private/intermediate.key.pem"], "gm:build-ca:intermediate-keygen"),
            (
                [
                    "openssl",
                    "req",
                    "-config",
                    self.gm_inter_cfg,
                    "-new",
                    "-sm3",
                    "-key",
                    "gm/ca/intermediate/private/intermediate.key.pem",
                    "-subj",
                    "/C=CN/ST=Shanghai/O=Koal/OU=Training/CN=Koal GM Intermediate CA",
                    "-out",
                    "gm/ca/intermediate/csr/intermediate.csr.pem",
                ],
                "gm:build-ca:intermediate-csr",
            ),
            (
                [
                    "openssl",
                    "ca",
                    "-batch",
                    "-config",
                    self.gm_root_cfg,
                    "-extensions",
                    "v3_ca",
                    "-days",
                    "1825",
                    "-notext",
                    "-md",
                    "sm3",
                    "-in",
                    "gm/ca/intermediate/csr/intermediate.csr.pem",
                    "-out",
                    "gm/ca/intermediate/certs/intermediate.cert.pem",
                ],
                "gm:build-ca:issue-intermediate",
            ),
            (
                [
                    "openssl",
                    "verify",
                    "-CAfile",
                    "gm/ca/root/certs/ca.cert.pem",
                    "gm/ca/intermediate/certs/intermediate.cert.pem",
                ],
                "gm:build-ca:verify-chain",
            ),
            (
                [
                    "openssl",
                    "pkcs12",
                    "-export",
                    "-nokeys",
                    "-in",
                    "gm/ca/root/certs/ca.cert.pem",
                    "-out",
                    "gm/ca/root/certs/ca.cert.p12",
                    "-password",
                    "pass:123456",
                ],
                "gm:build-ca:export-root-p12",
            ),
            (
                [
                    "openssl",
                    "pkcs12",
                    "-export",
                    "-nokeys",
                    "-in",
                    "gm/ca/intermediate/certs/intermediate.cert.pem",
                    "-certfile",
                    "gm/ca/root/certs/ca.cert.pem",
                    "-out",
                    "gm/ca/intermediate/certs/intermediate.cert.p12",
                    "-password",
                    "pass:123456",
                ],
                "gm:build-ca:export-intermediate-p12",
            ),
        ]
        for cmd, step in cmds:
            ok, rc = self._run_checked(cmd, timeout=900, logs=logs, steps=steps, step=step)
            if not ok:
                stdout, stderr = self._join_logs(logs)
                return WorkflowResult(False, "OPENSSL_FAILED", "gm build-ca failed", rc, stdout, stderr, int((time.perf_counter() - start) * 1000), steps, [])
        inter = (self.repo_root / "gm/ca/intermediate/certs/intermediate.cert.pem").read_text(encoding="utf-8")
        root = (self.repo_root / "gm/ca/root/certs/ca.cert.pem").read_text(encoding="utf-8")
        (self.repo_root / "gm/ca/intermediate/certs/ca-chain.cert.pem").write_text(f"{inter}{root}", encoding="ascii")
        steps.append("gm:build-ca:write-chain")
        stdout, stderr = self._join_logs(logs)
        return WorkflowResult(
            True,
            "WORKFLOW_OK",
            "gm build-ca succeeded",
            0,
            (
                stdout
                + "\nGM Root/Intermediate CA build completed."
                + "\nGM CA P12 files (cert-only):"
                + "\n- gm/ca/root/certs/ca.cert.p12"
                + "\n- gm/ca/intermediate/certs/intermediate.cert.p12"
                + "\nP12 password: 123456"
            ).strip(),
            stderr,
            int((time.perf_counter() - start) * 1000),
            steps,
            [],
        )

    def issue_server(self) -> WorkflowResult:
        start = time.perf_counter()
        logs: list[tuple[str, str]] = []
        steps: list[str] = []
        commands: list[tuple[list[str], str]] = [
            (["openssl", "ecparam", "-name", "SM2", "-genkey", "-out", "gm/server/server.key.pem"], "gm:issue-server:keygen"),
            (
                [
                    "openssl",
                    "req",
                    "-config",
                    self.gm_inter_cfg,
                    "-new",
                    "-sm3",
                    "-key",
                    "gm/server/server.key.pem",
                    "-subj",
                    "/C=CN/ST=Shanghai/O=Koal/OU=PKI/CN=localhost",
                    "-out",
                    "gm/ca/intermediate/csr/server.csr.pem",
                ],
                "gm:issue-server:csr",
            ),
            (
                [
                    "openssl",
                    "ca",
                    "-batch",
                    "-config",
                    self.gm_inter_cfg,
                    "-extensions",
                    "server_cert",
                    "-days",
                    "825",
                    "-notext",
                    "-md",
                    "sm3",
                    "-in",
                    "gm/ca/intermediate/csr/server.csr.pem",
                    "-out",
                    "gm/server/server.cert.pem",
                ],
                "gm:issue-server:sign",
            ),
        ]
        for cmd, step in commands:
            ok, rc = self._run_checked(cmd, timeout=900, logs=logs, steps=steps, step=step)
            if not ok:
                stdout, stderr = self._join_logs(logs)
                return WorkflowResult(False, "OPENSSL_FAILED", "gm issue-server failed", rc, stdout, stderr, int((time.perf_counter() - start) * 1000), steps, [])
        stdout, stderr = self._join_logs(logs)
        return WorkflowResult(True, "WORKFLOW_OK", "gm issue-server succeeded", 0, (stdout + "\nGM server certificate issued.").strip(), stderr, int((time.perf_counter() - start) * 1000), steps, [])

    def issue_client(self, *, client_name: str, p12_password: str) -> WorkflowResult:
        start = time.perf_counter()
        logs: list[tuple[str, str]] = []
        steps: list[str] = []
        commands: list[tuple[list[str], str]] = [
            (["openssl", "ecparam", "-name", "SM2", "-genkey", "-out", f"gm/client/client-{client_name}.key.pem"], "gm:issue-client:keygen"),
            (
                [
                    "openssl",
                    "req",
                    "-config",
                    self.gm_inter_cfg,
                    "-new",
                    "-sm3",
                    "-key",
                    f"gm/client/client-{client_name}.key.pem",
                    "-subj",
                    f"/C=CN/ST=Shanghai/O=Koal/OU=PKI/CN={client_name}",
                    "-out",
                    f"gm/ca/intermediate/csr/client-{client_name}.csr.pem",
                ],
                "gm:issue-client:csr",
            ),
            (
                [
                    "openssl",
                    "ca",
                    "-batch",
                    "-config",
                    self.gm_inter_cfg,
                    "-extensions",
                    "usr_cert",
                    "-days",
                    "825",
                    "-notext",
                    "-md",
                    "sm3",
                    "-in",
                    f"gm/ca/intermediate/csr/client-{client_name}.csr.pem",
                    "-out",
                    f"gm/client/client-{client_name}.cert.pem",
                ],
                "gm:issue-client:sign",
            ),
            (
                [
                    "openssl",
                    "pkcs12",
                    "-export",
                    "-inkey",
                    f"gm/client/client-{client_name}.key.pem",
                    "-in",
                    f"gm/client/client-{client_name}.cert.pem",
                    "-certfile",
                    "gm/ca/intermediate/certs/ca-chain.cert.pem",
                    "-out",
                    f"gm/client/client-{client_name}.p12",
                    "-password",
                    f"pass:{p12_password}",
                ],
                "gm:issue-client:export-p12",
            ),
        ]
        for cmd, step in commands:
            ok, rc = self._run_checked(cmd, timeout=900, logs=logs, steps=steps, step=step)
            if not ok:
                stdout, stderr = self._join_logs(logs)
                return WorkflowResult(False, "OPENSSL_FAILED", "gm issue-client failed", rc, stdout, stderr, int((time.perf_counter() - start) * 1000), steps, [])
        stdout, stderr = self._join_logs(logs)
        return WorkflowResult(True, "WORKFLOW_OK", "gm issue-client succeeded", 0, (stdout + f"\nGM client certificate issued.\nGM Client P12 file: gm/client/client-{client_name}.p12").strip(), stderr, int((time.perf_counter() - start) * 1000), steps, [])

    def verify(self, *, client_name: str) -> WorkflowResult:
        start = time.perf_counter()
        logs: list[tuple[str, str]] = []
        steps: list[str] = []
        logs_dir = self.repo_root / "artifacts/logs/gm"
        logs_dir.mkdir(parents=True, exist_ok=True)
        tasks = [
            (["openssl", "verify", "-CAfile", "gm/ca/root/certs/ca.cert.pem", "gm/ca/intermediate/certs/intermediate.cert.pem"], logs_dir / "verify-chain.log", "gm:verify:chain"),
            (["openssl", "verify", "-CAfile", "gm/ca/intermediate/certs/ca-chain.cert.pem", "gm/server/server.cert.pem"], logs_dir / "verify-server.log", "gm:verify:server"),
            (["openssl", "verify", "-CAfile", "gm/ca/intermediate/certs/ca-chain.cert.pem", f"gm/client/client-{client_name}.cert.pem"], logs_dir / "verify-client.log", "gm:verify:client"),
        ]
        for cmd, outfile, step in tasks:
            r = self.runner.run(self._gm_cmd(cmd), timeout=600)
            combined = (r.stdout + ("\n" if r.stdout and r.stderr else "") + r.stderr).strip()
            outfile.write_text(combined + ("\n" if combined else ""), encoding="utf-8")
            logs.append((r.stdout, r.stderr))
            steps.append(step)
            if not r.ok:
                stdout, stderr = self._join_logs(logs)
                return WorkflowResult(False, "OPENSSL_FAILED", "gm verify failed", r.returncode, stdout, stderr, int((time.perf_counter() - start) * 1000), steps, [])
        stdout, stderr = self._join_logs(logs)
        return WorkflowResult(True, "WORKFLOW_OK", "gm verify succeeded", 0, (stdout + "\nGM certificate verification logs written to artifacts/logs/gm.").strip(), stderr, int((time.perf_counter() - start) * 1000), steps, [])

    def revoke_server(self) -> WorkflowResult:
        start = time.perf_counter()
        cert_rel = "gm/server/server.cert.pem"
        if not (self.repo_root / cert_rel).exists():
            return WorkflowResult(False, "STATE_INVALID", "gm revoke-server failed", 2, "", f"Server certificate not found: {cert_rel}", int((time.perf_counter() - start) * 1000), ["gm:revoke-server:precheck"], [])
        logs: list[tuple[str, str]] = []
        steps: list[str] = []
        for cmd, step in [
            (["openssl", "ca", "-config", self.gm_inter_cfg, "-revoke", cert_rel], "gm:revoke-server:mark-revoked"),
            (["openssl", "ca", "-config", self.gm_inter_cfg, "-gencrl", "-out", "gm/ca/intermediate/crl/intermediate.crl.pem"], "gm:revoke-server:gen-crl"),
        ]:
            ok, rc = self._run_checked(cmd, timeout=600, logs=logs, steps=steps, step=step)
            if not ok:
                stdout, stderr = self._join_logs(logs)
                if "already revoked" in (stderr or "").lower():
                    continue
                return WorkflowResult(False, "OPENSSL_FAILED", "gm revoke-server failed", rc, stdout, stderr, int((time.perf_counter() - start) * 1000), steps, [])
        stdout, stderr = self._join_logs(logs)
        return WorkflowResult(True, "WORKFLOW_OK", "gm revoke-server succeeded", 0, (stdout + "\nGM server certificate revoked and CRL generated.").strip(), stderr, int((time.perf_counter() - start) * 1000), steps, [])

    def revoke_client(self, *, client_name: str) -> WorkflowResult:
        start = time.perf_counter()
        cert_rel = f"gm/client/client-{client_name}.cert.pem"
        if not (self.repo_root / cert_rel).exists():
            return WorkflowResult(False, "STATE_INVALID", "gm revoke-client failed", 2, "", f"Client certificate not found: {cert_rel}", int((time.perf_counter() - start) * 1000), ["gm:revoke-client:precheck"], [])
        logs: list[tuple[str, str]] = []
        steps: list[str] = []
        for cmd, step in [
            (["openssl", "ca", "-config", self.gm_inter_cfg, "-revoke", cert_rel], "gm:revoke-client:mark-revoked"),
            (["openssl", "ca", "-config", self.gm_inter_cfg, "-gencrl", "-out", "gm/ca/intermediate/crl/intermediate.crl.pem"], "gm:revoke-client:gen-crl"),
        ]:
            ok, rc = self._run_checked(cmd, timeout=600, logs=logs, steps=steps, step=step)
            if not ok:
                stdout, stderr = self._join_logs(logs)
                if "already revoked" in (stderr or "").lower():
                    continue
                return WorkflowResult(False, "OPENSSL_FAILED", "gm revoke-client failed", rc, stdout, stderr, int((time.perf_counter() - start) * 1000), steps, [])
        stdout, stderr = self._join_logs(logs)
        return WorkflowResult(True, "WORKFLOW_OK", "gm revoke-client succeeded", 0, (stdout + "\nGM client certificate revoked and CRL generated.").strip(), stderr, int((time.perf_counter() - start) * 1000), steps, [])

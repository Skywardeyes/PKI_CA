from __future__ import annotations

import shutil
import socket
import subprocess
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

    def _run_s_client(
        self,
        args: list[str],
        *,
        tls_version: str = "tls1_2",
        timeout: int = 45,
    ) -> tuple[bool, int, str, str]:
        tls_flag = "-tls1_3" if tls_version == "tls1_3" else "-tls1_2"
        cmd = ["openssl", "s_client", tls_flag, *args]
        try:
            p = subprocess.run(
                cmd,
                cwd=str(self.repo_root),
                input="Q\n",
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            return (p.returncode == 0, p.returncode, p.stdout or "", p.stderr or "")
        except subprocess.TimeoutExpired:
            return (False, -1, "", "openssl s_client timed out")

    def _run_s_client_trace(
        self,
        *,
        port: int,
        tls_flag: str,
        with_client_cert: bool,
        client_name: str,
        timeout: int = 45,
    ) -> tuple[bool, int, str, str]:
        args = [
            "s_client",
            "-connect",
            f"127.0.0.1:{port}",
            "-servername",
            "localhost",
            "-CAfile",
            "ca/intermediate/certs/ca-chain.cert.pem",
            "-brief",
            tls_flag,
        ]
        if with_client_cert:
            args.extend(
                [
                    "-cert",
                    f"client/client-{client_name}.cert.pem",
                    "-key",
                    f"client/client-{client_name}.key.pem",
                ]
            )
        try:
            p = subprocess.run(
                ["openssl", *args],
                cwd=str(self.repo_root),
                input="Q\n",
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            return (p.returncode == 0, p.returncode, p.stdout or "", p.stderr or "")
        except subprocess.TimeoutExpired:
            return (False, -1, "", "openssl s_client trace timed out")

    def _write_log_file(self, name: str, stdout: str, stderr: str) -> str:
        logs_dir = self.repo_root / "artifacts/logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        path = logs_dir / name
        body = (stdout + ("\n" if stdout and stderr else "") + stderr).strip()
        path.write_text(body + ("\n" if body else ""), encoding="utf-8")
        return str(path.relative_to(self.repo_root)).replace("\\", "/")

    def _is_already_revoked(self, text: str) -> bool:
        lower = text.lower()
        return "already revoked" in lower or "error:already revoked" in lower

    def _pick_free_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            return int(s.getsockname()[1])

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
        stdout = (stdout + "\nRoot/Intermediate CA build completed.").strip()
        return WorkflowResult(True, "WORKFLOW_OK", "build-ca succeeded", 0, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)

    def issue(self, *, client_name: str, p12_password: str) -> WorkflowResult:
        start = time.perf_counter()
        logs: list[tuple[str, str]] = []
        steps: list[str] = []
        server_cert = self.repo_root / "server/server.cert.pem"
        commands: list[tuple[list[str], str]] = []
        if not server_cert.exists():
            commands.extend([
                (["openssl", "genrsa", "-out", "server/server.key.pem", "2048"], "issue:server-keygen"),
                ([
                    "openssl", "req", "-config", self.inter_ca_cfg, "-new", "-sha256", "-key", "server/server.key.pem",
                    "-subj", "/C=CN/ST=Shanghai/O=Koal/OU=PKI/CN=localhost", "-out", "ca/intermediate/csr/server.csr.pem",
                ], "issue:server-csr"),
                ([
                    "openssl", "ca", "-batch", "-config", self.inter_ca_cfg, "-extensions", "server_cert", "-days", "825",
                    "-notext", "-md", "sha256", "-in", "ca/intermediate/csr/server.csr.pem", "-out", "server/server.cert.pem",
                ], "issue:server-sign"),
            ])
        commands.extend([
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
        ])
        for cmd, step in commands:
            ok, rc = self._run_checked(cmd, timeout=900, logs=logs, steps=steps, step=step)
            if not ok:
                stdout, stderr = self._join_logs(logs)
                return WorkflowResult(False, "OPENSSL_FAILED", "issue failed", rc, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)
        stdout, stderr = self._join_logs(logs)
        stdout = (stdout + f"\nServer and client certificates issued.\nClient P12 file: client/client-{client_name}.p12").strip()
        return WorkflowResult(True, "WORKFLOW_OK", "issue succeeded", 0, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)

    def revoke(self, *, client_name: str) -> WorkflowResult:
        start = time.perf_counter()
        cert_rel = f"client/client-{client_name}.cert.pem"
        cert_path = self.repo_root / cert_rel
        if not cert_path.exists():
            return WorkflowResult(False, "STATE_INVALID", "revoke failed", 2, "", f"Client certificate not found: {cert_rel}", int((time.perf_counter() - start) * 1000), ["revoke:precheck"])
        logs: list[tuple[str, str]] = []
        steps: list[str] = []
        for cmd, step in [
            (["openssl", "ca", "-config", self.inter_ca_cfg, "-revoke", cert_rel], "revoke:mark-revoked"),
            (["openssl", "ca", "-config", self.inter_ca_cfg, "-gencrl", "-out", "ca/intermediate/crl/intermediate.crl.pem"], "revoke:gen-crl"),
        ]:
            ok, rc = self._run_checked(cmd, timeout=600, logs=logs, steps=steps, step=step)
            if not ok:
                stdout, stderr = self._join_logs(logs)
                return WorkflowResult(False, "OPENSSL_FAILED", "revoke failed", rc, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)
        stdout, stderr = self._join_logs(logs)
        stdout = (stdout + "\nClient certificate revoked and CRL generated.").strip()
        return WorkflowResult(True, "WORKFLOW_OK", "revoke succeeded", 0, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)

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

    def mtls_validate(self, *, client_name: str, tls_version: str = "tls1_2") -> WorkflowResult:
        start = time.perf_counter()
        logs_dir = self.repo_root / "artifacts/logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        suffix = "-tls13" if tls_version == "tls1_3" else ""
        server_log = logs_dir / f"mtls-server{suffix}.log"
        server_err_log = logs_dir / f"mtls-server.err{suffix}.log"
        success_log = logs_dir / f"mtls-success{suffix}.log"
        no_cert_log = logs_dir / f"mtls-no-cert{suffix}.log"
        revoked_log = logs_dir / f"mtls-revoked{suffix}.log"
        steps: list[str] = []
        logs: list[tuple[str, str]] = []
        crl_path = self.repo_root / "ca/intermediate/crl/intermediate.crl.pem"
        if not crl_path.exists():
            ok, rc = self._run_checked(
                ["openssl", "ca", "-config", self.inter_ca_cfg, "-gencrl", "-out", "ca/intermediate/crl/intermediate.crl.pem"],
                timeout=600, logs=logs, steps=steps, step="mtls:gen-crl",
            )
            if not ok:
                stdout, stderr = self._join_logs(logs)
                return WorkflowResult(False, "OPENSSL_FAILED", "mtls-validate failed", rc, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)
        port = self._pick_free_port()
        cmd = [
            "openssl", "s_server",
            "-accept", str(port),
            "-naccept", "8",
            "-cert", "server/server.cert.pem",
            "-key", "server/server.key.pem",
            "-CAfile", "ca/intermediate/certs/ca-chain.cert.pem",
            "-Verify", "1",
            "-verify_return_error",
            "-CRL", "ca/intermediate/crl/intermediate.crl.pem",
            "-crl_check_all",
        ]
        with server_log.open("w", encoding="utf-8") as out, server_err_log.open("w", encoding="utf-8") as err:
            proc = subprocess.Popen(cmd, cwd=str(self.repo_root), stdout=out, stderr=err, text=True)
            steps.append("mtls:start-server")
            try:
                # 不要用裸 TCP 探测端口：会占用 s_server 的一次 accept，易导致后续 s_client 挂起。
                time.sleep(2.0)
                _, _, c1_out, c1_err = self._run_s_client(
                    [
                        "-connect", f"127.0.0.1:{port}",
                        "-servername", "localhost",
                        "-cert", f"client/client-{client_name}.cert.pem",
                        "-key", f"client/client-{client_name}.key.pem",
                        "-CAfile", "ca/intermediate/certs/ca-chain.cert.pem",
                        "-brief",
                    ],
                    tls_version=tls_version,
                    timeout=45,
                )
                success_log.write_text((c1_out + ("\n" if c1_out and c1_err else "") + c1_err).strip() + "\n", encoding="utf-8")
                logs.append((c1_out, c1_err))
                steps.append("mtls:client-with-cert")
                _, _, c2_out, c2_err = self._run_s_client(
                    [
                        "-connect", f"127.0.0.1:{port}",
                        "-servername", "localhost",
                        "-CAfile", "ca/intermediate/certs/ca-chain.cert.pem",
                        "-brief",
                    ],
                    tls_version=tls_version,
                    timeout=45,
                )
                no_cert_log.write_text((c2_out + ("\n" if c2_out and c2_err else "") + c2_err).strip() + "\n", encoding="utf-8")
                logs.append((c2_out, c2_err))
                steps.append("mtls:client-without-cert")
                revoke_result = self.revoke(client_name=client_name)
                logs.append((revoke_result.stdout, revoke_result.stderr))
                steps.extend(revoke_result.steps)
                if not revoke_result.ok:
                    stdout, stderr = self._join_logs(logs)
                    return WorkflowResult(False, revoke_result.code, "mtls-validate failed", revoke_result.returncode, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)
                _, _, c3_out, c3_err = self._run_s_client(
                    [
                        "-connect", f"127.0.0.1:{port}",
                        "-servername", "localhost",
                        "-cert", f"client/client-{client_name}.cert.pem",
                        "-key", f"client/client-{client_name}.key.pem",
                        "-CAfile", "ca/intermediate/certs/ca-chain.cert.pem",
                        "-brief",
                    ],
                    tls_version=tls_version,
                    timeout=45,
                )
                revoked_log.write_text((c3_out + ("\n" if c3_out and c3_err else "") + c3_err).strip() + "\n", encoding="utf-8")
                logs.append((c3_out, c3_err))
                steps.append("mtls:client-revoked")
                stdout, stderr = self._join_logs(logs)
                tls_label = "TLS1.3" if tls_version == "tls1_3" else "TLS1.2"
                stdout = (stdout + f"\nmTLS validation ({tls_label}) logs generated under artifacts/logs.").strip()
                return WorkflowResult(True, "WORKFLOW_OK", "mtls-validate succeeded", 0, stdout, stderr, int((time.perf_counter() - start) * 1000), steps)
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()

    def tls_observe(self, *, client_name: str, tls_version: str = "tls1_2") -> WorkflowResult:
        start = time.perf_counter()
        is_tls13 = tls_version == "tls1_3"
        suffix = "-tls13" if is_tls13 else ""
        tls_tag = "tls13" if is_tls13 else "tls12"
        steps = [
            "tls-observe:tcp-connect",
            "tls-observe:server-cert-verify",
            "tls-observe:client-cert-auth",
            "tls-observe:key-exchange",
            "tls-observe:cipher-ready",
        ]
        artifacts: list[str] = []
        mtls = self.mtls_validate(client_name=client_name, tls_version=tls_version)
        if not mtls.ok:
            return WorkflowResult(
                ok=False,
                code=mtls.code,
                message="tls-observe failed",
                returncode=mtls.returncode,
                stdout=mtls.stdout,
                stderr=mtls.stderr,
                duration_ms=int((time.perf_counter() - start) * 1000),
                steps=steps + ["tls-observe:mtls-baseline-failed"],
                artifacts=[],
            )
        logs_dir = self.repo_root / "artifacts/logs"
        mappings = [
            (f"mtls-success{suffix}.log", f"tls-observe-{tls_tag}-with-cert.log"),
            (f"mtls-no-cert{suffix}.log", f"tls-observe-{tls_tag}-no-cert.log"),
            (f"mtls-revoked{suffix}.log", f"tls-observe-{tls_tag}-revoked.log"),
            (f"mtls-server{suffix}.log", f"tls-observe-server{suffix}.log"),
            (f"mtls-server.err{suffix}.log", f"tls-observe-server.err{suffix}.log"),
        ]
        for src_name, dst_name in mappings:
            src = logs_dir / src_name
            dst = logs_dir / dst_name
            if src.exists():
                shutil.copyfile(src, dst)
                artifacts.append(str(dst.relative_to(self.repo_root)).replace("\\", "/"))
        cipher_cmd = ["openssl", "ciphers", "-v", "-tls1_3"] if is_tls13 else ["openssl", "ciphers", "-v", "-tls1_2"]
        ciphers = self.runner.run(cipher_cmd, timeout=120)
        artifacts.append(self._write_log_file(f"tls-observe-ciphers-{tls_tag}.log", ciphers.stdout, ciphers.stderr))
        steps.extend([f"tls-observe:{tls_tag}-cipher-catalog", "tls-observe:revoked-cert-rejected"])
        stdout = (
            f"TLS observe ({'TLS1.3' if is_tls13 else 'TLS1.2'}) generated from mTLS baseline + OpenSSL cipher catalog.\n"
            f"Use tls-observe-{tls_tag}-*.log for handshake evidence."
        )
        stderr = ((mtls.stderr or "") + ("\n" if mtls.stderr and ciphers.stderr else "") + (ciphers.stderr or "")).strip()
        return WorkflowResult(
            ok=True,
            code="WORKFLOW_OK",
            message="tls-observe succeeded",
            returncode=0,
            stdout=stdout,
            stderr=stderr,
            duration_ms=int((time.perf_counter() - start) * 1000),
            steps=steps,
            artifacts=artifacts,
        )

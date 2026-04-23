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


class PKIWorkflowGM:
    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root
        self.runner = OpenSSLRunner(repo_root)
        self.gm_root_cfg = "gm/ca/openssl-root-gm.cnf"
        self.gm_inter_cfg = "gm/ca/openssl-intermediate-gm.cnf"

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

    def _pick_free_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            return int(s.getsockname()[1])

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
            r = self.runner.run(cmd, timeout=60)
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
        return WorkflowResult(True, "WORKFLOW_OK", "gm build-ca succeeded", 0, (stdout + "\nGM Root/Intermediate CA build completed.").strip(), stderr, int((time.perf_counter() - start) * 1000), steps, [])

    def issue(self, *, client_name: str, p12_password: str) -> WorkflowResult:
        start = time.perf_counter()
        logs: list[tuple[str, str]] = []
        steps: list[str] = []
        commands: list[tuple[list[str], str]] = []
        if not (self.repo_root / "gm/server/server.cert.pem").exists():
            commands.extend(
                [
                    (["openssl", "ecparam", "-name", "SM2", "-genkey", "-out", "gm/server/server.key.pem"], "gm:issue:server-keygen"),
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
                        "gm:issue:server-csr",
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
                        "gm:issue:server-sign",
                    ),
                ]
            )
        commands.extend(
            [
                (["openssl", "ecparam", "-name", "SM2", "-genkey", "-out", f"gm/client/client-{client_name}.key.pem"], "gm:issue:client-keygen"),
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
                    "gm:issue:client-csr",
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
                    "gm:issue:client-sign",
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
                    "gm:issue:export-p12",
                ),
            ]
        )
        for cmd, step in commands:
            ok, rc = self._run_checked(cmd, timeout=900, logs=logs, steps=steps, step=step)
            if not ok:
                stdout, stderr = self._join_logs(logs)
                return WorkflowResult(False, "OPENSSL_FAILED", "gm issue failed", rc, stdout, stderr, int((time.perf_counter() - start) * 1000), steps, [])
        stdout, stderr = self._join_logs(logs)
        return WorkflowResult(True, "WORKFLOW_OK", "gm issue succeeded", 0, (stdout + f"\nGM server and client certificates issued.\nGM Client P12 file: gm/client/client-{client_name}.p12").strip(), stderr, int((time.perf_counter() - start) * 1000), steps, [])

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
            r = self.runner.run(cmd, timeout=600)
            combined = (r.stdout + ("\n" if r.stdout and r.stderr else "") + r.stderr).strip()
            outfile.write_text(combined + ("\n" if combined else ""), encoding="utf-8")
            logs.append((r.stdout, r.stderr))
            steps.append(step)
            if not r.ok:
                stdout, stderr = self._join_logs(logs)
                return WorkflowResult(False, "OPENSSL_FAILED", "gm verify failed", r.returncode, stdout, stderr, int((time.perf_counter() - start) * 1000), steps, [])
        stdout, stderr = self._join_logs(logs)
        return WorkflowResult(True, "WORKFLOW_OK", "gm verify succeeded", 0, (stdout + "\nGM certificate verification logs written to artifacts/logs/gm.").strip(), stderr, int((time.perf_counter() - start) * 1000), steps, [])

    def revoke(self, *, client_name: str) -> WorkflowResult:
        start = time.perf_counter()
        cert_rel = f"gm/client/client-{client_name}.cert.pem"
        if not (self.repo_root / cert_rel).exists():
            return WorkflowResult(False, "STATE_INVALID", "gm revoke failed", 2, "", f"Client certificate not found: {cert_rel}", int((time.perf_counter() - start) * 1000), ["gm:revoke:precheck"], [])
        logs: list[tuple[str, str]] = []
        steps: list[str] = []
        for cmd, step in [
            (["openssl", "ca", "-config", self.gm_inter_cfg, "-revoke", cert_rel], "gm:revoke:mark-revoked"),
            (["openssl", "ca", "-config", self.gm_inter_cfg, "-gencrl", "-out", "gm/ca/intermediate/crl/intermediate.crl.pem"], "gm:revoke:gen-crl"),
        ]:
            ok, rc = self._run_checked(cmd, timeout=600, logs=logs, steps=steps, step=step)
            if not ok:
                stdout, stderr = self._join_logs(logs)
                if "already revoked" in (stderr or "").lower():
                    continue
                return WorkflowResult(False, "OPENSSL_FAILED", "gm revoke failed", rc, stdout, stderr, int((time.perf_counter() - start) * 1000), steps, [])
        stdout, stderr = self._join_logs(logs)
        return WorkflowResult(True, "WORKFLOW_OK", "gm revoke succeeded", 0, (stdout + "\nGM client certificate revoked and CRL generated.").strip(), stderr, int((time.perf_counter() - start) * 1000), steps, [])

    def mtls_validate(self, *, client_name: str, tls_version: str = "tls1_2") -> WorkflowResult:
        start = time.perf_counter()
        logs_dir = self.repo_root / "artifacts/logs/gm"
        logs_dir.mkdir(parents=True, exist_ok=True)
        strict_mode = tls_version == "tls1_3"
        suffix = "-tls13" if strict_mode else ""
        server_log = logs_dir / f"mtls-server{suffix}.log"
        server_err_log = logs_dir / f"mtls-server.err{suffix}.log"
        success_log = logs_dir / f"mtls-success{suffix}.log"
        no_cert_log = logs_dir / f"mtls-no-cert{suffix}.log"
        revoked_log = logs_dir / f"mtls-revoked{suffix}.log"
        logs: list[tuple[str, str]] = []
        steps: list[str] = []
        if not (self.repo_root / "gm/ca/intermediate/crl/intermediate.crl.pem").exists():
            ok, rc = self._run_checked(
                ["openssl", "ca", "-config", self.gm_inter_cfg, "-gencrl", "-out", "gm/ca/intermediate/crl/intermediate.crl.pem"],
                timeout=600,
                logs=logs,
                steps=steps,
                step="gm:mtls:gen-crl",
            )
            if not ok:
                stdout, stderr = self._join_logs(logs)
                return WorkflowResult(False, "OPENSSL_FAILED", "gm mtls-validate failed", rc, stdout, stderr, int((time.perf_counter() - start) * 1000), steps, [])
        port = self._pick_free_port()
        cmd = [
            "openssl",
            "s_server",
            "-accept",
            str(port),
            "-naccept",
            "8",
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
            "-crl_check_all",
        ]
        with server_log.open("w", encoding="utf-8") as out, server_err_log.open("w", encoding="utf-8") as err:
            proc = subprocess.Popen(cmd, cwd=str(self.repo_root), stdout=out, stderr=err, text=True)
            steps.append("gm:mtls:start-server")
            try:
                time.sleep(2.0)
                ok1, rc1, c1_out, c1_err = self._run_s_client(
                    [
                        "-connect",
                        f"127.0.0.1:{port}",
                        "-servername",
                        "localhost",
                        "-cert",
                        f"gm/client/client-{client_name}.cert.pem",
                        "-key",
                        f"gm/client/client-{client_name}.key.pem",
                        "-CAfile",
                        "gm/ca/intermediate/certs/ca-chain.cert.pem",
                        "-brief",
                    ],
                    tls_version=tls_version,
                )
                success_log.write_text((c1_out + ("\n" if c1_out and c1_err else "") + c1_err).strip() + "\n", encoding="utf-8")
                logs.append((c1_out, c1_err))
                steps.append("gm:mtls:with-cert")
                if strict_mode and not ok1:
                    stdout, stderr = self._join_logs(logs)
                    return WorkflowResult(False, "OPENSSL_FAILED", "gm mtls-validate failed", rc1, stdout, stderr, int((time.perf_counter() - start) * 1000), steps, [])
                ok2, rc2, c2_out, c2_err = self._run_s_client(
                    [
                        "-connect",
                        f"127.0.0.1:{port}",
                        "-servername",
                        "localhost",
                        "-CAfile",
                        "gm/ca/intermediate/certs/ca-chain.cert.pem",
                        "-brief",
                    ],
                    tls_version=tls_version,
                )
                no_cert_log.write_text((c2_out + ("\n" if c2_out and c2_err else "") + c2_err).strip() + "\n", encoding="utf-8")
                logs.append((c2_out, c2_err))
                steps.append("gm:mtls:no-cert")
                if strict_mode and not ok2:
                    stdout, stderr = self._join_logs(logs)
                    return WorkflowResult(False, "OPENSSL_FAILED", "gm mtls-validate failed", rc2, stdout, stderr, int((time.perf_counter() - start) * 1000), steps, [])
                revoke_res = self.revoke(client_name=client_name)
                logs.append((revoke_res.stdout, revoke_res.stderr))
                steps.extend(revoke_res.steps)
                if strict_mode and not revoke_res.ok:
                    stdout, stderr = self._join_logs(logs)
                    return WorkflowResult(False, revoke_res.code, "gm mtls-validate failed", revoke_res.returncode, stdout, stderr, int((time.perf_counter() - start) * 1000), steps, [])
                ok3, rc3, c3_out, c3_err = self._run_s_client(
                    [
                        "-connect",
                        f"127.0.0.1:{port}",
                        "-servername",
                        "localhost",
                        "-cert",
                        f"gm/client/client-{client_name}.cert.pem",
                        "-key",
                        f"gm/client/client-{client_name}.key.pem",
                        "-CAfile",
                        "gm/ca/intermediate/certs/ca-chain.cert.pem",
                        "-brief",
                    ],
                    tls_version=tls_version,
                )
                revoked_log.write_text((c3_out + ("\n" if c3_out and c3_err else "") + c3_err).strip() + "\n", encoding="utf-8")
                logs.append((c3_out, c3_err))
                steps.append("gm:mtls:revoked")
                if strict_mode and not ok3:
                    stdout, stderr = self._join_logs(logs)
                    return WorkflowResult(False, "OPENSSL_FAILED", "gm mtls-validate failed", rc3, stdout, stderr, int((time.perf_counter() - start) * 1000), steps, [])
                stdout, stderr = self._join_logs(logs)
                tls_label = "TLS1.3" if strict_mode else "TLS1.2"
                return WorkflowResult(True, "WORKFLOW_OK", "gm mtls-validate succeeded", 0, (stdout + f"\nGM mTLS validation ({tls_label}) logs generated under artifacts/logs/gm.").strip(), stderr, int((time.perf_counter() - start) * 1000), steps, [])
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
        baseline = self.mtls_validate(client_name=client_name, tls_version=tls_version)
        if not baseline.ok:
            return WorkflowResult(False, baseline.code, "gm tls-observe failed", baseline.returncode, baseline.stdout, baseline.stderr, int((time.perf_counter() - start) * 1000), ["gm:tls-observe:baseline-failed"], [])
        logs_dir = self.repo_root / "artifacts/logs/gm"
        artifacts: list[str] = []
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
        cipher_log = logs_dir / f"tls-observe-ciphers-{tls_tag}.log"
        cipher_log.write_text((ciphers.stdout + ("\n" if ciphers.stdout and ciphers.stderr else "") + ciphers.stderr).strip() + "\n", encoding="utf-8")
        artifacts.append(str(cipher_log.relative_to(self.repo_root)).replace("\\", "/"))
        if is_tls13 and not ciphers.ok:
            return WorkflowResult(
                False,
                "OPENSSL_FAILED",
                "gm tls-observe failed",
                ciphers.returncode,
                baseline.stdout,
                ((baseline.stderr or "") + ("\n" if baseline.stderr and ciphers.stderr else "") + (ciphers.stderr or "")).strip(),
                int((time.perf_counter() - start) * 1000),
                ["gm:tls-observe:ciphers-failed"],
                artifacts,
            )
        return WorkflowResult(
            True,
            "WORKFLOW_OK",
            "gm tls-observe succeeded",
            0,
            f"GM TLS observe ({'TLS1.3' if is_tls13 else 'TLS1.2'}) logs generated under artifacts/logs/gm.",
            "",
            int((time.perf_counter() - start) * 1000),
            [
                "gm:tls-observe:tcp-connect",
                "gm:tls-observe:server-cert-verify",
                "gm:tls-observe:client-cert-auth",
                "gm:tls-observe:key-exchange",
                "gm:tls-observe:cipher-ready",
            ],
            artifacts,
        )

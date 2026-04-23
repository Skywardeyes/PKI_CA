from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CommandResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    command: list[str]


class OpenSSLRunner:
    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root

    def run(
        self,
        command: list[str],
        *,
        timeout: int = 600,
        cwd: Path | None = None,
    ) -> CommandResult:
        start = time.perf_counter()
        try:
            p = subprocess.run(
                command,
                cwd=str(cwd or self.repo_root),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            duration_ms = int((time.perf_counter() - start) * 1000)
            return CommandResult(
                ok=p.returncode == 0,
                returncode=p.returncode,
                stdout=p.stdout or "",
                stderr=p.stderr or "",
                duration_ms=duration_ms,
                command=command,
            )
        except subprocess.TimeoutExpired:
            duration_ms = int((time.perf_counter() - start) * 1000)
            return CommandResult(
                ok=False,
                returncode=-1,
                stdout="",
                stderr="Command timed out",
                duration_ms=duration_ms,
                command=command,
            )

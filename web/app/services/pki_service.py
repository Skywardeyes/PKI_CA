from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ScriptResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str


class PKIService:
    def __init__(self, repo_root: Path, scripts_dir: Path) -> None:
        self.repo_root = repo_root
        self.scripts_dir = scripts_dir

    def run_ps1(
        self,
        script: str,
        args: list[str] | None = None,
        timeout: int = 600,
    ) -> ScriptResult:
        script_path = self.scripts_dir / script
        if not script_path.is_file():
            raise FileNotFoundError(f"Script not found: {script}")

        cmd = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path),
        ]
        if args:
            cmd.extend(args)

        try:
            p = subprocess.run(
                cmd,
                cwd=str(self.repo_root),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return ScriptResult(
                ok=False,
                returncode=-1,
                stdout="",
                stderr="Command timed out",
            )

        return ScriptResult(
            ok=p.returncode == 0,
            returncode=p.returncode,
            stdout=p.stdout or "",
            stderr=p.stderr or "",
        )


from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class AuditReadResult:
    ok: bool
    code: str
    message: str
    entries: list[dict]


class AuditService:
    def __init__(self, audit_path: Path) -> None:
        self.audit_path = audit_path

    def append(
        self,
        action: str,
        *,
        ok: bool,
        code: str,
        profile: str = "intl",
        client_name: str | None = None,
        reason: str | None = None,
    ) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "profile": profile,
            "ok": ok,
            "code": code,
            "client_name": client_name,
            "reason": (reason or "")[:500] or None,
        }
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def tail(self, n: int) -> AuditReadResult:
        if not self.audit_path.is_file():
            return AuditReadResult(ok=True, code="AUDIT_EMPTY", message="audit log not found", entries=[])
        try:
            raw = self.audit_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return AuditReadResult(ok=False, code="AUDIT_READ_FAILED", message="failed to read audit log", entries=[])
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        parsed: list[dict] = []
        for ln in lines[-n:]:
            try:
                parsed.append(json.loads(ln))
            except json.JSONDecodeError:
                parsed.append({"raw": ln})
        return AuditReadResult(ok=True, code="AUDIT_OK", message="audit entries fetched", entries=parsed)

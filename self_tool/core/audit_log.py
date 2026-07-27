"""Append-only local audit log for SELF.

The audit log records every material, fingerprint-scoped action:
* network updates applied (and rolled back)
* suppressions applied
* feedback entries added, removed, imported, or exported
* calibration runs

Records are written as JSONL under ``~/.self-auditor/audit.log.jsonl``
by default. The path is user-local and never published in reports.

The log is append-only. To \"modify\" an entry, append a new event that
references the prior event id. Consumers should treat the chain as
tamper-evident but not cryptographically signed — this is a local
forensic aid, not a regulatory audit log.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_PATH = Path.home() / ".self-auditor" / "audit.log.jsonl"


def log_dir(custom: Optional[Path] = None) -> Path:
    base = Path(custom) if custom else DEFAULT_PATH.parent
    base.mkdir(parents=True, exist_ok=True)
    return base


def log_path(custom: Optional[Path] = None) -> Path:
    return log_dir(custom) / DEFAULT_PATH.name


def _now() -> float:
    return time.time()


def record(event: str, *, details: Optional[Dict[str, Any]] = None,
           actor: str = "self", path: Optional[Path] = None) -> Dict[str, Any]:
    entry = {
        "id": uuid.uuid4().hex,
        "ts": _now(),
        "actor": actor,
        "event": event,
        "details": details or {},
    }
    target = log_path(path)
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def read(path: Optional[Path] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    target = log_path(path)
    if not target.exists():
        return []
    out: List[Dict[str, Any]] = []
    with target.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if limit is not None:
        out = out[-limit:]
    return out


def path_for(path: Optional[Path] = None) -> Path:
    """Return the audit log path for a custom override, creating the dir."""
    return log_path(path)


def env_override_path() -> Optional[Path]:
    raw = os.environ.get("SELF_AUDIT_LOG")
    return Path(raw) if raw else None

"""Versioned snapshot directory under ``~/.self-auditor/intelligence/``."""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from self_tool.core.fingerprints import sha256_hex


SNAPSHOT_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class Snapshot:
    snapshot_id: str
    path: Path

    def record_path(self, source: str) -> Path:
        return self.path / "records" / f"{source}.json"


def _base() -> Path:
    base = Path(os.environ.get("SELF_DATA_DIR") or Path.home() / ".self-auditor" / "intelligence")
    base.mkdir(parents=True, exist_ok=True)
    return base


def latest_link() -> Path:
    return _base() / "latest"


class Cache:
    """Disk-backed snapshot cache.

    Each snapshot lives at ``<base>/<snapshot_id>/`` and contains:
        * ``manifest.json`` — the verified manifest
        * ``records/<source>.json`` — per-source record lists
        * ``meta.json`` — installation metadata
    """

    def __init__(self, base: Optional[Path] = None):
        self.base = Path(base) if base else _base()

    def _latest_link(self) -> Path:
        return self.base / "latest"

    def create_snapshot(self, snapshot_id: str) -> Snapshot:
        path = self.base / snapshot_id
        if path.exists():
            raise FileExistsError(f"snapshot already exists: {path}")
        (path / "records").mkdir(parents=True)
        return Snapshot(snapshot_id=snapshot_id, path=path)

    def write_manifest(self, snapshot: Snapshot, manifest_obj: dict) -> None:
        manifest_path = snapshot.path / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest_obj, indent=2, sort_keys=True), encoding="utf-8"
        )

    def write_records(self, snapshot: Snapshot, source: str, payload: dict) -> Path:
        target = snapshot.record_path(source)
        target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return target

    def write_meta(self, snapshot: Snapshot, *, manifest_hash: str,
                   rule_version: str) -> None:
        meta = {
            "snapshot_id": snapshot.snapshot_id,
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "manifest_sha256": sha256_hex(manifest_hash),
            "rule_version": rule_version,
            "installed_at": _now_iso(),
        }
        (snapshot.path / "meta.json").write_text(
            json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8"
        )

    def activate(self, snapshot: Snapshot) -> None:
        link = self._latest_link()
        if link.is_symlink() or link.exists():
            try:
                link.unlink()
            except IsADirectoryError:
                shutil.rmtree(link)
        try:
            os.symlink(snapshot.path.name, link)
        except (OSError, NotImplementedError):
            link.write_text(snapshot.path.name, encoding="utf-8")

    def list_snapshots(self) -> List[Snapshot]:
        out = []
        for child in sorted(self.base.iterdir()):
            if child.is_dir() and (child / "manifest.json").exists():
                out.append(Snapshot(snapshot_id=child.name, path=child))
        return out

    def latest(self) -> Optional[Snapshot]:
        link = self.base / "latest"
        if link.is_symlink():
            target = link.resolve()
        elif link.exists():
            target = self.base / link.read_text().strip()
        else:
            return None
        if not (target / "manifest.json").exists():
            return None
        return Snapshot(snapshot_id=target.name, path=target)

    def get(self, snapshot_id: str) -> Optional[Snapshot]:
        path = self.base / snapshot_id
        if not (path / "manifest.json").exists():
            return None
        return Snapshot(snapshot_id=snapshot_id, path=path)

    def remove(self, snapshot_id: str) -> bool:
        path = self.base / snapshot_id
        if not path.exists():
            return False
        shutil.rmtree(path)
        return True


def _now_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

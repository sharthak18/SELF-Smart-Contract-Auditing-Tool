"""Atomic install and rollback for advisory snapshots."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Optional

from self_tool.core import audit_log
from self_tool.intelligence.cache import Cache, Snapshot
from self_tool.intelligence.manifest import Manifest, verify_manifest
from self_tool.intelligence.validator import validate_record_list


class InstallError(RuntimeError):
    pass


def install_snapshot(
    manifest_payload: dict,
    *,
    per_source_payloads: dict,
    cache: Optional[Cache] = None,
    rule_version: str = "",
    pinned_payload_hash: Optional[str] = None,
) -> Snapshot:
    """Validate manifest, write snapshot to disk, and atomically activate.

    ``per_source_payloads`` is a mapping of source_id → JSON dict for
    the corresponding manifest entry. Each must be a list of records
    or an object containing a ``records`` list.
    """
    cache = cache or Cache()
    manifest = verify_manifest(manifest_payload, pinned_payload_hash=pinned_payload_hash)
    sources = {entry.source for entry in manifest.entries}
    missing = sorted(sources - set(per_source_payloads))
    if missing:
        raise InstallError(f"missing per-source payloads: {missing}")
    extra = sorted(set(per_source_payloads) - sources)
    if extra:
        raise InstallError(f"unexpected per-source payloads: {extra}")

    snapshot = cache.create_snapshot(manifest.snapshot_id)
    cache.write_manifest(snapshot, manifest.to_dict())
    for source, payload in per_source_payloads.items():
        cleaned = validate_record_list(payload)
        cache.write_records(snapshot, source, cleaned)
    cache.write_meta(snapshot, manifest_hash=manifest.payload_sha256,
                     rule_version=rule_version)
    cache.activate(snapshot)
    audit_log.record("intelligence.install", details={
        "snapshot_id": snapshot.snapshot_id,
        "manifest_sha256": manifest.payload_sha256,
        "sources": sorted(sources),
    })
    return snapshot


def rollback(snapshot_id: str, *, cache: Optional[Cache] = None) -> Optional[Snapshot]:
    cache = cache or Cache()
    snapshot = cache.get(snapshot_id)
    if snapshot is None:
        return None
    cache.activate(snapshot)
    audit_log.record("intelligence.rollback", details={"snapshot_id": snapshot_id})
    return snapshot

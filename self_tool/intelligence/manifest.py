"""Manifest schema and integrity verification for advisory intelligence.

The manifest is a deterministic JSON document. Every entry advertises
its expected SHA-256; the manifest itself carries a top-level
``payload_sha256`` field pinning the canonical-JSON hash of its body.
SELF verifies both the manifest hash against the pinned value
(``tools_pinned_manifest_hash``) and the per-entry hashes against the
fetched file contents.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from self_tool.core.fingerprints import canonical_json, sha256_hex


@dataclass(frozen=True)
class ManifestEntry:
    source: str
    url: str
    sha256: str
    size_bytes: int
    kind: str = "advisory-list"
    revision: str = ""


@dataclass(frozen=True)
class Manifest:
    schema_version: int
    snapshot_id: str
    generated_at: str
    entries: List[ManifestEntry]
    payload_sha256: str = ""

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "snapshot_id": self.snapshot_id,
            "generated_at": self.generated_at,
            "payload_sha256": self.payload_sha256,
            "entries": [
                {
                    "source": e.source,
                    "url": e.url,
                    "sha256": e.sha256,
                    "size_bytes": e.size_bytes,
                    "kind": e.kind,
                    "revision": e.revision,
                }
                for e in self.entries
            ],
        }


class ManifestError(ValueError):
    """Raised when a manifest fails integrity verification."""


def verify_manifest(payload: dict, *, pinned_payload_hash: Optional[str] = None) -> Manifest:
    """Validate ``payload`` and return a :class:`Manifest`.

    If ``pinned_payload_hash`` is provided (as the tool ships), the
    manifest's ``payload_sha256`` must match it; otherwise a mismatch
    raises :class:`ManifestError`.
    """
    if payload.get("schema_version") != 1:
        raise ManifestError(
            f"unsupported manifest schema version {payload.get('schema_version')}"
        )
    entries: List[ManifestEntry] = []
    seen_sources: Dict[str, ManifestEntry] = {}
    for raw in payload.get("entries", []):
        try:
            entry = ManifestEntry(
                source=raw["source"],
                url=raw["url"],
                sha256=raw["sha256"],
                size_bytes=int(raw["size_bytes"]),
                kind=raw.get("kind", "advisory-list"),
                revision=raw.get("revision", ""),
            )
        except KeyError as exc:
            raise ManifestError(f"manifest entry missing field {exc.args[0]}") from exc
        if entry.source in seen_sources:
            raise ManifestError(f"duplicate manifest source {entry.source}")
        if not entry.url.startswith("https://"):
            raise ManifestError(f"manifest entry {entry.source} must use HTTPS")
        if entry.size_bytes <= 0 or entry.size_bytes > 2 * 1024 * 1024:
            raise ManifestError(
                f"manifest entry {entry.source} size out of bounds ({entry.size_bytes})"
            )
        if len(entry.sha256) != 64:
            raise ManifestError(f"manifest entry {entry.source} sha256 malformed")
        seen_sources[entry.source] = entry
        entries.append(entry)

    body = {k: v for k, v in payload.items() if k != "payload_sha256"}
    body_hash = sha256_hex(canonical_json(body))
    declared = payload.get("payload_sha256", "")
    if declared != body_hash:
        raise ManifestError(
            f"manifest payload hash mismatch: declared={declared[:12]}… computed={body_hash[:12]}…"
        )
    if pinned_payload_hash is not None and pinned_payload_hash != body_hash:
        raise ManifestError(
            "manifest payload hash does not match the tool-pinned value"
        )
    return Manifest(
        schema_version=int(payload["schema_version"]),
        snapshot_id=payload["snapshot_id"],
        generated_at=payload.get("generated_at", ""),
        entries=entries,
        payload_sha256=body_hash,
    )


def manifest_to_canonical(manifest: Manifest) -> str:
    return canonical_json(manifest.to_dict())

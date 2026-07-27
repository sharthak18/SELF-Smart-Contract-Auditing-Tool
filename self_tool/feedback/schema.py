"""Stable schema for the persistent feedback store."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from self_tool.core.fingerprints import canonical_json, sha256_hex
from self_tool.core.versions import FEEDBACK_SCHEMA_VERSION


DISPOSITIONS = ("confirmed", "false_positive", "accepted_risk", "fixed")


def schema_version() -> int:
    return FEEDBACK_SCHEMA_VERSION


@dataclass(frozen=True)
class FeedbackEntry:
    id: int
    project_fingerprint: str
    detector_id: str
    semantic_fingerprint: str
    source_hash: str
    rule_version: str
    disposition: str
    reason: str = ""
    author: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0
    active: bool = True
    target_file: str = ""
    target_line: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "schema_version": FEEDBACK_SCHEMA_VERSION,
            "project_fingerprint": self.project_fingerprint,
            "detector_id": self.detector_id,
            "semantic_fingerprint": self.semantic_fingerprint,
            "source_hash": self.source_hash,
            "rule_version": self.rule_version,
            "disposition": self.disposition,
            "reason": self.reason,
            "author": self.author,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "active": self.active,
            "target_file": self.target_file,
            "target_line": self.target_line,
        }

    def matches(self, *, project_fingerprint: str, detector_id: str,
                semantic_fingerprint: str, source_hash: str,
                rule_version: str) -> bool:
        return (
            self.active
            and self.project_fingerprint == project_fingerprint
            and self.detector_id == detector_id
            and self.semantic_fingerprint == semantic_fingerprint
            and self.source_hash == source_hash
            and self.rule_version == rule_version
        )


def content_hash(payload: dict) -> str:
    """Stable content hash excluding volatile fields like timestamps and id."""
    stable = {k: v for k, v in payload.items() if k not in {"id", "created_at", "updated_at"}}
    return sha256_hex(canonical_json(stable))

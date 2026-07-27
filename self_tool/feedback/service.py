"""Public service layer for the feedback store."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from self_tool.core.issue import Issue
from self_tool.feedback.store import FeedbackStore, default_path


def apply_suppressions(issues: List[Issue], *,
                       project_fingerprint: str,
                       store: Optional[FeedbackStore] = None) -> int:
    """Mark matching issues as suppressed based on stored dispositions.

    Only ``false_positive`` and ``accepted_risk`` dispositions suppress;
    ``confirmed`` and ``fixed`` only annotate the issue without flipping
    the ``suppressed`` flag.
    """
    if not issues:
        return 0
    s = store or FeedbackStore()
    entries = s.list(project_fingerprint=project_fingerprint)
    entries = [e for e in entries if e.active]
    if not entries:
        return 0
    suppressed = 0
    for issue in issues:
        if not (issue.semantic_fingerprint and issue.source_hash and issue.rule_version):
            continue
        if issue.project_fingerprint and issue.project_fingerprint != project_fingerprint:
            continue
        for entry in entries:
            if not entry.matches(
                project_fingerprint=project_fingerprint,
                detector_id=issue.id,
                semantic_fingerprint=issue.semantic_fingerprint,
                source_hash=issue.source_hash,
                rule_version=issue.rule_version,
            ):
                continue
            if entry.disposition in {"false_positive", "accepted_risk"}:
                issue.suppressed = True
                issue.suppression_state = entry.disposition
                issue.suppression_reason = entry.reason or entry.disposition
                suppressed += 1
            elif entry.disposition in {"confirmed", "fixed"}:
                issue.context_note = (
                    issue.context_note + "\n" if issue.context_note else ""
                ) + f"feedback[{entry.disposition}] {entry.reason}".strip()
            break
    return suppressed


def export_to(path: Path, *, project_fingerprint: Optional[str] = None,
              store: Optional[FeedbackStore] = None) -> Path:
    s = store or FeedbackStore()
    payload = s.export_entries(project_fingerprint=project_fingerprint)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def import_from(path: Path, *, replace: bool = False,
                store: Optional[FeedbackStore] = None) -> int:
    s = store or FeedbackStore()
    payload = json.loads(path.read_text(encoding="utf-8"))
    return s.import_entries(payload, replace=replace)

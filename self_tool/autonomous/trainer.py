"""Train (or refresh) the local knowledge index from real data.

This is not neural-network training. It builds a deterministic retrieval
index and playbook weights from:

* the bundled exploit corpus (historic incidents that also mint detectors)
* the bundled brain (attack vectors, math, business logic, on-chain)
* recent public incidents and expert tactics (retrieval only — no catalog IDs)
* optional extra JSON the user points at (audit notes, extra exploits)
* the local feedback store (confirmed raises a weight; false_positive lowers it)

The artifact lives under ``$SELF_DATA_DIR/brain/index.json``
(default ``~/.self-auditor/brain/index.json``).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from self_tool.autonomous.brain import (
    bundled_documents,
    incident_doc,
    load_attack_vectors,
    load_incidents,
    tactic_doc,
    tokenize,
)
from self_tool.autonomous.models import TrainedIndex
from self_tool.core import audit_log


# Bumped when bundled corpora change shape so ensure_trained rebuilds.
INDEX_SCHEMA = 2
INCIDENT_WEIGHT_CAP = 1.15
INCIDENT_WEIGHT_STEP = 1.1


def data_dir() -> Path:
    return Path(os.environ.get("SELF_DATA_DIR") or (Path.home() / ".self-auditor"))


def index_path(root: Optional[Path] = None) -> Path:
    base = Path(root) if root else data_dir()
    return base / "brain" / "index.json"


def load_index(root: Optional[Path] = None) -> Optional[TrainedIndex]:
    path = index_path(root)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        index = TrainedIndex.from_dict(data)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    if index.schema_version != INDEX_SCHEMA:
        return None
    return index


def train(
    extra_paths: Optional[Sequence[Path]] = None,
    *,
    root: Optional[Path] = None,
    include_feedback: bool = True,
) -> TrainedIndex:
    documents: List[Dict[str, object]] = []
    sources: List[str] = []
    weights = {playbook.id: 1.0 for playbook in load_attack_vectors()}

    documents.extend(bundled_documents())
    _apply_incident_weights(weights)
    sources.append("bundled-brain")
    sources.append("bundled-exploit-corpus")
    sources.append("bundled-incidents")
    sources.append("bundled-expert-tactics")

    for extra in extra_paths or []:
        path = Path(extra)
        docs, extra_weights = _ingest_extra(path)
        documents.extend(docs)
        for key, value in extra_weights.items():
            weights[key] = weights.get(key, 1.0) * value
        sources.append(str(path))

    if include_feedback:
        _apply_feedback_weights(weights)

    df: Dict[str, int] = {}
    for doc in documents:
        seen = set(tokenize(str(doc.get("text") or "")))
        for token in seen:
            df[token] = df.get(token, 0) + 1

    index = TrainedIndex(
        schema_version=INDEX_SCHEMA,
        built_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        document_count=len(documents),
        term_document_frequency=df,
        documents=documents,
        playbook_weights=weights,
        sources=sources,
    )
    path = index_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(index.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    audit_log.record("autonomous.train", details={
        "documents": index.document_count,
        "sources": sources,
        "path": str(path),
    })
    return index


def ensure_trained(root: Optional[Path] = None) -> TrainedIndex:
    existing = load_index(root)
    if existing is not None:
        return existing
    return train(root=root)


def _apply_incident_weights(weights: Dict[str, float], incidents: Optional[Iterable[dict]] = None) -> None:
    """Nudge playbooks that real post-mortems named, without auto-High."""
    known = set(weights) or {item.id for item in load_attack_vectors()}
    boosted = set()
    for incident in incidents if incidents is not None else load_incidents():
        for playbook_id in incident.get("playbooks") or []:
            if playbook_id not in known or playbook_id in boosted:
                continue
            weights[playbook_id] = min(
                weights.get(playbook_id, 1.0) * INCIDENT_WEIGHT_STEP,
                INCIDENT_WEIGHT_CAP,
            )
            boosted.add(playbook_id)


def _ingest_extra(path: Path) -> tuple:
    if not path.is_file():
        raise FileNotFoundError(str(path))
    data = json.loads(path.read_text(encoding="utf-8"))
    docs: List[Dict[str, object]] = []
    weights: Dict[str, float] = {}
    if isinstance(data, dict) and "exploits" in data:
        for raw in data.get("exploits") or []:
            docs.append({
                "id": raw.get("id") or path.name,
                "kind": "exploit",
                "title": raw.get("title") or raw.get("name") or "",
                "text": " ".join(str(raw.get(key) or "") for key in (
                    "name", "title", "description", "root_cause_class", "target",
                )),
            })
            detector = raw.get("root_cause_class") or ""
            if detector:
                for playbook in load_attack_vectors():
                    if detector.replace("_", "-") in playbook.id.lower() or detector in playbook.search_text().lower():
                        weights[playbook.id] = 1.15
    elif isinstance(data, dict) and "vectors" in data:
        for raw in data.get("vectors") or []:
            docs.append({
                "id": raw.get("id") or "",
                "kind": "attack_vector",
                "title": raw.get("title") or "",
                "text": " ".join(str(raw.get(key) or "") for key in (
                    "id", "title", "description", "exploit", "remediation",
                )),
            })
    elif isinstance(data, dict) and "incidents" in data:
        for raw in data.get("incidents") or []:
            docs.append(incident_doc(raw))
        _apply_incident_weights(weights, data.get("incidents") or [])
    elif isinstance(data, dict) and "tactics" in data:
        for raw in data.get("tactics") or []:
            docs.append(tactic_doc(raw))
    elif isinstance(data, dict) and "documents" in data:
        for raw in data.get("documents") or []:
            docs.append({
                "id": raw.get("id") or "",
                "kind": raw.get("kind") or "document",
                "title": raw.get("title") or "",
                "text": raw.get("text") or "",
            })
    else:
        docs.append({
            "id": path.name,
            "kind": "document",
            "title": path.name,
            "text": json.dumps(data, sort_keys=True)[:8000],
        })
    return docs, weights


def _apply_feedback_weights(weights: Dict[str, float]) -> None:
    try:
        from self_tool.feedback.store import FeedbackStore
        store = FeedbackStore()
        entries = store.list(include_inactive=False)
    except Exception:
        return
    for entry in entries:
        # Map detector ids back to playbooks that list them.
        for playbook in load_attack_vectors():
            if entry.detector_id in playbook.related_detectors or entry.detector_id == playbook.id:
                if entry.disposition == "confirmed":
                    weights[playbook.id] = weights.get(playbook.id, 1.0) * 1.2
                elif entry.disposition == "false_positive":
                    weights[playbook.id] = weights.get(playbook.id, 1.0) * 0.7
                elif entry.disposition == "accepted_risk":
                    weights[playbook.id] = weights.get(playbook.id, 1.0) * 0.85

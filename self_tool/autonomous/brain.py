"""Load, validate, and retrieve from the trained security brain.

The brain is bundled JSON (attack vectors, language semantics, math
models, business-logic playbooks, on-chain behaviours, dependency
advisories, recent incidents, expert review tactics) plus the existing
exploit corpus. A trained index produced by ``self train`` re-weights
playbooks and adds extra documents. New real-world lessons go in
``incidents.json`` / ``expert_tactics.json`` so they train retrieval
without minting catalog detectors.
"""

from __future__ import annotations

import json
import math
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from self_tool.autonomous.models import Playbook, RetrievedDoc, TrainedIndex


BRAIN_DIR = Path(__file__).resolve().parent.parent / "knowledge" / "brain"
TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")

_REQUIRED_PLAYBOOK_FIELDS = (
    "id", "title", "severity", "description", "exploit", "remediation",
    "proof_obligation",
)


def tokenize(text: str) -> List[str]:
    return TOKEN_RE.findall((text or "").lower())


def _load_json(name: str) -> dict:
    path = BRAIN_DIR / name
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


@lru_cache(maxsize=1)
def load_attack_vectors() -> List[Playbook]:
    data = _load_json("attack_vectors.json")
    if data.get("kind") != "attack_vectors":
        raise ValueError("attack_vectors.json has unexpected kind")
    playbooks: List[Playbook] = []
    seen = set()
    for raw in data.get("vectors", []):
        missing = [field for field in _REQUIRED_PLAYBOOK_FIELDS if not raw.get(field)]
        if missing:
            raise ValueError(f"playbook {raw.get('id')} missing {missing}")
        if raw["id"] in seen:
            raise ValueError(f"duplicate playbook id {raw['id']}")
        seen.add(raw["id"])
        severity = raw["severity"]
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            raise ValueError(f"{raw['id']} has invalid severity {severity}")
        playbooks.append(Playbook(
            id=raw["id"],
            title=raw["title"],
            severity=severity,
            languages=list(raw.get("languages") or []),
            protocol_types=list(raw.get("protocol_types") or []),
            owasp=raw.get("owasp") or "",
            cwe=list(raw.get("cwe") or []),
            swc=list(raw.get("swc") or []),
            required_any_patterns=list(raw.get("required_any_patterns") or []),
            required_all_patterns=list(raw.get("required_all_patterns") or []),
            forbidden_patterns=list(raw.get("forbidden_patterns") or []),
            fact_predicates=list(raw.get("fact_predicates") or []),
            related_detectors=list(raw.get("related_detectors") or []),
            description=raw["description"],
            exploit=raw["exploit"],
            remediation=raw["remediation"],
            proof_obligation=raw["proof_obligation"],
            real_incidents=list(raw.get("real_incidents") or []),
        ))
    return playbooks


@lru_cache(maxsize=1)
def load_language_semantics() -> Dict[str, dict]:
    data = _load_json("language_semantics.json")
    return {item["id"]: item for item in data.get("languages", [])}


@lru_cache(maxsize=1)
def load_math_models() -> List[dict]:
    data = _load_json("math_models.json")
    return list(data.get("models") or [])


@lru_cache(maxsize=1)
def load_business_logic() -> Dict[str, dict]:
    data = _load_json("business_logic.json")
    return {item["id"]: item for item in data.get("protocols", [])}


@lru_cache(maxsize=1)
def load_onchain_behaviors() -> List[dict]:
    data = _load_json("onchain_behaviors.json")
    return list(data.get("behaviors") or [])


@lru_cache(maxsize=1)
def load_dependency_advisories() -> List[dict]:
    data = _load_json("dependency_advisories.json")
    return list(data.get("advisories") or [])


@lru_cache(maxsize=1)
def load_incidents() -> List[dict]:
    data = _load_json("incidents.json")
    if data.get("kind") != "incidents":
        raise ValueError("incidents.json has unexpected kind")
    incidents: List[dict] = []
    seen = set()
    for raw in data.get("incidents") or []:
        ident = raw.get("id")
        if not ident:
            raise ValueError("incident missing id")
        if ident in seen:
            raise ValueError(f"duplicate incident id {ident}")
        if not raw.get("name") or not raw.get("lesson"):
            raise ValueError(f"incident {ident} missing name or lesson")
        seen.add(ident)
        incidents.append(raw)
    return incidents


@lru_cache(maxsize=1)
def load_expert_tactics() -> List[dict]:
    data = _load_json("expert_tactics.json")
    if data.get("kind") != "expert_tactics":
        raise ValueError("expert_tactics.json has unexpected kind")
    tactics: List[dict] = []
    seen = set()
    for raw in data.get("tactics") or []:
        ident = raw.get("id")
        if not ident:
            raise ValueError("tactic missing id")
        if ident in seen:
            raise ValueError(f"duplicate tactic id {ident}")
        if not raw.get("title") or not raw.get("why"):
            raise ValueError(f"tactic {ident} missing title or why")
        seen.add(ident)
        tactics.append(raw)
    return tactics


def incident_doc(raw: dict) -> Dict[str, Any]:
    return {
        "id": raw.get("id") or "",
        "kind": "incident",
        "title": raw.get("name") or raw.get("id") or "",
        "text": " ".join([
            str(raw.get("id") or ""),
            str(raw.get("name") or ""),
            str(raw.get("root_cause_class") or ""),
            str(raw.get("summary") or ""),
            str(raw.get("lesson") or ""),
            str(raw.get("date") or ""),
            str(raw.get("chain") or ""),
            " ".join(raw.get("playbooks") or []),
            " ".join(raw.get("facts") or []),
            " ".join(raw.get("protocol_types") or []),
            " ".join(raw.get("references") or []),
        ]),
    }


def tactic_doc(raw: dict) -> Dict[str, Any]:
    return {
        "id": raw.get("id") or "",
        "kind": "expert_tactic",
        "title": raw.get("title") or raw.get("id") or "",
        "text": " ".join([
            str(raw.get("id") or ""),
            str(raw.get("source") or ""),
            str(raw.get("title") or ""),
            str(raw.get("lens") or ""),
            str(raw.get("why") or ""),
            " ".join(raw.get("questions") or []),
            " ".join(raw.get("applies_to") or []),
            " ".join(raw.get("references") or []),
        ]),
    }


def incidents_for_playbook(playbook_id: str) -> List[str]:
    names: List[str] = []
    for incident in load_incidents():
        if playbook_id in (incident.get("playbooks") or []):
            names.append(str(incident.get("name") or incident["id"]))
    return names


def bundled_documents() -> List[Dict[str, Any]]:
    """Every bundled brain document. Shared by retrieve() and trainer."""
    docs: List[Dict[str, Any]] = []
    for playbook in load_attack_vectors():
        docs.append({
            "id": playbook.id,
            "kind": "attack_vector",
            "title": playbook.title,
            "text": playbook.search_text(),
        })
    for model in load_math_models():
        docs.append({
            "id": model["id"],
            "kind": "math_model",
            "title": model["name"],
            "text": " ".join([
                model["name"],
                " ".join(model.get("signals") or []),
                " ".join(model.get("invariants") or []),
                " ".join(model.get("hazards") or []),
                model.get("safe_pattern") or "",
            ]),
        })
    for proto in load_business_logic().values():
        docs.append({
            "id": f"BIZ-{proto['id']}",
            "kind": "business_logic",
            "title": proto["name"],
            "text": " ".join([
                proto["name"], proto["id"],
                " ".join(proto.get("must_hold") or []),
                " ".join(proto.get("common_breaks") or []),
                " ".join(proto.get("entry_verbs") or []),
            ]),
        })
    for behaviour in load_onchain_behaviors():
        docs.append({
            "id": behaviour["id"],
            "kind": "onchain",
            "title": behaviour["title"],
            "text": " ".join([
                behaviour["title"], behaviour.get("description", ""),
                " ".join(behaviour.get("signals") or []),
                " ".join(behaviour.get("facts") or []),
                behaviour.get("defense", ""),
            ]),
        })
    for incident in load_incidents():
        docs.append(incident_doc(incident))
    for tactic in load_expert_tactics():
        docs.append(tactic_doc(tactic))
    try:
        from self_tool.knowledge.exploit_corpus import load_exploit_corpus
        for exp in load_exploit_corpus().values():
            docs.append({
                "id": exp.id,
                "kind": "exploit",
                "title": exp.title,
                "text": " ".join([
                    exp.name, exp.title, exp.description, exp.root_cause_class,
                    exp.target, exp.chain,
                    " ".join(exp.invariant_violations),
                    " ".join(exp.exploit_pattern),
                ]),
            })
    except Exception:
        pass
    return docs


def playbook_by_id() -> Dict[str, Playbook]:
    return {item.id: item for item in load_attack_vectors()}


def apply_weights(playbooks: Sequence[Playbook], index: Optional[TrainedIndex]) -> List[Playbook]:
    if index is None:
        return list(playbooks)
    weighted: List[Playbook] = []
    for playbook in playbooks:
        clone = Playbook(**{**playbook.__dict__})
        clone.weight = float(index.playbook_weights.get(playbook.id, playbook.weight))
        weighted.append(clone)
    return weighted


def _idf(df: int, n_docs: int) -> float:
    return math.log((n_docs + 1) / (df + 1)) + 1.0


def score_query(query: str, document: str, df: Dict[str, int], n_docs: int) -> float:
    q_tokens = tokenize(query)
    d_tokens = tokenize(document)
    if not q_tokens or not d_tokens:
        return 0.0
    q_tf: Dict[str, int] = {}
    d_tf: Dict[str, int] = {}
    for token in q_tokens:
        q_tf[token] = q_tf.get(token, 0) + 1
    for token in d_tokens:
        d_tf[token] = d_tf.get(token, 0) + 1
    score = 0.0
    d_len = float(len(d_tokens))
    for token, q_count in q_tf.items():
        if token not in d_tf:
            continue
        score += (q_count) * (d_tf[token] / d_len) * _idf(df.get(token, 0), n_docs)
    return score


def retrieve(
    query: str,
    index: Optional[TrainedIndex],
    limit: int = 8,
) -> List[RetrievedDoc]:
    """Rank trained (or bundled) documents against a project briefing."""
    documents: List[Dict[str, Any]]
    df: Dict[str, int]
    if index is not None and index.documents:
        documents = index.documents
        df = index.term_document_frequency
    else:
        documents, df = _bundled_documents()
    n_docs = max(len(documents), 1)
    ranked: List[Tuple[float, Dict[str, Any]]] = []
    for doc in documents:
        ranked.append((score_query(query, doc.get("text", ""), df, n_docs), doc))
    ranked.sort(key=lambda item: (-item[0], item[1].get("id", "")))
    out: List[RetrievedDoc] = []
    for score, doc in ranked[:limit]:
        if score <= 0:
            continue
        text = doc.get("text") or ""
        out.append(RetrievedDoc(
            doc_id=doc.get("id", ""),
            kind=doc.get("kind", ""),
            title=doc.get("title", ""),
            score=round(score, 6),
            snippet=text[:280],
        ))
    return out


@lru_cache(maxsize=1)
def _bundled_documents() -> Tuple[Tuple[Dict[str, Any], ...], Dict[str, int]]:
    docs = bundled_documents()
    df: Dict[str, int] = {}
    for doc in docs:
        seen = set(tokenize(doc["text"]))
        for token in seen:
            df[token] = df.get(token, 0) + 1
    return tuple(docs), df


def brain_stats() -> Dict[str, int]:
    exploits = 0
    try:
        from self_tool.knowledge.exploit_corpus import load_exploit_corpus
        exploits = len(load_exploit_corpus())
    except Exception:
        exploits = 0
    return {
        "attack_vectors": len(load_attack_vectors()),
        "languages": len(load_language_semantics()),
        "math_models": len(load_math_models()),
        "business_logic": len(load_business_logic()),
        "onchain_behaviors": len(load_onchain_behaviors()),
        "dependency_advisories": len(load_dependency_advisories()),
        "incidents": len(load_incidents()),
        "expert_tactics": len(load_expert_tactics()),
        "exploits": exploits,
    }

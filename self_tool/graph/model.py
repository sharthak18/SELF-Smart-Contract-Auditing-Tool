"""Graph model dataclasses.

All node ids are computed deterministically from ``(file, kind, name)``
so they are stable across re-runs. The graph is *serialization-stable*
via :mod:`self_tool.graph.serialization`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple


NODE_KINDS = (
    "file", "contract", "interface", "library", "abstract",
    "function", "modifier", "state_var", "event", "import",
)
EDGE_KINDS = (
    "imports", "inherits", "implements", "calls_internal",
    "calls_external", "delegatecall", "reads", "writes",
    "guards", "uses_library", "declared_in",
)


NodeKind = str
EdgeKind = str


@dataclass(frozen=True)
class EvidenceLink:
    file: str
    start_line: int
    end_line: int
    text_hash: str = ""
    snippet: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "text_hash": self.text_hash,
            "snippet": self.snippet,
        }


@dataclass(frozen=True)
class Node:
    id: str
    kind: NodeKind
    name: str
    file: str
    span: Tuple[int, int]
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "file": self.file,
            "span": list(self.span),
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class Edge:
    kind: EdgeKind
    src: str
    dst: str
    confidence: float = 1.0
    evidence: Tuple[EvidenceLink, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "src": self.src,
            "dst": self.dst,
            "confidence": self.confidence,
            "evidence": [link.to_dict() for link in self.evidence],
        }


@dataclass(frozen=True)
class UnresolvedEdge:
    """An edge the builder could not close.

    Kept separate so detectors can emit explicit uncertainty findings
    (e.g. ``PROJECT-UNRESOLVED-001``) without guessing.
    """

    kind: EdgeKind
    src: str
    hint: str
    file: str
    line: int
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "src": self.src,
            "hint": self.hint,
            "file": self.file,
            "line": self.line,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class Graph:
    project_fingerprint: str
    nodes: Tuple[Node, ...]
    edges: Tuple[Edge, ...]
    unresolved: Tuple[UnresolvedEdge, ...] = ()
    function_bodies: Tuple[Tuple[str, str], ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "project_fingerprint": self.project_fingerprint,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "unresolved": [u.to_dict() for u in self.unresolved],
        }

    def by_kind(self, kind: NodeKind) -> List[Node]:
        return [n for n in self.nodes if n.kind == kind]

    def edges_from(self, src: str) -> List[Edge]:
        return [e for e in self.edges if e.src == src]

    def edges_to(self, dst: str) -> List[Edge]:
        return [e for e in self.edges if e.dst == dst]

    def body_for(self, node_id: str) -> str:
        for fid, body in self.function_bodies:
            if fid == node_id:
                return body
        return ""
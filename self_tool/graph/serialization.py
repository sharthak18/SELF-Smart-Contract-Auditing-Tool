"""Deterministic JSON serialization for project graphs."""

from __future__ import annotations

from typing import List

from self_tool.core.fingerprints import canonical_json
from self_tool.graph.model import Graph


def serialize_graph(graph: Graph) -> str:
    """Serialize a graph deterministically using canonical JSON."""
    payload = graph.to_dict()
    nodes_sorted = sorted(payload["nodes"], key=lambda n: n["id"])
    edges_sorted = sorted(payload["edges"], key=lambda e: (e["src"], e["kind"], e["dst"]))
    unresolved_sorted = sorted(
        payload["unresolved"],
        key=lambda u: (u["src"], u["kind"], u["hint"], u["file"], u["line"]),
    )
    payload["nodes"] = nodes_sorted
    payload["edges"] = edges_sorted
    payload["unresolved"] = unresolved_sorted
    return canonical_json(payload)


def fingerprint_of(graph: Graph) -> str:
    """A short fingerprint for log/CLI reporting."""
    return graph.project_fingerprint

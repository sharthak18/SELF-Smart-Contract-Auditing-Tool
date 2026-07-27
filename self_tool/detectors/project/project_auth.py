"""PROJECT-AUTH-001: authorization-to-state-write coverage."""

from __future__ import annotations

from typing import List

from self_tool.core.issue import Confidence, Severity
from self_tool.core.project import ProjectContext
from self_tool.detectors.project.project_base import (
    edges_of_kind,
    make_issue,
)


def detect_project(ctx: ProjectContext):
    issues = []
    graph = ctx.graph
    for edge in edges_of_kind(graph, "writes"):
        func_id = edge.src
        func = next((n for n in graph.nodes if n.id == func_id), None)
        if func is None:
            continue
        if func.attributes.get("is_constructor") or func.attributes.get("is_fallback"):
            continue
        if func.attributes.get("visibility") not in {"public", "external"}:
            continue
        modifiers = func.attributes.get("modifiers") or []
        if "nonreentrant" in modifiers:
            continue
        if any(mod.startswith("only") or mod.endswith("only") for mod in modifiers):
            continue
        issues.append(make_issue(
            detector_id="PROJECT-AUTH-001",
            title=f"State write from {func.attributes.get('contract', '')}.{func.attributes.get('name', '')} has no obvious access modifier",
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            file=func.file,
            line=func.span[0],
            snippet=f"function {func.attributes.get('name', '')}",
            description=(
                "The graph connected a state write to a public function without a "
                "recognized access modifier. Internal guards may exist; this finding "
                "is informational pending review."
            ),
            exploit_scenario="Unauthorized caller may be able to write state directly.",
            remediation=(
                "Apply a recognized access modifier (onlyOwner, onlyRole, etc.) or "
                "document an internal guard with explicit test coverage."
            ),
            evidence_paths=[func] + list(edge.evidence),
            confidence_reasons=[
                "Writes edge present",
                "No only-prefixed modifier detected by static extraction",
            ],
        ))
    return issues
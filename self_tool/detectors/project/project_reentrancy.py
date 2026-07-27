"""PROJECT-REENTRANCY-001: cross-contract reentrancy paths."""

from __future__ import annotations

from typing import List

from self_tool.core.issue import Confidence, Severity
from self_tool.core.project import ProjectContext
from self_tool.detectors.project.project_base import (
    edges_of_kind,
    make_issue,
    nodes_of_kind,
)


def detect_project(ctx: ProjectContext):
    issues = []
    graph = ctx.graph
    mutating_funcs = {
        n.id for n in nodes_of_kind(graph, "function")
        if n.attributes.get("visibility") in {"public", "external"}
        and not n.attributes.get("is_constructor")
        and not n.attributes.get("is_fallback")
        and not n.attributes.get("is_receive")
    }
    guarded = {n.id for n in nodes_of_kind(graph, "function")
               if "nonreentrant" in (n.attributes.get("modifiers") or [])}
    for edge in edges_of_kind(graph, "calls_external"):
        if edge.src in mutating_funcs and edge.src not in guarded:
            func = next((n for n in graph.nodes if n.id == edge.src), None)
            if func is None:
                continue
            issues.append(make_issue(
                detector_id="PROJECT-REENTRANCY-001",
                title=f"Cross-contract call from {func.attributes.get('contract', '')}.{func.attributes.get('name', '')} lacks reentrancy guard",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                file=func.file,
                line=func.span[0],
                snippet=f"function {func.attributes.get('name', '')}",
                description=(
                    "The project graph identified a state-mutating function making "
                    "a cross-contract external call without a nonReentrant guard."
                ),
                exploit_scenario=(
                    "A callback contract re-enters the function through a sibling "
                    "cross-contract path before the originating call settles state."
                ),
                remediation=(
                    "Apply nonReentrant to the originating function and follow "
                    "checks-effects-interactions."
                ),
                evidence_paths=[func] + list(edge.evidence),
                confidence_reasons=[
                    "Cross-contract call edge from a state-mutating function",
                    "nonReentrant guard not present on the originating function",
                ],
            ))
    return issues
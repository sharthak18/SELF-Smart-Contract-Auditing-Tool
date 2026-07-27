"""PROJECT-ACCESS-001: cross-contract access-control mismatches.

This detector runs over the project graph and looks for state-mutating
functions in a child contract that *override* a base contract function
whose guard is stronger. It is conservative: it emits an INFO with a
specific evidence path so reviewers can decide.
"""

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
    for inherits in edges_of_kind(graph, "inherits"):
        child = _lookup(graph, inherits.src)
        parent = _lookup(graph, inherits.dst)
        if not child or not parent:
            continue
        child_funcs = {n.attributes.get("name"): n for n in nodes_of_kind(graph, "function")
                       if n.attributes.get("contract") == child.attributes.get("name")}
        parent_funcs = {n.attributes.get("name"): n for n in nodes_of_kind(graph, "function")
                        if n.attributes.get("contract") == parent.attributes.get("name")}
        for name, parent_fn in parent_funcs.items():
            if name not in child_funcs:
                continue
            child_fn = child_funcs[name]
            parent_mods = set(parent_fn.attributes.get("modifiers") or [])
            child_mods = set(child_fn.attributes.get("modifiers") or [])
            if parent_mods and not parent_mods.issubset(child_mods):
                issues.append(make_issue(
                    detector_id="PROJECT-ACCESS-001",
                    title=f"{child.attributes['name']}.{name} may relax {parent.attributes['name']}.{name} access",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    file=child.file,
                    line=child_fn.span[0],
                    snippet=f"contract {child.attributes['name']} overrides {parent.attributes['name']}.{name}",
                    description=(
                        f"The child contract {child.attributes['name']} overrides "
                        f"{parent.attributes['name']}.{name} but does not preserve the "
                        f"access modifiers {sorted(parent_mods)} from the parent."
                    ),
                    exploit_scenario=(
                        "A caller authorized only against the parent's stricter check "
                        "may be blocked, while direct callers of the child can bypass "
                        "the parent contract's expected access control."
                    ),
                    remediation=(
                        "Re-declare the same modifiers in the override or repeat the "
                        "guard inside the child implementation."
                    ),
                    evidence_paths=[parent_fn, child_fn],
                    confidence_reasons=[
                        "Inheritance edge resolved by the project graph",
                        "Modifier set differs between parent and child",
                    ],
                ))
    return issues


def _lookup(graph, node_id):
    for n in graph.nodes:
        if n.id == node_id:
            return n
    return None
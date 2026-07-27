"""PROJECT-PROXY-001: proxy / delegatecall hazards across the project."""

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
    delegates = edges_of_kind(graph, "delegatecall")
    contracts = {n.attributes.get("name"): n for n in nodes_of_kind(graph, "contract")
                 if n.attributes.get("is_upgradeable")}
    if not delegates:
        return issues
    for edge in delegates:
        target = next((n for n in graph.nodes if n.id == edge.dst), None)
        if target is None or not target.attributes.get("is_upgradeable"):
            issues.append(make_issue(
                detector_id="PROJECT-PROXY-001",
                title="Delegatecall target is not a typed upgradeable implementation",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                file=edge.evidence[0].file if edge.evidence else "",
                line=edge.evidence[0].start_line if edge.evidence else 0,
                snippet="delegatecall target unresolved or not declared upgradeable",
                description=(
                    "The project graph resolved a delegatecall but could not bind "
                    "the target to a declared upgradeable implementation."
                ),
                exploit_scenario=(
                    "An attacker-controlled or stale implementation can hijack the "
                    "caller's storage and privileged state."
                ),
                remediation=(
                    "Constrain the delegatecall target to a typed immutable address, "
                    "and verify the implementation's storage layout and initializer."
                ),
                evidence_paths=list(edge.evidence),
                confidence_reasons=[
                    "Static delegatecall edge found without typed implementation binding",
                ],
            ))
    for contract_name, contract_node in contracts.items():
        inits = [n for n in nodes_of_kind(graph, "function")
                 if n.attributes.get("contract") == contract_name
                 and (n.attributes.get("is_constructor")
                      or "initializer" in (n.attributes.get("modifiers") or []))]
        if not inits:
            issues.append(make_issue(
                detector_id="PROJECT-PROXY-001",
                title=f"{contract_name} is upgradeable without an explicit initializer",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                file=contract_node.file,
                line=contract_node.span[0],
                snippet=f"contract {contract_name} {{",
                description=(
                    f"{contract_name} is detected as upgradeable but the graph did "
                    "not find an initializer or constructor declaring it."
                ),
                exploit_scenario="Front-run initialization can claim proxy admin.",
                remediation="Add an explicit initializer() with access control.",
                evidence_paths=[contract_node],
                confidence_reasons=["upgradeable marker present"],
            ))
    return issues
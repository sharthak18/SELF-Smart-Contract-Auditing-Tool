"""PROJECT-ORACLE-001: oracle / external dependency trust boundaries."""

from __future__ import annotations

import re
from typing import List

from self_tool.core.issue import Confidence, Severity
from self_tool.core.project import ProjectContext
from self_tool.detectors.project.project_base import (
    edges_of_kind,
    make_issue,
    nodes_of_kind,
)


_ORACLE_RE = re.compile(
    r"(?:latestRoundData|getPrice|priceOracle|aggregator\.|chainlink|uniswap.*twap)",
    re.IGNORECASE,
)


def detect_project(ctx: ProjectContext):
    issues = []
    graph = ctx.graph
    for func in nodes_of_kind(graph, "function"):
        body = graph.body_for(func.id)
        if not body:
            continue
        if not _ORACLE_RE.search(body):
            continue
        calls_external = [e for e in edges_of_kind(graph, "calls_external") if e.src == func.id]
        if not calls_external:
            issues.append(make_issue(
                detector_id="PROJECT-ORACLE-001",
                title=f"Oracle usage in {func.attributes.get('contract', '')}.{func.attributes.get('name', '')} is unresolved",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                file=func.file,
                line=func.span[0],
                snippet=func.attributes.get("name", ""),
                description=(
                    "The project graph detected oracle-style identifiers in the "
                    "function body but no external call edges leading to a typed "
                    "oracle dependency."
                ),
                exploit_scenario="Static extractor could not bind the oracle dependency.",
                remediation=(
                    "Add an explicit external call graph edge or constrain the "
                    "dependency to a typed interface."
                ),
                evidence_paths=[func],
                confidence_reasons=[
                    "Oracle identifier pattern matched",
                    "No external call edges resolved for this function",
                ],
            ))
    return issues
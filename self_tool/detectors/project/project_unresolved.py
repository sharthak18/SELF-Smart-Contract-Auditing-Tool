"""PROJECT-UNRESOLVED-001: surface unresolved graph edges."""

from __future__ import annotations

from typing import List

from self_tool.core.issue import Confidence, Severity
from self_tool.core.project import ProjectContext
from self_tool.detectors.project.project_base import (
    _evidence,
    make_issue,
)


def detect_project(ctx: ProjectContext):
    issues = []
    if not ctx.graph.unresolved:
        return issues
    sample = list(ctx.graph.unresolved)[:10]
    for entry in sample:
        issues.append(make_issue(
            detector_id="PROJECT-UNRESOLVED-001",
            title=f"Unresolved {entry.kind} edge: {entry.hint}",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            file=entry.file or "<graph>",
            line=entry.line or 0,
            snippet=entry.hint,
            description=(
                f"The project graph could not resolve a {entry.kind} edge "
                f"pointing at `{entry.hint}` because {entry.reason}."
            ),
            exploit_scenario=(
                "Unresolved edges reduce confidence in static findings; "
                "reviewers must complete resolution manually before trusting "
                "this audit's coverage claims."
            ),
            remediation=(
                "Resolve the edge manually or import the missing contract "
                "into the audited scope, then re-run the audit."
            ),
            evidence_paths=[
                _evidence(entry.file or "<graph>", entry.line or 0,
                          entry.line or 0, entry.hint)
            ],
            confidence_reasons=[
                "Graph builder kept the edge in graph.unresolved",
            ],
        ))
    return issues
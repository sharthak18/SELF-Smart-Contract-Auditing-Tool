"""Shared helpers for project-level detectors."""

from __future__ import annotations

from typing import Iterable, List, Optional

from self_tool.core.fingerprints import source_context_hash
from self_tool.core.issue import Confidence, EvidenceLink, Issue, Severity
from self_tool.core.project import ProjectContext
from self_tool.core.scanner import FileContext
from self_tool.graph.model import Edge, Graph, Node


def _files_with(contract_name: str, ctx: ProjectContext) -> List[FileContext]:
    return [f for f in ctx.files if contract_name in f.content]


def _evidence(file: str, start: int, end: int, snippet: str) -> EvidenceLink:
    return EvidenceLink(
        file=file,
        start_line=start,
        end_line=end,
        text_hash=source_context_hash(file, start, end, snippet),
        relation="graph-edge",
    )


def make_issue(
    *,
    detector_id: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    file: str,
    line: int,
    snippet: str,
    description: str,
    exploit_scenario: str,
    remediation: str,
    evidence_paths: Iterable[EvidenceLink],
    confidence_reasons: Iterable[str],
) -> Issue:
    return Issue(
        id=detector_id,
        title=title,
        severity=severity,
        confidence=confidence,
        file=file,
        line=line,
        snippet=snippet,
        description=description,
        exploit_scenario=exploit_scenario,
        remediation=remediation,
        evidence_paths=list(evidence_paths),
        confidence_reasons=list(confidence_reasons),
    )


def edges_of_kind(graph: Graph, kind: str) -> List[Edge]:
    return [e for e in graph.edges if e.kind == kind]


def nodes_of_kind(graph: Graph, kind: str) -> List[Node]:
    return graph.by_kind(kind)
"""Orchestrate an autonomous audit.

Steps (all local and deterministic unless ``use_llm`` is set):

1. Ingest the entire project (source, extra languages, manifests, docs).
2. Build protocol context + semantic understanding.
3. Run the existing static + project detectors (offline).
4. Ensure a trained knowledge index exists; retrieve relevant playbooks.
5. Symbolically apply trained attack / math / business-logic playbooks.
6. Scan lockfiles and manifests for known-vulnerable dependencies.
7. Synthesize multi-hop exploit paths.
8. Optionally ask an LLM to propose extra business-logic findings.
9. Emit a Markdown/JSON report.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import List, Optional

from self_tool.autonomous.brain import (
    apply_weights,
    brain_stats,
    load_attack_vectors,
    retrieve,
)
from self_tool.autonomous.dependencies import hits_as_findings, scan_dependencies
from self_tool.autonomous.exploit_paths import synthesize_paths
from self_tool.autonomous.ingest import all_file_contexts, ingest_project
from self_tool.autonomous.models import AutonomousAudit, AutonomousFinding
from self_tool.autonomous.reason import reason
from self_tool.autonomous.report import write_reports
from self_tool.autonomous.trainer import ensure_trained
from self_tool.autonomous.understand import understand
from self_tool.core.builtin_reviewer import review_issues
from self_tool.core.detector_engine import DetectorEngine
from self_tool.core.doc_reader import build_protocol_context
from self_tool.core.project import ProjectContext
from self_tool.core.scanner import FrameworkInfo
from self_tool.version import __version__


def run_autonomous_audit(
    target: str,
    *,
    output: Optional[str] = None,
    also_json: bool = False,
    force_lang: Optional[str] = None,
    use_llm: bool = False,
    llm_provider: str = "auto",
    apply_suppressions: bool = False,
    skip_static: bool = False,
    index_root: Optional[Path] = None,
    no_docs: bool = False,
) -> AutonomousAudit:
    started = time.time()
    diagnostics: List[str] = []

    ingestion = ingest_project(target, force_lang=force_lang)
    files = all_file_contexts(ingestion)
    if not files:
        raise FileNotFoundError("No supported source files found in the target.")

    if no_docs:
        from self_tool.core.protocol_context import ProtocolContext
        protocol_ctx = ProtocolContext()
    else:
        protocol_ctx = build_protocol_context(ingestion.root)

    understanding = understand(ingestion, protocol_ctx)

    try:
        project_ctx = ProjectContext.build(
            files=ingestion.files,
            framework=ingestion.framework if isinstance(ingestion.framework, FrameworkInfo)
            else FrameworkInfo("unknown", ingestion.root, [ingestion.root]),
            knowledge_snapshot={},
        )
        project_fingerprint = project_ctx.project_fingerprint
    except Exception as exc:
        diagnostics.append(f"graph: {type(exc).__name__}: {exc}")
        from self_tool.core.scanner import project_fingerprint_for
        project_fingerprint = project_fingerprint_for(ingestion.files, ingestion.framework)

    static_issues = []
    engine_diagnostics = []
    if not skip_static:
        engine = DetectorEngine()
        try:
            static_issues = engine.run_project(
                ingestion.files,
                protocol_ctx=protocol_ctx,
                apply_suppressions=apply_suppressions,
            )
            review_issues(static_issues)
        except Exception as exc:
            diagnostics.append(f"static: {type(exc).__name__}: {exc}")
            static_issues = engine.run(ingestion.files, protocol_ctx=protocol_ctx)
            try:
                review_issues(static_issues)
            except Exception as exc2:
                diagnostics.append(f"review: {type(exc2).__name__}: {exc2}")
        engine_diagnostics = [
            f"{item.phase}:{item.detector}:{item.message}" for item in engine.diagnostics
        ]
        diagnostics.extend(engine_diagnostics)

    index = ensure_trained(root=index_root)
    retrieved = retrieve(understanding.briefing(), index, limit=8)
    playbooks = apply_weights(load_attack_vectors(), index)
    findings: List[AutonomousFinding] = reason(
        understanding, playbooks, files, static_issues, project_fingerprint,
    )

    dep_hits = scan_dependencies(ingestion.manifests, understanding)
    findings.extend(hits_as_findings(dep_hits, project_fingerprint))

    paths = synthesize_paths(understanding, static_issues, findings)

    llm_used = False
    llm_error = ""
    if use_llm:
        from self_tool.autonomous.llm import refine_with_llm
        extra, llm_error = refine_with_llm(
            understanding=understanding,
            static_issues=static_issues,
            findings=findings,
            retrieved=retrieved,
            known_files=[ctx.relative_path for ctx in files],
            provider=llm_provider,
            project_fingerprint=project_fingerprint,
        )
        llm_used = not llm_error
        findings.extend(extra)

    findings.sort(key=lambda item: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(item.severity, 9),
        item.source, item.file, item.line, item.id,
    ))

    stats = brain_stats()
    stats.update({
        "documents": index.document_count,
        "built_at": index.built_at,
        "sources": list(index.sources),
    })

    audit = AutonomousAudit(
        version=__version__,
        target=str(Path(target).resolve()),
        project_fingerprint=project_fingerprint,
        understanding=understanding,
        static_issues=static_issues,
        findings=findings,
        exploit_paths=paths,
        dependencies=dep_hits,
        retrieved=retrieved,
        trained_on=stats,
        llm_used=llm_used,
        llm_error=llm_error,
        elapsed=time.time() - started,
        diagnostics=diagnostics,
    )

    if output:
        report_path = output
    else:
        target_path = Path(target).resolve()
        report_root = target_path if target_path.is_dir() else target_path.parent
        report_path = str(report_root / "self-autonomous.md")
    write_reports(audit, report_path, also_json=also_json)
    audit.trained_on["report_path"] = report_path
    return audit


def exit_code_for(audit: AutonomousAudit) -> int:
    if any(
        item.startswith((
            "import:", "runtime:", "project-import", "project-runtime", "static:",
        ))
        for item in audit.diagnostics
    ):
        return 3
    issues = [item for item in audit.findings] + [
        issue for issue in audit.static_issues if not issue.suppressed
    ]
    if any(getattr(item, "severity", "") == "CRITICAL" for item in issues):
        return 2
    if any(getattr(item, "severity", "") == "HIGH" for item in issues):
        return 1
    return 0

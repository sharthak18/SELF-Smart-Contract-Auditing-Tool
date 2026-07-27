"""
SELF — Smart Contract Exploit & Logic Finder
Detector engine: loads all detectors, runs them, applies doc-context suppression.
"""

import importlib
import pkgutil
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set

from self_tool.core.detector_catalog import load_detector_catalog
from self_tool.core.builtin_reviewer import validate_review_profiles
from self_tool.core.issue import Issue, Severity
from self_tool.core.scanner import FileContext
from self_tool.core.protocol_context import ProtocolContext, EMPTY_CONTEXT
from self_tool.core.project import ProjectContext
from self_tool.core.versions import RULE_VERSION


@dataclass(frozen=True)
class DetectorDiagnostic:
    phase: str
    detector: str
    message: str
    file: str = ""


class DetectorEngine:
    """Loads all detector modules and orchestrates their execution."""

    def __init__(
        self,
        severity_filter: Optional[List[str]] = None,
        trust_doc_suppressions: bool = False,
    ):
        self.severity_filter = severity_filter  # None = all
        self.trust_doc_suppressions = trust_doc_suppressions
        self._detectors = {}  # lang → list of detector modules
        self.diagnostics: List[DetectorDiagnostic] = []
        validate_review_profiles(rule.id for rule in load_detector_catalog())
        self._load_all_detectors()

    def _load_all_detectors(self):
        """Dynamically load all detector modules from detectors/ package."""
        detectors_pkg_path = Path(__file__).parent.parent / "detectors"
        for lang_dir in sorted(detectors_pkg_path.iterdir()):
            if not lang_dir.is_dir() or lang_dir.name.startswith("_"):
                continue
            lang = lang_dir.name
            self._detectors[lang] = []
            for mod_info in pkgutil.iter_modules([str(lang_dir)]):
                try:
                    module = importlib.import_module(
                        f"self_tool.detectors.{lang}.{mod_info.name}"
                    )
                    if hasattr(module, "detect"):
                        self._detectors[lang].append(module)
                except Exception as exc:
                    self.diagnostics.append(DetectorDiagnostic(
                        phase="import",
                        detector=f"self_tool.detectors.{lang}.{mod_info.name}",
                        message=f"{type(exc).__name__}: {exc}",
                    ))

    def run(
        self,
        files: List[FileContext],
        protocol_ctx: Optional[ProtocolContext] = None,
    ) -> List[Issue]:
        """
        Run all applicable detectors on all files.
        Applies doc-context suppression if protocol_ctx is provided.
        Returns sorted, deduplicated issues (suppressed ones included but flagged).
        """
        ctx = protocol_ctx or EMPTY_CONTEXT
        all_issues: Set[Issue] = set()

        for file_ctx in files:
            lang = file_ctx.language
            detectors = self._detectors.get(lang, [])
            for detector in detectors:
                try:
                    issues = detector.detect(file_ctx)
                    for issue in (issues or []):
                        if self._passes_filter(issue):
                            # Apply doc-context suppression
                            self._apply_context_suppression(issue, ctx)
                            all_issues.add(issue)
                except Exception as exc:
                    self.diagnostics.append(DetectorDiagnostic(
                        phase="runtime",
                        detector=detector.__name__,
                        file=file_ctx.relative_path,
                        message=f"{type(exc).__name__}: {exc}",
                    ))

        # Sort: suppressed last, then severity, then file, then line
        sorted_issues = sorted(all_issues, key=lambda i: (
            i.suppressed,
            Severity.sort_key(i),
            i.file,
            i.line,
        ))
        return sorted_issues

    def run_project(
        self,
        files: List[FileContext],
        protocol_ctx: Optional[ProtocolContext] = None,
        apply_suppressions: bool = False,
    ) -> List[Issue]:
        """Run per-file detectors and project-level detectors.

        Per-file detectors continue to see only their own ``FileContext``.
        Project-level detectors (under ``self_tool.detectors.project``)
        receive a ``ProjectContext`` and may emit findings that span
        multiple files.
        """
        base_issues = self.run(files, protocol_ctx=protocol_ctx)
        # Mark per-file findings with the rule version so suppression
        # records distinguish runs across tool versions.
        for issue in base_issues:
            if not issue.rule_version:
                issue.rule_version = RULE_VERSION

        try:
            project_ctx = ProjectContext.build(
                files=files,
                framework=self._framework_for(files, protocol_ctx),
                knowledge_snapshot={},
            )
        except Exception as exc:
            self.diagnostics.append(DetectorDiagnostic(
                phase="graph", detector="project_graph",
                message=f"{type(exc).__name__}: {exc}",
            ))
            return base_issues

        for detector in self._project_detectors():
            try:
                issues = detector.detect_project(project_ctx)
                for issue in (issues or []):
                    if self._passes_filter(issue):
                        if not issue.project_fingerprint:
                            issue.project_fingerprint = project_ctx.project_fingerprint
                        if not issue.rule_version:
                            issue.rule_version = RULE_VERSION
                        self._apply_context_suppression(issue, protocol_ctx or EMPTY_CONTEXT)
                        base_issues.append(issue)
            except Exception as exc:
                self.diagnostics.append(DetectorDiagnostic(
                    phase="project-runtime",
                    detector=detector.__name__,
                    message=f"{type(exc).__name__}: {exc}",
                ))

        if apply_suppressions:
            self._apply_feedback_suppressions(base_issues, project_ctx.project_fingerprint)

        return sorted(
            base_issues,
            key=lambda i: (
                i.suppressed,
                Severity.sort_key(i),
                i.file,
                i.line,
            ),
        )

    def _framework_for(
        self,
        files: List[FileContext],
        protocol_ctx: Optional[ProtocolContext],
    ):
        from self_tool.core.scanner import detect_framework, FrameworkInfo

        if not files:
            return FrameworkInfo("unknown", "", [])
        root = str(Path(files[0].path).parent)
        framework = detect_framework(root)
        if framework.name == "unknown" and protocol_ctx is not None:
            framework = FrameworkInfo(
                name=protocol_ctx.protocol_type,
                root=framework.root or root,
                src_dirs=framework.src_dirs or [root],
            )
        return framework

    def _apply_feedback_suppressions(self, issues: List[Issue], project_fingerprint: str) -> None:
        """Apply the local feedback suppression overlay."""
        try:
            from self_tool.feedback.service import apply_suppressions
            apply_suppressions(issues, project_fingerprint=project_fingerprint)
        except Exception as exc:
            self.diagnostics.append(DetectorDiagnostic(
                phase="feedback",
                detector="apply_suppressions",
                message=f"{type(exc).__name__}: {exc}",
            ))

    def _project_detectors(self):
        try:
            from self_tool.detectors.project import discover_project_detectors
            return list(discover_project_detectors())
        except Exception as exc:
            self.diagnostics.append(DetectorDiagnostic(
                phase="project-import", detector="project_detectors",
                message=f"{type(exc).__name__}: {exc}",
            ))
            return []

    def _apply_context_suppression(self, issue: Issue, ctx: ProtocolContext):
        """
        Check if the protocol context suppresses this finding.
        Does NOT remove the issue — marks it as suppressed with reason.
        """
        if ctx.suppresses(issue.id) and self.trust_doc_suppressions:
            issue.suppressed = True
            issue.suppression_reason = ctx.suppression_reason(issue.id)
            return
        if ctx.suppresses(issue.id):
            issue.context_note = ctx.suppression_reason(issue.id)

        # Documentation is evidence for review, not proof that code is safe.
        if issue.id == "SOL-MED-001" and ctx.uses_multisig:
            issue.context_note = "Centralization may be partially mitigated; docs mention a multisig"

        # Preserve legacy suppression only behind an explicit opt-in.
        if issue.id in ("SOL-CRIT-007", "SOL-INFO-002") and ctx.is_upgradeable:
            if self.trust_doc_suppressions:
                issue.suppressed = True
                issue.suppression_reason = "Upgradeability is documented and expected"
            else:
                issue.context_note = "Upgradeability is documented; verify implementation safety"

    def _passes_filter(self, issue: Issue) -> bool:
        if not self.severity_filter:
            return True
        sev_order = Severity.ORDER
        min_sev = min(sev_order.get(s.upper(), 99) for s in self.severity_filter)
        return sev_order.get(issue.severity, 99) <= min_sev

    def detector_count(self) -> int:
        return len(load_detector_catalog())

    def module_count(self) -> int:
        return sum(len(v) for v in self._detectors.values())

    def supported_languages(self) -> List[str]:
        return [lang for lang, dets in self._detectors.items() if dets]

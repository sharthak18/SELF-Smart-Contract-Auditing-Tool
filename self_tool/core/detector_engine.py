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

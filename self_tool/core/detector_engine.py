"""
SELF — Smart Contract Exploit & Logic Finder
Detector engine: loads all detectors, runs them, applies doc-context suppression.
"""

import importlib
import pkgutil
import traceback
from pathlib import Path
from typing import List, Optional, Set

from self_tool.core.issue import Issue, Severity
from self_tool.core.scanner import FileContext
from self_tool.core.protocol_context import ProtocolContext, EMPTY_CONTEXT


class DetectorEngine:
    """Loads all detector modules and orchestrates their execution."""

    def __init__(self, severity_filter: Optional[List[str]] = None):
        self.severity_filter = severity_filter  # None = all
        self._detectors = {}  # lang → list of detector modules
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
                except Exception:
                    pass  # Silently skip broken detectors

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
                except Exception:
                    pass  # Never let a broken detector crash the tool

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
        if ctx.suppresses(issue.id):
            issue.suppressed = True
            issue.suppression_reason = ctx.suppression_reason(issue.id)
            return

        # Downgrade centralization risk if multisig is documented
        if issue.id == "SOL-MED-001" and ctx.uses_multisig:
            issue.suppression_reason = "Centralization partially mitigated (multisig documented)"
            # Don't fully suppress — still worth knowing, just context

        # Downgrade proxy warning if upgradeability is documented
        if issue.id in ("SOL-CRIT-007", "SOL-INFO-002") and ctx.is_upgradeable:
            issue.suppressed = True
            issue.suppression_reason = "Upgradeability is documented and expected"

    def _passes_filter(self, issue: Issue) -> bool:
        if not self.severity_filter:
            return True
        sev_order = Severity.ORDER
        min_sev = min(sev_order.get(s.upper(), 99) for s in self.severity_filter)
        return sev_order.get(issue.severity, 99) <= min_sev

    def detector_count(self) -> int:
        return sum(len(v) for v in self._detectors.values())

    def supported_languages(self) -> List[str]:
        return [lang for lang, dets in self._detectors.items() if dets]

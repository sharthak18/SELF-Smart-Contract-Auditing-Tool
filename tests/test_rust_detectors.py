"""End-to-end tests for the Rust/Anchor detector pack on focused fixtures."""
import unittest
from pathlib import Path

from self_tool.core.detector_engine import DetectorEngine
from self_tool.core.scanner import FileContext, discover_files
from self_tool.detectors.rust.rust_detectors import detect as rust_detect
from self_tool.parsers.rust_parser import parse_rust
from self_tool.core.builtin_reviewer import review_issues


ROOT = Path(__file__).resolve().parents[1]
SOLANA_DIR = ROOT / "tests" / "contracts" / "solana"


def _ids_for(issues):
    return {issue.id for issue in issues}


class AnchorFixtureTests(unittest.TestCase):
    def _run_file(self, name: str):
        path = SOLANA_DIR / name
        ctx = FileContext(str(path), name, "rust", path.read_text(encoding="utf-8"))
        issues = rust_detect(ctx)
        review_issues(issues)
        return issues

    def test_vulnerable_anchor_regression(self):
        issues = self._run_file("vulnerable_anchor.rs")
        ids = _ids_for(issues)
        self.assertIn("SOL-RUST-003", ids)
        self.assertIn("SOL-RUST-002", ids)

    def test_semantic_vulnerable_fixture(self):
        issues = self._run_file("anchor_semantic_vulnerable.rs")
        ids = _ids_for(issues)
        # Missing signer on privileged AccountInfo.
        self.assertIn("SOL-RUST-001", ids)
        # Raw untyped token program / sysvar.
        self.assertIn("SOL-RUST-010", ids)
        self.assertIn("SOL-RUST-011", ids)
        # init_if_needed without payer.
        self.assertIn("SOL-RUST-009", ids)
        # Arbitrary CPI target.
        self.assertIn("SOL-RUST-003", ids)

    def test_semantic_safe_fixture_is_clean(self):
        issues = self._run_file("anchor_semantic_safe.rs")
        # The safe fixture must not surface the new high-severity
        # semantic detectors. Allow the engine to still emit info-level
        # notes via the reviewer but assert zero critical/high findings.
        severe = [i for i in issues if i.severity in ("CRITICAL", "HIGH")]
        self.assertEqual([], severe,
                         msg=f"unexpected severe findings in safe fixture: "
                             f"{[(i.id, i.severity, i.line) for i in severe]}")

    def test_full_engine_run_on_solana_dir(self):
        """The full engine should also succeed on the corpus without
        raising or producing diagnostic errors."""
        files, _ = discover_files(str(SOLANA_DIR))
        engine = DetectorEngine()
        issues = engine.run(files)
        review_issues(issues)
        self.assertEqual([], engine.diagnostics,
                         msg=f"unexpected diagnostics: {engine.diagnostics}")
        # Sanity: at least one finding expected from the vulnerable file.
        ids = {issue.id for issue in issues}
        self.assertIn("SOL-RUST-003", ids)


if __name__ == "__main__":
    unittest.main()
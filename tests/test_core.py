import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from self_tool.core.builtin_reviewer import (
    REVIEW_PROFILES,
    STATUS_MANUAL_PROOF,
    review_issue,
    review_issues,
    validate_review_profiles,
)
from self_tool.core.detector_catalog import load_detector_catalog
from self_tool.core.detector_engine import DetectorEngine
from self_tool.core.detector_engine import DetectorDiagnostic
from self_tool.core.issue import Confidence, Issue, Severity
from self_tool.core.knowledge_base import load_security_knowledge
from self_tool.core.protocol_context import ProtocolContext
from self_tool.core.scanner import FileContext, discover_files
from self_tool.core.xray import analyze_entry_points
from self_tool.parsers.solidity_parser import parse_solidity
from self_tool.self import cli


ROOT = Path(__file__).resolve().parents[1]
VULNERABLE_VAULT = ROOT / "tests" / "contracts" / "VulnerableVault.sol"


class DetectorCatalogTests(unittest.TestCase):
    def test_catalog_matches_implemented_rules(self):
        rules = load_detector_catalog()
        self.assertEqual(108, len(rules))
        self.assertEqual(108, len({rule.id for rule in rules}))
        self.assertNotIn("UNKNOWN", {rule.severity for rule in rules})
        for rule in rules:
            if "-CRIT-" in rule.id:
                self.assertEqual("CRITICAL", rule.severity, rule.id)
            if "-HIGH-" in rule.id:
                self.assertEqual("HIGH", rule.severity, rule.id)
            if "-MED-" in rule.id:
                self.assertEqual("MEDIUM", rule.severity, rule.id)
            if "-LOW-" in rule.id:
                self.assertEqual("LOW", rule.severity, rule.id)
            if "-INFO-" in rule.id:
                self.assertEqual("INFO", rule.severity, rule.id)

    def test_all_detector_modules_run_without_diagnostics(self):
        files, _ = discover_files(str(VULNERABLE_VAULT))
        engine = DetectorEngine()
        issues = engine.run(files)
        review_issues(issues)
        self.assertEqual([], engine.diagnostics)
        self.assertIn("SOL-HIGH-007", {issue.id for issue in issues})
        self.assertTrue(all(issue.review_status for issue in issues))

    def test_every_detector_has_one_hardcoded_review_profile(self):
        rules = load_detector_catalog()
        validate_review_profiles(rule.id for rule in rules)
        self.assertEqual(108, len(REVIEW_PROFILES))
        self.assertEqual({rule.id for rule in rules}, set(REVIEW_PROFILES))

    def test_review_profile_mismatch_is_fatal(self):
        with self.assertRaisesRegex(ValueError, "missing=.*CUSTOM-HIGH-001"):
            validate_review_profiles(
                [rule.id for rule in load_detector_catalog()] + ["CUSTOM-HIGH-001"]
            )


class SolidityParserTests(unittest.TestCase):
    def test_interface_declaration_does_not_capture_next_body(self):
        source = """pragma solidity ^0.8.20;
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}
contract Vault {
    uint256 public total;
    function deposit() external payable { total += msg.value; }
    receive() external payable {}
}
"""
        context = FileContext("/tmp/Vault.sol", "Vault.sol", "solidity", source)
        info = parse_solidity(context)
        interface, vault = info.contracts
        self.assertEqual(2, interface.line)
        self.assertEqual("", interface.functions[0].body)
        self.assertEqual(["total"], [state.name for state in vault.state_vars])
        self.assertIn("receive", {function.name for function in vault.functions})

    def test_state_assignments_are_not_state_declarations(self):
        context = FileContext(
            str(VULNERABLE_VAULT),
            VULNERABLE_VAULT.name,
            "solidity",
            VULNERABLE_VAULT.read_text(encoding="utf-8"),
        )
        vault = parse_solidity(context).contracts[0]
        self.assertEqual(
            ["balances", "owner", "users", "WETH"],
            [state.name for state in vault.state_vars],
        )


class ContextSafetyTests(unittest.TestCase):
    @staticmethod
    def _issue():
        return Issue(
            id="SOL-HIGH-008",
            title="Unchecked transfer",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            file="Token.sol",
            line=1,
            snippet="",
            description="",
            exploit_scenario="",
            remediation="",
        )

    def test_docs_are_notes_by_default(self):
        context = ProtocolContext(uses_safeERC20=True)
        context.build_suppressions()
        issue = self._issue()
        DetectorEngine()._apply_context_suppression(issue, context)
        self.assertFalse(issue.suppressed)
        self.assertIn("SafeERC20", issue.context_note)

    def test_doc_suppression_requires_explicit_opt_in(self):
        context = ProtocolContext(uses_safeERC20=True)
        context.build_suppressions()
        issue = self._issue()
        DetectorEngine(trust_doc_suppressions=True)._apply_context_suppression(issue, context)
        self.assertTrue(issue.suppressed)

    def test_builtin_review_is_always_attached_and_never_suppresses(self):
        issue = self._issue()
        review_issue(issue)
        self.assertEqual(STATUS_MANUAL_PROOF, issue.review_status)
        self.assertIn("Token transfer result", issue.review_reasoning)
        self.assertTrue(issue.review_test)
        self.assertEqual("SELF built-in deterministic reviewer", issue.review_engine)
        self.assertFalse(issue.suppressed)


class KnowledgeAndXrayTests(unittest.TestCase):
    def test_knowledge_base_has_current_top_ten(self):
        data = load_security_knowledge()
        categories = data["taxonomies"][0]["categories"]
        self.assertEqual("2026-06-09", data["reviewed_at"])
        self.assertEqual(10, len(categories))

    def test_xray_classifies_caller_restrictions_and_receive(self):
        context = FileContext(
            str(VULNERABLE_VAULT),
            VULNERABLE_VAULT.name,
            "solidity",
            VULNERABLE_VAULT.read_text(encoding="utf-8"),
        )
        entries, _ = analyze_entry_points([context])
        by_name = {entry.function: entry for entry in entries}
        self.assertEqual("caller-restricted", by_name["adminWithdraw"].access)
        self.assertEqual("in", by_name["receive"].value_flow)
        self.assertIn("users", by_name["addUser"].state_writes)
        self.assertIn("transfer", by_name["pay"].external_calls)


class CliTests(unittest.TestCase):
    def test_version(self):
        result = CliRunner().invoke(cli, ["--version"])
        self.assertEqual(0, result.exit_code)
        self.assertIn("2.2.0", result.output)

    def test_extensionless_report_does_not_get_overwritten_by_json(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            contract = Path("Risk.sol")
            contract.write_text(
                "pragma solidity ^0.8.20; contract Risk { "
                "function destroy() external { selfdestruct(payable(msg.sender)); } }",
                encoding="utf-8",
            )
            result = runner.invoke(cli, [
                str(contract),
                "--no-docs",
                "--quiet",
                "--output",
                "report",
                "--json",
            ])
            self.assertEqual(2, result.exit_code)
            self.assertTrue(Path("report").exists())
            self.assertTrue(Path("report.json").exists())
            parsed = json.loads(Path("report.json").read_text(encoding="utf-8"))
            self.assertEqual("2.2.0", parsed["version"])
            self.assertTrue(parsed["issues"])
            for issue in parsed["issues"]:
                self.assertTrue(issue["review_status"])
                self.assertTrue(issue["review_reasoning"])
                self.assertTrue(issue["review_test"])

    def test_project_scan_skips_test_directories(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "src").mkdir()
            (root / "tests").mkdir()
            (root / "src" / "Main.sol").write_text("contract Main {}", encoding="utf-8")
            (root / "tests" / "Fixture.sol").write_text("contract Fixture {}", encoding="utf-8")
            files, _ = discover_files(str(root))
            self.assertEqual(["src/Main.sol"], [file.relative_path for file in files])

    def test_no_supported_files_is_not_reported_as_clean(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            Path("README.txt").write_text("nothing to scan", encoding="utf-8")
            result = runner.invoke(cli, [".", "--quiet"])
            self.assertEqual(4, result.exit_code)
            self.assertIn("No supported source files", result.output)

    def test_detector_failure_always_exits_incomplete(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            Path("Main.sol").write_text("contract Main {}", encoding="utf-8")

            def fail_detector(engine, files, protocol_ctx=None):
                engine.diagnostics.append(
                    DetectorDiagnostic(
                        phase="runtime",
                        detector="test.detector",
                        message="forced failure",
                    )
                )
                return []

            with patch.object(DetectorEngine, "run", fail_detector):
                result = runner.invoke(cli, [".", "--quiet", "--no-docs"])

            self.assertEqual(3, result.exit_code)
            self.assertIn("Detector health warning", result.output)

    def test_source_read_failure_exits_incomplete(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            Path("Main.sol").write_text("contract Main {}", encoding="utf-8")
            with patch(
                "self_tool.self.discover_files",
                side_effect=PermissionError("source denied"),
            ):
                result = runner.invoke(cli, [".", "--quiet", "--no-docs"])

            self.assertEqual(3, result.exit_code)
            self.assertIn("source discovery failed", result.output)

    def test_documentation_failure_exits_incomplete(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            Path("Main.sol").write_text("contract Main {}", encoding="utf-8")
            with patch(
                "self_tool.self.build_protocol_context",
                side_effect=PermissionError("documentation denied"),
            ):
                result = runner.invoke(cli, [".", "--quiet"])

            self.assertEqual(3, result.exit_code)
            self.assertIn("documentation context failed", result.output)


if __name__ == "__main__":
    unittest.main()

import unittest
from pathlib import Path

from self_tool.core.detector_engine import DetectorEngine
from self_tool.core.scanner import discover_files
from self_tool.core.builtin_reviewer import review_issues

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = ROOT / "tests" / "contracts"
NEGATIVE_DIR = CONTRACTS_DIR / "negative"

class NewDetectorsTests(unittest.TestCase):
    def test_erc_conformance(self):
        files, _ = discover_files(str(CONTRACTS_DIR / "ERC20Vulnerable.sol"))
        engine = DetectorEngine()
        issues = engine.run(files)
        
        issue_ids = {issue.id for issue in issues}
        self.assertIn("SOL-HIGH-014", issue_ids)
        self.assertIn("SOL-HIGH-016", issue_ids)
        self.assertIn("SOL-MED-014", issue_ids)
        
    def test_proxy_storage_collision(self):
        files, _ = discover_files(str(CONTRACTS_DIR / "ProxyStorageCollision.sol"))
        engine = DetectorEngine()
        issues = engine.run(files)
        
        issue_ids = {issue.id for issue in issues}
        self.assertIn("SOL-HIGH-020", issue_ids)

    def test_signature_attacks(self):
        files, _ = discover_files(str(CONTRACTS_DIR / "SignatureMalleability.sol"))
        engine = DetectorEngine()
        issues = engine.run(files)
        
        issue_ids = {issue.id for issue in issues}
        self.assertIn("SOL-CRIT-014", issue_ids)
        self.assertIn("SOL-HIGH-023", issue_ids)

    def test_mev_target(self):
        files, _ = discover_files(str(CONTRACTS_DIR / "MEVTarget.sol"))
        engine = DetectorEngine()
        issues = engine.run(files)
        
        issue_ids = {issue.id for issue in issues}
        self.assertIn("SOL-HIGH-018", issue_ids)
        self.assertIn("SOL-HIGH-019", issue_ids)
        
    def test_gas_griefing(self):
        files, _ = discover_files(str(CONTRACTS_DIR / "GasGriefing.sol"))
        engine = DetectorEngine()
        issues = engine.run(files)
        
        issue_ids = {issue.id for issue in issues}
        self.assertIn("SOL-HIGH-024", issue_ids)
        self.assertIn("SOL-CRIT-011", issue_ids)
        self.assertIn("SOL-CRIT-012", issue_ids)
        self.assertIn("SOL-LOW-008", issue_ids)
        self.assertIn("SOL-LOW-009", issue_ids)

    def test_zodiac_style_signature_bypass(self):
        """SOL-CRIT-015: staticcall success discarded before magic-value compare."""
        files, _ = discover_files(str(CONTRACTS_DIR / "ZodiacSignatureBypass.sol"))
        engine = DetectorEngine()
        issues = engine.run(files)
        self.assertIn("SOL-CRIT-015", {issue.id for issue in issues})

        files, _ = discover_files(str(NEGATIVE_DIR / "SafeCallResultIntegrity.sol"))
        issues = engine.run(files)
        self.assertNotIn("SOL-CRIT-015", {issue.id for issue in issues})

    def test_tstore_poison_compiler_bug(self):
        """SOL-CRIT-016: transient/persistent storage clearing collision (solc 0.8.28-0.8.33)."""
        files, _ = discover_files(str(CONTRACTS_DIR / "CompilerBugTstorePoison.sol"))
        engine = DetectorEngine()
        issues = engine.run(files)
        self.assertIn("SOL-CRIT-016", {issue.id for issue in issues})

        files, _ = discover_files(str(NEGATIVE_DIR / "SafeCompilerPin.sol"))
        issues = engine.run(files)
        self.assertNotIn("SOL-CRIT-016", {issue.id for issue in issues})

    def test_unguarded_oracle_view_readonly_reentrancy(self):
        """SOL-CRIT-017: Curve-style get_virtual_price() with no reentrancy guard."""
        files, _ = discover_files(str(CONTRACTS_DIR / "OracleReadOnlyReentrancy.sol"))
        engine = DetectorEngine()
        issues = engine.run(files)
        self.assertIn("SOL-CRIT-017", {issue.id for issue in issues})

        files, _ = discover_files(str(NEGATIVE_DIR / "SafeOraclePool.sol"))
        issues = engine.run(files)
        self.assertNotIn("SOL-CRIT-017", {issue.id for issue in issues})

    def test_caller_supplied_domain_separator(self):
        """SOL-CRIT-018: caller-supplied EIP-712 domain separator enables cross-chain replay."""
        files, _ = discover_files(str(CONTRACTS_DIR / "DomainSeparatorArg.sol"))
        engine = DetectorEngine()
        issues = engine.run(files)
        self.assertIn("SOL-CRIT-018", {issue.id for issue in issues})

        files, _ = discover_files(str(NEGATIVE_DIR / "SafeDomainSeparator.sol"))
        issues = engine.run(files)
        self.assertNotIn("SOL-CRIT-018", {issue.id for issue in issues})

    def test_permit_frontrun_dos(self):
        """SOL-HIGH-026: unconditional permit() + dependent action is front-run DoS-able."""
        files, _ = discover_files(str(CONTRACTS_DIR / "PermitFrontrunDos.sol"))
        engine = DetectorEngine()
        issues = engine.run(files)
        self.assertIn("SOL-HIGH-026", {issue.id for issue in issues})

        files, _ = discover_files(str(NEGATIVE_DIR / "SafePermitRouter.sol"))
        issues = engine.run(files)
        self.assertNotIn("SOL-HIGH-026", {issue.id for issue in issues})

if __name__ == "__main__":
    unittest.main()

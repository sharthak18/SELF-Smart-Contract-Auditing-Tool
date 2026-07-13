import unittest
from pathlib import Path

from self_tool.core.detector_engine import DetectorEngine
from self_tool.core.scanner import discover_files
from self_tool.core.builtin_reviewer import review_issues

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = ROOT / "tests" / "contracts"

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

if __name__ == "__main__":
    unittest.main()

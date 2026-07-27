"""Tests for schema versions, fingerprints, Issue evidence, and audit log."""

import json
import tempfile
import unittest
from pathlib import Path

from self_tool.core.audit_log import read, record
from self_tool.core.fingerprints import (
    canonical_json,
    project_fingerprint,
    semantic_fingerprint,
    source_context_hash,
)
from self_tool.core.issue import Confidence, EvidenceLink, Issue, Severity


class FoundationTests(unittest.TestCase):
    def test_canonical_json_is_order_independent(self):
        self.assertEqual(canonical_json({"b": 2, "a": 1}), canonical_json({"a": 1, "b": 2}))

    def test_fingerprints_are_deterministic_and_namespaced(self):
        project = {"files": ["A.sol"], "framework": "foundry"}
        self.assertEqual(project_fingerprint(project), project_fingerprint(project))
        self.assertTrue(project_fingerprint(project).startswith("pf_"))
        self.assertTrue(source_context_hash("A.sol", 1, 1, "contract A {}").startswith("sh_"))
        self.assertTrue(
            semantic_fingerprint("D-1", "1", {"contract": "A", "fn": "f"}).startswith("sf_")
        )

    def test_issue_serializes_evidence_additively(self):
        link = EvidenceLink("A.sol", 4, 6, "sh_deadbeef", relation="calls", node_id="fn:A.f")
        issue = Issue(
            id="TEST-001", title="test", severity=Severity.INFO,
            confidence=Confidence.LOW, file="A.sol", line=4,
            snippet="f();", description="d", exploit_scenario="e", remediation="r",
            project_fingerprint="pf_x", semantic_fingerprint="sf_x",
            source_hash="sh_x", rule_version="1", evidence_paths=[link],
        )
        data = issue.to_dict()
        self.assertEqual(data["evidence_paths"][0]["relation"], "calls")
        self.assertEqual(data["suppression_state"], "none")

    def test_audit_log_is_append_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = record("feedback.add", details={"id": 1}, path=root)
            second = record("feedback.remove", details={"id": 1}, path=root)
            events = read(path=root)
            self.assertEqual([e["event"] for e in events], ["feedback.add", "feedback.remove"])
            self.assertNotEqual(first["id"], second["id"])
            log_file = root / "audit.log.jsonl"
            self.assertEqual(len(log_file.read_text().splitlines()), 2)


if __name__ == "__main__":
    unittest.main()

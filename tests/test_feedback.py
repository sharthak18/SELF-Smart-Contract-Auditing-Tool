"""Tests for the persistent feedback store."""

import json
import tempfile
import unittest
from pathlib import Path

from self_tool.core.fingerprints import project_fingerprint
from self_tool.core.issue import Confidence, Issue, Severity
from self_tool.feedback.service import FeedbackStore, apply_suppressions
from self_tool.feedback.store import default_path


def _make_issue(*, id="SOL-MED-002", project="pf_abc", semantic="sf_x",
                source="sh_x", rule="1.0", suppressed=False, state="none"):
    return Issue(
        id=id,
        title="test",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        file="A.sol",
        line=1,
        snippet="x",
        description="",
        exploit_scenario="",
        remediation="",
        project_fingerprint=project,
        semantic_fingerprint=semantic,
        source_hash=source,
        rule_version=rule,
        suppression_state=state,
        suppressed=suppressed,
    )


class FeedbackStoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "feedback.sqlite3"
        self.store = FeedbackStore(path=self.path)

    def tearDown(self):
        self._tmp.cleanup()

    def test_add_list_remove_roundtrip(self):
        fid = self.store.add(
            project_fingerprint="pf_abc", detector_id="SOL-MED-002",
            semantic_fingerprint="sf_x", source_hash="sh_x",
            rule_version="1.0", disposition="false_positive",
            reason="manual review", author="alice",
        )
        listed = self.store.list("pf_abc")
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0].id, fid)
        self.assertTrue(self.store.remove(fid))
        self.assertEqual(len(self.store.list("pf_abc")), 0)
        self.assertEqual(len(self.store.list("pf_abc", include_inactive=True)), 1)

    def test_export_and_import(self):
        self.store.add(
            project_fingerprint="pf_abc", detector_id="SOL-MED-002",
            semantic_fingerprint="sf_x", source_hash="sh_x",
            rule_version="1.0", disposition="confirmed",
        )
        payload = self.store.export_entries(project_fingerprint="pf_abc")
        export_path = Path(self._tmp.name) / "export.json"
        export_path.write_text(json.dumps(payload), encoding="utf-8")

        fresh = FeedbackStore(path=Path(self._tmp.name) / "fresh.sqlite3")
        inserted = fresh.import_entries(json.loads(export_path.read_text()))
        self.assertEqual(inserted, 1)
        self.assertEqual(len(fresh.list("pf_abc")), 1)

    def test_apply_suppressions_skips_stale_hash(self):
        self.store.add(
            project_fingerprint="pf_abc", detector_id="SOL-MED-002",
            semantic_fingerprint="sf_x", source_hash="sh_x",
            rule_version="1.0", disposition="false_positive",
        )
        match = _make_issue()
        apply_suppressions([match], project_fingerprint="pf_abc", store=self.store)
        self.assertTrue(match.suppressed)
        self.assertEqual(match.suppression_state, "false_positive")

        changed = _make_issue(source="sh_y")
        apply_suppressions([changed], project_fingerprint="pf_abc", store=self.store)
        self.assertFalse(changed.suppressed)

        other_project = _make_issue(project="pf_other")
        apply_suppressions([other_project], project_fingerprint="pf_abc", store=self.store)
        self.assertFalse(other_project.suppressed)

    def test_confirmed_does_not_suppress(self):
        self.store.add(
            project_fingerprint="pf_abc", detector_id="SOL-MED-002",
            semantic_fingerprint="sf_x", source_hash="sh_x",
            rule_version="1.0", disposition="confirmed",
            reason="reviewed",
        )
        issue = _make_issue()
        apply_suppressions([issue], project_fingerprint="pf_abc", store=self.store)
        self.assertFalse(issue.suppressed)
        self.assertIn("feedback[confirmed] reviewed", issue.context_note)

    def test_invalid_disposition_rejected(self):
        with self.assertRaises(ValueError):
            self.store.add(
                project_fingerprint="pf_abc", detector_id="SOL-MED-002",
                semantic_fingerprint="sf_x", source_hash="sh_x",
                rule_version="1.0", disposition="bogus",
            )


if __name__ == "__main__":
    unittest.main()
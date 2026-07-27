"""Tests for the deterministic calibration runner."""

import json
import tempfile
import unittest
from pathlib import Path

from self_tool.calibration.metrics import DetectorMetrics, summarize
from self_tool.calibration.runner import run_calibration


class CalibrationTests(unittest.TestCase):
    def test_metrics_precision_and_recall(self):
        m = DetectorMetrics(detector_id="D-1", true_positives=8,
                            false_positives=2, true_negatives=5, false_negatives=1)
        self.assertAlmostEqual(m.precision, 0.8)
        self.assertAlmostEqual(m.recall, 8 / 9)
        self.assertAlmostEqual(m.false_positive_rate, 2 / 7)

    def test_summary_flags_low_precision(self):
        a = DetectorMetrics(detector_id="A", true_positives=1, false_positives=9)
        b = DetectorMetrics(detector_id="B", true_positives=8, false_positives=2)
        s = summarize([a, b])
        self.assertEqual(s["detector_count"], 2)
        self.assertEqual([d["detector_id"] for d in s["low_precision_detectors"]], ["A"])

    def test_runner_requires_fixtures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "positive").mkdir()
            (root / "positive" / "ok.sol").write_text(
                "pragma solidity ^0.8.0; contract A { uint x; }", encoding="utf-8"
            )
            (root / "negative").mkdir()
            (root / "negative" / "bad.sol").write_text(
                "pragma solidity ^0.8.0; contract B { uint x; }", encoding="utf-8"
            )
            metrics = run_calibration(root)
            self.assertIsInstance(metrics, list)


if __name__ == "__main__":
    unittest.main()
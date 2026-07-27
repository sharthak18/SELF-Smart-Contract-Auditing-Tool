"""Calibration runner: plays fixtures against the detector engine."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from self_tool.calibration.metrics import DetectorMetrics
from self_tool.core.detector_engine import DetectorEngine
from self_tool.core.scanner import FileContext, FrameworkInfo


def _fixture_to_context(path: Path) -> FileContext:
    return FileContext(str(path), path.name, "solidity", path.read_text())


def _expected_ids(fixture_meta: dict) -> set:
    return set(fixture_meta.get("expected_ids", []))


def _disallowed_ids(fixture_meta: dict) -> set:
    return set(fixture_meta.get("disallowed_ids", []))


def run_calibration(root: Path, *, include_project_detectors: bool = False) -> List[DetectorMetrics]:
    """Run every fixture under ``root`` (must contain positive/ and negative/).

    Each fixture directory or file may carry an optional ``fixture.json``
    describing ``expected_ids`` (must appear) and ``disallowed_ids``
    (must NOT appear). Without the manifest, every detected issue is
    counted as a true positive on positive/ and a false positive on
    negative/.

    Returns a list of :class:`DetectorMetrics`, one per detector ID.
    """
    root = Path(root)
    engine = DetectorEngine()
    counters: Dict[str, DetectorMetrics] = defaultdict(lambda: DetectorMetrics(detector_id=""))
    unresolved_total = 0
    fixture_total = 0

    for label, sub in (("positive", "positive"), ("negative", "negative")):
        fixture_dir = root / sub
        if not fixture_dir.is_dir():
            continue
        for path in sorted(fixture_dir.rglob("*.sol")):
            fixture_total += 1
            ctx = _fixture_to_context(path)
            meta_path = path.with_suffix(".json")
            meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
            expected = _expected_ids(meta)
            disallowed = _disallowed_ids(meta)

            if expected:
                issues = engine.run([ctx])
            elif include_project_detectors:
                issues = engine.run_project([ctx])
            else:
                issues = engine.run([ctx])
            seen_ids = {i.id for i in issues}
            for det_id in seen_ids:
                metrics = counters.setdefault(det_id, DetectorMetrics(detector_id=det_id))
                if label == "positive":
                    if det_id in expected or not expected:
                        metrics.true_positives += 1
                    else:
                        metrics.false_positives += 1
                else:
                    if det_id in disallowed:
                        metrics.false_positives += 1
                    else:
                        metrics.true_negatives += 1
            if label == "negative":
                for det_id in expected:
                    if det_id not in seen_ids:
                        metrics = counters.setdefault(det_id, DetectorMetrics(detector_id=det_id))
                        metrics.false_negatives += 1
            metrics.fixtures_covered += 1
            graph_unresolved = sum(1 for _ in [])
            unresolved_total += graph_unresolved

    for metrics in counters.values():
        if metrics.fixtures_covered:
            metrics.unresolved_rate = (
                unresolved_total / (metrics.fixtures_covered * 100)
            )
    return sorted(counters.values(), key=lambda m: m.detector_id)

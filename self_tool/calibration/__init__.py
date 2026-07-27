"""Deterministic calibration framework for SELF detectors.

The calibration runner plays known positive/negative fixtures through
the engine and computes confusion-matrix metrics per detector and
rule version. Candidate rules live in ``candidates/`` and are excluded
from production scans until they pass calibration.
"""

from .runner import run_calibration
from .metrics import DetectorMetrics, summarize

__all__ = ["run_calibration", "DetectorMetrics", "summarize"]

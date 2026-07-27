"""Confusion-matrix metrics for calibration runs."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DetectorMetrics:
    detector_id: str
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    fixtures_covered: int = 0
    unresolved_rate: float = 0.0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom else 0.0

    def to_dict(self) -> dict:
        return {
            "detector_id": self.detector_id,
            "tp": self.true_positives,
            "fp": self.false_positives,
            "tn": self.true_negatives,
            "fn": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "fp_rate": round(self.false_positive_rate, 4),
            "fixtures_covered": self.fixtures_covered,
            "unresolved_rate": round(self.unresolved_rate, 4),
        }


def summarize(metrics: list) -> dict:
    if not metrics:
        return {"detector_count": 0, "low_precision_detectors": []}
    low = sorted(
        (m for m in metrics if m.precision < 0.6 and (m.true_positives + m.false_positives) >= 2),
        key=lambda m: m.detector_id,
    )
    return {
        "detector_count": len(metrics),
        "low_precision_detectors": [
            {
                "detector_id": m.detector_id,
                "precision": round(m.precision, 4),
                "fp": m.false_positives,
                "tp": m.true_positives,
                "fp_rate": round(m.false_positive_rate, 4),
            }
            for m in low
        ],
    }

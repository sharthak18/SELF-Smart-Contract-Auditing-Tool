"""CLI subcommand for calibration runs."""

from __future__ import annotations

import json
from pathlib import Path

import click

from self_tool.calibration.metrics import summarize
from self_tool.calibration.runner import run_calibration


@click.command("calibrate")
@click.option("--root", default="tests/fixtures/calibration",
              help="Directory containing positive/ and negative/ fixtures")
@click.option("--json", "as_json", is_flag=True, default=False)
def calibrate(root, as_json) -> None:
    """Run the calibration corpus and report detector precision."""
    metrics = run_calibration(Path(root))
    payload = {
        "metrics": [m.to_dict() for m in metrics],
        "summary": summarize(metrics),
    }
    if as_json:
        click.echo(json.dumps(payload, indent=2))
        return
    for m in metrics:
        click.echo(
            f"{m.detector_id:30s}  precision={m.precision:0.3f}  "
            f"recall={m.recall:0.3f}  fp_rate={m.false_positive_rate:0.3f}  "
            f"tp={m.true_positives} fp={m.false_positives} tn={m.true_negatives} fn={m.false_negatives}"
        )

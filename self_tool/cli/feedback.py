"""CLI subcommand for the local feedback store."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from self_tool.core.fingerprints import project_fingerprint
from self_tool.core.scanner import detect_framework, discover_files
from self_tool.feedback.service import FeedbackStore, export_to, import_from


def _project_fingerprint(target: str) -> str:
    path = Path(target).resolve()
    files, framework = discover_files(str(path))
    return project_fingerprint({
        "framework": framework.name,
        "files": sorted(f.relative_path for f in files),
    })


@click.group(help="Manage local, fingerprint-scoped feedback for SELF scans.")
def feedback() -> None:
    pass


@feedback.command("add")
@click.argument("target")
@click.option("--detector", "detector_id", required=True)
@click.option("--semantic", "semantic_fingerprint", required=True)
@click.option("--source", "source_hash", required=True)
@click.option("--rule-version", required=True)
@click.option("--disposition", required=True,
              type=click.Choice(["confirmed", "false_positive", "accepted_risk", "fixed"]))
@click.option("--reason", default="")
@click.option("--author", default="self")
@click.option("--file", "target_file", default="")
@click.option("--line", "target_line", default=0, type=int)
def add(target, detector_id, semantic_fingerprint, source_hash, rule_version,
        disposition, reason, author, target_file, target_line) -> None:
    """Add a feedback record for the target project."""
    pf = _project_fingerprint(target)
    store = FeedbackStore()
    fb_id = store.add(
        project_fingerprint=pf,
        detector_id=detector_id,
        semantic_fingerprint=semantic_fingerprint,
        source_hash=source_hash,
        rule_version=rule_version,
        disposition=disposition,
        reason=reason,
        author=author,
        target_file=target_file,
        target_line=target_line,
    )
    click.echo(f"stored feedback #{fb_id} for {pf[:24]}…")


@feedback.command("list")
@click.argument("target")
@click.option("--include-inactive", is_flag=True, default=False)
def list_cmd(target, include_inactive) -> None:
    """List feedback records for the target project."""
    pf = _project_fingerprint(target)
    store = FeedbackStore()
    entries = store.list(project_fingerprint=pf, include_inactive=include_inactive)
    click.echo(json.dumps(
        [e.to_dict() for e in entries],
        indent=2, sort_keys=True,
    ))


@feedback.command("remove")
@click.argument("feedback_id", type=int)
def remove(feedback_id) -> None:
    """Deactivate a feedback record by id."""
    store = FeedbackStore()
    if store.remove(feedback_id):
        click.echo(f"deactivated feedback #{feedback_id}")
    else:
        click.echo(f"feedback #{feedback_id} not found", err=True)
        sys.exit(1)


@feedback.command("export")
@click.argument("target")
@click.option("--output", "-o", required=True)
@click.option("--project-fingerprint", default=None)
def export(target, output, project_fingerprint) -> None:
    """Export feedback entries to a JSON file."""
    if project_fingerprint is None:
        project_fingerprint = _project_fingerprint(target)
    out = export_to(Path(output), project_fingerprint=project_fingerprint)
    click.echo(f"wrote feedback export to {out}")


@feedback.command("import")
@click.argument("file_path")
@click.option("--replace", is_flag=True, default=False)
def import_cmd(file_path, replace) -> None:
    """Import feedback entries from a JSON file."""
    inserted = import_from(Path(file_path), replace=replace)
    click.echo(f"imported {inserted} feedback entries")

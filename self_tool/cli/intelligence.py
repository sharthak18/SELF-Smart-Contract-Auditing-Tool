"""CLI subcommands for the metadata-only advisory updater."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict

import click

from self_tool.core import audit_log
from self_tool.intelligence.cache import Cache
from self_tool.intelligence.fetcher import fetch_https, host_for
from self_tool.intelligence.install import install_snapshot
from self_tool.intelligence.manifest import verify_manifest


def _allowed_hosts() -> set:
    hosts = set()
    for source_id, host in host_for.__globals__["ALLOWED_HOSTS"].items():
        hosts.add(host)
    return hosts


@click.group(help="Manage local advisory intelligence snapshots.")
def intelligence() -> None:
    pass


@intelligence.command("status")
def status() -> None:
    """Show installed snapshots and the active one."""
    cache = Cache()
    snapshots = cache.list_snapshots()
    if not snapshots:
        click.echo("no intelligence snapshots installed")
        return
    for snap in snapshots:
        meta_path = snap.path / "meta.json"
        meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
        marker = " * active" if cache.latest() and cache.latest().snapshot_id == snap.snapshot_id else ""
        click.echo(
            f"{snap.snapshot_id}{marker}: rule={meta.get('rule_version', '-')}, "
            f"manifest={meta.get('manifest_sha256', '-')[:12]}…"
        )


@intelligence.command("rollback")
@click.argument("snapshot_id")
def rollback(snapshot_id) -> None:
    """Activate a previously installed snapshot."""
    from self_tool.intelligence.install import rollback as do_rollback
    snap = do_rollback(snapshot_id)
    if snap is None:
        click.echo(f"snapshot not found: {snapshot_id}", err=True)
        sys.exit(1)
    click.echo(f"activated snapshot {snap.snapshot_id}")


@click.command("update")
@click.option("--manifest-url", required=True,
              help="HTTPS URL of the signed manifest to fetch")
@click.option("--pinned-payload-hash", default=None,
              help="Override the tool-pinned payload hash (advanced)")
@click.option("--dry-run", is_flag=True, default=False,
              help="Fetch and validate the manifest only; do not install")
def update(manifest_url, pinned_payload_hash, dry_run) -> None:
    """Fetch a signed advisory manifest and install its records."""
    audit_log.record("intelligence.update.start", details={"url": manifest_url})
    try:
        result = fetch_https(manifest_url, allowed_hosts=_allowed_hosts())
    except Exception as exc:
        audit_log.record("intelligence.update.error", details={"error": str(exc)})
        click.echo(f"update failed: {exc}", err=True)
        sys.exit(1)
    try:
        payload = json.loads(result.body)
    except json.JSONDecodeError as exc:
        click.echo(f"manifest is not valid JSON: {exc}", err=True)
        sys.exit(1)
    try:
        manifest = verify_manifest(payload, pinned_payload_hash=pinned_payload_hash)
    except Exception as exc:
        click.echo(f"manifest rejected: {exc}", err=True)
        sys.exit(1)
    click.echo(f"manifest verified: snapshot={manifest.snapshot_id}, "
              f"entries={len(manifest.entries)}")
    if dry_run:
        click.echo("dry-run: skipping per-source fetch and install")
        return

    per_source: Dict[str, dict] = {}
    for entry in manifest.entries:
        try:
            fetch = fetch_https(entry.url, allowed_hosts=_allowed_hosts())
        except Exception as exc:
            click.echo(f"failed to fetch {entry.source}: {exc}", err=True)
            sys.exit(1)
        if fetch.sha256 != entry.sha256:
            click.echo(
                f"hash mismatch for {entry.source}: declared={entry.sha256[:12]}… "
                f"actual={fetch.sha256[:12]}…", err=True,
            )
            sys.exit(1)
        try:
            per_source[entry.source] = json.loads(fetch.body)
        except json.JSONDecodeError as exc:
            click.echo(f"invalid JSON for {entry.source}: {exc}", err=True)
            sys.exit(1)

    try:
        snap = install_snapshot(
            payload, per_source_payloads=per_source,
            pinned_payload_hash=pinned_payload_hash,
        )
    except Exception as exc:
        click.echo(f"install failed: {exc}", err=True)
        sys.exit(1)
    click.echo(f"installed snapshot {snap.snapshot_id}")

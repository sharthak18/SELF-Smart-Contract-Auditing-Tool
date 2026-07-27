"""CLI subcommand for project semantic graph export."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from self_tool.core.scanner import discover_files
from self_tool.graph.builder import build_project_graph
from self_tool.graph.serialization import serialize_graph


@click.command("graph")
@click.argument("target")
@click.option("--output", "-o", default=None)
@click.option("--json", "as_json", is_flag=True, default=False)
def graph(target, output, as_json) -> None:
    """Build and (optionally) write the project semantic graph."""
    path = Path(target).resolve()
    files, framework = discover_files(str(path))
    if not files:
        click.echo("no source files discovered", err=True)
        sys.exit(1)
    g = build_project_graph(files, framework=framework.name)
    if as_json:
        click.echo(json.dumps(g.to_dict(), indent=2, sort_keys=True))
    else:
        click.echo(serialize_graph(g))
    if output:
        out = Path(output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(serialize_graph(g), encoding="utf-8")
        click.echo(f"graph written to {out}")

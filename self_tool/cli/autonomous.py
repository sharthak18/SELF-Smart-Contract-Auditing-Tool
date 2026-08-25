"""CLI for autonomous audit and knowledge training."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from self_tool.version import __version__


console = Console()


@click.command("autonomous")
@click.argument("target", default=".")
@click.option("--output", "-o", default=None, help="Markdown report path.")
@click.option("--json", "also_json", is_flag=True, default=False, help="Also write JSON.")
@click.option("--lang", "-l", default=None,
              type=click.Choice(["solidity", "vyper", "huff", "rust", "move", "typescript"],
                                case_sensitive=False))
@click.option("--llm", "use_llm", is_flag=True, default=False,
              help="Opt-in LLM refinement (requires API key or Ollama).")
@click.option("--llm-provider", default="auto",
              type=click.Choice(["auto", "openai", "anthropic", "ollama"], case_sensitive=False))
@click.option("--apply-suppressions", is_flag=True, default=False)
@click.option("--skip-static", is_flag=True, default=False,
              help="Skip the deterministic detector pass (not recommended).")
@click.option("--no-docs", is_flag=True, default=False)
@click.option("--online", is_flag=True, default=False,
              help="Opt-in: fetch inventoried https links and query OSV for pinned deps.")
@click.option("--quiet", "-q", is_flag=True, default=False)
def autonomous(target, output, also_json, lang, use_llm, llm_provider,
               apply_suppressions, skip_static, no_docs, online, quiet):
    """Read a whole project and run the autonomous AI auditor.

    Offline by default. Trains (or reuses) a local knowledge index built
    from real exploits, then reasons about business logic, math, on-chain
    behaviour, and dependency versions. Pass --online to fetch inventoried
    documentation links and query OSV for pinned dependencies. Pass --llm
    to add a cloud/local model on top of the symbolic pass.
    """
    from self_tool.autonomous.pipeline import exit_code_for, run_autonomous_audit

    if not quiet:
        console.print(
            f"[bold red]SELF v{__version__}[/bold red] "
            "[white]autonomous auditor[/white]"
        )
    try:
        audit = run_autonomous_audit(
            target,
            output=output,
            also_json=also_json,
            force_lang=lang,
            use_llm=use_llm,
            llm_provider=llm_provider,
            apply_suppressions=apply_suppressions,
            skip_static=skip_static,
            no_docs=no_docs,
            online=online,
        )
    except FileNotFoundError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(4)
    except Exception as exc:
        console.print(f"[bold red]Incomplete audit:[/bold red] {type(exc).__name__}: {exc}")
        sys.exit(3)

    if not quiet:
        _print_summary(audit)
    report_path = audit.trained_on.get("report_path", "")
    if report_path:
        console.print(f"[bold green]Report:[/bold green] [cyan]{report_path}[/cyan]")
    sys.exit(exit_code_for(audit))


@click.command("train")
@click.argument("extras", nargs=-1, type=click.Path(exists=True, dir_okay=False))
@click.option("--reset", is_flag=True, default=False, help="Rebuild the index from scratch.")
@click.option("--status", "show_status", is_flag=True, default=False, help="Show index stats only.")
@click.option("--json", "as_json", is_flag=True, default=False)
def train(extras, reset, show_status, as_json):
    """Train the local knowledge index on real exploit / audit data.

    With no arguments, rebuilds the index from the bundled exploit corpus,
    security brain, recent incidents, and expert tactics. Extra JSON files
    (exploit corpus, playbooks, incidents, tactics, or {\"documents\": [...]} )
    deepen the retrieval model.
    """
    from self_tool.autonomous.brain import brain_stats
    from self_tool.autonomous.trainer import index_path, load_index, train as do_train

    if show_status:
        index = load_index()
        payload = {
            "index": index.to_dict() if index else None,
            "bundled": brain_stats(),
            "path": str(index_path()),
        }
        if as_json:
            click.echo(json.dumps(payload, indent=2, sort_keys=True, default=str))
            return
        if index is None:
            click.echo(f"no trained index at {index_path()}")
            click.echo("bundled brain: " + json.dumps(brain_stats(), sort_keys=True))
            return
        click.echo(
            f"index {index_path()}: docs={index.document_count} "
            f"built={index.built_at} sources={len(index.sources)}"
        )
        return

    if reset:
        path = index_path()
        if path.exists():
            path.unlink()

    index = do_train([Path(item) for item in extras])
    if as_json:
        click.echo(json.dumps({
            "documents": index.document_count,
            "built_at": index.built_at,
            "sources": index.sources,
            "path": str(index_path()),
            "bundled": brain_stats(),
        }, indent=2, sort_keys=True))
        return
    click.echo(
        f"trained index with {index.document_count} documents "
        f"from {len(index.sources)} source(s) → {index_path()}"
    )


def _print_summary(audit) -> None:
    table = Table(title="Autonomous audit", show_header=True)
    table.add_column("Surface")
    table.add_column("Count", justify="right")
    table.add_row("Languages", ", ".join(audit.understanding.languages) or "-")
    table.add_row("Contracts / programs", str(len(audit.understanding.contracts)))
    table.add_row("Static findings", str(sum(1 for i in audit.static_issues if not i.suppressed)))
    table.add_row("Autonomous findings", str(len(audit.findings)))
    table.add_row("Exploit paths", str(len(audit.exploit_paths)))
    table.add_row("Dependency hits", str(len(audit.dependencies)))
    table.add_row("Elapsed", f"{audit.elapsed:.2f}s")
    console.print(table)
    if audit.findings:
        console.print("[bold]Top autonomous findings[/bold]")
        for item in audit.findings[:12]:
            console.print(
                f"  {item.severity:8s} {item.id}  {item.title[:70]}  "
                f"[dim]{item.file}:{item.line}[/dim]"
            )
    if audit.exploit_paths:
        console.print("[bold]Exploit paths[/bold]")
        for path in audit.exploit_paths:
            console.print(f"  {path.severity:8s} {path.id}  {path.title}")

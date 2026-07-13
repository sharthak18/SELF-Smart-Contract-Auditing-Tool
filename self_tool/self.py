"""
SELF — Smart Contract Auditing Tool
Main CLI entry point.

Usage:
    self .                      Scan current directory
    self <path>                 Scan specific file or directory
    self . --severity high      Only show high+ findings
    self . --output report.md   Custom output file
    self . --no-info            Hide informational findings
    self . --json               Also output JSON report
    self . --lang solidity      Force language
    self --list-detectors       Show all available detectors
"""

import sys
import json
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
from rich.rule import Rule

from self_tool.core.scanner import discover_files
from self_tool.core.detector_engine import DetectorEngine
from self_tool.core.reporter import generate_report
from self_tool.core.issue import Severity
from self_tool.core.doc_reader import build_protocol_context
from self_tool.core.protocol_context import ProtocolContext
from self_tool.core.detector_catalog import load_detector_catalog
from self_tool.core.knowledge_base import load_security_knowledge, knowledge_coverage
from self_tool.core.builtin_reviewer import REVIEW_PROFILES, review_issues
from self_tool.core.xray import generate_xray_report
from self_tool.version import __version__

console = Console()

BANNER = """
███████╗███████╗██╗     ███████╗
██╔════╝██╔════╝██║     ██╔════╝
███████╗█████╗  ██║     █████╗  
╚════██║██╔══╝  ██║     ██╔══╝  
███████║███████╗███████╗██║     
╚══════╝╚══════╝╚══════╝╚═╝     
"""

TOOL_TAGLINE = "Smart Contract Auditing Tool — The Devil That Kills All Evil"
TOOL_VERSION = __version__

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "bold yellow",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "green",
    Severity.INFO:     "cyan",
}

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🟢",
    Severity.INFO:     "ℹ️ ",
}


def print_banner():
    console.print(f"[bold red]{BANNER}[/bold red]")
    console.print(Panel(
        f"[bold white]{TOOL_TAGLINE}[/bold white]\n"
        f"[dim]Version {TOOL_VERSION} | Python | Multi-Language | Zero Cloud[/dim]\n"
        f"[dim]Sources: Rekt.news · Solodit · Trail of Bits · OpenZeppelin · Pashov · Sherlock · Immunefi[/dim]",
        border_style="red",
        expand=False,
    ))
    console.print()


@click.command()
@click.version_option(version=TOOL_VERSION, prog_name="SELF")
@click.argument("target", default=".", required=False)
@click.option("--severity", "-s", default=None,
              help="Minimum severity to show: critical|high|medium|low|info",
              type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False))
@click.option("--output", "-o", default=None,
              help="Output report file path (default: self-report.md)")
@click.option("--lang", "-l", default=None,
              help="Force language: solidity|vyper|huff|rust|move",
              type=click.Choice(["solidity", "vyper", "huff", "rust", "move", "typescript"], case_sensitive=False))
@click.option("--no-info", is_flag=True, default=False,
              help="Hide informational findings")
@click.option("--json", "output_json", is_flag=True, default=False,
              help="Also generate JSON output (self-report.json)")
@click.option("--list-detectors", is_flag=True, default=False,
              help="List all available detectors and exit")
@click.option("--knowledge-status", is_flag=True, default=False,
              help="Show knowledge sources and OWASP coverage, then exit")
@click.option("--quiet", "-q", is_flag=True, default=False,
              help="Suppress banner and progress, only show summary")
@click.option("--no-docs", is_flag=True, default=False,
              help="Disable documentation and NatSpec context collection")
@click.option("--show-suppressed", is_flag=True, default=False,
              help="Include context-suppressed findings in report")
@click.option("--trust-doc-suppressions", is_flag=True, default=False,
              help="Allow documentation claims to suppress findings (unsafe; off by default)")
@click.option("--xray", is_flag=True, default=False,
              help="Generate a deterministic pre-audit attack-surface report")
@click.option("--xray-output", default=None,
              help="X-ray report path (default: self-xray.md beside the target)")
def cli(target, severity, output, lang, no_info, output_json, list_detectors,
        knowledge_status, quiet,
        no_docs, show_suppressed,
        trust_doc_suppressions, xray, xray_output):
    """
    \b
    SELF — Smart Contract Auditing Tool
    Scan smart contract codebases for security vulnerabilities.

    \b
    Examples:
      self .                    Scan current directory
      self src/Contract.sol     Scan a single file
      self . -s high            Only report high+ severity
      self . -o my-report.md    Custom report filename
    """
    if not quiet:
        print_banner()

    # ── List detectors mode ──────────────────────────────────────────────────
    if list_detectors:
        _show_detector_list()
        return
    if knowledge_status:
        _show_knowledge_status()
        return

    # ── Validate target ──────────────────────────────────────────────────────
    target_path = Path(target).resolve()
    if not target_path.exists():
        console.print(f"[bold red]❌ Error:[/bold red] Target not found: `{target}`")
        sys.exit(1)

    # ── Load detectors ───────────────────────────────────────────────────────
    severity_filter = [severity] if severity else None
    engine = DetectorEngine(
        severity_filter=severity_filter,
        trust_doc_suppressions=trust_doc_suppressions,
    )

    if not quiet:
        console.print(f"[dim]Loaded [bold]{engine.detector_count()}[/bold] rules "
                      f"from {engine.module_count()} detector modules "
                      f"for: {', '.join(engine.supported_languages())}[/dim]")
        console.print()

    # ── Build Protocol Context from docs ─────────────────────────────────────
    protocol_ctx = None
    project_root = str(target_path.parent if target_path.is_file() else target_path)

    if not no_docs:
        try:
            with Progress(
                SpinnerColumn(style="blue"),
                TextColumn("[progress.description]{task.description}"),
                console=console, transient=True, disable=quiet,
            ) as progress:
                progress.add_task("[blue]Reading documentation & NatSpec...", total=None)
                protocol_ctx = build_protocol_context(project_root)
        except Exception as exc:
            console.print(
                f"[bold red]Incomplete audit:[/bold red] "
                f"documentation context failed: {type(exc).__name__}: {exc}"
            )
            sys.exit(3)

        if not quiet and protocol_ctx and protocol_ctx.protocol_name != "Unknown Protocol":
            console.print(
                f"[bold blue]🧠 Protocol:[/bold blue] [white]{protocol_ctx.protocol_name}[/white] "
                f"[dim]({protocol_ctx.protocol_type.upper()})[/dim]"
            )
            signals = []
            if protocol_ctx.uses_multisig:     signals.append("multisig")
            if protocol_ctx.uses_timelock:     signals.append("timelock")
            if protocol_ctx.uses_twap:         signals.append("TWAP")
            if protocol_ctx.uses_chainlink:    signals.append("Chainlink")
            if protocol_ctx.uses_safeERC20:    signals.append("SafeERC20")
            if protocol_ctx.is_upgradeable:    signals.append("upgradeable")
            if signals:
                console.print(f"[dim]   Signals: {', '.join(signals)}[/dim]")
            console.print()

    # ── Discover files & run detectors ───────────────────────────────────────
    start_time = time.time()

    with Progress(
        SpinnerColumn(style="red"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30, style="red"),
        console=console,
        transient=True,
        disable=quiet,
    ) as progress:
        task = progress.add_task("[red]Scanning files...", total=None)
        try:
            files, framework = discover_files(str(target_path), force_lang=lang)
        except Exception as exc:
            progress.stop()
            console.print(
                f"[bold red]Incomplete audit:[/bold red] "
                f"source discovery failed: {type(exc).__name__}: {exc}"
            )
            sys.exit(3)
        if not files:
            progress.stop()
            console.print(
                "[bold red]Error:[/bold red] No supported source files found in the target."
            )
            sys.exit(4)
        progress.update(task, description=f"[red]Found {len(files)} files, running detectors...")
        issues = engine.run(files, protocol_ctx=protocol_ctx)
        try:
            review_issues(issues)
        except ValueError as exc:
            progress.stop()
            console.print(f"[bold red]Incomplete audit:[/bold red] {exc}")
            sys.exit(3)

    elapsed = time.time() - start_time
    if engine.diagnostics:
        console.print(
            f"[bold yellow]Detector health warning:[/bold yellow] "
            f"{len(engine.diagnostics)} detector error(s) occurred."
        )
        for diagnostic in engine.diagnostics[:10]:
            location = f" on {diagnostic.file}" if diagnostic.file else ""
            console.print(
                f"[yellow]- {diagnostic.phase}: {diagnostic.detector}{location}: "
                f"{diagnostic.message}[/yellow]"
            )

    # ── Filter ───────────────────────────────────────────────────────────────
    active_issues = [i for i in issues if not i.suppressed]
    visible_issues = active_issues if not no_info else [
        i for i in active_issues if i.severity != Severity.INFO
    ]
    suppressed_count = sum(1 for i in issues if i.suppressed)

    # ── Print summary to terminal ─────────────────────────────────────────────
    _print_terminal_summary(files, framework, visible_issues, elapsed, target_path,
                            suppressed_count=suppressed_count)

    # ── Determine output path ─────────────────────────────────────────────────
    if output:
        report_path = str(Path(output).resolve())
    else:
        report_path = str(target_path / "self-report.md") if target_path.is_dir() else "self-report.md"

    # ── Generate Markdown report ──────────────────────────────────────────────
    generate_report(
        issues=visible_issues + ([i for i in issues if i.suppressed] if show_suppressed else []),
        files=files,
        framework=framework,
        target=str(target_path),
        output_path=report_path,
        include_info=not no_info,
        protocol_ctx=protocol_ctx,
        show_suppressed=show_suppressed,
    )
    console.print(f"\n[bold green]📄 Report saved:[/bold green] [cyan]{report_path}[/cyan]")
    if suppressed_count:
        console.print(f"[dim]   {suppressed_count} findings suppressed by documentation context "
                      f"(use --show-suppressed to include in report)[/dim]")

    # ── Optional JSON output ──────────────────────────────────────────────────
    if output_json:
        report_file = Path(report_path)
        json_path = str(
            report_file.with_suffix(".json")
            if report_file.suffix.lower() == ".md"
            else Path(str(report_file) + ".json")
        )
        _write_json_report(visible_issues, files, framework, json_path, protocol_ctx)
        console.print(f"[bold green]📊 JSON saved:[/bold green]  [cyan]{json_path}[/cyan]")

    if xray:
        if xray_output:
            xray_path = str(Path(xray_output).resolve())
        else:
            xray_root = target_path if target_path.is_dir() else target_path.parent
            xray_path = str(xray_root / "self-xray.md")
        generate_xray_report(
            files=files,
            framework=framework,
            target=str(target_path),
            output_path=xray_path,
        )
        console.print(f"[bold green]X-ray saved:[/bold green] [cyan]{xray_path}[/cyan]")

    # ── Exit code based on severity ───────────────────────────────────────────
    from self_tool.core.issue import Severity as S
    has_critical = any(i.severity == S.CRITICAL and not i.suppressed for i in issues)
    has_high = any(i.severity == S.HIGH and not i.suppressed for i in issues)
    if engine.diagnostics:
        sys.exit(3)
    if has_critical:
        sys.exit(2)
    elif has_high:
        sys.exit(1)
    else:
        sys.exit(0)


def _print_terminal_summary(files, framework, issues, elapsed, target, suppressed_count=0):
    """Print a rich terminal summary table."""
    from collections import Counter
    # Only count non-suppressed in the active column
    sev_counts = Counter(i.severity for i in issues if not i.suppressed)
    review_count = sum(1 for i in issues if i.review_status)

    console.print(Rule(style="dim red"))

    # Stats row
    stats = Table.grid(padding=(0, 2))
    stats.add_row(
        f"[dim]📁 Files:[/dim] [bold]{len(files)}[/bold]",
        f"[dim]🔧 Framework:[/dim] [bold]{framework.name.capitalize()}[/bold]",
        f"[dim]⏱  Time:[/dim] [bold]{elapsed:.2f}s[/bold]",
        f"[dim]🔕 Suppressed:[/dim] [bold]{suppressed_count}[/bold]" if suppressed_count else "",
        f"[dim]Built-in reviews:[/dim] [bold]{review_count}[/bold]" if review_count else "",
    )
    console.print(stats)
    console.print()

    # Summary table
    table = Table(
        title="[bold]Audit Summary[/bold]",
        box=box.ROUNDED,
        border_style="dim red",
        show_header=True,
        header_style="bold",
    )
    table.add_column("Severity", style="bold", width=12)
    table.add_column("Count", justify="center", width=8)
    table.add_column("Status", width=30)

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        cnt = sev_counts.get(sev, 0)
        emoji = SEVERITY_EMOJI[sev]
        color = SEVERITY_COLORS[sev]
        status = "[bold red]⚠ ACTION REQUIRED[/bold red]" if cnt > 0 and sev in (Severity.CRITICAL, Severity.HIGH) else (
            "[yellow]Review recommended[/yellow]" if cnt > 0 else "[dim green]None found[/dim green]"
        )
        table.add_row(
            f"{emoji} [{color}]{sev}[/{color}]",
            f"[{color}]{cnt}[/{color}]" if cnt > 0 else "[dim]0[/dim]",
            status,
        )
    console.print(table)

    # Per-finding quick list (top 10)
    if issues:
        console.print()
        console.print("[bold]Findings:[/bold]")
        for i, issue in enumerate(issues[:15], 1):
            color = SEVERITY_COLORS.get(issue.severity, "white")
            emoji = SEVERITY_EMOJI.get(issue.severity, "•")
            console.print(
                f"  {emoji} [{color}]{issue.id}[/{color}]  "
                f"[white]{issue.title[:65]}[/white]  "
                f"[dim]{issue.file}:{issue.line}[/dim]"
            )
        if len(issues) > 15:
            console.print(f"  [dim]... and {len(issues)-15} more — see report[/dim]")


def _write_json_report(issues, files, framework, path, protocol_ctx=None):
    """Write machine-readable JSON report."""
    data = {
        "tool": "SELF — Smart Contract Auditing Tool",
        "version": TOOL_VERSION,
        "framework": framework.name,
        "files_scanned": len(files),
        "total_issues": len(issues),
        "protocol": {
            "name": protocol_ctx.protocol_name if protocol_ctx else "Unknown",
            "type": protocol_ctx.protocol_type if protocol_ctx else "unknown",
        } if protocol_ctx else {},
        "issues": [
            {
                "id": i.id,
                "title": i.title,
                "severity": i.severity,
                "confidence": i.confidence,
                "file": i.file,
                "line": i.line,
                "language": i.language,
                "suppressed": i.suppressed,
                "suppression_reason": i.suppression_reason,
                "context_note": i.context_note,
                "review_status": i.review_status,
                "review_reasoning": i.review_reasoning,
                "review_test": i.review_test,
                "review_engine": i.review_engine,
                "references": i.references,
            }
            for i in issues
        ]
    }
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")



def _show_detector_list():
    """Print all available detectors in a table."""
    detectors = load_detector_catalog()

    table = Table(
        title="[bold red]SELF — All Detectors[/bold red]",
        box=box.ROUNDED,
        border_style="dim red",
    )
    table.add_column("ID", style="bold cyan", no_wrap=True)
    table.add_column("Language", style="dim")
    table.add_column("Severity", width=10)
    table.add_column("Description")

    for detector in detectors:
        color = SEVERITY_COLORS.get(detector.severity, "white")
        table.add_row(
            detector.id,
            detector.language.capitalize(),
            f"[{color}]{detector.severity}[/{color}]",
            detector.title,
        )

    console.print(table)
    language_count = len({detector.language for detector in detectors})
    console.print(f"\n[dim]Total: {len(detectors)} rules across {language_count} languages[/dim]")


def _show_knowledge_status():
    """Print source provenance and taxonomy coverage."""
    data = load_security_knowledge()
    detectors = load_detector_catalog()

    console.print(
        f"[bold]Security knowledge schema {data['schema_version']}[/bold] "
        f"[dim](reviewed {data['reviewed_at']})[/dim]"
    )
    console.print(
        f"[bold]Built-in review profiles:[/bold] "
        f"{len(REVIEW_PROFILES)}/{len(detectors)} detector IDs"
    )

    coverage_table = Table(title="OWASP Smart Contract Top 10: 2026 Coverage", box=box.ROUNDED)
    coverage_table.add_column("Category", style="bold cyan")
    coverage_table.add_column("Name")
    coverage_table.add_column("Mapped Rules", justify="right")
    for category in knowledge_coverage(data, detectors):
        coverage_table.add_row(category["id"], category["name"], str(category["mapped"]))
    console.print(coverage_table)

    source_table = Table(title="Knowledge Sources", box=box.ROUNDED)
    source_table.add_column("Source", style="bold")
    source_table.add_column("Kind")
    source_table.add_column("Status")
    source_table.add_column("Ingestion")
    for source in data["sources"]:
        source_table.add_row(
            source["name"],
            source["kind"],
            source["status"],
            source["ingestion"],
        )
    console.print(source_table)


if __name__ == "__main__":
    cli()

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
import os
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
TOOL_VERSION = "2.0.0"

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
@click.option("--quiet", "-q", is_flag=True, default=False,
              help="Suppress banner and progress, only show summary")
# ── Intelligence flags ──────────────────────────────────────────────────
@click.option("--ai", is_flag=True, default=False,
              help="Enable local LLM analysis via Ollama (Critical+High findings)")
@click.option("--ai-all", is_flag=True, default=False,
              help="AI reviews ALL findings including Medium (slower)")
@click.option("--ai-model", default="deepseek-coder:6.7b", show_default=True,
              help="Ollama model to use for AI analysis")
@click.option("--ai-timeout", default=90, show_default=True,
              help="Seconds to wait per finding before skipping AI analysis")
@click.option("--no-docs", is_flag=True, default=False,
              help="Disable documentation reading (skip false-positive suppression)")
@click.option("--show-suppressed", is_flag=True, default=False,
              help="Include context-suppressed findings in report")
def cli(target, severity, output, lang, no_info, output_json, list_detectors, quiet,
        ai, ai_all, ai_model, ai_timeout, no_docs, show_suppressed):
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

    # ── Validate target ──────────────────────────────────────────────────────
    target_path = Path(target).resolve()
    if not target_path.exists():
        console.print(f"[bold red]❌ Error:[/bold red] Target not found: `{target}`")
        sys.exit(1)

    # ── Load detectors ───────────────────────────────────────────────────────
    severity_filter = [severity] if severity else None
    engine = DetectorEngine(severity_filter=severity_filter)

    if not quiet:
        console.print(f"[dim]Loaded [bold]{engine.detector_count()}[/bold] detectors "
                      f"for: {', '.join(engine.supported_languages())}[/dim]")
        console.print()

    # ── Build Protocol Context from docs ─────────────────────────────────────
    protocol_ctx = None
    project_root = str(target_path.parent if target_path.is_file() else target_path)

    if not no_docs:
        with Progress(
            SpinnerColumn(style="blue"),
            TextColumn("[progress.description]{task.description}"),
            console=console, transient=True, disable=quiet,
        ) as progress:
            progress.add_task("[blue]Reading documentation & NatSpec...", total=None)
            protocol_ctx = build_protocol_context(project_root)

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
        files, framework = discover_files(str(target_path), force_lang=lang)
        progress.update(task, description=f"[red]Found {len(files)} files, running detectors...")
        issues = engine.run(files, protocol_ctx=protocol_ctx)

    elapsed = time.time() - start_time

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

    # ── Optional AI Analysis ──────────────────────────────────────────────────
    if ai or ai_all:
        _run_ai_analysis(visible_issues, protocol_ctx, ai_model, ai_timeout,
                         analyze_all=ai_all, quiet=quiet)

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
        json_path = report_path.replace(".md", ".json")
        _write_json_report(visible_issues, files, framework, json_path, protocol_ctx)
        console.print(f"[bold green]📊 JSON saved:[/bold green]  [cyan]{json_path}[/cyan]")

    # ── Exit code based on severity ───────────────────────────────────────────
    from self_tool.core.issue import Severity as S
    has_critical = any(i.severity == S.CRITICAL and not i.suppressed for i in issues)
    has_high = any(i.severity == S.HIGH and not i.suppressed for i in issues)
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
    ai_count = sum(1 for i in issues if i.ai_verdict)

    console.print(Rule(style="dim red"))

    # Stats row
    stats = Table.grid(padding=(0, 2))
    stats.add_row(
        f"[dim]📁 Files:[/dim] [bold]{len(files)}[/bold]",
        f"[dim]🔧 Framework:[/dim] [bold]{framework.name.capitalize()}[/bold]",
        f"[dim]⏱  Time:[/dim] [bold]{elapsed:.2f}s[/bold]",
        f"[dim]🔕 Suppressed:[/dim] [bold]{suppressed_count}[/bold]" if suppressed_count else "",
        f"[dim]🤖 AI reviews:[/dim] [bold]{ai_count}[/bold]" if ai_count else "",
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


def _run_ai_analysis(issues, protocol_ctx, model, timeout, analyze_all, quiet):
    """Run LLM analysis on flagged findings."""
    try:
        from self_tool.core.llm_analyzer import create_analyzer
    except ImportError:
        console.print("[yellow]⚠ LLM analyzer not available.[/yellow]")
        return

    analyzer = create_analyzer(model=model, timeout=timeout, analyze_all=analyze_all)
    available, msg = analyzer.check()
    if not available:
        console.print(f"[yellow]⚠ AI analysis skipped: {msg}[/yellow]")
        console.print("[dim]  Install: pip install ollama && ollama pull deepseek-coder:6.7b[/dim]")
        return

    from self_tool.core.issue import Severity as S
    if analyze_all:
        to_review = [i for i in issues if not i.suppressed]
    else:
        to_review = [i for i in issues if not i.suppressed
                     and i.severity in (S.CRITICAL, S.HIGH)]

    if not to_review:
        return

    console.print(f"\n[bold blue]🤖 AI Analysis:[/bold blue] reviewing {len(to_review)} findings "
                  f"via [cyan]{model}[/cyan]")

    from self_tool.core.protocol_context import EMPTY_CONTEXT
    ctx = protocol_ctx or EMPTY_CONTEXT

    with Progress(
        SpinnerColumn(style="blue"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=25, style="blue"),
        console=console,
        transient=False,
        disable=quiet,
    ) as progress:
        task = progress.add_task("[blue]AI reviewing...", total=len(to_review))

        def on_progress(idx, total, issue):
            progress.update(task,
                            completed=idx,
                            description=f"[blue]AI: {issue.id} — {issue.title[:40]}...")

        analyzer.analyze(to_review, ctx, progress_callback=on_progress)
        progress.update(task, completed=len(to_review), description="[blue]AI analysis complete")

    fp_count   = sum(1 for i in to_review if i.ai_verdict == "LIKELY_FALSE_POSITIVE")
    confirmed  = sum(1 for i in to_review if i.ai_verdict == "CONFIRMED")
    uncertain  = len(to_review) - confirmed - fp_count
    console.print(f"[dim]   ✅ Confirmed: {confirmed}  ⚠️  Likely FP: {fp_count}  "
                  f"❓ Uncertain: {uncertain}[/dim]")


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
                "ai_verdict": i.ai_verdict,
                "ai_reasoning": i.ai_reasoning,
                "references": i.references,
            }
            for i in issues
        ]
    }
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")



def _show_detector_list():
    """Print all available detectors in a table."""
    detectors = [
        # CRITICAL
        ("SOL-CRIT-001", "Solidity", "CRITICAL", "Reentrancy: Classic (CEI Violation)"),
        ("SOL-CRIT-002", "Solidity", "CRITICAL", "Reentrancy: Cross-Function"),
        ("SOL-CRIT-003", "Solidity", "CRITICAL", "Reentrancy: Read-Only (Curve pattern)"),
        ("SOL-CRIT-004", "Solidity", "CRITICAL", "Unchecked .call() Return Value"),
        ("SOL-CRIT-005", "Solidity", "CRITICAL", "Arbitrary DELEGATECALL"),
        ("SOL-CRIT-006", "Solidity", "CRITICAL", "Unprotected selfdestruct"),
        ("SOL-CRIT-007", "Solidity", "CRITICAL", "Uninitialized Proxy (missing initializer)"),
        ("SOL-CRIT-008", "Solidity", "CRITICAL", "Proxy Storage Collision"),
        ("SOL-CRIT-009", "Solidity", "CRITICAL", "tx.origin Authentication"),
        ("SOL-CRIT-010", "Solidity", "CRITICAL", "Signature Replay (no nonce/chainId)"),
        # HIGH
        ("SOL-HIGH-001", "Solidity", "HIGH", "Oracle Spot Price (no TWAP)"),
        ("SOL-HIGH-002", "Solidity", "HIGH", "Integer Overflow (pre-0.8, no SafeMath)"),
        ("SOL-HIGH-003", "Solidity", "HIGH", "Unchecked Math in unchecked{} block"),
        ("SOL-HIGH-004", "Solidity", "HIGH", "Flash Loan Callback No Validation"),
        ("SOL-HIGH-005", "Solidity", "HIGH", "Missing Access Control on Critical Function"),
        ("SOL-HIGH-006", "Solidity", "HIGH", "ERC20 approve() Race Condition"),
        ("SOL-HIGH-007", "Solidity", "HIGH", "Unbounded Loop DoS"),
        ("SOL-HIGH-008", "Solidity", "HIGH", "ERC20 transfer() Return Unchecked"),
        ("SOL-HIGH-009", "Solidity", "HIGH", "Zero Slippage — MEV/Sandwich Attack"),
        ("SOL-HIGH-010", "Solidity", "HIGH", "block.timestamp as Randomness"),
        ("SOL-HIGH-011", "Solidity", "HIGH", "Divide-Before-Multiply"),
        ("SOL-HIGH-012", "Solidity", "HIGH", "Flash Loan Governance Attack"),
        ("SOL-HIGH-013", "Solidity", "HIGH", "Unprotected initialize()"),
        # MEDIUM
        ("SOL-MED-001", "Solidity", "MEDIUM", "Centralization Risk"),
        ("SOL-MED-002", "Solidity", "MEDIUM", "Missing Zero-Address Check"),
        ("SOL-MED-003", "Solidity", "MEDIUM", "Missing Deadline on Swap/Permit"),
        ("SOL-MED-004", "Solidity", "MEDIUM", "Stale Chainlink Price Feed"),
        ("SOL-MED-005", "Solidity", "MEDIUM", "ERC777 Reentrancy Hook"),
        ("SOL-MED-006", "Solidity", "MEDIUM", "Missing Event on State Change"),
        ("SOL-MED-007", "Solidity", "MEDIUM", "Unsafe Downcast (Truncation)"),
        ("SOL-MED-008", "Solidity", "MEDIUM", "Divide-Before-Multiply (Percentage)"),
        ("SOL-MED-009", "Solidity", "MEDIUM", "Gas Griefing (Hardcoded Gas)"),
        ("SOL-MED-010", "Solidity", "MEDIUM", "ERC-4626 Inflation Attack"),
        ("SOL-MED-011", "Solidity", "MEDIUM", "Push Payment Loop DoS"),
        ("SOL-MED-012", "Solidity", "MEDIUM", "msg.value Reuse in Loop"),
        # LOW/INFO
        ("SOL-LOW-001", "Solidity", "LOW",    "Floating Pragma"),
        ("SOL-LOW-002", "Solidity", "LOW",    "Outdated Compiler Version"),
        ("SOL-LOW-003", "Solidity", "LOW",    "Shadowed State Variable"),
        ("SOL-LOW-004", "Solidity", "LOW",    "Hardcoded Address"),
        ("SOL-LOW-005", "Solidity", "LOW",    "Magic Numbers"),
        ("SOL-LOW-006", "Solidity", "LOW",    "Missing NatSpec Documentation"),
        ("SOL-LOW-007", "Solidity", "LOW",    "Deprecated Functions (suicide/throw/sha3)"),
        ("SOL-INFO-001", "Solidity", "INFO",  "Inline Assembly Detected"),
        ("SOL-INFO-002", "Solidity", "INFO",  "Upgradeable Contract Detected"),
        ("SOL-INFO-003", "Solidity", "INFO",  "External Protocol Dependencies"),
        # VYPER
        ("VYP-CRIT-001", "Vyper",   "CRITICAL", "Reentrancy Lock Bug / Missing @nonreentrant"),
        ("VYP-CRIT-002", "Vyper",   "CRITICAL", "raw_call() Return Value Unchecked"),
        ("VYP-HIGH-001", "Vyper",   "HIGH",     "slice() Without Bounds Validation"),
        ("VYP-HIGH-002", "Vyper",   "HIGH",     "** Operator Overflow"),
        ("VYP-INFO-001", "Vyper",   "HIGH",     "Outdated Vyper Version (Known CVEs)"),
        # RUST/SOLANA
        ("SOL-RUST-001", "Rust",    "CRITICAL", "Missing Signer Check (Anchor)"),
        ("SOL-RUST-002", "Rust",    "HIGH",     "Missing Owner Check"),
        ("SOL-RUST-003", "Rust",    "CRITICAL", "Arbitrary CPI"),
        ("SOL-RUST-004", "Rust",    "HIGH",     "PDA Without Canonical Bump"),
        ("SOL-RUST-005", "Rust",    "HIGH",     "Unchecked Arithmetic in Release"),
        ("SOL-RUST-006", "Rust",    "MEDIUM",   "Stale Account Data After CPI"),
        # HUFF
        ("HUFF-CRIT-001", "Huff",  "CRITICAL", "Stack Underflow in Macro"),
        ("HUFF-HIGH-001", "Huff",  "HIGH",     "Missing RETURN/STOP in MAIN"),
        ("HUFF-HIGH-002", "Huff",  "HIGH",     "CALLVALUE Unchecked"),
        ("HUFF-MED-001",  "Huff",  "MEDIUM",   "CALLDATASIZE Not Validated"),
        # MOVE
        ("MOV-CRIT-001", "Move",   "CRITICAL", "Entry Function Missing Signer"),
        ("MOV-CRIT-002", "Move",   "CRITICAL", "borrow_global Without acquires"),
        ("MOV-HIGH-001", "Move",   "HIGH",     "Unchecked Capability Usage"),
        ("MOV-HIGH-002", "Move",   "HIGH",     "Unchecked Arithmetic"),
        ("MOV-HIGH-003", "Move",   "HIGH",     "Global State Write Without Auth"),
    ]

    table = Table(
        title="[bold red]SELF — All Detectors[/bold red]",
        box=box.ROUNDED,
        border_style="dim red",
    )
    table.add_column("ID", style="bold cyan", no_wrap=True)
    table.add_column("Language", style="dim")
    table.add_column("Severity", width=10)
    table.add_column("Description")

    for det_id, lang, sev, desc in detectors:
        color = SEVERITY_COLORS.get(sev, "white")
        table.add_row(det_id, lang, f"[{color}]{sev}[/{color}]", desc)

    console.print(table)
    console.print(f"\n[dim]Total: {len(detectors)} detectors across 5 languages[/dim]")


if __name__ == "__main__":
    cli()

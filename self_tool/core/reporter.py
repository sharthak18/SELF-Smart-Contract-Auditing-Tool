"""
SELF — Smart Contract Exploit & Logic Finder
Report generator: produces professional Markdown audit reports.
Phase 3: Includes AI verdict column, suppression context, protocol context summary.
"""

import datetime
from collections import Counter
from pathlib import Path
from typing import List, Dict, Optional

from self_tool.core.issue import Issue, Severity
from self_tool.core.scanner import FrameworkInfo, FileContext
from self_tool.core.protocol_context import ProtocolContext


TOOL_VERSION = "2.0.0"

SEVERITY_BADGE = {
    Severity.CRITICAL: "🔴 **CRITICAL**",
    Severity.HIGH:     "🟠 **HIGH**",
    Severity.MEDIUM:   "🟡 **MEDIUM**",
    Severity.LOW:      "🟢 **LOW**",
    Severity.INFO:     "ℹ️ **INFO**",
}

CONFIDENCE_BADGE = {
    "High":   "🔵 High",
    "Medium": "🟣 Medium",
    "Low":    "🟤 Low",
}

AI_VERDICT_BADGE = {
    "CONFIRMED":             "✅ Confirmed",
    "LIKELY_FALSE_POSITIVE": "⚠️ Likely False Positive",
    "UNCERTAIN":             "❓ Uncertain",
}


def generate_report(
    issues: List[Issue],
    files: List[FileContext],
    framework: FrameworkInfo,
    target: str,
    output_path: str,
    include_info: bool = True,
    protocol_ctx: Optional[ProtocolContext] = None,
    show_suppressed: bool = False,
) -> str:
    """Generate the full Markdown audit report and write it to output_path."""
    project_name = Path(target).resolve().name or "Unknown Project"
    scan_time = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    total_lines = sum(f.line_count for f in files)
    lang_counts: Counter = Counter(f.language for f in files)

    # Separate active vs suppressed issues
    active_issues = [i for i in issues if not i.suppressed]
    suppressed_issues = [i for i in issues if i.suppressed]

    if not include_info:
        active_issues = [i for i in active_issues if i.severity != Severity.INFO]
        suppressed_issues = [i for i in suppressed_issues if i.severity != Severity.INFO]

    # Count by severity (active only)
    sev_counts: Dict[str, int] = {s: 0 for s in [
        Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
    ]}
    for issue in active_issues:
        sev_counts[issue.severity] = sev_counts.get(issue.severity, 0) + 1

    has_ai = any(i.ai_verdict for i in issues)
    sections = []

    # ── Header ──────────────────────────────────────────────────────────────
    sections.append(f"""# SELF Audit Report

> **SELF — Smart Contract Exploit & Logic Finder** v{TOOL_VERSION}
> Powered by hardcoded exploit-class detectors sourced from Rekt.news, Solodit,
> Trail of Bits, OpenZeppelin, and Pashov Audit Group methodology.
{'> 🧠 **AI-Assisted Analysis** enabled via Ollama local LLM.' if has_ai else ''}

---

## Project Info

| Field | Value |
|-------|-------|
| **Project** | `{project_name}` |
| **Scan Date** | {scan_time} |
| **Framework** | {framework.name.capitalize()} |
| **Files Scanned** | {len(files)} |
| **Total Lines** | {total_lines:,} |
| **Languages** | {", ".join(f"{lang} ({cnt})" for lang, cnt in sorted(lang_counts.items()))} |
""")

    # ── Protocol Context (if doc reader ran) ─────────────────────────────────
    if protocol_ctx and protocol_ctx.protocol_name != "Unknown Protocol":
        sections.append(_format_protocol_context(protocol_ctx, suppressed_issues))

    # ── Summary Table ────────────────────────────────────────────────────────
    total_active = sum(sev_counts.values())
    sections.append(f"""---

## Summary

| Severity | Active Findings | Suppressed by Context |
|----------|:--------------:|:--------------------:|
| 🔴 Critical | **{sev_counts[Severity.CRITICAL]}** | {sum(1 for i in suppressed_issues if i.severity == Severity.CRITICAL)} |
| 🟠 High | **{sev_counts[Severity.HIGH]}** | {sum(1 for i in suppressed_issues if i.severity == Severity.HIGH)} |
| 🟡 Medium | **{sev_counts[Severity.MEDIUM]}** | {sum(1 for i in suppressed_issues if i.severity == Severity.MEDIUM)} |
| 🟢 Low | **{sev_counts[Severity.LOW]}** | {sum(1 for i in suppressed_issues if i.severity == Severity.LOW)} |
| ℹ️ Info | **{sev_counts[Severity.INFO]}** | {sum(1 for i in suppressed_issues if i.severity == Severity.INFO)} |
| **Total** | **{total_active}** | {len(suppressed_issues)} |
""")

    if total_active == 0:
        sections.append("""
> ✅ **No active issues detected.** The codebase appears clean for the detectors run.
> This does not guarantee the absence of vulnerabilities. Always combine tool
> output with expert manual review.
""")
    else:
        if sev_counts[Severity.CRITICAL] > 0:
            risk = "🔴 **CRITICAL RISK** — Immediate action required before any deployment."
        elif sev_counts[Severity.HIGH] > 0:
            risk = "🟠 **HIGH RISK** — Significant vulnerabilities found. Do not deploy without fixing."
        elif sev_counts[Severity.MEDIUM] > 0:
            risk = "🟡 **MEDIUM RISK** — Vulnerabilities found that should be addressed."
        else:
            risk = "🟢 **LOW RISK** — Minor issues found. Review and address before deployment."
        sections.append(f"\n**Overall Risk Assessment:** {risk}\n")

    # ── Findings Index ───────────────────────────────────────────────────────
    if active_issues:
        ai_col = " | AI Verdict" if has_ai else ""
        index_header = f"| # | Severity | ID | Title | Location{ai_col} |"
        index_sep    = f"|---|----------|----|-------|----------{' | ---' if has_ai else ''} |"
        index_rows = []
        for i, issue in enumerate(active_issues, 1):
            ai_cell = ""
            if has_ai and issue.ai_verdict:
                ai_cell = f" | {AI_VERDICT_BADGE.get(issue.ai_verdict, issue.ai_verdict)}"
            index_rows.append(
                f"| {i} | {SEVERITY_BADGE[issue.severity]} "
                f"| [{issue.id}](#{issue.id.lower()}) "
                f"| {issue.title[:70]} "
                f"| `{issue.file}:{issue.line}`"
                f"{ai_cell} |"
            )
        sections.append(f"""---

## Findings Index

{index_header}
{index_sep}
""" + "\n".join(index_rows) + "\n")

    # ── Detailed Findings ────────────────────────────────────────────────────
    if active_issues:
        sections.append("---\n\n## Detailed Findings\n")

    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        group = [i for i in active_issues if i.severity == severity]
        if not group:
            continue
        emoji = Severity.emoji(severity)
        sections.append(f"\n### {emoji} {severity} Findings\n")
        for issue in group:
            sections.append(_format_issue(issue, has_ai))

    # ── Suppressed Findings ──────────────────────────────────────────────────
    if suppressed_issues and show_suppressed:
        sections.append(_format_suppressed_section(suppressed_issues))

    # ── Files Scanned ────────────────────────────────────────────────────────
    sections.append("---\n\n## Files Scanned\n")
    file_rows = [
        f"| `{f.relative_path}` | {f.language.capitalize()} | {f.line_count} |"
        for f in files
    ]
    sections.append(
        "| File | Language | Lines |\n|------|----------|-------|\n"
        + "\n".join(file_rows) + "\n"
    )

    # ── Disclaimer ───────────────────────────────────────────────────────────
    ai_note = (
        "\n\nThis report includes **AI-assisted analysis** via a local Ollama model. "
        "AI verdicts are advisory only and should be verified by a human auditor."
        if has_ai else ""
    )
    sections.append(f"""---

## Disclaimer

This report was generated by **SELF — Smart Contract Exploit & Logic Finder**.
It is an automated static analysis tool and may produce false positives or miss
complex, protocol-specific vulnerabilities. This report is **not a substitute**
for a professional manual security audit.{ai_note}

**Always:**
- Conduct manual expert review alongside automated tools
- Write comprehensive test suites including fuzz tests
- Have your code audited by an experienced security firm before mainnet deployment

---
*Generated by SELF v{TOOL_VERSION} | github.com/self-auditor/self*
""")

    report_content = "\n".join(sections)
    Path(output_path).write_text(report_content, encoding="utf-8")
    return report_content


def _format_protocol_context(ctx: ProtocolContext, suppressed: List[Issue]) -> str:
    """Format the protocol intelligence summary section."""
    signals = []
    if ctx.uses_multisig:       signals.append("✅ Multisig ownership documented")
    if ctx.uses_timelock:       signals.append("✅ Timelock documented")
    if ctx.uses_twap:           signals.append("✅ TWAP oracle documented")
    if ctx.uses_chainlink:      signals.append("✅ Chainlink oracle documented")
    if ctx.uses_safeERC20:      signals.append("✅ SafeERC20 used")
    if ctx.uses_reentrancy_guard: signals.append("✅ ReentrancyGuard used")
    if ctx.is_upgradeable:      signals.append("⚠️ Upgradeable proxy pattern")
    if ctx.has_audit_history:   signals.append("✅ Previous audits documented")
    if ctx.has_emergency_pause: signals.append("✅ Emergency pause mechanism")
    if ctx.only_standard_erc20: signals.append("✅ Standard ERC20 only (no FoT)")
    if ctx.supports_fee_on_transfer: signals.append("⚠️ Fee-on-transfer tokens supported")

    signals_str = "\n".join(f"- {s}" for s in signals) if signals else "- No specific signals detected"

    sup_str = ""
    if suppressed:
        sup_str = f"\n\n**Context-Suppressed Findings ({len(suppressed)}):**\n"
        for i in suppressed:
            sup_str += f"- `{i.id}` {i.title[:60]} — *{i.suppression_reason}*\n"

    return f"""---

## 🧠 Protocol Intelligence

| Field | Value |
|-------|-------|
| **Protocol Name** | {ctx.protocol_name} |
| **Protocol Type** | {ctx.protocol_type.upper()} |
| **Description** | {ctx.description[:200] + '...' if len(ctx.description) > 200 else ctx.description} |

**Security Signals Detected from Documentation:**
{signals_str}
{sup_str}
"""


def _format_suppressed_section(issues: List[Issue]) -> str:
    """Format suppressed findings as a collapsed reference section."""
    rows = [
        f"| `{i.id}` | {SEVERITY_BADGE[i.severity]} | {i.title[:60]} | {i.suppression_reason[:80]} |"
        for i in issues
    ]
    return f"""---

## 📋 Suppressed Findings ({len(issues)})

> These findings were detected but suppressed based on documentation context or AI analysis.
> Review manually to confirm they are truly not applicable.

| ID | Severity | Title | Suppression Reason |
|----|----------|-------|--------------------|
""" + "\n".join(rows) + "\n"


def _format_issue(issue: Issue, show_ai: bool = False) -> str:
    """Format a single Issue as a Markdown section."""
    severity_badge = SEVERITY_BADGE.get(issue.severity, issue.severity)
    confidence_badge = CONFIDENCE_BADGE.get(issue.confidence, issue.confidence)

    refs_str = ""
    if issue.references:
        refs_str = "\n**References:**\n" + "\n".join(f"- {r}" for r in issue.references)

    snippet_block = ""
    if issue.snippet:
        snippet_block = f"""
**Vulnerable Code:**
```solidity
{issue.snippet}
```"""

    ai_block = ""
    if show_ai and issue.ai_verdict:
        verdict_badge = AI_VERDICT_BADGE.get(issue.ai_verdict, issue.ai_verdict)
        ai_block = f"""
**🤖 AI Analysis** *(via {issue.ai_model or 'local LLM'})*
> **Verdict:** {verdict_badge}
> {issue.ai_reasoning or 'No reasoning provided.'}
"""

    return f"""
---

#### [{issue.id}] {issue.title}

| Field | Value |
|-------|-------|
| **Severity** | {severity_badge} |
| **Confidence** | {confidence_badge} |
| **File** | `{issue.file}` |
| **Line** | {issue.line if issue.line > 0 else "N/A (file-level)"} |
| **Language** | {issue.language.capitalize()} |

**Description:**
{issue.description}
{snippet_block}
**Exploit Scenario:**
{issue.exploit_scenario}

**Remediation:**
{issue.remediation}
{ai_block}{refs_str}
"""

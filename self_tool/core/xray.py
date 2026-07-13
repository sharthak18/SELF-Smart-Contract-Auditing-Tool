"""Deterministic pre-audit surface mapping for Solidity projects."""

import datetime
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

from self_tool.core.scanner import FileContext, FrameworkInfo
from self_tool.parsers.solidity_parser import SolFunction, parse_solidity
from self_tool.version import __version__


ADMIN_MARKERS = ("onlyowner", "onlyadmin", "default_admin", "governor", "timelock")
NON_ACCESS_MODIFIERS = {
    "nonreentrant", "whennotpaused", "whenpaused", "initializer",
    "reinitializer", "virtual", "override",
}
EXTERNAL_CALL_RE = re.compile(
    r"\b[A-Za-z_]\w*(?:\s*\([^;\n]*?\))?\s*\.\s*"
    r"(call|delegatecall|staticcall|transfer|send|transferFrom|safeTransfer|"
    r"safeTransferFrom|approve|mint|burn)\s*(?:\{|\()"
)
GUARD_RE = re.compile(r"\b(require|assert)\s*\((.+?)\)\s*;", re.DOTALL)
CALLER_CHECK_RE = re.compile(
    r"(?:require\s*\(\s*(?:msg\.sender|tx\.origin)\s*(?:==|!=)|"
    r"if\s*\(\s*(?:msg\.sender|tx\.origin)\s*(?:==|!=)|"
    r"(?:msg\.sender|tx\.origin)\s*(?:==|!=))"
)


@dataclass
class EntryPoint:
    file: str
    contract: str
    function: str
    line: int
    access: str
    modifiers: List[str]
    parameters: str
    external_calls: List[str]
    state_writes: List[str]
    value_flow: str
    reentrancy_guard: bool


def _clean_modifiers(modifiers: Sequence[str]) -> List[str]:
    cleaned = []
    for modifier in modifiers:
        lower = modifier.lower()
        if lower in {"uint", "uint256", "address", "bool", "bytes", "string"}:
            continue
        if modifier not in cleaned:
            cleaned.append(modifier)
    return cleaned


def _classify_access(function: SolFunction) -> str:
    modifiers = _clean_modifiers(function.modifiers)
    lowered = [modifier.lower() for modifier in modifiers]
    if any(marker in modifier for marker in ADMIN_MARKERS for modifier in lowered):
        return "admin"
    access_modifiers = [
        modifier for modifier in modifiers
        if modifier.lower() not in NON_ACCESS_MODIFIERS
        and (modifier.lower().startswith("only") or "role" in modifier.lower())
    ]
    if access_modifiers:
        return "role-gated"
    if CALLER_CHECK_RE.search(function.body):
        return "caller-restricted"
    return "permissionless"


def _state_writes(function: SolFunction, state_names: Sequence[str]) -> List[str]:
    writes = []
    for name in state_names:
        pattern = re.compile(
            rf"(?:\b{name}\b(?:\s*\[[^\]]+\])?\s*(?:=|\+=|-=|\*=|/=|\+\+|--)|"
            rf"\bdelete\s+{name}\b|\b{name}\s*\.\s*(?:push|pop)\s*\()"
        )
        if pattern.search(function.body):
            writes.append(name)
    return writes


def _value_flow(function: SolFunction, calls: Sequence[str]) -> str:
    body = function.body
    incoming = function.mutability == "payable" or "transferFrom" in calls
    outgoing = bool(
        re.search(r"\.call\s*\{\s*value\s*:|\.transfer\s*\(|\.send\s*\(", body)
        or any(call in {"transfer", "safeTransfer"} for call in calls)
    )
    if incoming and outgoing:
        return "in/out"
    if incoming:
        return "in"
    if outgoing:
        return "out"
    return "none"


def analyze_entry_points(files: Sequence[FileContext]) -> Tuple[List[EntryPoint], List[Tuple[str, int, str]]]:
    entry_points: List[EntryPoint] = []
    guards: List[Tuple[str, int, str]] = []

    for file_ctx in files:
        if file_ctx.language != "solidity":
            continue
        info = parse_solidity(file_ctx)
        for contract in info.contracts:
            if contract.kind in {"interface", "library"}:
                continue
            state_names = list(dict.fromkeys(state.name for state in contract.state_vars))
            for function in contract.functions:
                if function.is_constructor or function.mutability in {"view", "pure"}:
                    continue
                if function.visibility not in {"public", "external"}:
                    continue

                calls = sorted({
                    match.group(1) for match in EXTERNAL_CALL_RE.finditer(function.body)
                })
                modifiers = _clean_modifiers(function.modifiers)
                entry_points.append(EntryPoint(
                    file=file_ctx.relative_path,
                    contract=contract.name,
                    function=function.name,
                    line=function.line,
                    access=_classify_access(function),
                    modifiers=modifiers,
                    parameters=" ".join(function.params.split()),
                    external_calls=calls,
                    state_writes=_state_writes(function, state_names),
                    value_flow=_value_flow(function, calls),
                    reentrancy_guard=any(
                        modifier.lower() == "nonreentrant" for modifier in modifiers
                    ),
                ))

                for match in GUARD_RE.finditer(function.body):
                    expression = " ".join(match.group(2).split())
                    if len(expression) > 180:
                        expression = expression[:177] + "..."
                    relative_line = function.body[:match.start()].count("\n")
                    guards.append((
                        f"{file_ctx.relative_path}:{function.line + relative_line}",
                        function.line + relative_line,
                        expression,
                    ))

    entry_points.sort(key=lambda item: (item.file, item.line, item.contract, item.function))
    return entry_points, guards


def _test_posture(root: Path) -> Dict[str, int]:
    result = {"files": 0, "fuzz": 0, "invariant": 0}
    for directory_name in ("test", "tests"):
        directory = root / directory_name
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".sol", ".ts", ".js", ".rs", ".move"}:
                continue
            result["files"] += 1
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            result["fuzz"] += len(re.findall(r"\b(?:testFuzz|fuzz)\w*\b", content, re.IGNORECASE))
            result["invariant"] += len(re.findall(r"\binvariant\w*\b", content, re.IGNORECASE))
    return result


def _git_risk(root: Path) -> Dict[str, object]:
    result: Dict[str, object] = {
        "available": False,
        "recent_commits": [],
        "risk_commits": [],
        "churn": [],
    }
    try:
        completed = subprocess.run(
            [
                "git", "-C", str(root), "log", "-100",
                "--date=short", "--format=commit:%h|%ad|%s", "--numstat", "--", ".",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return result
    if completed.returncode != 0:
        return result

    result["available"] = True
    commits = []
    churn: Counter = Counter()
    risk_pattern = re.compile(
        r"\b(security|vuln|exploit|auth|oracle|upgrade|reentran|hotfix|incident|audit)\b",
        re.IGNORECASE,
    )
    for line in completed.stdout.splitlines():
        if line.startswith("commit:"):
            parts = line[7:].split("|", 2)
            if len(parts) == 3:
                commits.append({"hash": parts[0], "date": parts[1], "subject": parts[2]})
            continue
        fields = line.split("\t")
        if len(fields) == 3 and fields[0].isdigit() and fields[1].isdigit():
            churn[fields[2]] += int(fields[0]) + int(fields[1])

    result["recent_commits"] = commits[:10]
    result["risk_commits"] = [
        commit for commit in commits if risk_pattern.search(commit["subject"])
    ][:10]
    result["churn"] = churn.most_common(10)
    return result


def _md_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def generate_xray_report(
    files: Sequence[FileContext],
    framework: FrameworkInfo,
    target: str,
    output_path: str,
) -> str:
    target_path = Path(target).resolve()
    root = target_path if target_path.is_dir() else target_path.parent
    entry_points, guards = analyze_entry_points(files)
    tests = _test_posture(root)
    git = _git_risk(root)
    solidity_files = [file_ctx for file_ctx in files if file_ctx.language == "solidity"]
    access_counts = Counter(entry.access for entry in entry_points)

    lines = [
        "# SELF X-Ray Pre-Audit Report",
        "",
        f"> Generated by SELF v{__version__} on "
        f"{datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.",
        "> This maps attack surface and review priorities. It does not prove safety.",
        "",
        "## Scope",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Framework | {framework.name} |",
        f"| Solidity files | {len(solidity_files)} |",
        f"| Lines of Solidity | {sum(file.line_count for file in solidity_files)} |",
        f"| State-changing entry points | {len(entry_points)} |",
        f"| Permissionless entry points | {access_counts['permissionless']} |",
        f"| Admin entry points | {access_counts['admin']} |",
        "",
        "## Entry Points",
        "",
        "| Location | Contract.Function | Access | Value | External Calls | State Writes | Guard |",
        "|---|---|---|---|---|---|---|",
    ]

    if entry_points:
        for entry in entry_points:
            lines.append(
                f"| `{entry.file}:{entry.line}` | `{entry.contract}.{entry.function}()` | "
                f"{entry.access} | {entry.value_flow} | "
                f"{_md_cell(', '.join(entry.external_calls) or '-')} | "
                f"{_md_cell(', '.join(entry.state_writes) or '-')} | "
                f"{'nonReentrant' if entry.reentrancy_guard else '-'} |"
            )
    else:
        lines.append("| - | - | - | - | - | - | - |")

    permissionless = [
        entry for entry in entry_points
        if entry.access == "permissionless"
        and (entry.value_flow != "none" or entry.external_calls or entry.state_writes)
    ]
    privileged = [entry for entry in entry_points if entry.access != "permissionless"]

    lines.extend([
        "",
        "## Priority Surfaces",
        "",
        "### Permissionless Value and State Paths",
        "",
    ])
    if permissionless:
        lines.extend(
            f"- `{entry.contract}.{entry.function}()` at `{entry.file}:{entry.line}`: "
            f"value `{entry.value_flow}`, calls `{', '.join(entry.external_calls) or 'none'}`, "
            f"writes `{', '.join(entry.state_writes) or 'unresolved'}`."
            for entry in permissionless
        )
    else:
        lines.append("- No permissionless value/state path was resolved by the static mapper.")

    lines.extend(["", "### Privileged Operations", ""])
    if privileged:
        lines.extend(
            f"- `{entry.access}`: `{entry.contract}.{entry.function}()` "
            f"at `{entry.file}:{entry.line}`."
            for entry in privileged
        )
    else:
        lines.append("- No privileged state-changing entry point was identified.")

    lines.extend([
        "",
        "## Code-Enforced Guard Candidates",
        "",
        "> These are extracted predicates, not verified protocol invariants.",
        "",
    ])
    if guards:
        lines.extend(
            f"- `{location}`: `{_md_cell(expression)}`"
            for location, _, expression in guards[:80]
        )
        if len(guards) > 80:
            lines.append(f"- {len(guards) - 80} additional guards omitted from this report.")
    else:
        lines.append("- No `require` or `assert` predicates were extracted from entry points.")

    lines.extend([
        "",
        "## Test Posture",
        "",
        f"- Test source files: **{tests['files']}**",
        f"- Fuzz-style test declarations: **{tests['fuzz']}**",
        f"- Invariant-style declarations: **{tests['invariant']}**",
        "",
        "## Git Change Risk",
        "",
    ])
    if git["available"]:
        churn = git["churn"]
        if churn:
            lines.append("Highest-churn files in the last 100 commits:")
            lines.extend(f"- `{path}`: {changes} changed lines" for path, changes in churn)
        else:
            lines.append("- No numeric churn data was available for this scope.")
        risk_commits = git["risk_commits"]
        if risk_commits:
            lines.append("")
            lines.append("Security-relevant commit subjects:")
            lines.extend(
                f"- `{commit['hash']}` {commit['date']}: {commit['subject']}"
                for commit in risk_commits
            )
    else:
        lines.append("- Git history was unavailable for this target.")

    lines.extend([
        "",
        "## Review Lenses",
        "",
        "Use these as independent passes over the priority surfaces:",
        "",
        "1. Access control and privilege escalation",
        "2. Economic and oracle manipulation",
        "3. Execution traces and reentrancy",
        "4. Invariant and state-transition violations",
        "5. Math, rounding, and boundary values",
        "6. Asymmetric deposit/withdraw and mint/burn paths",
        "7. External dependency and trust-boundary failures",
        "8. Flow gaps between guards, writes, and external calls",
        "",
        "A finding should include a code-level root cause, a concrete trace or numbers, "
        "and the smallest effective remediation. Unproven concerns should remain leads.",
        "",
    ])

    report = "\n".join(lines)
    Path(output_path).write_text(report, encoding="utf-8")
    return report

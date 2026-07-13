"""
SELF — Vyper language detectors
Sources: Rekt.news (Curve Vyper 2023), Vyper security advisories, Trail of Bits
"""
import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext


def detect(file_ctx: FileContext) -> List[Issue]:
    issues = []
    content = file_ctx.content
    _reentrancy_lock(file_ctx, content, issues)
    _slice_bounds(file_ctx, content, issues)
    _unsafe_pow(file_ctx, content, issues)
    _raw_call_unchecked(file_ctx, content, issues)
    _old_vyper_version(file_ctx, content, issues)
    return issues


def _reentrancy_lock(file_ctx, content, issues):
    """VYP-CRIT-001: External calls without @nonreentrant decorator.
    The 2023 Curve exploit was a Vyper reentrancy lock compiler bug in <0.3.8."""
    has_ext_call = bool(re.search(r'(raw_call|send\s*\(|\.transfer\s*\()', content))
    if not has_ext_call:
        return
    has_nonreentrant = bool(re.search(r'@nonreentrant', content))
    version_m = re.search(r'#\s*@version\s+([\d.]+)', content)
    vulnerable_version = False
    if version_m:
        parts = version_m.group(1).split('.')
        try:
            if int(parts[0]) == 0 and int(parts[1]) == 3 and int(parts[2]) < 8:
                vulnerable_version = True
        except (IndexError, ValueError):
            pass
    if not has_nonreentrant or vulnerable_version:
        m = re.search(r'(raw_call|send\s*\()', content)
        line = content[:m.start()].count('\n') + 1 if m else 1
        sev = Severity.CRITICAL if vulnerable_version else Severity.HIGH
        issues.append(Issue(
            id="VYP-CRIT-001",
            title="Vyper Reentrancy: " + ("Vulnerable Compiler Version <0.3.8" if vulnerable_version else "Missing @nonreentrant"),
            severity=sev, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                "Vyper versions 0.2.15, 0.2.16, and 0.3.0 had a broken `@nonreentrant` "
                "lock — the reentrancy guard compiled incorrectly, providing no protection.\n\n"
                "**Real incident:** Curve Finance (2023) — $70M at risk across multiple pools "
                "running vulnerable Vyper versions."
            ) if vulnerable_version else (
                "External calls (raw_call/send) detected without `@nonreentrant` decorator. "
                "Vyper's reentrancy protection requires explicit decoration."
            ),
            exploit_scenario="Attacker re-enters contract mid-execution via ETH callback. State not yet updated — funds withdrawn multiple times.",
            remediation=(
                "1. Upgrade to Vyper >=0.3.8 immediately.\n"
                "2. Add `@nonreentrant('lock')` to all functions with external calls:\n"
                "```vyper\n"
                "@nonreentrant('lock')\n"
                "@external\n"
                "def withdraw(amount: uint256):\n"
                "    ...\n"
                "```"
            ),
            references=["https://rekt.news/curve-vyper-rekt/", "https://github.com/vyperlang/vyper/security/advisories/GHSA-5824-cm3x-3c38"],
            language="vyper",
        ))


def _slice_bounds(file_ctx, content, issues):
    """VYP-HIGH-001: Vyper slice() with unchecked bounds."""
    pattern = re.compile(r'slice\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)', re.MULTILINE)
    for m in pattern.finditer(content):
        surrounding = content[max(0, m.start()-100):m.start()]
        if not re.search(r'(assert|require|<\s*len)', surrounding):
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="VYP-HIGH-001",
                title="Vyper `slice()` Without Bounds Validation",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description="Vyper's `slice()` built-in with runtime-computed length/offset may panic or produce unexpected results if bounds exceed the buffer. Vyper <0.3.4 had a slice bounds check bug.",
                exploit_scenario="Attacker passes crafted offset/length to trigger out-of-bounds read or cause unexpected truncation.",
                remediation="Validate slice bounds before calling: `assert offset + length <= len(data)`. Upgrade to Vyper >=0.3.4.",
                references=["https://github.com/vyperlang/vyper/blob/master/SECURITY.md"],
                language="vyper",
            ))


def _unsafe_pow(file_ctx, content, issues):
    """VYP-HIGH-002: Vyper ** operator overflow risk."""
    pattern = re.compile(r'\w+\s*\*\*\s*\w+', re.MULTILINE)
    if not pattern.search(content):
        return
    version_m = re.search(r'#\s*@version\s+([\d.]+)', content)
    if version_m:
        parts = version_m.group(1).split('.')
        try:
            if int(parts[0]) == 0 and int(parts[1]) >= 4:
                return  # Safe in Vyper >=0.4.0
        except (IndexError, ValueError):
            pass
    m = pattern.search(content)
    line = content[:m.start()].count('\n') + 1
    issues.append(Issue(
        id="VYP-HIGH-002",
        title="Vyper `**` Power Operator: Potential Overflow",
        severity=Severity.HIGH, confidence=Confidence.LOW,
        file=file_ctx.relative_path, line=line,
        snippet=file_ctx.get_snippet(line, context=3),
        description="The `**` operator in Vyper can overflow for large exponents. Vyper <0.4.0 does not always check power overflow in all contexts.",
        exploit_scenario="Large exponent causes overflow — computed value wraps to near-zero, corrupting financial calculations.",
        remediation="Validate exponent bounds before use. Consider fixed-point math libraries instead of raw `**`.",
        references=["Vyper changelog", "https://github.com/vyperlang/vyper/issues"],
        language="vyper",
    ))


def _raw_call_unchecked(file_ctx, content, issues):
    """VYP-CRIT-002: raw_call return value not checked."""
    pattern = re.compile(r'^[ \t]*raw_call\s*\([^)]+\)\s*$', re.MULTILINE)
    for m in pattern.finditer(content):
        # Check if result is captured
        surrounding = content[max(0,m.start()-10):m.end()+10]
        if not re.search(r'(success|result|response|ret)\s*[:=]', surrounding):
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="VYP-CRIT-002",
                title="Vyper `raw_call()` Return Value Not Checked",
                severity=Severity.CRITICAL, confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description="`raw_call()` can fail silently if the return value is not captured. Unlike Solidity, Vyper's `raw_call` does not automatically revert on failure unless `revert_on_failure=True`.",
                exploit_scenario="raw_call to a token transfer fails. Return value ignored. State updated as if transfer succeeded — double accounting.",
                remediation=(
                    "```vyper\n"
                    "success: bool = raw_call(\n"
                    "    token, _data, max_outsize=32, revert_on_failure=False\n"
                    ")\n"
                    "assert success, 'Call failed'\n"
                    "# Or: use revert_on_failure=True (default)\n"
                    "```"
                ),
                references=["Vyper docs: raw_call"],
                language="vyper",
            ))


def _old_vyper_version(file_ctx, content, issues):
    """VYP-INFO-001: Old Vyper version with known bugs."""
    version_m = re.search(r'#\s*@version\s+([\d.]+)', content)
    if not version_m:
        return
    ver = version_m.group(1)
    parts = ver.split('.')
    try:
        major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2] if len(parts) > 2 else 0)
    except (ValueError, IndexError):
        return
    if major == 0 and (minor < 3 or (minor == 3 and patch < 10)):
        line = content[:version_m.start()].count('\n') + 1
        issues.append(Issue(
            id="VYP-INFO-001",
            title=f"Outdated Vyper Version: `{ver}` — Known Security Bugs",
            severity=Severity.INFO, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=1),
            description=(
                f"Vyper `{ver}` has known security vulnerabilities:\n"
                "- 0.2.15, 0.2.16, 0.3.0: Broken nonreentrant lock (Curve hack)\n"
                "- <0.3.4: Slice bounds check bug\n"
                "- <0.3.8: Multiple compiler bugs"
            ),
            exploit_scenario="Compiler bug generates incorrect bytecode — reentrancy guards, bounds checks, or arithmetic may silently fail.",
            remediation="Upgrade to Vyper >=0.3.10 (latest stable). Reaudit all contracts after upgrade.",
            references=["https://github.com/vyperlang/vyper/security/advisories", "https://rekt.news/curve-vyper-rekt/"],
            language="vyper",
        ))

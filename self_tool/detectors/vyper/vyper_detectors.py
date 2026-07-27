"""
SELF — Vyper language detectors
Sources: Rekt.news (Curve Vyper 2023), Vyper security advisories,
Trail of Bits Vyper audit reports, OtterSec Vyper findings.

Detector IDs use prefix VYP-.
"""
import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext
from self_tool.parsers.vyper_parser import parse_vyper



# ──────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────
def detect(file_ctx: FileContext) -> List[Issue]:
    issues: List[Issue] = []
    content = file_ctx.content
    # Heuristic-only detectors (regex over raw text)
    _reentrancy_lock(file_ctx, content, issues)
    _raw_call_unchecked(file_ctx, content, issues)
    _old_vyper_version(file_ctx, content, issues)
    _slice_bounds(file_ctx, content, issues)
    _unsafe_pow(file_ctx, content, issues)
    _send_failure_ignored(file_ctx, content, issues)
    _unsafe_selfdestruct(file_ctx, content, issues)
    _create_from_blueprint_post_cancun(file_ctx, content, issues)
    _raw_call_default_revert(file_ctx, content, issues)
    _default_visibility(file_ctx, content, issues)

    # Parser-aware detectors (require parsed structure)
    info = parse_vyper(file_ctx)
    if info.contracts:
        c = info.contracts[0]
        _missing_access_control_on_privileged(file_ctx, c, issues)
        _division_by_zero_guarded(file_ctx, c, content, issues)
        _unsafe_eth_transfer_no_reentrancy(file_ctx, c, issues)
        _unsafe_erc20_transfer_return(file_ctx, c, issues)
        _unbounded_loop(file_ctx, c, issues)
        _public_state_var_sensitive(file_ctx, c, issues)
        _weak_randomness_blockhash(file_ctx, c, issues)
        _timestamp_dependence(file_ctx, c, content, issues)
    return issues


# ──────────────────────────────────────────────────────────────────────────
# Heuristic detectors (regex over raw text)
# ──────────────────────────────────────────────────────────────────────────
def _reentrancy_lock(file_ctx, content, issues):
    """VYP-CRIT-001: External calls without @nonreentrant decorator.
    The 2023 Curve exploit was a Vyper reentrancy lock compiler bug in <0.3.8.
    Also: missing @nonreentrant on functions performing raw_call/send/transfer."""
    # Parse the file so we can iterate per-function
    info = parse_vyper(file_ctx)
    if not info.contracts:
        return
    # Compiler-version check (single file-wide finding)
    version_m = re.search(r"#\s*@version\s+([\d.]+)", content)
    vulnerable_version = False
    if version_m:
        parts = version_m.group(1).split(".")
        try:
            major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2] if len(parts) > 2 else 0)
            if major == 0 and minor == 3 and patch < 8:
                vulnerable_version = True
            if major == 0 and minor == 2 and patch in (15, 16):
                vulnerable_version = True
        except (ValueError, IndexError):
            pass
    # Per-function checks
    for c in info.contracts:
        for fn in c.functions:
            if fn.is_constructor or fn.is_default:
                continue
            body = fn.body
            if not re.search(r"(raw_call|send\s*\(|\.transfer\s*\()", body):
                continue
            if "@nonreentrant" in fn.decorators and not vulnerable_version:
                continue
            # Find the line of the first external call
            m = re.search(r"(raw_call|send\s*\(|\.transfer\s*\()", body)
            call_line = fn.body_start_line + (body[:m.start()].count("\n") if m else 0)
            sev = Severity.CRITICAL if vulnerable_version else Severity.HIGH
            issues.append(Issue(
                id="VYP-CRIT-001",
                title=(f"Vyper Reentrancy in `{fn.name}()` — "
                       + ("Vulnerable Compiler <0.3.8" if vulnerable_version else "Missing @nonreentrant")),
                severity=sev, confidence=Confidence.HIGH,
                file=file_ctx.relative_path, line=call_line,
                snippet=file_ctx.get_snippet(call_line, context=4),
                description=(
                    "Vyper versions 0.2.15, 0.2.16, and 0.3.0–0.3.7 had a broken `@nonreentrant` "
                    "lock — the reentrancy guard compiled incorrectly, providing no protection.\n\n"
                    "**Real incident:** Curve Finance (2023) — ~$70M drained across multiple pools "
                    "running vulnerable Vyper versions."
                ) if vulnerable_version else (
                    f"Function `{fn.name}()` makes external calls (raw_call/send/transfer) "
                    f"without `@nonreentrant` decorator. Vyper's reentrancy protection requires "
                    f"explicit decoration per function."
                ),
                exploit_scenario=f"Attacker re-enters `{fn.name}()` via callback. State not yet updated — funds withdrawn multiple times.",
                remediation=(
                    f"```vyper\n"
                    f"@nonreentrant('lock')\n"
                    f"@external\n"
                    f"def {fn.name}(...):\n"
                    f"    ...\n"
                    f"```"
                ),
                references=["https://rekt.news/curve-vyper-rekt/", "https://github.com/vyperlang/vyper/security/advisories/GHSA-5824-cm3x-3c38"],
                language="vyper",
            ))


def _raw_call_unchecked(file_ctx, content, issues):
    """VYP-CRIT-002: raw_call with revert_on_failure=False and return not checked."""
    pattern = re.compile(r"^\s*raw_call\s*\([^)]*\)\s*$", re.MULTILINE)
    for m in pattern.finditer(content):
        surrounding = content[max(0, m.start() - 200): m.end() + 50]
        # If `success:` or `result:` is captured before raw_call OR after, it could be checked
        # If raw_call has revert_on_failure=False or no second positional arg with True
        raw_call_args = m.group(0)
        has_revert_false = "revert_on_failure=False" in raw_call_args
        has_explicit_check = re.search(r"(success|result|ret|response)\s*:\s*\w+", surrounding)
        # If result captured, fine. If raw_call standalone without explicit revert_on_failure=True, still risky.
        if has_explicit_check and not has_revert_false:
            continue
        line = content[:m.start()].count("\n") + 1
        sev = Severity.CRITICAL if has_revert_false and not has_explicit_check else Severity.MEDIUM
        issues.append(Issue(
            id="VYP-CRIT-002" if has_revert_false else "VYP-MED-002",
            title=("Vyper `raw_call()` With `revert_on_failure=False` — Return Not Captured"
                   if has_revert_false else "Vyper `raw_call()` Return Value Not Captured"),
            severity=sev, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "`raw_call(..., revert_on_failure=False)` swallows the failure. "
                "The return value must be captured and asserted, or downstream state changes "
                "proceed on a failed call."
            ),
            exploit_scenario="raw_call to a token transfer fails silently. State updates as if transfer succeeded — double accounting / drained funds.",
            remediation=(
                "```vyper\n"
                "success: bool = raw_call(\n"
                "    token, _data, max_outsize=32, revert_on_failure=False\n"
                ")\n"
                "assert success, 'External call failed'\n"
                "# Or omit revert_on_failure=False (defaults to True).\n"
                "```"
            ),
            references=["Vyper docs: raw_call"],
            language="vyper",
        ))


def _old_vyper_version(file_ctx, content, issues):
    """VYP-INFO-001: Old Vyper version with known security bugs."""
    version_m = re.search(r"#\s*@version\s+([\d.]+)", content)
    if not version_m:
        return
    ver = version_m.group(1)
    parts = ver.split(".")
    try:
        major = int(parts[0]); minor = int(parts[1])
        patch = int(parts[2] if len(parts) > 2 else 0)
    except (ValueError, IndexError):
        return
    if major == 0 and (minor < 3 or (minor == 3 and patch < 10)):
        line = content[:version_m.start()].count("\n") + 1
        issues.append(Issue(
            id="VYP-INFO-001",
            title=f"Outdated Vyper Version: `{ver}` — Known Security Bugs",
            severity=Severity.INFO, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=1),
            description=(
                f"Vyper `{ver}` has known security vulnerabilities:\n"
                "- 0.2.15, 0.2.16, 0.3.0–0.3.7: Broken nonreentrant lock (Curve hack)\n"
                "- <0.3.4: Slice bounds check bug\n"
                "- <0.3.10: Multiple compiler bugs\n"
                "- 0.4.0: Breaking storage layout changes"
            ),
            exploit_scenario="Compiler bug generates incorrect bytecode — reentrancy guards, bounds checks, or arithmetic may silently fail.",
            remediation="Upgrade to Vyper >=0.3.10 (latest stable). Reaudit all contracts after upgrade.",
            references=["https://github.com/vyperlang/vyper/security/advisories", "https://rekt.news/curve-vyper-rekt/"],
            language="vyper",
        ))


def _slice_bounds(file_ctx, content, issues):
    """VYP-HIGH-001: slice() with runtime-computed bounds, no assert."""
    pattern = re.compile(r"slice\s*\(\s*\w+(\s*\*\s*\d+)?\s*,\s*[^,]+,\s*[^)]+\)", re.MULTILINE)
    for m in pattern.finditer(content):
        surrounding = content[max(0, m.start() - 200): m.start()]
        if not re.search(r"assert\s+", surrounding):
            line = content[:m.start()].count("\n") + 1
            issues.append(Issue(
                id="VYP-HIGH-001",
                title="Vyper `slice()` Without Bounds Validation",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description="Vyper's `slice()` with runtime-computed length/offset may panic or produce unexpected results if bounds exceed the buffer. Vyper <0.3.4 had a slice bounds check bug.",
                exploit_scenario="Attacker passes crafted offset/length to trigger out-of-bounds read or cause unexpected truncation.",
                remediation="Validate slice bounds before calling: `assert offset + length <= len(data)`. Upgrade to Vyper >=0.3.4.",
                references=["https://github.com/vyperlang/vyper/blob/master/SECURITY.md"],
                language="vyper",
            ))


def _unsafe_pow(file_ctx, content, issues):
    """VYP-HIGH-002: `**` operator overflow risk."""
    pattern = re.compile(r"\w+\s*\*\*\s*\w+", re.MULTILINE)
    if not pattern.search(content):
        return
    version_m = re.search(r"#\s*@version\s+([\d.]+)", content)
    if version_m:
        parts = version_m.group(1).split(".")
        try:
            if int(parts[0]) == 0 and int(parts[1]) >= 4:
                return  # Safe in Vyper >=0.4.0
        except (ValueError, IndexError):
            pass
    m = pattern.search(content)
    line = content[:m.start()].count("\n") + 1
    issues.append(Issue(
        id="VYP-HIGH-002",
        title="Vyper `**` Power Operator: Potential Overflow",
        severity=Severity.HIGH, confidence=Confidence.LOW,
        file=file_ctx.relative_path, line=line,
        snippet=file_ctx.get_snippet(line, context=3),
        description="The `**` operator in Vyper can overflow for large exponents. Vyper <0.4.0 does not always check power overflow in all contexts.",
        exploit_scenario="Large exponent causes overflow — computed value wraps to near-zero, corrupting financial calculations.",
        remediation="Validate exponent bounds before use. Consider fixed-point math libraries instead of raw `**`.",
        references=["Vyper changelog"],
        language="vyper",
    ))


def _send_failure_ignored(file_ctx, content, issues):
    """VYP-HIGH-003: `send()` is unreliable (2300 gas) and failure not checked."""
    pattern = re.compile(r"^\s*(success\s*:\s*\w+\s*=\s*)?send\s*\(", re.MULTILINE)
    for m in pattern.finditer(content):
        # Skip if the return was captured
        if m.group(1):
            continue
        line = content[:m.start()].count("\n") + 1
        issues.append(Issue(
            id="VYP-HIGH-003",
            title="Vyper `send()`: Failure Not Captured — Unreliable for ETH Transfer",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "`send()` forwards only 2300 gas — insufficient for any contract that does work "
                "in its receive/fallback function. Failure must be captured (`success: bool = send(...)`) "
                "and asserted. Prefer `raw_call(to, b'', value=amount)` for contract recipients."
            ),
            exploit_scenario="Recipients with non-trivial fallback (e.g. multisig) silently fail to receive ETH. State updated as if payment succeeded.",
            remediation=(
                "```vyper\n"
                "success: bool = raw_call(to, b'', value=amount, max_outsize=0)\n"
                "assert success\n"
                "```"
            ),
            references=["Vyper docs: send", "Vyper docs: raw_call"],
            language="vyper",
        ))


def _unsafe_selfdestruct(file_ctx, content, issues):
    """VYP-CRIT-003: selfdestruct — forcibly removed in 0.3.10+ EIPs but still in legacy code."""
    pattern = re.compile(r"^\s*selfdestruct\s*\(", re.MULTILINE)
    for m in pattern.finditer(content):
        line = content[:m.start()].count("\n") + 1
        # Check for any access control within the function
        func_start = content.rfind("@external", 0, m.start())
        func_body = content[func_start: m.end() + 200]
        has_owner_check = bool(re.search(r"assert\s+msg\.sender\s*==\s*self\.owner", func_body))
        issues.append(Issue(
            id="VYP-CRIT-003" if not has_owner_check else "VYP-INFO-002",
            title=("Vyper `selfdestruct()` Without Owner Check" if not has_owner_check else "Vyper `selfdestruct()` — Deprecated Post-EIP-6780"),
            severity=Severity.CRITICAL if not has_owner_check else Severity.INFO,
            confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                "selfdestruct on mainnet is effectively a no-op post-EIP-6780 (Dencun) unless "
                "called in the same transaction as creation. On L2s and legacy chains, it still "
                "destroys the contract. Missing access control means anyone can destroy the contract "
                "and seize its balance."
            ),
            exploit_scenario="Attacker calls selfdestruct, contract is destroyed, remaining ETH locked or sent to attacker.",
            remediation=(
                "Remove selfdestruct entirely. Use a pause/unpause pattern. If you must retain "
                "kill switch, gate it behind a multisig + timelock."
            ),
            references=["EIP-6780", "https://eips.ethereum.org/EIPS/eip-6780"],
            language="vyper",
        ))


def _create_from_blueprint_post_cancun(file_ctx, content, issues):
    """VYP-MED-003: create_from_blueprint — checks post-Cancun behavior."""
    if not re.search(r"create_from_blueprint", content):
        return
    version_m = re.search(r"#\s*@version\s+([\d.]+)", content)
    if version_m:
        parts = version_m.group(1).split(".")
        try:
            if int(parts[0]) == 0 and int(parts[1]) >= 4:
                return  # safe in 0.4.x
        except (ValueError, IndexError):
            pass
    m = re.search(r"create_from_blueprint", content)
    line = content[:m.start()].count("\n") + 1
    issues.append(Issue(
        id="VYP-MED-003",
        title="Vyper `create_from_blueprint` — Verify Post-Cancun Behavior",
        severity=Severity.MEDIUM, confidence=Confidence.LOW,
        file=file_ctx.relative_path, line=line,
        snippet=file_ctx.get_snippet(line, context=3),
        description=(
            "`create_from_blueprint` semantics changed after EIP-6780 (Cancun). Audit this "
            "call manually — ensure it is not relied upon as an atomic initialization primitive."
        ),
        exploit_scenario="Blueprint creation behaves differently than expected post-Dencun upgrade.",
        remediation="Upgrade to Vyper >=0.4.0 and reaudit blueprint deployment flow.",
        references=["EIP-6780"],
        language="vyper",
    ))


def _raw_call_default_revert(file_ctx, content, issues):
    """VYP-INFO-003: raw_call with no explicit revert_on_failure argument (silent)."""
    # Match raw_call that doesn't specify revert_on_failure
    pat = re.compile(r"raw_call\s*\(\s*[^\n]+?\)", re.MULTILINE)
    for m in pat.finditer(content):
        call = m.group(0)
        if "revert_on_failure" in call or "max_outsize" not in call:
            continue  # explicit or no max_outsize (means default)
        # Heuristic: only flag if used in a state-modifying context (no `@view`)
        # We can't easily check, so low confidence
        line = content[:m.start()].count("\n") + 1
        issues.append(Issue(
            id="VYP-INFO-003",
            title="Vyper `raw_call()` Without `revert_on_failure` Argument",
            severity=Severity.INFO, confidence=Confidence.LOW,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "For readability and explicitness, always pass `revert_on_failure=True|False` "
                "as a keyword argument to `raw_call`. The default is `True` but relies on the "
                "caller knowing the default."
            ),
            exploit_scenario="Future Vyper version changes default, behavior diverges silently.",
            remediation="Add explicit `revert_on_failure=True` or `=False` to every raw_call.",
            references=["Vyper docs"],
            language="vyper",
        ))


def _default_visibility(file_ctx, content, issues):
    """VYP-HIGH-004: function without @external/@internal decorator (0.2.x only)."""
    # In 0.3+, all functions must have decorator. In 0.2.x, top-level def is public.
    version_m = re.search(r"#\s*@version\s+([\d.]+)", content)
    if not version_m:
        return
    parts = version_m.group(1).split(".")
    try:
        if int(parts[0]) == 0 and int(parts[1]) >= 3:
            return  # 0.3+ requires explicit decorator, won't compile without
    except (ValueError, IndexError):
        return
    # 0.2.x: look for `def fn(` not preceded by decorator
    func_re = re.compile(r"^def\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE)
    for m in func_re.finditer(content):
        fname = m.group(1)
        if fname in ("__init__", "__default__"):
            continue
        line = content[:m.start()].count("\n") + 1
        issues.append(Issue(
            id="VYP-HIGH-004",
            title=f"Vyper 0.2.x: Function `{fname}()` Default Public Visibility",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "In Vyper 0.2.x, top-level `def` is public by default. Sensitive functions "
                "may be unintentionally callable. Always use explicit `@internal` for helpers."
            ),
            exploit_scenario="Sensitive helper function callable by external actors.",
            remediation="Upgrade to Vyper >=0.3.0 and use explicit `@internal` / `@external` decorators.",
            references=["Vyper 0.3.0 changelog"],
            language="vyper",
        ))


# ──────────────────────────────────────────────────────────────────────────
# Parser-aware detectors
# ──────────────────────────────────────────────────────────────────────────
def _missing_access_control_on_privileged(file_ctx, contract, issues):
    """VYP-CRIT-004: privileged function without msg.sender check."""
    privileged_names = ("owner", "admin", "set_", "emergency", "pause", "unpause",
                        "withdraw", "mint", "burn", "upgrade", "kill", "reset")
    for fn in contract.functions:
        if fn.is_constructor or fn.is_default:
            continue
        if fn.visibility != "external":
            continue
        # Privileged if name contains any marker
        if not any(m in fn.name.lower() for m in privileged_names):
            continue
        # Skip view functions
        if fn.mutability in ("view", "pure"):
            continue
        body = fn.body
        has_auth = bool(re.search(
            r"(assert\s+msg\.sender\s*==\s*self\.owner|"
            r"assert\s+msg\.sender\s*==\s*self\.admin|"
            r"assert\s+self\.owner\s*==\s*msg\.sender)",
            body,
        ))
        if not has_auth:
            issues.append(Issue(
                id="VYP-CRIT-004",
                title=f"Vyper Privileged Function `{fn.name}()` Missing Access Control",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                file=file_ctx.relative_path, line=fn.line,
                snippet=file_ctx.get_snippet(fn.line, context=4),
                description=(
                    f"`{fn.name}()` mutates state but does not assert `msg.sender == self.owner` "
                    f"(or equivalent). Any external caller can invoke it."
                ),
                exploit_scenario=f"Attacker calls `{fn.name}()` directly — drains funds or hijacks admin.",
                remediation=(
                    "```vyper\n"
                    f"@external\n"
                    f"def {fn.name}(...):\n"
                    f"    assert msg.sender == self.owner, 'not owner'\n"
                    "    ...\n"
                    "```"
                ),
                references=["Solidity-style SWC-105", "Vyper access control best practice"],
                language="vyper",
            ))


def _division_by_zero_guarded(file_ctx, contract, content, issues):
    """VYP-HIGH-005: division where denominator could be zero."""
    for fn in contract.functions:
        body = fn.body
        # Find all `... // ...` and `... % ...` where rhs is a state var
        # We only check denominators that read storage or external balance
        divs = re.findall(r"(\w+)\s*//\s*(\w[\w\[\]\.]*)", body)
        for lhs, rhs in divs:
            # Skip if rhs is a literal
            if rhs.isdigit():
                continue
            # Heuristic: risky denominators
            risky = any(tok in rhs for tok in (
                "balanceOf", "totalSupply", "self.", "self.total_", "self.token.",
            ))
            if not risky:
                continue
            # Check for guard
            guard_re = re.search(rf"assert\s+{re.escape(rhs)}\s*[><!=]+\s*0", body)
            if guard_re:
                continue
            issues.append(Issue(
                id="VYP-HIGH-005",
                title=f"Vyper Division by `{rhs}` Without Zero Check",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=fn.line,
                snippet=file_ctx.get_snippet(fn.line, context=4),
                description=(
                    f"Function `{fn.name}()` divides by `{rhs}`. If this value is zero "
                    f"(e.g. before first deposit, or after a full withdraw), the transaction reverts "
                    f"with arithmetic error — DoS for legitimate users."
                ),
                exploit_scenario="Attacker manipulates state so `rhs == 0`, DoS-ing the function.",
                remediation=f"Add `assert {rhs} > 0` before the division.",
                references=["Vyper docs: arithmetic"],
                language="vyper",
            ))


def _unsafe_eth_transfer_no_reentrancy(file_ctx, contract, issues):
    """VYP-CRIT-005: external ETH transfer in non-reentrant function."""
    for fn in contract.functions:
        if "@nonreentrant" in fn.decorators:
            continue
        body = fn.body
        # raw_call with value=, or send(
        if re.search(r"(raw_call\s*\([^)]*value\s*=\s*\w+|^\s*send\s*\()", body, re.MULTILINE):
            # Find the line of the call
            m = re.search(r"(raw_call|send)\s*\(", body)
            if not m:
                continue
            call_line = fn.body_start_line + body[:m.start()].count("\n")
            issues.append(Issue(
                id="VYP-CRIT-005",
                title=f"Vyper `{fn.name}()` Performs ETH Transfer Without @nonreentrant",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                file=file_ctx.relative_path, line=call_line,
                snippet=file_ctx.get_snippet(call_line, context=4),
                description=(
                    f"`{fn.name}()` sends ETH (raw_call with value, or send) without `@nonreentrant`. "
                    f"State updates after the transfer are vulnerable to reentrancy."
                ),
                exploit_scenario="Attacker re-enters via fallback, drains balance before state update.",
                remediation=f"Add `@nonreentrant('lock')` to `{fn.name}`.",
                references=["Vyper reentrancy best practice"],
                language="vyper",
            ))


def _unsafe_erc20_transfer_return(file_ctx, contract, issues):
    """VYP-MED-004: ERC20 transfer/transferFrom called but return not asserted.
    In Vyper, `IERC20(self.token).transfer(...)` is a typed call; failures auto-revert.
    But raw calls to arbitrary tokens may return False silently. This detector flags
    raw calls to token addresses where the return value is discarded.
    """
    for fn in contract.functions:
        body = fn.body
        # raw_call where first arg looks like a token address
        # and the body shape matches ERC20 transfer selector
        # We can't decode selectors easily; instead we look for any raw_call
        # whose returned result isn't captured.
        pat = re.compile(r"raw_call\s*\(\s*([\w\.]+)\s*,\s*([^,]+),\s*([^)]*)\)", re.MULTILINE)
        for m in pat.finditer(body):
            target = m.group(1)
            data = m.group(2)
            kwargs = m.group(3)
            # Only flag if no explicit revert_on_failure=False (meaning success could still be swallowed)
            if "revert_on_failure=False" not in kwargs:
                continue
            # Look ahead 2 lines to see if `success:` is captured
            after = body[m.end(): m.end() + 200]
            if re.search(r"(success|result|res)\s*:\s*\w+", after):
                continue
            line = fn.body_start_line + body[:m.start()].count("\n")
            issues.append(Issue(
                id="VYP-MED-004",
                title=f"Vyper `raw_call()` to `{target}` With `revert_on_failure=False` — No `success` Captured",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description=(
                    "raw_call explicitly opts out of revert on failure but doesn't capture the "
                    "boolean result. The call may have failed and downstream state will be wrong."
                ),
                exploit_scenario="Transfer to fee-on-transfer or blacklistable token fails silently — accounting drift.",
                remediation=(
                    "```vyper\n"
                    "success: bool = raw_call(token, data, max_outsize=32, revert_on_failure=False)\n"
                    "assert success\n"
                    "```"
                ),
                references=["Vyper docs"],
                language="vyper",
            ))


def _unbounded_loop(file_ctx, contract, issues):
    """VYP-MED-005: `for i in range(N)` where N is a state var or unbounded."""
    for fn in contract.functions:
        body = fn.body
        # `for i in range(N):` where N is not a literal
        m = re.search(r"for\s+\w+\s+in\s+range\s*\(\s*([A-Za-z_]\w*)\s*\)", body)
        if not m:
            continue
        rng = m.group(1)
        # If range is a state var or external call, unbounded
        if not rng.isdigit():
            line = fn.body_start_line + body[:m.start()].count("\n")
            issues.append(Issue(
                id="VYP-MED-005",
                title=f"Vyper `for i in range({rng})` — Unbounded Loop in `{fn.name}()`",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=4),
                description=(
                    f"Loop bound `{rng}` is not a literal. An attacker can grow this value "
                    f"until gas exceeds the block limit, DoS-ing `{fn.name}()`."
                ),
                exploit_scenario="Attacker pushes enough items to exceed block gas limit — function reverts for everyone.",
                remediation="Cap loop bound with `assert N < MAX` or paginate.",
                references=["Solidity SWC-128"],
                language="vyper",
            ))


def _public_state_var_sensitive(file_ctx, contract, issues):
    """VYP-LOW-001: public state var exposes sensitive value (read-only reentrancy surface)."""
    sensitive_names = ("balance", "total_supply", "price", "rate", "fee", "owner")
    for v in contract.state_vars:
        if not v.is_public:
            continue
        if not any(s in v.name.lower() for s in sensitive_names):
            continue
        issues.append(Issue(
            id="VYP-LOW-001",
            title=f"Vyper Public State Var `{v.name}` — Read-Only Reentrancy Surface",
            severity=Severity.LOW, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=v.line,
            snippet=file_ctx.get_snippet(v.line, context=2),
            description=(
                f"`{v.name}` is auto-generated as a public getter. Combined with a callback-"
                f"capable token (ERC777/ERC13620/HOOKS), this creates a read-only reentrancy "
                f"surface where attackers see stale state during cross-contract callbacks."
            ),
            exploit_scenario="Attacker sees stale `balance` during a hook callback, exploits time-of-check vs time-of-use.",
            remediation="Add a reentrancy guard to any function that reads this var, or use transient storage.",
            references=["Read-only reentrancy (Uniswap V4, Balancer)"],
            language="vyper",
        ))


def _weak_randomness_blockhash(file_ctx, contract, issues):
    """VYP-HIGH-006: `blockhash`, `block.timestamp`, or `block.prevrandao` used for randomness."""
    for fn in contract.functions:
        body = fn.body
        # Vyper: block.timestamp, block.number, blockhash(...), block.prevrandao
        if re.search(r"(block\.prevrandao|blockhash\s*\(|block\.timestamp\s*%\s*|block\.number\s*%)", body):
            line = fn.line
            issues.append(Issue(
                id="VYP-HIGH-006",
                title=f"Vyper Weak Randomness Source in `{fn.name}()`",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=4),
                description=(
                    "block.prevrandao (formerly block.difficulty), block.timestamp, and block.number "
                    "are all miner/validator-influenceable. Using them as randomness sources is "
                    "manipulable within the same block."
                ),
                exploit_scenario="Validator/sequencer manipulates the source value to bias the random outcome.",
                remediation="Use VRF (Chainlink VRF, drand, or a commit-reveal scheme).",
                references=["SWC-120"],
                language="vyper",
            ))


def _timestamp_dependence(file_ctx, contract, content, issues):
    """VYP-LOW-002: block.timestamp used in a state-changing decision (loose check)."""
    # Stricter than randomness — also flags when used in unlock logic, etc.
    # We avoid duplicating the randomness check by ID prefix.
    for fn in contract.functions:
        if fn.is_constructor or fn.is_default:
            continue
        body = fn.body
        if "block.timestamp" in body and re.search(r"(unlock|deadline|window|period|vest)", body, re.IGNORECASE):
            # This is a tighter match — would already have been flagged as VYP-HIGH-006 if randomness
            # If it has not, flag as low-severity timestamp-dependence.
            if re.search(r"(prevrandao|blockhash)", body):
                continue  # randomness flag handles it
            issues.append(Issue(
                id="VYP-LOW-002",
                title=f"Vyper `block.timestamp` Used in Time-Gated Logic in `{fn.name}()`",
                severity=Severity.LOW, confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=fn.line,
                snippet=file_ctx.get_snippet(fn.line, context=3),
                description=(
                    "Time-gated logic that depends on block.timestamp can be skewed by ~15 seconds "
                    "by validators. Avoid tight windows (<5 minutes) on mainnet."
                ),
                exploit_scenario="Validator nudges timestamp to claim slightly before/after deadline.",
                remediation="Use block.number for tighter windows; widen time tolerances.",
                references=["SWC-116"],
                language="vyper",
            ))

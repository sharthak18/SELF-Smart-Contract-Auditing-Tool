"""
SELF — Taint Tracker (Data Flow Analysis)
Tracks user-controlled values (msg.sender, calldata, function params) flowing
into critical sinks without proper sanitization.

Sources: Trail of Bits, Spearbit, Code4rena top findings, Certora analysis
This catches logic bugs that pure regex cannot — multi-step taint propagation.
"""
import re
from typing import List, Dict, Set, Tuple
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext


# Sources: values controlled by caller
TAINT_SOURCES = {
    'msg.sender', 'msg.value', 'msg.data', 'msg.sig',
    'tx.origin', 'block.timestamp', 'block.number',
    'calldata', 'calldataload', 'calldatacopy',
}

# Critical sinks: operations that must not use unsanitized user input
DANGEROUS_SINKS = {
    'selfdestruct': ('SOL-TAINT-001', Severity.CRITICAL, 'selfdestruct with user-controlled argument'),
    'delegatecall': ('SOL-TAINT-002', Severity.CRITICAL, 'delegatecall with user-controlled target'),
    'call':         ('SOL-TAINT-003', Severity.HIGH,     'external call with user-controlled value'),
    'transfer':     ('SOL-TAINT-004', Severity.HIGH,     'ETH transfer with user-controlled amount'),
    'sstore':       ('SOL-TAINT-005', Severity.HIGH,     'storage write from user-controlled slot'),
}

# Variable assignment patterns — for propagation tracking
RE_ASSIGNMENT = re.compile(
    r'\b(\w+)\s*=\s*([^;]+);',
    re.MULTILINE
)

RE_FUNC_PARAM = re.compile(
    r'function\s+(\w+)\s*\(([^)]*)\)',
    re.MULTILINE
)


def detect(file_ctx: FileContext) -> List[Issue]:
    issues = []
    content = file_ctx.content

    # Per-function taint analysis
    func_pattern = re.compile(
        r'function\s+(\w+)\s*\(([^)]*)\)\s*(?:public|external|internal|private)?[^{]*\{',
        re.MULTILINE
    )

    for func_m in func_pattern.finditer(content):
        fname = func_m.group(1)
        params = func_m.group(2)

        # Extract parameter names (these are tainted if visible from outside)
        is_public = bool(re.search(r'(public|external)', content[func_m.start():func_m.start()+len(func_m.group(0))+20]))

        # Build initial taint set
        tainted: Set[str] = set(TAINT_SOURCES)

        # All parameters of public/external functions are tainted (caller-controlled)
        if is_public:
            param_names = _extract_param_names(params)
            tainted.update(param_names)

        # Extract function body
        func_start = func_m.end()
        depth = 1; i = func_start
        while i < len(content) and depth > 0:
            if content[i] == '{': depth += 1
            elif content[i] == '}': depth -= 1
            i += 1
        body = content[func_start:i]

        # Propagate taint through assignments
        tainted = _propagate_taint(body, tainted)

        # Check sinks
        func_abs_start = func_m.start()
        _check_sinks(file_ctx, body, func_abs_start, fname, tainted, issues, content)

    return issues


def _extract_param_names(params: str) -> List[str]:
    """Extract variable names from function parameter list."""
    names = []
    if not params.strip():
        return names
    for param in params.split(','):
        param = param.strip()
        # Last token in "address memory _addr" is the name
        tokens = param.split()
        if tokens:
            name = tokens[-1].strip('_')
            if name and re.match(r'^[a-zA-Z_]\w*$', name):
                names.append(name)
                names.append(tokens[-1])  # Also with underscore prefix
    return names


def _propagate_taint(body: str, tainted: Set[str]) -> Set[str]:
    """Simple one-pass taint propagation through assignments."""
    changed = True
    iterations = 0
    while changed and iterations < 5:
        changed = False
        iterations += 1
        for m in RE_ASSIGNMENT.finditer(body):
            lhs = m.group(1).strip()
            rhs = m.group(2).strip()
            # If any tainted variable appears in RHS, LHS becomes tainted
            for t in list(tainted):
                if re.search(r'\b' + re.escape(t) + r'\b', rhs):
                    if lhs not in tainted:
                        tainted.add(lhs)
                        changed = True
    return tainted


def _check_sinks(file_ctx, body: str, func_offset: int, fname: str,
                 tainted: Set[str], issues: List[Issue], full_content: str):
    """Check if tainted values reach dangerous sinks."""

    # SOL-TAINT-001: User-controlled selfdestruct target
    sd = re.search(r'selfdestruct\s*\(\s*(\w+)', body)
    if sd:
        arg = sd.group(1)
        if arg in tainted or arg in ('msg.sender', 'to', 'recipient', 'target'):
            line = full_content[:func_offset + sd.start()].count('\n') + 1
            issues.append(Issue(
                id="SOL-TAINT-001",
                title=f"`selfdestruct` Target Controlled by Caller in `{fname}()`",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description=(
                    f"`selfdestruct` in `{fname}()` takes a recipient address derived from "
                    "caller-controlled input. Even with access control on the function, "
                    "an authorized caller can self-destruct the contract and send all ETH "
                    "to an arbitrary address."
                ),
                exploit_scenario="Privileged caller passes attacker address to selfdestruct — all ETH forwarded to attacker.",
                remediation="Hardcode the selfdestruct recipient to a known safe address (treasury, multisig). Never use caller-supplied address.",
                references=["SWC-106", "Trail of Bits: dangerous-sinks"],
                language="solidity",
            ))

    # SOL-TAINT-002: User-controlled delegatecall target
    dc = re.search(r'(\w+)\.delegatecall\s*\(', body)
    if dc:
        target_var = dc.group(1)
        if target_var in tainted or target_var in ('target', 'impl', 'implementation', 'addr'):
            line = full_content[:func_offset + dc.start()].count('\n') + 1
            issues.append(Issue(
                id="SOL-TAINT-002",
                title=f"Tainted `delegatecall` Target in `{fname}()` — Arbitrary Code Execution",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=4),
                description=(
                    "Data flow analysis shows a caller-controlled value reaches the "
                    f"`delegatecall` target in `{fname}()`. An attacker can provide "
                    "a malicious contract address — executing arbitrary code in this "
                    "contract's storage context."
                ),
                exploit_scenario="Attacker passes malicious contract → delegatecall executes it → overwrites owner slot → drains funds.",
                remediation="Never use caller-supplied addresses as delegatecall targets. Whitelist allowed implementations.",
                references=["SWC-112", "Parity Wallet Hack"],
                language="solidity",
            ))

    # SOL-TAINT-003: Tainted amount in ETH send
    call_pattern = re.compile(r'\.call\s*\{\s*value\s*:\s*(\w+)', re.MULTILINE)
    for m in call_pattern.finditer(body):
        amount_var = m.group(1)
        if amount_var in tainted and amount_var not in ('amount', 'value'):
            # Only flag if it's not a validated parameter
            surrounding = body[max(0, m.start()-300):m.start()]
            if not re.search(rf'require\s*\([^)]*{re.escape(amount_var)}', surrounding):
                line = full_content[:func_offset + m.start()].count('\n') + 1
                issues.append(Issue(
                    id="SOL-TAINT-003",
                    title=f"Unvalidated Tainted Amount in ETH Transfer (`{fname}()`)",
                    severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                    file=file_ctx.relative_path, line=line,
                    snippet=file_ctx.get_snippet(line, context=3),
                    description=(
                        f"Data flow: caller-controlled value `{amount_var}` flows into "
                        f"`.call{{value:}}` in `{fname}()` without a `require` bounds check. "
                        "If `{amount_var}` can exceed the contract's balance, the call fails "
                        "silently (if unchecked) or reverts."
                    ),
                    exploit_scenario=f"Attacker passes `{amount_var}` = contract_balance + 1, causing DoS or draining via logic error.",
                    remediation=f"Add: `require({amount_var} <= maxAllowed && {amount_var} <= address(this).balance);`",
                    references=["Solodit: taint-analysis", "Code4rena: unchecked-amount"],
                    language="solidity",
                ))

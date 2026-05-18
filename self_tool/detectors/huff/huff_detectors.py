"""
SELF — Huff language detectors
Sources: Huff documentation, Trail of Bits EVM security, EVM Yellow Paper,
         Huff smart contract security best practices
"""
import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext


def detect(file_ctx: FileContext) -> List[Issue]:
    content = file_ctx.content
    issues = []
    _stack_underflow(file_ctx, content, issues)
    _missing_return(file_ctx, content, issues)
    _callvalue_unchecked(file_ctx, content, issues)
    _calldatasize_unchecked(file_ctx, content, issues)
    return issues


def _stack_underflow(file_ctx, content, issues):
    """HUFF-CRIT-001: Potential stack underflow in macro."""
    # Find macros and check for POP without prior PUSH
    macro_pattern = re.compile(r'#define\s+macro\s+(\w+)\s*\([^)]*\)\s*=\s*takes\s*\((\d+)\)\s*returns\s*\((\d+)\)\s*\{([^}]+)\}', re.DOTALL)
    for m in macro_pattern.finditer(content):
        macro_name = m.group(1)
        takes = int(m.group(2))
        returns = int(m.group(3))
        body = m.group(4)
        # Count pushes and pops (simplified)
        push_count = len(re.findall(r'\bPUSH\d*\b|\bDUP\d+\b|\bSWAP\d+\b', body, re.IGNORECASE))
        pop_count = len(re.findall(r'\bPOP\b|\bADD\b|\bSUB\b|\bMUL\b|\bDIV\b|\bEQ\b|\bLT\b|\bGT\b', body, re.IGNORECASE))
        # Very rough heuristic — flag if more pops than pushes+takes
        if pop_count > push_count + takes + 5:
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="HUFF-CRIT-001",
                title=f"Huff Macro `{macro_name}`: Potential Stack Underflow",
                severity=Severity.CRITICAL, confidence=Confidence.LOW,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=5),
                description=(
                    f"Macro `{macro_name}` has more stack-consuming operations than stack-producing ones. "
                    "Stack underflow in EVM causes invalid opcode — contract permanently reverts."
                ),
                exploit_scenario="Stack underflow causes INVALID opcode at runtime — function always fails, DoS.",
                remediation="Use the Huff compiler's stack checker and verify `takes`/`returns` annotations match actual stack behavior.",
                references=["https://docs.huff.sh/", "EVM Yellow Paper: stack"],
                language="huff",
            ))


def _missing_return(file_ctx, content, issues):
    """HUFF-HIGH-001: MAIN macro missing RETURN/REVERT/STOP at end of dispatcher."""
    main_m = re.search(r'#define\s+macro\s+MAIN\s*\([^)]*\)\s*=\s*takes\s*\(\d+\)\s*returns\s*\(\d+\)\s*\{([^}]+)\}', content, re.DOTALL)
    if not main_m:
        return
    body = main_m.group(1)
    has_return = bool(re.search(r'\b(RETURN|REVERT|STOP|SELFDESTRUCT)\b', body, re.IGNORECASE))
    if not has_return:
        line = content[:main_m.start()].count('\n') + 1
        issues.append(Issue(
            id="HUFF-HIGH-001",
            title="Huff MAIN Macro: Missing RETURN/STOP — Execution Falls Through",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=5),
            description="The MAIN dispatcher macro does not contain a RETURN, STOP, or REVERT. Execution may fall off the end of the dispatcher, causing undefined behavior or consuming all gas.",
            exploit_scenario="Unmatched function selector causes execution to reach undefined opcodes — transaction fails and wastes gas.",
            remediation="Ensure every code path in MAIN ends with STOP, RETURN, or REVERT.",
            references=["https://docs.huff.sh/tutorial/hello-world/"],
            language="huff",
        ))


def _callvalue_unchecked(file_ctx, content, issues):
    """HUFF-HIGH-002: Non-payable function doesn't check CALLVALUE == 0."""
    # If there are macros that don't check CALLVALUE but handle state changes
    if re.search(r'CALLVALUE', content, re.IGNORECASE):
        return  # File checks callvalue somewhere
    has_sstore = bool(re.search(r'\bSSTORE\b', content, re.IGNORECASE))
    if has_sstore:
        issues.append(Issue(
            id="HUFF-HIGH-002",
            title="Huff: State-Changing Functions Don't Check CALLVALUE",
            severity=Severity.HIGH, confidence=Confidence.LOW,
            file=file_ctx.relative_path, line=1,
            snippet="",
            description="State-modifying macros (SSTORE detected) do not check CALLVALUE. If ETH is sent to a non-payable function in Huff, it is NOT automatically rejected — unlike Solidity. ETH may be permanently locked.",
            exploit_scenario="User accidentally sends ETH. No CALLVALUE check — ETH accepted and locked forever.",
            remediation=(
                "Add CALLVALUE check at the start of non-payable functions:\n"
                "```huff\n"
                "callvalue iszero valid jumpi\n"
                "0x00 0x00 revert\n"
                "valid:\n"
                "```"
            ),
            references=["https://docs.huff.sh/", "EVM: CALLVALUE opcode"],
            language="huff",
        ))


def _calldatasize_unchecked(file_ctx, content, issues):
    """HUFF-MED-001: Function dispatcher doesn't check CALLDATASIZE >= 4."""
    has_dispatch = bool(re.search(r'(0x[0-9a-fA-F]{8}|__FUNC_SIG)', content))
    has_cdsize_check = bool(re.search(r'CALLDATASIZE', content, re.IGNORECASE))
    if has_dispatch and not has_cdsize_check:
        issues.append(Issue(
            id="HUFF-MED-001",
            title="Huff Dispatcher: Missing CALLDATASIZE Check (< 4 bytes)",
            severity=Severity.MEDIUM, confidence=Confidence.LOW,
            file=file_ctx.relative_path, line=1,
            snippet="",
            description="The function dispatcher compares function selectors but doesn't verify CALLDATASIZE >= 4. With <4 bytes of calldata, CALLDATALOAD returns padded zeros, potentially matching an unintended selector.",
            exploit_scenario="Attacker sends empty calldata. Dispatcher matches selector 0x00000000 — may trigger fallback or unintended function.",
            remediation=(
                "Check calldata size first:\n"
                "```huff\n"
                "calldatasize 0x04 lt bad_call jumpi\n"
                "```"
            ),
            references=["EVM Yellow Paper", "https://docs.huff.sh/"],
            language="huff",
        ))

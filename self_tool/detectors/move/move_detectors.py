"""
SELF — Move language detectors (Aptos, Sui)
Sources: Aptos security guidelines, Sui Move documentation,
         Trail of Bits Move security audit findings, Certora Move analysis
"""
import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext


def detect(file_ctx: FileContext) -> List[Issue]:
    content = file_ctx.content
    is_move = bool(re.search(r'(module\s+\w+::\w+|use aptos_framework|use sui::|fun\s+\w+\s*\()', content))
    if not is_move:
        return []
    issues = []
    _missing_signer_aptos(file_ctx, content, issues)
    _unchecked_capability(file_ctx, content, issues)
    _integer_overflow_move(file_ctx, content, issues)
    _missing_acquires(file_ctx, content, issues)
    _public_entry_no_auth(file_ctx, content, issues)
    return issues


def _missing_signer_aptos(file_ctx, content, issues):
    """MOV-CRIT-001: Entry functions lacking signer parameter."""
    entry_fn = re.compile(r'public\s+entry\s+fun\s+(\w+)\s*\(([^)]*)\)', re.MULTILINE)
    for m in entry_fn.finditer(content):
        fname = m.group(1)
        params = m.group(2)
        if 'signer' not in params and '&signer' not in params:
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="MOV-CRIT-001",
                title=f"Move: Entry Function `{fname}()` Missing Signer — No Auth",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=4),
                description=(
                    f"`{fname}` is a `public entry` function without a `signer` parameter. "
                    "Without a signer, the function has no way to verify who is calling it. "
                    "Anyone can invoke this function without authorization."
                ),
                exploit_scenario=f"Any account calls `{fname}()` and executes privileged logic without authentication.",
                remediation=(
                    "```move\n"
                    f"public entry fun {fname}(caller: &signer, ...) {{\n"
                    "    let caller_addr = signer::address_of(caller);\n"
                    "    assert!(caller_addr == @admin, error::permission_denied(ENOT_ADMIN));\n"
                    "}}\n"
                    "```"
                ),
                references=["https://aptos.dev/move/book/signer/", "Trail of Bits: Move audit"],
                language="move",
            ))


def _unchecked_capability(file_ctx, content, issues):
    """MOV-HIGH-001: Capability used without verification of holder."""
    cap_pattern = re.compile(r'(MintCapability|BurnCapability|FreezeCapability|AdminCapability)\s*<', re.MULTILINE)
    for m in cap_pattern.finditer(content):
        cap_name = m.group(1)
        surrounding = content[max(0, m.start()-200):m.start()+300]
        if not re.search(r'(borrow_global|move_from|assert)', surrounding):
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="MOV-HIGH-001",
                title=f"Move: `{cap_name}` Used Without Holder Verification",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description=f"`{cap_name}` is referenced but the holder is not verified via `borrow_global` or explicit assertion. Capabilities must be properly constrained to prevent unauthorized minting/burning.",
                exploit_scenario=f"Unauthorized module obtains `{cap_name}` reference and mints unlimited tokens.",
                remediation=(
                    "```move\n"
                    "public fun mint(account: &signer, amount: u64): Coin<T> acquires MintCapability {\n"
                    "    let addr = signer::address_of(account);\n"
                    "    assert!(exists<MintCapability<T>>(addr), error::not_found(ENO_CAP));\n"
                    "    let cap = borrow_global<MintCapability<T>>(addr);\n"
                    "    coin::mint(amount, cap)\n"
                    "}\n"
                    "```"
                ),
                references=["https://aptos.dev/move/book/abilities/", "Aptos capability pattern"],
                language="move",
            ))


def _integer_overflow_move(file_ctx, content, issues):
    """MOV-HIGH-002: Arithmetic without overflow protection in Move."""
    arith = re.compile(r'(\w+)\s*\+\s*(\w+)|(\w+)\s*\*\s*(\w+)', re.MULTILINE)
    checked = re.compile(r'(checked_add|overflow_add|safe_math|math::|Math::)', re.IGNORECASE)
    if checked.search(content) or not arith.search(content):
        return
    m = arith.search(content)
    line = content[:m.start()].count('\n') + 1
    issues.append(Issue(
        id="MOV-HIGH-002",
        title="Move: Unchecked Arithmetic — Runtime Abort on Overflow",
        severity=Severity.HIGH, confidence=Confidence.LOW,
        file=file_ctx.relative_path, line=line,
        snippet=file_ctx.get_snippet(line, context=3),
        description="Move aborts on arithmetic overflow (unlike Solidity <0.8 which wraps). While safer than wrapping, unexpected aborts can cause DoS in critical paths if inputs are user-controlled.",
        exploit_scenario="Attacker passes crafted values causing arithmetic overflow — transaction aborts, user funds locked.",
        remediation="Validate input bounds before arithmetic. Use `aptos_std::math64` or `math128` for safe operations.",
        references=["https://aptos.dev/move/book/integers/"],
        language="move",
    ))


def _missing_acquires(file_ctx, content, issues):
    """MOV-CRIT-002: Function borrows global resource without acquires annotation."""
    borrow_global = re.compile(r'borrow_global(?:_mut)?\s*<(\w+)>', re.MULTILINE)
    for m in borrow_global.finditer(content):
        resource = m.group(1)
        # Find enclosing function
        func_before = content[:m.start()].rfind('fun ')
        if func_before == -1:
            continue
        func_sig_end = content.find('{', func_before)
        func_sig = content[func_before:func_sig_end]
        if f'acquires {resource}' not in func_sig:
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="MOV-CRIT-002",
                title=f"Move: `borrow_global<{resource}>` Without `acquires {resource}`",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description=(
                    f"Function borrows global resource `{resource}` but is missing the "
                    f"`acquires {resource}` annotation. Move's bytecode verifier will reject "
                    "this — the module will fail to publish."
                ),
                exploit_scenario="Module cannot be deployed — all functionality is blocked.",
                remediation=f"Add `acquires {resource}` to the function signature: `fun my_func(...): ... acquires {resource} {{`",
                references=["https://aptos.dev/move/book/global-storage-operators/"],
                language="move",
            ))


def _public_entry_no_auth(file_ctx, content, issues):
    """MOV-HIGH-003: Public entry function modifying global state with no auth check."""
    entry_fn = re.compile(r'public\s+entry\s+fun\s+(\w+)\s*\(([^)]*)\)[^{]*\{', re.MULTILINE)
    for m in entry_fn.finditer(content):
        fname = m.group(1)
        params = m.group(2)
        func_start = m.end(); depth = 1; i = func_start
        while i < len(content) and depth > 0:
            if content[i] == '{': depth += 1
            elif content[i] == '}': depth -= 1
            i += 1
        body = content[func_start:i]
        has_move_to = bool(re.search(r'(move_to|move_from|borrow_global_mut)', body))
        has_assert = bool(re.search(r'assert!', body))
        if has_move_to and not has_assert and 'signer' not in params:
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="MOV-HIGH-003",
                title=f"Move: Entry `{fname}()` Modifies Global State Without Authorization",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=4),
                description=f"`{fname}()` writes to global storage (`move_to`/`move_from`) without any authorization check or signer parameter.",
                exploit_scenario=f"Anyone calls `{fname}()`, corrupting protocol state.",
                remediation="Add a `signer` parameter and assert caller's authority before state modifications.",
                references=["https://aptos.dev/move/book/global-storage-operators/"],
                language="move",
            ))

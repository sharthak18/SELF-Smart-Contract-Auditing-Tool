"""
SELF — Smart Contract Auditing Tool
Detector: SOL-CRIT-001 / SOL-CRIT-002 / SOL-CRIT-003
Reentrancy (Classic, Cross-function, Read-Only)

Sources: Slither, Trail of Bits, Rekt.news (DAO Hack, Cream Finance, Curve Finance),
         SWC-107, DeFiHackLabs, Spearbit, Immunefi top findings
"""

import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext

# External call patterns (all variants)
RE_EXTERNAL_CALL = re.compile(
    r'(\.\s*call\s*[({]|\.\s*send\s*\(|\.\s*transfer\s*\('
    r'|\.delegatecall\s*\(|\.staticcall\s*\('
    r'|IERC20\([^)]+\)\.transfer|\.safeTransfer\(|\.safeTransferFrom\()',
    re.MULTILINE
)

# State-modifying patterns (balance, mapping, storage updates)
RE_STATE_CHANGE = re.compile(
    r'(\w+\s*[\[\(][^\]\)]*[\]\)]\s*[-+*/]?=(?!=)'
    r'|\w+\.\w+\s*=(?!=)'
    r'|balances\['
    r'|_balances\['
    r'|totalSupply\s*[-+]?='
    r'|_totalSupply\s*[-+]?=)',
    re.MULTILINE
)

# Reentrancy guard patterns (things that protect)
RE_GUARD = re.compile(
    r'(nonReentrant|ReentrancyGuard|_status\s*=|locked\s*=|mutex\s*=|noReentrancy)',
    re.IGNORECASE
)

# Read-only reentrancy: view functions called on other protocols mid-execution
RE_READONLY_REENTRY = re.compile(
    r'\.(balanceOf|totalSupply|getReserves|getPrice|exchangeRate'
    r'|pricePerShare|convertToAssets|totalAssets|getPricePerFullShare)\s*\(',
    re.MULTILINE
)

# Tokens received / fallback hooks that can re-enter
RE_HOOK = re.compile(
    r'(tokensReceived|onERC721Received|onERC1155Received'
    r'|onERC1155BatchReceived|receive\s*\(\)|fallback\s*\(\))',
    re.MULTILINE
)


def detect(file_ctx: FileContext) -> List[Issue]:
    issues = []
    content = file_ctx.content
    lines = file_ctx.lines

    # ── SOL-CRIT-001: Classic Reentrancy (CEI violation) ─────────────────────
    # Look for functions where an external call appears before a state change
    _detect_classic_reentrancy(file_ctx, issues)

    # ── SOL-CRIT-002: Cross-function Reentrancy ──────────────────────────────
    # Shared state variable updated in one function, external call in another
    _detect_cross_function_reentrancy(file_ctx, issues)

    # ── SOL-CRIT-003: Read-Only Reentrancy ──────────────────────────────────
    # View/price functions called after external calls; exploited by Curve, etc.
    _detect_readonly_reentrancy(file_ctx, issues)

    return issues


def _detect_classic_reentrancy(file_ctx: FileContext, issues: List[Issue]):
    """
    SOL-CRIT-001: Detect functions that make external calls before updating state.
    Pattern: call → state_update (should be state_update → call)
    """
    content = file_ctx.content

    # Simple heuristic: find function bodies where .call( appears before balances[ update
    func_pattern = re.compile(
        r'function\s+(\w+)\s*\([^)]*\)[^{]*\{',
        re.MULTILINE
    )

    for func_m in func_pattern.finditer(content):
        fname = func_m.group(1)
        func_start = func_m.end()

        # Find matching closing brace
        depth = 1
        i = func_start
        while i < len(content) and depth > 0:
            if content[i] == '{':
                depth += 1
            elif content[i] == '}':
                depth -= 1
            i += 1
        func_body = content[func_start:i]

        # Skip if protected by reentrancy guard
        if RE_GUARD.search(func_body):
            continue

        # Find position of first external call
        call_m = re.search(
            r'(\.\s*call\s*[({]'
            r'|\.\s*send\s*\('
            r'|\.\s*transfer\s*\('
            r'|\.safeTransfer\s*\('
            r'|\.safeTransferFrom\s*\('
            r'|IERC\d+[^.]*\.\s*(transfer|send)\s*\()',
            func_body
        )
        if not call_m:
            continue

        call_pos = call_m.start()

        # Find if a state change happens AFTER the external call
        after_call = func_body[call_pos:]
        state_m = re.search(
            r'(\b\w+\s*\[[^\]]*\]\s*[-+*/]?=(?!=)'
            r'|\b_?\w*(balance|supply|amount|debt|share|deposit)\w*\s*[-+*/]?=(?!=)'
            r'|\b\w+\.\w+\s*=(?!=))',
            after_call,
            re.IGNORECASE
        )
        if not state_m:
            continue

        # Get line number of the external call
        func_line_start = content[:func_m.start()].count('\n') + 1
        call_line = content[:func_m.end() + call_pos].count('\n') + 1

        issues.append(Issue(
            id="SOL-CRIT-001",
            title=f"Reentrancy: State Update After External Call in `{fname}()`",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            file=file_ctx.relative_path,
            line=call_line,
            snippet=file_ctx.get_snippet(call_line, context=4),
            description=(
                "The function `{fname}()` makes an external call (`.call()`, `.transfer()`, "
                "`.safeTransfer()`, etc.) **before** updating its internal state. "
                "This violates the Checks-Effects-Interactions (CEI) pattern and creates "
                "a classic reentrancy vector — the most common critical vulnerability in DeFi. "
                "An attacker can re-enter this function recursively before state is updated, "
                "draining funds or corrupting state.\n\n"
                "**Real-world incidents using this exact pattern:**\n"
                "- DAO Hack (2016) — $60M\n"
                "- Cream Finance (2021) — $130M\n"
                "- Siren Protocol (2021) — $3.5M\n"
                "- Paraluni (2022) — $1.7M"
            ).format(fname=fname),
            exploit_scenario=(
                "1. Attacker deploys `MaliciousContract` with a `receive()` or `fallback()` "
                "that calls back into `{fname}()`.\n"
                "2. Attacker calls `{fname}()`, triggering the external ETH/token transfer.\n"
                "3. Before the state update (`balances[msg.sender] -= amount`) executes, "
                "the attacker's `receive()` fires and re-enters `{fname}()`.\n"
                "4. The old (un-updated) balance is still valid — withdrawal succeeds again.\n"
                "5. Repeat until contract is drained."
            ).format(fname=fname),
            remediation=(
                "**Follow the Checks-Effects-Interactions (CEI) pattern:**\n"
                "```solidity\n"
                "function withdraw(uint256 amount) external {\n"
                "    // 1. CHECKS\n"
                "    require(balances[msg.sender] >= amount, 'Insufficient');\n"
                "    // 2. EFFECTS — update state BEFORE any external call\n"
                "    balances[msg.sender] -= amount;\n"
                "    // 3. INTERACTIONS — external call last\n"
                "    (bool ok,) = msg.sender.call{value: amount}('');\n"
                "    require(ok, 'Transfer failed');\n"
                "}\n"
                "```\n"
                "**Or use OpenZeppelin's `ReentrancyGuard`:**\n"
                "```solidity\n"
                "import '@openzeppelin/contracts/security/ReentrancyGuard.sol';\n"
                "contract Vault is ReentrancyGuard {\n"
                "    function withdraw(uint256 amount) external nonReentrant { ... }\n"
                "}\n"
                "```"
            ),
            references=[
                "SWC-107: Reentrancy",
                "https://swcregistry.io/docs/SWC-107",
                "https://rekt.news/cream-rekt-2/",
                "https://blog.openzeppelin.com/reentrancy-after-istanbul/",
                "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
            ],
            language="solidity",
        ))


def _detect_cross_function_reentrancy(file_ctx: FileContext, issues: List[Issue]):
    """
    SOL-CRIT-002: Cross-function reentrancy.
    Function A makes an external call; the callback re-enters Function B
    which reads shared state not yet updated by A.
    """
    content = file_ctx.content

    # Look for contracts with multiple external-call functions sharing state
    # Heuristic: multiple public/external functions with .call( and no global nonReentrant
    func_names_with_calls = []
    func_pattern = re.compile(
        r'function\s+(\w+)\s*\([^)]*\)\s*(?:public|external)[^{]*\{',
        re.MULTILINE
    )

    for m in func_pattern.finditer(content):
        fname = m.group(1)
        func_start = m.end()
        depth = 1
        i = func_start
        while i < len(content) and depth > 0:
            if content[i] == '{':
                depth += 1
            elif content[i] == '}':
                depth -= 1
            i += 1
        body = content[func_start:i]

        if RE_EXTERNAL_CALL.search(body) and not RE_GUARD.search(body):
            func_names_with_calls.append((fname, m.start()))

    # If 2+ unguarded public functions have external calls → potential cross-function reentrancy
    if len(func_names_with_calls) >= 2:
        line = content[:func_names_with_calls[0][1]].count('\n') + 1
        names = [f[0] for f in func_names_with_calls[:4]]
        issues.append(Issue(
            id="SOL-CRIT-002",
            title=f"Cross-Function Reentrancy: Multiple Unguarded External Call Functions",
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path,
            line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                f"Functions `{'`, `'.join(names)}` all make external calls without a "
                "global reentrancy guard. Even if each function individually follows CEI, "
                "cross-function reentrancy is possible: an attacker's callback from function "
                "A can re-enter function B before A's state changes are committed, since "
                "both read from the same shared storage.\n\n"
                "**Real-world incidents:**\n"
                "- Uniswap V1 (2019) via ERC-777 token reentrancy\n"
                "- OUSD Hack (2020) — $7M (cross-function reentrancy via rebase)"
            ),
            exploit_scenario=(
                "1. Contract has `deposit()` and `withdraw()` both external with no guard.\n"
                "2. Attacker calls `deposit()` with a malicious ERC-777/ERC-1155 token.\n"
                "3. The token's `tokensReceived` hook fires during deposit, re-entering `withdraw()`.\n"
                "4. At this point, the deposit state hasn't finalized — attacker withdraws "
                "more than entitled."
            ),
            remediation=(
                "Apply `nonReentrant` to **all** state-changing public/external functions, "
                "or use a contract-level mutex. Consider using a global `locked` flag:\n"
                "```solidity\n"
                "// Option A: OpenZeppelin ReentrancyGuard\n"
                "function deposit() external nonReentrant { ... }\n"
                "function withdraw() external nonReentrant { ... }\n\n"
                "// Option B: Transient storage lock (Solidity >=0.8.24)\n"
                "modifier noReentrant() {\n"
                "    assembly { if tload(0) { revert(0,0) } tstore(0, 1) }\n"
                "    _;\n"
                "    assembly { tstore(0, 0) }\n"
                "}\n"
                "```"
            ),
            references=[
                "SWC-107: Reentrancy",
                "https://blog.trailofbits.com/2021/02/11/protecting-against-reentrancy-with-solidity-0-8/",
                "https://rekt.news/ousd-rekt/",
            ],
            language="solidity",
        ))


def _detect_readonly_reentrancy(file_ctx: FileContext, issues: List[Issue]):
    """
    SOL-CRIT-003: Read-Only Reentrancy.
    An attacker re-enters a VIEW function mid-execution to read stale state
    (e.g. totalSupply, balanceOf, getReserves) that hasn't been updated yet.
    Used in Curve Finance exploit (2023).
    """
    content = file_ctx.content

    # Look for external calls followed by reads of common price/state view functions
    func_pattern = re.compile(
        r'function\s+(\w+)\s*\([^)]*\)[^{]*\{',
        re.MULTILINE
    )

    for func_m in func_pattern.finditer(content):
        fname = func_m.group(1)
        func_start = func_m.end()
        depth = 1
        i = func_start
        while i < len(content) and depth > 0:
            if content[i] == '{':
                depth += 1
            elif content[i] == '}':
                depth -= 1
            i += 1
        body = content[func_start:i]

        # Has external call (especially ETH transfer)
        has_ext_call = bool(re.search(r'\.\s*(call|send|transfer)\s*\(', body))
        # Calls a price/balance view function
        has_readonly_read = bool(RE_READONLY_REENTRY.search(body))

        if has_ext_call and has_readonly_read:
            call_line = content[:func_m.start()].count('\n') + 1
            issues.append(Issue(
                id="SOL-CRIT-003",
                title=f"Read-Only Reentrancy: View State Read After External Call in `{fname}()`",
                severity=Severity.CRITICAL,
                confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path,
                line=call_line,
                snippet=file_ctx.get_snippet(call_line, context=4),
                description=(
                    f"Function `{fname}()` makes an external call (ETH/token transfer) "
                    "and then reads a view function like `totalSupply()`, `balanceOf()`, "
                    "`getReserves()`, or `pricePerShare()`. During the external call, an "
                    "attacker can re-enter a dependent contract that calls one of these "
                    "view functions — reading **stale values** not yet reflecting the current "
                    "transaction state. This was the core mechanism of the Curve Finance "
                    "reentrancy exploit (2023, $70M at risk).\n\n"
                    "**Key insight:** Even contracts with `nonReentrant` can be vulnerable "
                    "if they expose price/balance reads that other contracts rely on."
                ),
                exploit_scenario=(
                    "1. Protocol B uses `getReserves()` or `totalSupply()` from Protocol A as a price oracle.\n"
                    "2. Attacker calls Protocol A's withdrawal function which sends ETH before updating reserves.\n"
                    "3. During ETH transfer, attacker's callback calls Protocol B.\n"
                    "4. Protocol B reads stale `getReserves()` from Protocol A — price is skewed.\n"
                    "5. Attacker exploits the mispriced collateral/liquidity."
                ),
                remediation=(
                    "1. **Complete all state updates before any external interaction.**\n"
                    "2. **If your protocol is used as a price source**, add `nonReentrant` to all "
                    "view functions that expose prices (e.g., `getVirtualPrice()`).\n"
                    "3. **Consumers of external price feeds**: use `nonReentrant` or check a "
                    "`_reentrancyGuard` before trusting external view calls:\n"
                    "```solidity\n"
                    "// Curve-style read-only reentrancy guard\n"
                    "function get_virtual_price() external view nonReentrant returns (uint256) {\n"
                    "    return _get_virtual_price();\n"
                    "}\n"
                    "```"
                ),
                references=[
                    "https://rekt.news/curve-vyper-rekt/",
                    "https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/",
                    "https://blog.trailofbits.com/2023/08/14/ethereum-is-a-dark-forest/",
                    "SWC-107",
                ],
                language="solidity",
            ))

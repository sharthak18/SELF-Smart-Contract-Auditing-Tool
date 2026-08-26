"""
SELF — Smart Contract Auditing Tool
Detector: SOL-CRIT-011 / SOL-CRIT-012 / SOL-CRIT-017 / SOL-HIGH-017
Advanced reentrancy patterns (Transient storage, Create2, ERC hooks,
unguarded price-oracle view functions).
"""

import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext
from self_tool.parsers.solidity_parser import parse_solidity

# View function names commonly consumed by third-party protocols as a price
# or exchange-rate oracle. Modeled on Curve's get_virtual_price() (2023,
# $70M at risk across CRV/ETH, pETH/ETH, msETH/ETH, alETH/ETH pools) and the
# equivalent Balancer getRate() incident.
_ORACLE_VIEW_NAMES = (
    "get_virtual_price", "getvirtualprice", "getrate", "get_rate",
    "pricepershare", "getpriceperfullshare", "sharevalue", "exchangerate",
    "converttoassets", "convert_to_assets",
)

RE_STATE_MUTATING_EXTERNAL_CALL = re.compile(
    r'\.\s*(call\s*[({]|send\s*\(|transfer\s*\('
    r'|safeTransfer\s*\(|safeTransferFrom\s*\()',
    re.MULTILINE,
)

RE_NONREENTRANT_MODIFIER = re.compile(r'\bnonReentrant\b|\breentrancyGuard\b', re.IGNORECASE)


def detect(file_ctx: FileContext) -> List[Issue]:
    issues = []
    
    _detect_transient_storage_reentrancy(file_ctx, issues)
    _detect_create2_reentrancy(file_ctx, issues)
    _detect_unguarded_oracle_view(file_ctx, issues)
    
    return issues


def _detect_unguarded_oracle_view(file_ctx: FileContext, issues: List[Issue]):
    """
    SOL-CRIT-017: A public/external view function that exposes a price,
    exchange rate, or share value -- the kind of function third-party
    protocols integrate as an oracle -- is not itself protected by a
    reentrancy guard, while the same contract has at least one
    state-mutating function that makes an external call (ETH/token
    transfer) and could therefore leave storage in a transient,
    inconsistent state mid-call.

    This is the producer-side fix for read-only reentrancy: SOL-CRIT-003
    flags a caller that reads a view mid-callback; this detector flags the
    protocol that failed to lock its own oracle-shaped view, which is
    exactly the mitigation Curve/Balancer adopted after the 2023 wave of
    read-only reentrancy incidents ($30M+ across the ecosystem).
    """
    info = parse_solidity(file_ctx)
    for contract in info.contracts:
        if contract.kind in {"interface", "library"}:
            continue

        has_risky_external_call = any(
            RE_STATE_MUTATING_EXTERNAL_CALL.search(fn.body)
            for fn in contract.functions
            if fn.visibility in {"public", "external"}
        )
        if not has_risky_external_call:
            continue

        for fn in contract.functions:
            if fn.mutability not in {"view"}:
                continue
            if fn.visibility not in {"public", "external"}:
                continue
            name_lower = fn.name.lower()
            if not any(marker in name_lower for marker in _ORACLE_VIEW_NAMES):
                continue
            if RE_NONREENTRANT_MODIFIER.search(" ".join(fn.modifiers)):
                continue

            issues.append(Issue(
                id="SOL-CRIT-017",
                title=f"Unguarded Price/Rate Oracle View `{fn.name}()` -- Read-Only Reentrancy Surface",
                severity=Severity.CRITICAL,
                confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path,
                line=fn.line,
                snippet=file_ctx.get_snippet(fn.line, context=4),
                description=(
                    f"`{fn.name}()` looks like a price / exchange-rate / share-value view "
                    "that other protocols would integrate as an oracle, but it carries no "
                    "reentrancy guard, and this contract has at least one state-mutating "
                    "function that performs an external call (ETH or token transfer). "
                    "During that external call -- before the callee returns -- this "
                    "contract's own accounting (reserves, total supply, share price) can "
                    "be in a transient, inconsistent state. Any external protocol that "
                    "calls back into this contract (directly, or indirectly through the "
                    "attacker's callback) and reads "
                    f"`{fn.name}()` during that window observes a manipulated value.\n\n"
                    "**Real incident: Curve Finance `get_virtual_price()` (2023)** -- the "
                    "numerator (pool assets) and denominator (LP supply) of the price "
                    "formula updated at different points inside `remove_liquidity()`. "
                    "Reentering during the ETH transfer let dependent lending markets "
                    "(dForce, Sentiment, and others) observe a wildly inflated virtual "
                    "price and lend against fictitious collateral. The same shape has hit "
                    "Balancer's `getRate()`."
                ),
                exploit_scenario=(
                    f"1. A third-party lending or vault protocol prices collateral using "
                    f"this contract's `{fn.name}()`.\n"
                    "2. Attacker calls a state-mutating function on this contract that "
                    "sends ETH/tokens externally before finishing its own accounting "
                    "update.\n"
                    "3. During that external call, the attacker's callback re-enters the "
                    f"dependent protocol, which reads `{fn.name}()` and sees a stale or "
                    "manipulated value (denominator decreased, numerator not yet updated, "
                    "or vice versa).\n"
                    "4. The dependent protocol acts on the corrupted price (over-mints, "
                    "under-collateralizes, or misprices a swap), and the attacker profits."
                ),
                remediation=(
                    "Add a reentrancy guard to every view function that exposes price, "
                    "rate, or share information, so it reverts if called during an "
                    "in-progress state-mutating call:\n"
                    "```solidity\n"
                    f"function {fn.name}() external view nonReentrant returns (uint256) {{\n"
                    "    return _computeValue();\n"
                    "}\n"
                    "```\n"
                    "`nonReentrant` on a `view` function requires a lock check without the "
                    "usual state write (Curve's own fix pattern); at minimum, gate the "
                    "read behind the same lock flag used by the mutating functions and "
                    "`require(!locked)`."
                ),
                references=[
                    "https://rekt.news/curve-vyper-rekt/",
                    "https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/",
                    "https://blog.trailofbits.com/2023/08/14/ethereum-is-a-dark-forest/",
                    "SWC-107",
                ],
                language="solidity",
            ))


def _detect_transient_storage_reentrancy(file_ctx: FileContext, issues: List[Issue]):
    """
    SOL-CRIT-011: Transient storage reentrancy (EIP-1153).
    Using tstore/tload without proper cleanup allows cross-transaction contamination 
    if the caller context isn't fully cleared.
    """
    content = file_ctx.content
    
    # Simple check for tstore without an accompanying clear/reset 
    # (very heuristic, proper check requires CFG)
    info = parse_solidity(file_ctx)
    for contract in info.contracts:
        for func in contract.functions:
            body = func.body
            if "tstore(" in body or "assembly" in body and "tstore" in body:
                # Check if there's a reset (storing 0)
                if not re.search(r'tstore\s*\([^,]+,\s*0\s*\)', body):
                    issues.append(Issue(
                        id="SOL-CRIT-011",
                        title="Transient Storage Contamination (EIP-1153)",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.MEDIUM,
                        file=file_ctx.relative_path,
                        line=func.line,
                        snippet=file_ctx.get_snippet(func.line, context=4),
                        description=(
                            "The function uses transient storage (`tstore`), but does not appear "
                            "to clear the slot (by storing 0) before returning. Because transient "
                            "storage persists for the entire transaction, an external call or a "
                            "subsequent transaction within the same bundle can read the leftover data."
                        ),
                        exploit_scenario="A reentrancy guard uses `tstore(1)`. It fails to `tstore(0)` on exit. The contract is permanently locked for the rest of the transaction, blocking valid batch operations.",
                        remediation="Always ensure transient storage slots are cleared (`tstore(slot, 0)`) at the end of the function, even in `catch` blocks.",
                        language="solidity"
                    ))


def _detect_create2_reentrancy(file_ctx: FileContext, issues: List[Issue]):
    """
    SOL-CRIT-012: Metamorphic contract attack surface.
    Using `create2` and then calling the resulting address before validating its code.
    """
    content = file_ctx.content
    
    info = parse_solidity(file_ctx)
    for contract in info.contracts:
        for func in contract.functions:
            body = func.body
            
            # Look for create2 followed by an external call
            create2_match = re.search(r'(new\s+[^\(]+\{salt:|create2\()', body)
            if create2_match:
                if re.search(r'\.\s*(call|delegatecall|send|transfer)\s*\(', body[create2_match.end():]):
                    issues.append(Issue(
                        id="SOL-CRIT-012",
                        title="CREATE2 Callback / Metamorphic Reentrancy",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.LOW,
                        file=file_ctx.relative_path,
                        line=func.line,
                        snippet=file_ctx.get_snippet(func.line, context=4),
                        description=(
                            "The function deploys a contract via `CREATE2` and interacts with it. "
                            "If the deployed contract is metamorphic (can be destroyed and redeployed "
                            "with different bytecode at the same address), an attacker can execute "
                            "arbitrary code during the callback or bypass initialization checks."
                        ),
                        exploit_scenario="Protocol deploys an Oracle via CREATE2 and calls `init()`. Attacker deploys a malicious Oracle, `selfdestruct`s it, and lets the protocol redeploy it. The protocol trusts the address, but the code is hostile.",
                        remediation="If relying on CREATE2 for address predictability, verify the deployed bytecode hash (`extcodehash`) before interacting.",
                        language="solidity"
                    ))

"""
SELF — Smart Contract Auditing Tool
Detector: SOL-HIGH-018 / SOL-HIGH-019 / SOL-MED-015 / SOL-MED-016 / SOL-HIGH-026
MEV and front-running attack patterns.
"""

import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext
from self_tool.parsers.solidity_parser import parse_solidity

def detect(file_ctx: FileContext) -> List[Issue]:
    issues = []
    
    _detect_predictable_commit_reveal(file_ctx, issues)
    _detect_missing_slippage_protection(file_ctx, issues)
    _detect_unconditional_permit_dos(file_ctx, issues)
    
    return issues


def _detect_unconditional_permit_dos(file_ctx: FileContext, issues: List[Issue]):
    """
    SOL-HIGH-026: ERC-2612 `permit()` front-running griefing / DoS.

    `permit()` is callable by anyone holding a valid signature. Routers that
    call `IERC20(token).permit(owner, spender, value, deadline, v, r, s)`
    unconditionally, then continue to a dependent action in the same
    function (e.g. `transferFrom`/`supply`/`deposit`), are vulnerable to a
    permit front-run: an attacker extracts (v, r, s) from the pending
    mempool transaction and submits it directly to the token's `permit()`
    first. The victim's nonce is consumed, so their own `permit()` call
    reverts and the entire batched transaction fails -- a persistent,
    zero-cost DoS on every user of the router (no funds are stolen, but
    every legitimate `permitAndCall`/`supplyWithPermit` style transaction
    can be griefed).

    Mitigation: wrap `permit()` in try/catch and fall back to checking the
    allowance is already sufficient (which it will be if an attacker
    front-ran the permit) before proceeding.
    """
    info = parse_solidity(file_ctx)
    for contract in info.contracts:
        if contract.kind in {"interface", "library"}:
            continue
        for func in contract.functions:
            body = func.body

            permit_calls = list(re.finditer(
                r'\.\s*permit\s*\(', body
            ))
            if not permit_calls:
                continue

            # try/catch around permit already handles a reverted permit safely.
            has_try_catch = bool(re.search(r'\btry\b[^;{]*\.permit\s*\(', body))
            if has_try_catch:
                continue

            # Does the function do something else meaningful after permit()
            # (i.e. it's a batched permit+action call, the vulnerable shape)?
            first_permit = permit_calls[0]
            after_permit = body[first_permit.end():]
            has_followup_action = bool(re.search(
                r'(transferFrom|safeTransferFrom|deposit|supply|mint|swap|stake)\s*\(',
                after_permit,
            ))
            if not has_followup_action:
                continue

            line = func.body_start_line + body[:first_permit.start()].count('\n')
            issues.append(Issue(
                id="SOL-HIGH-026",
                title=f"ERC-2612 `permit()` Front-Running DoS in `{func.name}()`",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path,
                line=line,
                snippet=file_ctx.get_snippet(line, context=4),
                description=(
                    f"`{func.name}()` calls `permit()` unconditionally and then performs a "
                    "dependent action (transfer/deposit/supply/etc.) in the same "
                    "transaction, without a `try/catch` around the permit call. Because "
                    "`permit()` is callable by anyone holding the `(v, r, s)` signature, an "
                    "attacker watching the mempool can front-run the victim's transaction by "
                    "calling the token's `permit()` directly with the extracted signature. "
                    "The victim's nonce is consumed, so their own `permit()` call inside "
                    f"`{func.name}()` reverts, and the entire batched transaction fails -- a "
                    "free, repeatable griefing/DoS vector against every user of this router."
                ),
                exploit_scenario=(
                    "1. User submits `permitAndCall(...)` (or similar) with a valid EIP-2612 "
                    "signature to a public mempool.\n"
                    "2. Attacker extracts `(v, r, s)` from the pending calldata and submits "
                    "`token.permit(user, spender, value, deadline, v, r, s)` directly with a "
                    "higher priority fee.\n"
                    "3. The attacker's transaction consumes the user's permit nonce.\n"
                    "4. The user's original transaction executes, its internal `permit()` "
                    "call reverts (nonce mismatch), and the whole transaction fails -- the "
                    "user pays gas for nothing and must retry."
                ),
                remediation=(
                    "Wrap the permit call in `try/catch` and continue if the required "
                    "allowance is already present (which it will be if the permit was "
                    "front-run):\n"
                    "```solidity\n"
                    "try IERC20Permit(token).permit(owner, address(this), value, deadline, v, r, s) {}\n"
                    "catch {\n"
                    "    // Permit may have been front-run; proceed only if allowance already covers it.\n"
                    "    require(IERC20(token).allowance(owner, address(this)) >= value, 'permit failed');\n"
                    "}\n"
                    "IERC20(token).transferFrom(owner, address(this), value);\n"
                    "```"
                ),
                references=[
                    "EIP-2612: Permit Extension for EIP-20 Signed Approvals",
                    "https://www.trust-security.xyz/post/permission-denied",
                    "https://blog.trailofbits.com/2023/12/12/some-legacy-tokens-arent-so-fungible/",
                ],
                language="solidity",
            ))


def _detect_predictable_commit_reveal(file_ctx: FileContext, issues: List[Issue]):
    """
    SOL-HIGH-018: Commit-reveal with predictable reveal.
    If a commit hash doesn't include msg.sender, anyone can front-run the reveal.
    """
    content = file_ctx.content
    
    # Heuristic: looking for keccak256 that does not include msg.sender
    # Used in a function that is likely a commit or hash generation
    info = parse_solidity(file_ctx)
    for contract in info.contracts:
        for func in contract.functions:
            body = func.body
            if "keccak256" in body and "abi.encodePacked" in body:
                if "msg.sender" not in body and "tx.origin" not in body:
                    # Is it a public/external function?
                    if func.visibility in {"public", "external"}:
                        issues.append(Issue(
                            id="SOL-HIGH-018",
                            title="Predictable Commit-Reveal Hash (Front-runnable)",
                            severity=Severity.HIGH,
                            confidence=Confidence.LOW,
                            file=file_ctx.relative_path,
                            line=func.line,
                            snippet=file_ctx.get_snippet(func.line, context=4),
                            description=(
                                "The function generates a hash using `keccak256` but does not "
                                "include `msg.sender`. If this hash is used for a commit-reveal "
                                "scheme (like an auction or voting), a front-runner can see the "
                                "reveal transaction, extract the plain text value, and submit their "
                                "own reveal transaction with the same value."
                            ),
                            exploit_scenario="User commits to a bid. User reveals bid. Front-runner sees the reveal, copies the plaintext bid, and submits it with a higher gas price. Front-runner wins the auction.",
                            remediation="Always include `msg.sender` in the `keccak256` payload for commit-reveal schemes: `keccak256(abi.encodePacked(value, salt, msg.sender))`.",
                            language="solidity"
                        ))


def _detect_missing_slippage_protection(file_ctx: FileContext, issues: List[Issue]):
    """
    SOL-HIGH-019: Missing slippage protection in AMM-style swaps.
    """
    content = file_ctx.content
    
    info = parse_solidity(file_ctx)
    for contract in info.contracts:
        for func in contract.functions:
            body = func.body
            
            # Check for common swap calls: swapExactTokensForTokens, etc.
            if re.search(r'\b(swap|exchange|trade)\w*\s*\(', body, re.IGNORECASE):
                # Does the function signature have a 'min' or 'deadline' param?
                if "min" not in func.params.lower() and "deadline" not in func.params.lower():
                    # Does it use block.timestamp directly as deadline?
                    if "block.timestamp" in body and not re.search(r'(require|assert)\s*\(.*(timestamp|deadline).*\)', body):
                        issues.append(Issue(
                            id="SOL-HIGH-019",
                            title="Missing Slippage or Deadline Protection (Sandwich Attack)",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            file=file_ctx.relative_path,
                            line=func.line,
                            snippet=file_ctx.get_snippet(func.line, context=4),
                            description=(
                                "The function performs a token swap but does not appear to accept "
                                "or enforce a `minAmountOut` or user-defined `deadline`. Hardcoding "
                                "`block.timestamp` as a deadline or using 0 for minimum output "
                                "allows miners and MEV bots to sandwich the transaction, extracting "
                                "maximum value."
                            ),
                            exploit_scenario="User submits a swap. MEV bot sees it, buys the asset (pumping price), processes user's swap at the inflated price, then dumps the asset. User gets almost 0 tokens.",
                            remediation="Require callers to pass `uint256 minAmountOut` and `uint256 deadline`, and enforce them in the swap router call.",
                            language="solidity"
                        ))

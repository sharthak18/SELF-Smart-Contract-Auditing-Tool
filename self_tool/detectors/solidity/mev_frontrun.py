"""
SELF — Smart Contract Auditing Tool
Detector: SOL-HIGH-018 / SOL-HIGH-019 / SOL-MED-015 / SOL-MED-016
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
    
    return issues


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

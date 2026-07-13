"""
SELF — Smart Contract Auditing Tool
Detector: SOL-HIGH-025 / SOL-MED-020 / SOL-MED-021 / SOL-LOW-008 / SOL-LOW-009
DeFi-specific architectural flaws.
"""

import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext
from self_tool.parsers.solidity_parser import parse_solidity

def detect(file_ctx: FileContext) -> List[Issue]:
    issues = []
    
    _detect_payable_missing_value(file_ctx, issues)
    _detect_missing_receive(file_ctx, issues)
    
    return issues


def _detect_payable_missing_value(file_ctx: FileContext, issues: List[Issue]):
    """
    SOL-LOW-009: Payable function that doesn't track msg.value.
    Often implies funds are locked in the contract accidentally.
    """
    info = parse_solidity(file_ctx)
    for contract in info.contracts:
        for func in contract.functions:
            if func.mutability == "payable" and not func.is_constructor and not func.is_receive and not func.is_fallback:
                body = func.body
                if "msg.value" not in body and "assembly" not in body and "callvalue()" not in body:
                    issues.append(Issue(
                        id="SOL-LOW-009",
                        title="Payable Function Ignores `msg.value`",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        file=file_ctx.relative_path,
                        line=func.line,
                        snippet=file_ctx.get_snippet(func.line, context=4),
                        description=(
                            "The function is marked as `payable` but does not appear to use "
                            "`msg.value` anywhere in its body. If users send ETH to this function, "
                            "it will be accepted but not accounted for, potentially locking it "
                            "forever."
                        ),
                        exploit_scenario="A user accidentally sends ETH while calling this function. The ETH is added to the contract balance but the protocol has no tracking or withdrawal mechanism for it. The ETH is permanently locked.",
                        remediation="Remove the `payable` modifier if ETH is not expected, or add logic to process `msg.value`.",
                        language="solidity"
                    ))


def _detect_missing_receive(file_ctx: FileContext, issues: List[Issue]):
    """
    SOL-LOW-008: Contract has payable functions or uses WETH, but no receive/fallback.
    """
    info = parse_solidity(file_ctx)
    for contract in info.contracts:
        if contract.kind in {"interface", "library"}:
            continue
            
        has_payable = any(f.mutability == "payable" for f in contract.functions)
        has_weth = "WETH" in file_ctx.content or "weth" in file_ctx.content.lower()
        has_receive = any(f.is_receive or f.is_fallback for f in contract.functions)
        
        # Heuristic: if it uses WETH but can't receive ETH, unwrap(WETH) will fail
        if has_weth and not has_receive:
            issues.append(Issue(
                id="SOL-LOW-008",
                title="Contract Handles WETH but Cannot Receive ETH",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                file=file_ctx.relative_path,
                line=contract.line,
                snippet=file_ctx.get_snippet(contract.line, context=2),
                description=(
                    "The contract references WETH but does not implement a `receive()` or `fallback()` "
                    "function. If the contract ever calls `WETH.withdraw()` to unwrap WETH into native ETH, "
                    "the call will revert because the contract cannot receive ETH."
                ),
                exploit_scenario="Protocol tries to unwrap WETH for a user. WETH contract sends native ETH via `.transfer()`. The call reverts because this contract has no `receive()` function.",
                remediation="Add `receive() external payable {}` to allow unwrapping WETH.",
                language="solidity"
            ))

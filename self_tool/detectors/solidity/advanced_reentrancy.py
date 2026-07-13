"""
SELF — Smart Contract Auditing Tool
Detector: SOL-CRIT-011 / SOL-CRIT-012 / SOL-HIGH-017
Advanced reentrancy patterns (Transient storage, Create2, ERC hooks).
"""

import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext
from self_tool.parsers.solidity_parser import parse_solidity

def detect(file_ctx: FileContext) -> List[Issue]:
    issues = []
    
    _detect_transient_storage_reentrancy(file_ctx, issues)
    _detect_create2_reentrancy(file_ctx, issues)
    
    return issues


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

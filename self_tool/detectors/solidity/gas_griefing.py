"""
SELF — Smart Contract Auditing Tool
Detector: SOL-HIGH-024 / SOL-MED-018 / SOL-MED-019
Gas manipulation and griefing attacks.
"""

import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext
from self_tool.parsers.solidity_parser import parse_solidity

def detect(file_ctx: FileContext) -> List[Issue]:
    issues = []
    
    _detect_returndata_bomb(file_ctx, issues)
    
    return issues


def _detect_returndata_bomb(file_ctx: FileContext, issues: List[Issue]):
    """
    SOL-HIGH-024: Returndata Bomb.
    External calls implicitly copy the return data to memory unless using assembly or 
    ignoring it explicitly. A malicious callee can return huge amounts of data to OOM 
    the caller.
    """
    info = parse_solidity(file_ctx)
    for contract in info.contracts:
        for func in contract.functions:
            body = func.body
            
            # Simple heuristic: looking for standard low-level calls that aren't wrapped in assembly
            if re.search(r'(?<!assembly\s\{)\s*\.\s*(call|staticcall|delegatecall)\s*\(', body):
                # Is the return data assigned to a variable? e.g. (, bytes memory data) =
                if re.search(r'(bytes\s+memory\s+\w+\s*=|\(\s*bool\s+\w+\s*,\s*bytes\s+memory\s+\w+\s*\)\s*=)', body):
                    issues.append(Issue(
                        id="SOL-HIGH-024",
                        title="Return-Data Bomb (Memory Exhaustion Griefing)",
                        severity=Severity.HIGH,
                        confidence=Confidence.LOW,
                        file=file_ctx.relative_path,
                        line=func.line,
                        snippet=file_ctx.get_snippet(func.line, context=4),
                        description=(
                            "The function performs a low-level call and copies the returned data into "
                            "memory (`bytes memory`). A malicious callee can return an extremely large "
                            "byte array (a 'return-data bomb'), which the EVM will blindly copy into "
                            "the caller's memory. This causes the caller to run out of gas and revert, "
                            "even if the call was in a `try/catch` or intended to safely fail."
                        ),
                        exploit_scenario="A protocol attempts to loop over an array of user addresses and call a hook on each, ignoring failures so one bad user can't halt the loop. However, an attacker's hook returns 10MB of garbage data. The implicit memory expansion cost consumes the entire block gas limit, halting the loop anyway.",
                        remediation="If the return data is not needed, use assembly to perform the call without copying returndata: `assembly { success := call(gas(), target, value, 0, 0, 0, 0) }`.",
                        language="solidity"
                    ))

"""
SELF — Smart Contract Auditing Tool
Detector: SOL-CRIT-013 / SOL-HIGH-020 / SOL-HIGH-021
Storage collision vulnerabilities for upgradeable contracts.
"""

import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext
from self_tool.parsers.solidity_parser import parse_solidity

def detect(file_ctx: FileContext) -> List[Issue]:
    issues = []
    
    _detect_missing_gap_in_upgradeable(file_ctx, issues)
    
    return issues


def _detect_missing_gap_in_upgradeable(file_ctx: FileContext, issues: List[Issue]):
    """
    SOL-HIGH-020: Missing __gap in upgradeable base contract.
    """
    info = parse_solidity(file_ctx)
    for contract in info.contracts:
        # Check if it looks like an upgradeable base contract
        if "Upgradeable" in contract.name or contract.is_upgradeable:
            
            # Is there a gap variable?
            has_gap = any("__gap" in var.name for var in contract.state_vars)
            
            # Does it have state variables?
            has_state = len([v for v in contract.state_vars if not v.is_constant]) > 0
            
            if has_state and not has_gap and contract.kind == "contract":
                issues.append(Issue(
                    id="SOL-HIGH-020",
                    title="Missing `__gap` in Upgradeable Base Contract",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    file=file_ctx.relative_path,
                    line=contract.line,
                    snippet=file_ctx.get_snippet(contract.line, context=2),
                    description=(
                        "This contract is upgradeable and defines state variables, but does not "
                        "include a storage `__gap` array at the end. If a new variable is added "
                        "to this contract in a future upgrade, it will shift the storage slots "
                        "of all child contracts, causing catastrophic storage collisions."
                    ),
                    exploit_scenario="V1 is deployed. V2 adds a new variable to `BaseUpgradeable`. Child contracts inherit `BaseUpgradeable`. The new variable overwrites slot 5, which the child contract previously used for `owner`. The protocol is compromised.",
                    remediation="Add `uint256[50] private __gap;` at the end of all upgradeable base contracts.",
                    language="solidity"
                ))

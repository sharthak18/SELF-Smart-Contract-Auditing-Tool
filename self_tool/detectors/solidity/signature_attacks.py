"""
SELF — Smart Contract Auditing Tool
Detector: SOL-CRIT-014 / SOL-HIGH-022 / SOL-HIGH-023
Signature cryptography exploits (Malleability, ecrecover 0, etc).
"""

import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext
from self_tool.parsers.solidity_parser import parse_solidity

def detect(file_ctx: FileContext) -> List[Issue]:
    issues = []
    
    _detect_ecrecover_zero(file_ctx, issues)
    _detect_signature_malleability(file_ctx, issues)
    
    return issues


def _detect_ecrecover_zero(file_ctx: FileContext, issues: List[Issue]):
    """
    SOL-HIGH-023: ecrecover returns address(0) on invalid signatures.
    If the result is not checked against address(0), invalid sigs map to the zero address.
    """
    info = parse_solidity(file_ctx)
    for contract in info.contracts:
        for func in contract.functions:
            body = func.body
            if "ecrecover" in body:
                # Is the result checked against 0?
                # This is a basic heuristic. A full check needs CFG/Taint.
                if not re.search(r'(require|assert|if)\s*\([^;]*(!=|==)\s*(0|address\(0\))', body):
                    issues.append(Issue(
                        id="SOL-HIGH-023",
                        title="Unchecked `ecrecover` Return Value (Returns `address(0)`)",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        file=file_ctx.relative_path,
                        line=func.line,
                        snippet=file_ctx.get_snippet(func.line, context=4),
                        description=(
                            "The built-in `ecrecover` function returns `address(0)` when given an "
                            "invalid signature. The code does not appear to explicitly check if the "
                            "recovered address is `address(0)`. If `address(0)` has special privileges "
                            "or owns tokens, anyone can submit an invalid signature to act as `address(0)`."
                        ),
                        exploit_scenario="An attacker submits a malformed signature. `ecrecover` returns `address(0)`. The contract checks if the recovered address equals the owner. If the owner variable was uninitialized (defaults to 0), the attacker bypasses authentication.",
                        remediation="Always check `require(recoveredAddress != address(0), 'Invalid signature');` after calling `ecrecover`, or use OpenZeppelin's `ECDSA.recover` library.",
                        language="solidity"
                    ))


def _detect_signature_malleability(file_ctx: FileContext, issues: List[Issue]):
    """
    SOL-CRIT-014: ECDSA signature malleability.
    If the 's' value isn't checked, a valid signature can be morphed into a second valid signature.
    """
    info = parse_solidity(file_ctx)
    for contract in info.contracts:
        for func in contract.functions:
            body = func.body
            
            # If doing raw ecrecover with v, r, s
            if "ecrecover" in body and "v, r, s" in body.lower():
                # Check for 's' upper bound validation
                # 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
                if "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" not in body:
                    issues.append(Issue(
                        id="SOL-CRIT-014",
                        title="ECDSA Signature Malleability",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.MEDIUM,
                        file=file_ctx.relative_path,
                        line=func.line,
                        snippet=file_ctx.get_snippet(func.line, context=4),
                        description=(
                            "The function uses `ecrecover` directly but does not validate the `s` "
                            "value of the signature. ECDSA signatures are malleable: given a valid "
                            "signature `(v, r, s)`, an attacker can compute a second valid signature "
                            "`(v', r, -s mod n)` without knowing the private key. If the signature "
                            "is used as a unique identifier (e.g., to prevent replay), an attacker "
                            "can replay the transaction."
                        ),
                        exploit_scenario="A protocol allows users to withdraw by providing a signature. To prevent replay, it marks the signature hash as 'used'. An attacker observes a valid withdrawal, flips the `s` value to generate a second valid signature, and withdraws a second time.",
                        remediation="Require that `s` is in the lower half of the curve order: `require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0);`. Better yet, use OpenZeppelin's `ECDSA` library.",
                        language="solidity"
                    ))

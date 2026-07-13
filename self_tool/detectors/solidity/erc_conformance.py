"""
SELF — Smart Contract Auditing Tool
Detector: SOL-HIGH-014 / SOL-HIGH-015 / SOL-HIGH-016 / SOL-MED-013 / SOL-MED-014
ERC standard violations and non-conformances that lead to fund loss or DoS.
"""

import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext
from self_tool.parsers.solidity_parser import parse_solidity

def detect(file_ctx: FileContext) -> List[Issue]:
    issues = []
    content = file_ctx.content
    
    _detect_erc20_approve_race(file_ctx, issues)
    _detect_erc721_safetransfer_check(file_ctx, issues)
    _detect_erc2612_permit_deadline(file_ctx, issues)
    
    return issues


def _detect_erc20_approve_race(file_ctx: FileContext, issues: List[Issue]):
    """
    SOL-HIGH-014: ERC-20 `approve` race condition.
    Approving a non-zero amount while a non-zero allowance exists allows front-running.
    """
    info = parse_solidity(file_ctx)
    for contract in info.contracts:
        if contract.kind in {"interface", "library"}:
            continue
            
        for func in contract.functions:
            if func.name == "approve" and "uint" in func.params:
                # Basic check: is there a requirement that the allowance is 0 or the new amount is 0?
                body = func.body
                
                # Check if it uses OpenZeppelin's safeApprove (which handles this)
                if "safeApprove" in body:
                    continue
                    
                has_zero_check = bool(re.search(
                    r'(require|assert)\s*\([^;]+(==\s*0|0\s*==)[^;]+\)', 
                    body
                ))
                
                if not has_zero_check:
                    issues.append(Issue(
                        id="SOL-HIGH-014",
                        title="ERC-20 `approve()` Race Condition",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        file=file_ctx.relative_path,
                        line=func.line,
                        snippet=file_ctx.get_snippet(func.line, context=4),
                        description=(
                            "The `approve()` function allows changing an allowance from a non-zero "
                            "value to another non-zero value. This creates a front-running vector: "
                            "if Alice changes Bob's allowance from 5 to 3, Bob can front-run the "
                            "transaction, spend 5, and then still have an allowance of 3."
                        ),
                        exploit_scenario=(
                            "1. Alice approves Bob to spend 50 tokens.\n"
                            "2. Alice decides to lower the allowance to 30.\n"
                            "3. Bob sees the transaction in the mempool, front-runs it, and spends 50.\n"
                            "4. Alice's transaction confirms, setting Bob's allowance to 30.\n"
                            "5. Bob spends another 30. Total spent: 80 (exceeding intended 50)."
                        ),
                        remediation=(
                            "1. Implement `increaseAllowance()` and `decreaseAllowance()` instead.\n"
                            "2. If `approve()` is strictly required, require the current allowance "
                            "or new value to be zero: `require(amount == 0 || allowance[msg.sender][spender] == 0)`"
                        ),
                        language="solidity",
                    ))


def _detect_erc721_safetransfer_check(file_ctx: FileContext, issues: List[Issue]):
    """
    SOL-HIGH-016: ERC-721 `transferFrom` used instead of `safeTransferFrom`.
    Transferring NFTs to contracts that don't support them locks the NFT forever.
    """
    info = parse_solidity(file_ctx)
    for contract in info.contracts:
        if contract.kind in {"interface", "library"}:
            continue
            
        for func in contract.functions:
            body = func.body
            
            # Find .transferFrom() calls that look like ERC721 (3 args)
            for match in re.finditer(r'\.\s*transferFrom\s*\([^,]+,[^,]+,[^)]+\)', body):
                line = file_ctx.content[:func.body_start_line + match.start()].count('\n') + 1
                
                issues.append(Issue(
                    id="SOL-HIGH-016",
                    title="Dangerous `transferFrom` (Missing `safeTransferFrom`)",
                    severity=Severity.HIGH,
                    confidence=Confidence.LOW,  # Could be ERC20, hard to tell without typing
                    file=file_ctx.relative_path,
                    line=line,
                    snippet=file_ctx.get_snippet(line, context=2),
                    description=(
                        "Using `transferFrom` instead of `safeTransferFrom` for NFTs (ERC-721/1155) "
                        "is dangerous. If the recipient is a smart contract that does not implement "
                        "`onERC721Received`, the NFT will be locked forever."
                    ),
                    exploit_scenario="A user interacts with a marketplace and transfers their NFT to a newly deployed smart contract wallet that hasn't implemented ERC721 receiver hooks. The NFT is permanently lost.",
                    remediation="Use `safeTransferFrom` which checks `onERC721Received` on contract recipients.",
                    language="solidity"
                ))


def _detect_erc2612_permit_deadline(file_ctx: FileContext, issues: List[Issue]):
    """
    SOL-MED-014: ERC-2612 permit with no deadline validation.
    """
    info = parse_solidity(file_ctx)
    for contract in info.contracts:
        for func in contract.functions:
            if func.name == "permit":
                if "block.timestamp" not in func.body:
                    issues.append(Issue(
                        id="SOL-MED-014",
                        title="ERC-2612 Permit Missing Deadline Validation",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        file=file_ctx.relative_path,
                        line=func.line,
                        snippet=file_ctx.get_snippet(func.line, context=4),
                        description=(
                            "The `permit` function accepts a `deadline` parameter but does not check "
                            "it against `block.timestamp`. This allows signed permits to be held and "
                            "executed indefinitely, violating the EIP-2612 specification."
                        ),
                        exploit_scenario="A user signs a permit for a dApp to spend tokens. The dApp holds the signature. Years later, the user deposits funds, and the dApp uses the old signature to drain them.",
                        remediation="Add `require(block.timestamp <= deadline, 'Permit expired');`",
                        language="solidity"
                    ))

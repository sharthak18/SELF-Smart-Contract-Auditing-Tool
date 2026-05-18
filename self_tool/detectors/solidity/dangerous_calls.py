"""
SELF — SOL-CRIT-004/005/006: Unchecked CALL, Arbitrary DELEGATECALL, Unprotected SELFDESTRUCT
Sources: SWC-104, SWC-112, SWC-106, Slither, Trail of Bits, DeFiHackLabs
"""
import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext


def detect(file_ctx: FileContext) -> List[Issue]:
    issues = []
    content = file_ctx.content

    # SOL-CRIT-004: Unchecked .call() return value
    call_pattern = re.compile(r'(\w+(?:\.\w+)*)\s*\.\s*call\s*\{[^}]*\}\s*\([^)]*\)\s*;', re.MULTILINE)
    ok_pattern = re.compile(r'\(bool\s+\w+\s*,', re.MULTILINE)
    for m in call_pattern.finditer(content):
        line = content[:m.start()].count('\n') + 1
        # Check if the call result is captured
        surrounding = content[max(0, m.start()-5):m.end()+5]
        if not ok_pattern.search(surrounding) and '(bool' not in surrounding:
            issues.append(Issue(
                id="SOL-CRIT-004",
                title="Unchecked External Call Return Value",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file=file_ctx.relative_path,
                line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description=(
                    "A low-level `.call()` is made without checking its boolean return value. "
                    "If the call fails (reverts or runs out of gas), execution silently continues "
                    "with corrupted state — funds may be lost with no indication of failure.\n\n"
                    "**Real incidents:** Unchecked send/call is one of the most common findings "
                    "across Sherlock, Code4rena, and Immunefi bounties."
                ),
                exploit_scenario=(
                    "1. Contract calls `recipient.call{value: amount}('')`.\n"
                    "2. Recipient is a contract that deliberately reverts.\n"
                    "3. Return value `false` is ignored — state is updated as if transfer succeeded.\n"
                    "4. Funds are permanently locked or double-counted."
                ),
                remediation=(
                    "Always capture and check the return value:\n"
                    "```solidity\n"
                    "(bool success, ) = target.call{value: amount}('');\n"
                    "require(success, 'ETH transfer failed');\n"
                    "```\n"
                    "Or use OpenZeppelin `Address.sendValue()` which reverts on failure."
                ),
                references=["SWC-104", "https://swcregistry.io/docs/SWC-104", "Slither: unchecked-lowlevel"],
                language="solidity",
            ))

    # SOL-CRIT-005: Arbitrary DELEGATECALL
    delcall = re.compile(r'\.delegatecall\s*\(', re.MULTILINE)
    user_input = re.compile(r'(msg\.data|calldata|_data|data_|calldatacopy)', re.MULTILINE)
    for m in delcall.finditer(content):
        line = content[:m.start()].count('\n') + 1
        surrounding = content[max(0, m.start()-300):m.start()+200]
        if user_input.search(surrounding):
            issues.append(Issue(
                id="SOL-CRIT-005",
                title="Arbitrary DELEGATECALL with User-Controlled Data",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                file=file_ctx.relative_path,
                line=line,
                snippet=file_ctx.get_snippet(line, context=4),
                description=(
                    "`delegatecall` executes external code in the caller's storage context. "
                    "When the target address or calldata is user-controlled, an attacker can "
                    "point it to a malicious contract and overwrite any storage slot — "
                    "including ownership, balances, or access control state.\n\n"
                    "**Real incidents:** Parity Wallet Hack (2017) — $30M frozen via delegatecall."
                ),
                exploit_scenario=(
                    "1. Attacker provides a malicious contract address as the `delegatecall` target.\n"
                    "2. The malicious contract writes `address(attacker)` to the `owner` storage slot.\n"
                    "3. Attacker is now owner and drains all funds."
                ),
                remediation=(
                    "Never use `delegatecall` with user-controlled targets or data. "
                    "If a proxy pattern is needed, hardcode the implementation address and "
                    "use OpenZeppelin's `TransparentUpgradeableProxy` or `UUPS` pattern with "
                    "strict upgrade guards."
                ),
                references=["SWC-112", "https://blog.openzeppelin.com/proxy-patterns/", "https://rekt.news/parity-wallet-hack-2/"],
                language="solidity",
            ))

    # SOL-CRIT-006: Unprotected SELFDESTRUCT
    selfd = re.compile(r'\bselfdestruct\s*\(', re.MULTILINE)
    auth_nearby = re.compile(r'(onlyOwner|require\s*\(\s*msg\.sender|onlyAdmin|onlyRole|hasRole)', re.MULTILINE)
    for m in selfd.finditer(content):
        line = content[:m.start()].count('\n') + 1
        surrounding = content[max(0, m.start()-500):m.start()]
        if not auth_nearby.search(surrounding):
            issues.append(Issue(
                id="SOL-CRIT-006",
                title="Unprotected `selfdestruct` — Contract Can Be Destroyed",
                severity=Severity.CRITICAL,
                confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path,
                line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description=(
                    "`selfdestruct` destroys the contract and sends all ETH to a specified address. "
                    "Without proper access control, any user can permanently destroy the contract "
                    "and steal all its ETH balance. Even with access control, `selfdestruct` is "
                    "dangerous in upgradeable contracts (EIP-4758 deprecates it post-Dencun)."
                ),
                exploit_scenario=(
                    "1. Attacker calls the function containing `selfdestruct`.\n"
                    "2. Contract is destroyed; all ETH forwarded to attacker.\n"
                    "3. Protocol state is permanently lost — no recovery possible."
                ),
                remediation=(
                    "1. Remove `selfdestruct` if not essential.\n"
                    "2. If required, add strict access control: `require(msg.sender == owner)`.\n"
                    "3. Consider using a `pause` + `emergencyWithdraw` pattern instead.\n"
                    "4. Note: Post-Dencun (EIP-6780), `selfdestruct` only works in the same transaction it's deployed."
                ),
                references=["SWC-106", "EIP-6780", "https://swcregistry.io/docs/SWC-106"],
                language="solidity",
            ))

    return issues

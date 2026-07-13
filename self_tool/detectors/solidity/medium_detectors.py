"""
SELF — MEDIUM severity detectors
SOL-MED-001 through SOL-MED-013
Sources: Solodit, Trail of Bits, OpenZeppelin, Sherlock, Code4rena, Chainlink best practices,
         EIP-4626 vulnerabilities, ConsenSys Diligence, Spearbit audit reports
"""
import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext


def detect(file_ctx: FileContext) -> List[Issue]:
    issues = []
    content = file_ctx.content
    _centralization_risk(file_ctx, content, issues)
    _missing_zero_address(file_ctx, content, issues)
    _missing_deadline(file_ctx, content, issues)
    _stale_price_feed(file_ctx, content, issues)
    _erc777_hook(file_ctx, content, issues)
    _missing_event(file_ctx, content, issues)
    _unsafe_cast(file_ctx, content, issues)
    _divide_before_multiply_med(file_ctx, content, issues)
    _gas_griefing(file_ctx, content, issues)
    _erc4626_inflation(file_ctx, content, issues)
    _pull_over_push(file_ctx, content, issues)
    _msg_value_loop(file_ctx, content, issues)
    return issues


def _centralization_risk(file_ctx, content, issues):
    """SOL-MED-001: Single owner with unchecked power over funds."""
    has_ownable = bool(re.search(r'(Ownable|onlyOwner)', content))
    if not has_ownable:
        return
    # Flag if owner can withdraw, drain, or mint without timelock
    danger_fns = re.compile(
        r'function\s+(withdraw|drain|emergencyWithdraw|rescueTokens|sweep|mint)\s*\([^)]*\)'
        r'[^{]*\{', re.MULTILINE
    )
    timelock = re.compile(r'(TimelockController|Timelock|timelock|delay\s*>=)', re.IGNORECASE)
    if timelock.search(content):
        return
    for m in danger_fns.finditer(content):
        func_start = m.end(); depth = 1; i = func_start
        while i < len(content) and depth > 0:
            if content[i] == '{': depth += 1
            elif content[i] == '}': depth -= 1
            i += 1
        body = content[func_start:i]
        if re.search(r'onlyOwner|onlyAdmin', m.group(0) + body[:100]):
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="SOL-MED-001",
                title=f"Centralization Risk: Owner Controls `{m.group(1)}()` Without Timelock",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description=(
                    "A single `owner` address can immediately call critical functions like "
                    f"`{m.group(1)}()` with no timelock or multi-sig requirement. "
                    "A compromised or malicious owner can rug-pull the protocol instantly."
                ),
                exploit_scenario="Owner's private key is compromised. Attacker calls withdraw() to drain all funds before the team can react.",
                remediation=(
                    "1. Use a Gnosis Safe multisig as owner.\n"
                    "2. Add a TimelockController (minimum 48h delay for critical ops).\n"
                    "3. Emit events on all owner actions for monitoring."
                ),
                references=["Solodit: centralization-risk", "https://docs.openzeppelin.com/contracts/4.x/api/governance#TimelockController"],
                language="solidity",
            ))
            break


def _missing_zero_address(file_ctx, content, issues):
    """SOL-MED-002: Address parameters set without zero-address validation."""
    setter_pattern = re.compile(
        r'function\s+(set\w+|update\w+|initialize\w*)\s*\([^)]*\baddress\b[^)]*\)[^{]*\{',
        re.MULTILINE
    )
    for m in setter_pattern.finditer(content):
        func_start = m.end(); depth = 1; i = func_start
        while i < len(content) and depth > 0:
            if content[i] == '{': depth += 1
            elif content[i] == '}': depth -= 1
            i += 1
        body = content[func_start:i]
        # Skip if zero-address check exists
        if re.search(r'(address\s*\(\s*0\s*\)|!= address\(0\)|== address\(0\)|ZeroAddress)', body):
            continue
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-MED-002",
            title=f"Missing Zero-Address Check in `{m.group(1)}()`",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                f"`{m.group(1)}()` accepts an `address` parameter but does not check for "
                "`address(0)`. Setting a critical address (owner, treasury, oracle) to zero "
                "permanently locks functionality or sends funds to the burn address."
            ),
            exploit_scenario="Admin accidentally calls `setTreasury(address(0))`. All fees are now burned forever. No way to recover.",
            remediation=(
                "```solidity\n"
                "function setTreasury(address _treasury) external onlyOwner {\n"
                "    require(_treasury != address(0), 'Zero address');\n"
                "    treasury = _treasury;\n"
                "}\n"
                "```\n"
                "Or use OZ's `Errors.AddressZero` in v5."
            ),
            references=["Slither: missing-zero-check", "Solodit: zero-address-check"],
            language="solidity",
        ))


def _missing_deadline(file_ctx, content, issues):
    """SOL-MED-003: Swap/permit/signature missing deadline check."""
    m = re.search(r'(swap|addLiquidity|removeLiquidity|permit)', content, re.IGNORECASE)
    if not m:
        return
    has_deadline = bool(re.search(r'(deadline|expiry|expiration|validUntil)', content, re.IGNORECASE))
    if has_deadline:
        return
    line = content[:m.start()].count('\n') + 1
    issues.append(Issue(
        id="SOL-MED-003",
        title="Missing Deadline on Swap/Permit — Transaction Can Be Delayed and Replayed",
        severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
        file=file_ctx.relative_path, line=line,
        snippet=file_ctx.get_snippet(line, context=3),
        description=(
            "Swap or permit operations have no `deadline` parameter. Transactions can "
            "be held in the mempool by a malicious validator and executed at a future "
            "time when conditions are unfavorable to the user."
        ),
        exploit_scenario="User submits a swap. Validator withholds it, waits for price to move, then includes it — user receives much less than expected.",
        remediation=(
            "Add deadline to all time-sensitive operations:\n"
            "```solidity\n"
            "require(block.timestamp <= deadline, 'Expired');\n"
            "```"
        ),
        references=["Solodit: missing-deadline", "Uniswap V2 best practices"],
        language="solidity",
    ))


def _stale_price_feed(file_ctx, content, issues):
    """SOL-MED-004: Chainlink oracle used without staleness check."""
    m = re.search(r'(latestRoundData|AggregatorV3Interface)', content)
    if not m:
        return
    has_staleness = bool(re.search(
        r'(updatedAt|answeredInRound|roundId|block\.timestamp\s*-\s*updatedAt'
        r'|STALE_THRESHOLD|maxStaleness)', content
    ))
    if has_staleness:
        return
    line = content[:m.start()].count('\n') + 1
    issues.append(Issue(
        id="SOL-MED-004",
        title="Chainlink Oracle: Missing Staleness / Heartbeat Check",
        severity=Severity.MEDIUM, confidence=Confidence.HIGH,
        file=file_ctx.relative_path, line=line,
        snippet=file_ctx.get_snippet(line, context=4),
        description=(
            "`latestRoundData()` is called but `updatedAt` timestamp is not validated. "
            "If a Chainlink feed goes stale (oracle stops updating), the contract will "
            "use an outdated price indefinitely — enabling exploitation when real price has moved."
        ),
        exploit_scenario="Chainlink feed freezes during market crash. Stale price shows asset at $100. True price is $10. Attacker borrows at inflated collateral value.",
        remediation=(
            "```solidity\n"
            "(uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound)\n"
            "    = priceFeed.latestRoundData();\n"
            "require(answeredInRound >= roundId, 'Stale round');\n"
            "require(block.timestamp - updatedAt <= MAX_STALENESS, 'Stale price');\n"
            "require(answer > 0, 'Negative price');\n"
            "```"
        ),
        references=["Chainlink docs: data feeds", "Solodit: stale-price-feed", "https://docs.chain.link/data-feeds/historical-data"],
        language="solidity",
    ))


def _erc777_hook(file_ctx, content, issues):
    """SOL-MED-005: ERC777 tokensReceived hook enabling reentrancy."""
    m = re.search(r'(ERC777|IERC777|tokensReceived|_callTokensReceived)', content)
    if not m:
        return
    has_guard = bool(re.search(r'(nonReentrant|ReentrancyGuard|_status)', content))
    if has_guard:
        return
    line = content[:m.start()].count('\n') + 1
    issues.append(Issue(
        id="SOL-MED-005",
        title="ERC777 `tokensReceived` Hook: Reentrancy Risk",
        severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
        file=file_ctx.relative_path, line=line,
        snippet=file_ctx.get_snippet(line, context=3),
        description=(
            "ERC777 tokens call `tokensReceived()` on the recipient before completing "
            "the transfer. Without a reentrancy guard, this hook can re-enter the contract "
            "in an inconsistent state.\n\n"
            "**Real incident:** Uniswap V1 LPs were drained via ERC777 reentrancy (2019)."
        ),
        exploit_scenario="Attacker sends ERC777 token. `tokensReceived()` fires, re-entering the contract before state update. Attacker drains funds.",
        remediation="Add `nonReentrant` to all functions that accept ERC777 tokens, or use CEI pattern strictly.",
        references=["https://github.com/OpenZeppelin/openzeppelin-contracts/issues/1681", "EIP-777"],
        language="solidity",
    ))


def _missing_event(file_ctx, content, issues):
    """SOL-MED-006: Critical state changes without event emission."""
    setter_pattern = re.compile(
        r'function\s+(set\w+|update\w+|change\w+)\s*\([^)]*\)\s*(?:public|external)[^{]*\{',
        re.MULTILINE
    )
    for m in setter_pattern.finditer(content):
        func_start = m.end(); depth = 1; i = func_start
        while i < len(content) and depth > 0:
            if content[i] == '{': depth += 1
            elif content[i] == '}': depth -= 1
            i += 1
        body = content[func_start:i]
        if not re.search(r'\bemit\b', body):
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="SOL-MED-006",
                title=f"Missing Event in `{m.group(1)}()`: State Change Not Logged",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description=(
                    f"`{m.group(1)}()` modifies critical state but emits no event. "
                    "Off-chain monitoring systems, indexers, and users cannot detect "
                    "state changes, making anomaly detection impossible."
                ),
                exploit_scenario="Admin silently changes fee to 100% or oracle address to attacker-controlled — no event means no alert.",
                remediation=(
                    "```solidity\n"
                    "event TreasuryUpdated(address indexed oldTreasury, address indexed newTreasury);\n"
                    "function setTreasury(address _new) external onlyOwner {\n"
                    "    emit TreasuryUpdated(treasury, _new);\n"
                    "    treasury = _new;\n"
                    "}\n"
                    "```"
                ),
                references=["Slither: events-maths", "Solodit: missing-event"],
                language="solidity",
            ))


def _unsafe_cast(file_ctx, content, issues):
    """SOL-MED-007: Unsafe downcasting that silently truncates."""
    # uint256 → uint128/64/32/16/8 without SafeCast
    cast_pattern = re.compile(
        r'\buint(?:128|64|32|16|8)\s*\(\s*\w+\s*\)',
        re.MULTILINE
    )
    safecast = re.compile(r'(SafeCast|toUint128|toUint64|toUint32)', re.MULTILINE)
    if safecast.search(content):
        return
    for m in cast_pattern.finditer(content):
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-MED-007",
            title=f"Unsafe Downcast: `{m.group(0).strip()}` May Silently Truncate",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "An explicit downcast truncates the upper bits without checking for overflow. "
                "If the original value exceeds the target type's range, the result is silently wrong."
            ),
            exploit_scenario="Amount=2^128+1 gets cast to uint128 → stored as 1. User's large deposit recorded as 1 wei.",
            remediation=(
                "Use OpenZeppelin's SafeCast:\n"
                "```solidity\n"
                "import '@openzeppelin/contracts/utils/math/SafeCast.sol';\n"
                "uint128 safeAmount = SafeCast.toUint128(amount);  // Reverts on overflow\n"
                "```"
            ),
            references=["Slither: safe-cast", "https://docs.openzeppelin.com/contracts/4.x/api/utils#SafeCast"],
            language="solidity",
        ))
        break  # One per file to avoid noise


def _divide_before_multiply_med(file_ctx, content, issues):
    """SOL-MED-008: Percentage calculation doing division first."""
    # amount * percent / 100 is fine; amount / 100 * percent is wrong
    pattern = re.compile(r'(\w+)\s*/\s*(\d+)\s*\*\s*(\w+)', re.MULTILINE)
    for m in pattern.finditer(content):
        divisor = int(m.group(2))
        if divisor in (100, 1000, 10000, 1e18):
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="SOL-MED-008",
                title="Percentage Calculation: Division Before Multiplication Loses Precision",
                severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description=f"`{m.group(0).strip()}` divides by {divisor} before multiplying. Integer division truncates first, amplifying rounding loss.",
                exploit_scenario="Fee calculation rounds down systematically — protocol loses revenue or users receive more than entitled over many transactions.",
                remediation=f"Reorder: `{m.group(1)} * {m.group(3)} / {divisor}` or use `Math.mulDiv({m.group(1)}, {m.group(3)}, {divisor})`.",
                references=["Slither: divide-before-multiply"],
                language="solidity",
            ))
            break


def _gas_griefing(file_ctx, content, issues):
    """SOL-MED-009: Forwarding exact gas amount — can be griefed."""
    pattern = re.compile(r'\.call\s*\{\s*value\s*:[^,}]+,\s*gas\s*:\s*\d+\s*\}', re.MULTILINE)
    for m in pattern.finditer(content):
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-MED-009",
            title="Gas Griefing: Hardcoded Gas in `.call{gas: N}`",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "A hardcoded gas stipend is forwarded in `.call{gas: N}`. If `N` is too low "
                "(after EIP-1884/2929 repricing), the call always fails. If too high, "
                "re-entrancy via gas is possible. Hardcoded gas is fragile across hard forks."
            ),
            exploit_scenario="EIP-2929 raised SLOAD cost. Hardcoded gas=2300 no longer covers simple storage reads — all withdrawals permanently fail.",
            remediation="Forward all available gas (omit `gas:`) or use `Address.sendValue()` from OpenZeppelin. Avoid hardcoded gas stipends.",
            references=["SWC-134", "EIP-2929", "https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/"],
            language="solidity",
        ))


def _erc4626_inflation(file_ctx, content, issues):
    """SOL-MED-010: ERC-4626 vault missing inflation attack protection."""
    m = re.search(r'(ERC4626|previewDeposit|convertToShares|totalAssets)', content)
    if not m:
        return
    has_protection = bool(re.search(
        r'(MINIMUM_SHARES|deadShares|_decimalsOffset|virtual shares|dead address'
        r'|1e3|offset\s*=)', content, re.IGNORECASE
    ))
    if has_protection:
        return
    line = content[:m.start()].count('\n') + 1
    issues.append(Issue(
        id="SOL-MED-010",
        title="ERC-4626 Vault: Missing Inflation Attack Protection",
        severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
        file=file_ctx.relative_path, line=line,
        snippet=file_ctx.get_snippet(line, context=3),
        description=(
            "This ERC-4626 vault has no protection against the share inflation attack. "
            "An attacker can be the first depositor, manipulate the share/asset ratio "
            "by donating tokens, and cause subsequent depositors to receive 0 shares.\n\n"
            "**Real incidents:** Multiple Code4rena findings on ERC-4626 forks (2022-2023)."
        ),
        exploit_scenario=(
            "1. Attacker deposits 1 wei, gets 1 share.\n"
            "2. Attacker donates 1e18 tokens to vault directly.\n"
            "3. `pricePerShare` = 1e18+1. Victim deposits 1e18 tokens — gets 0 shares (rounds down).\n"
            "4. Attacker redeems 1 share for all assets."
        ),
        remediation=(
            "Use OZ's virtual shares offset (ERC4626 v5) or mint dead shares on first deposit:\n"
            "```solidity\n"
            "// OZ ERC4626 v5 approach: _decimalsOffset() returns 3\n"
            "// This adds 10^3 virtual shares making inflation attacks 1000x more expensive\n"
            "function _decimalsOffset() internal pure override returns (uint8) { return 3; }\n"
            "```"
        ),
        references=["EIP-4626", "https://github.com/OpenZeppelin/openzeppelin-contracts/issues/3706", "Code4rena: erc4626-inflation"],
        language="solidity",
    ))


def _pull_over_push(file_ctx, content, issues):
    """SOL-MED-011: Push payment pattern (looping ETH sends) instead of pull."""
    # Loop with .call or .transfer inside
    loop_with_send = re.compile(
        r'for\s*\([^)]+\)[^{]*\{[^}]*(\.call\{value|\.transfer\(|\.send\()[^}]*\}',
        re.MULTILINE | re.DOTALL
    )
    for m in loop_with_send.finditer(content):
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-MED-011",
            title="Push Payment in Loop: DoS if Any Recipient Reverts",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                "ETH is pushed to multiple addresses in a loop. If any recipient's "
                "`receive()` reverts (malicious contract, out of gas), the entire "
                "distribution function is DoS'd — no one gets paid."
            ),
            exploit_scenario="Attacker includes a contract with reverting `receive()` in the recipient list. Entire payout function reverts permanently.",
            remediation=(
                "Use the pull payment pattern:\n"
                "```solidity\n"
                "mapping(address => uint256) public pendingWithdrawals;\n\n"
                "// Record entitlements (never revert)\n"
                "function distribute() external { pendingWithdrawals[user] += share; }\n\n"
                "// Users pull their own funds\n"
                "function withdraw() external {\n"
                "    uint256 amount = pendingWithdrawals[msg.sender];\n"
                "    pendingWithdrawals[msg.sender] = 0;\n"
                "    payable(msg.sender).transfer(amount);\n"
                "}\n"
                "```"
            ),
            references=["SWC-113", "https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/#favor-pull-over-push-for-external-calls"],
            language="solidity",
        ))


def _msg_value_loop(file_ctx, content, issues):
    """SOL-MED-012: msg.value used inside a loop — reuse across iterations."""
    loop_pattern = re.compile(r'for\s*\([^)]+\)[^{]*\{', re.MULTILINE)
    for m in loop_pattern.finditer(content):
        func_start = m.end(); depth = 1; i = func_start
        while i < len(content) and depth > 0:
            if content[i] == '{': depth += 1
            elif content[i] == '}': depth -= 1
            i += 1
        body = content[func_start:i]
        if re.search(r'msg\.value', body):
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="SOL-MED-012",
                title="`msg.value` Reused Inside Loop — ETH Amount Multiplied by Iterations",
                severity=Severity.MEDIUM, confidence=Confidence.HIGH,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=4),
                description=(
                    "`msg.value` is referenced inside a loop. `msg.value` is constant for "
                    "the entire transaction — using it in each loop iteration means the "
                    "same ETH amount is credited N times while only sent once.\n\n"
                    "**Real incident:** Opyn (2020) — $371k stolen via msg.value loop reuse."
                ),
                exploit_scenario="Loop runs 10 times. `msg.value=1 ETH` credited 10 times. Attacker sends 1 ETH, receives credit for 10 ETH.",
                remediation="Cache `msg.value` before the loop and track remaining amount, or redesign to avoid ETH in loops.",
                references=["https://rekt.news/opyn-rekt/", "Sherlock: msg-value-in-loop"],
                language="solidity",
            ))

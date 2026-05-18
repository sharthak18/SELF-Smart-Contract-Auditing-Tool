"""
SELF — HIGH severity detectors: ERC20, Slippage, Timestamp, Rounding, Governance, Init
SOL-HIGH-006 through SOL-HIGH-014
Sources: Rekt.news, Sherlock, Code4rena, Solodit, OpenZeppelin, DeFiHackLabs, Immunefi
"""
import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext


def detect(file_ctx: FileContext) -> List[Issue]:
    issues = []
    content = file_ctx.content
    _erc20_approval_race(file_ctx, content, issues)
    _unbounded_loop(file_ctx, content, issues)
    _erc20_transfer_unchecked(file_ctx, content, issues)
    _slippage_missing(file_ctx, content, issues)
    _block_timestamp(file_ctx, content, issues)
    _rounding_error(file_ctx, content, issues)
    _governance_flashloan(file_ctx, content, issues)
    _unprotected_initialize(file_ctx, content, issues)
    return issues


def _erc20_approval_race(file_ctx, content, issues):
    """SOL-HIGH-006: ERC20 approve() race condition — should use increaseAllowance."""
    pattern = re.compile(r'\.approve\s*\(\s*\w+\s*,\s*\w+\s*\)', re.MULTILINE)
    increase = re.compile(r'(increaseAllowance|safeIncreaseAllowance|forceApprove)', re.MULTILINE)
    for m in pattern.finditer(content):
        surrounding = content[max(0, m.start()-200):m.start()+100]
        if increase.search(surrounding):
            continue
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-HIGH-006",
            title="ERC20 `approve()` Race Condition",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "Calling `approve(spender, amount)` directly is vulnerable to a front-running "
                "race condition. If an allowance already exists, a malicious spender watching "
                "the mempool can spend the old allowance before the new `approve()` confirms, "
                "then spend the new one — double-spending.\n\n"
                "EIP-20 known issue: https://eips.ethereum.org/EIPS/eip-20#approve"
            ),
            exploit_scenario=(
                "1. Owner approves spender for 100 tokens. Spender immediately spends 100.\n"
                "2. Owner wants to change to 50 — broadcasts `approve(spender, 50)`.\n"
                "3. Spender front-runs, spends the original 100 again before it changes.\n"
                "4. Owner's approve goes through — spender spends 50 more. Total: 250 instead of 50."
            ),
            remediation=(
                "Use `safeIncreaseAllowance` / `safeDecreaseAllowance` from OpenZeppelin, "
                "or set allowance to 0 first:\n"
                "```solidity\n"
                "token.safeApprove(spender, 0);\n"
                "token.safeApprove(spender, newAmount);\n"
                "// Or: token.safeIncreaseAllowance(spender, addedAmount);\n"
                "```"
            ),
            references=["EIP-20", "SWC-114", "https://github.com/OpenZeppelin/openzeppelin-contracts/issues/738"],
            language="solidity",
        ))


def _unbounded_loop(file_ctx, content, issues):
    """SOL-HIGH-007: Unbounded loop over dynamic array — DoS via block gas limit."""
    # for loop over .length with no cap
    pattern = re.compile(
        r'for\s*\([^;]*;\s*\w+\s*<\s*(\w+)\.length\s*;[^)]*\)',
        re.MULTILINE
    )
    push_pattern = re.compile(r'\.push\s*\(', re.MULTILINE)
    for m in pattern.finditer(content):
        arr_name = m.group(1)
        func_start = max(0, m.start() - 500)
        surrounding = content[func_start:m.start() + 200]
        # Only flag if the array can grow (has .push())
        if not push_pattern.search(content):
            continue
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-HIGH-007",
            title=f"Unbounded Loop Over `{arr_name}` — Denial of Service Risk",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                f"A loop iterates over `{arr_name}.length` with no upper bound, and the "
                "array can grow via `.push()`. An attacker can add enough entries to "
                "push gas cost above the block limit, permanently bricking the function.\n\n"
                "**Real incidents:** Fomo3D (2018) — gas griefing to win jackpot."
            ),
            exploit_scenario=(
                f"1. Attacker calls the function that adds to `{arr_name}` thousands of times.\n"
                "2. Gas cost of the looping function exceeds block gas limit.\n"
                "3. The function is permanently DoS'd — withdrawals, distributions, etc. all fail."
            ),
            remediation=(
                "Use pagination or pull-payment patterns:\n"
                "```solidity\n"
                "// Paginated: process maxBatch items per call\n"
                "function processPage(uint256 offset, uint256 maxBatch) external {\n"
                "    uint256 end = Math.min(offset + maxBatch, items.length);\n"
                "    for (uint256 i = offset; i < end; i++) { ... }\n"
                "}\n"
                "```"
            ),
            references=["SWC-128", "Solodit: dos-unbounded-loop", "https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/"],
            language="solidity",
        ))


def _erc20_transfer_unchecked(file_ctx, content, issues):
    """SOL-HIGH-008: ERC20 transfer/transferFrom return value not checked."""
    # .transfer( or .transferFrom( not captured in bool
    pattern = re.compile(
        r'(?<!bool\s)(?<!\(bool\s*\w+\s*,\s*)(\w+(?:\.\w+)*)\.'
        r'(transfer|transferFrom)\s*\([^)]+\)\s*;',
        re.MULTILINE
    )
    safeTransfer = re.compile(r'(safeTransfer|SafeERC20)', re.MULTILINE)
    for m in pattern.finditer(content):
        # Skip if file uses SafeERC20 globally
        if safeTransfer.search(content):
            continue
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-HIGH-008",
            title="ERC20 `transfer()`/`transferFrom()` Return Value Ignored",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "Some ERC20 tokens (USDT, BNB, OMG) return `false` on failure instead of "
                "reverting. Ignoring the return value means a failed transfer is treated as "
                "success — state is updated even though no tokens moved."
            ),
            exploit_scenario="Contract calls `token.transfer(user, amount)` — token returns false (e.g. USDT on failure). Contract marks payment as complete. User never receives tokens.",
            remediation=(
                "Use OpenZeppelin's `SafeERC20`:\n"
                "```solidity\n"
                "using SafeERC20 for IERC20;\n"
                "token.safeTransfer(recipient, amount);  // Reverts on false return\n"
                "```"
            ),
            references=["https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol", "Slither: unchecked-transfer"],
            language="solidity",
        ))


def _slippage_missing(file_ctx, content, issues):
    """SOL-HIGH-009: Swap/liquidity with 0 or no minOut — sandwich attack."""
    # amountOutMinimum=0 or minOut=0 pattern
    zero_slippage = re.compile(
        r'(amountOutMin(?:imum)?\s*[=:,]\s*0'
        r'|minOut\s*[=:,]\s*0'
        r'|minAmountOut\s*[=:,]\s*0'
        r'|sqrtPriceLimitX96\s*[=:,]\s*0)',
        re.MULTILINE | re.IGNORECASE
    )
    swap_context = re.compile(r'(swap|exactInput|exactOutput|addLiquidity|removeLiquidity)', re.IGNORECASE)
    for m in zero_slippage.finditer(content):
        surrounding = content[max(0, m.start()-300):m.start()+300]
        if not swap_context.search(surrounding):
            continue
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-HIGH-009",
            title="Zero Slippage Tolerance: Sandwich Attack / MEV Vulnerability",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                "A swap or liquidity operation uses `amountOutMin=0` (or equivalent), "
                "meaning it accepts any output amount. MEV bots will sandwich this "
                "transaction — buying before and selling after — extracting maximum value.\n\n"
                "**Real incidents:** Hundreds of millions lost to sandwich attacks daily on DEXes."
            ),
            exploit_scenario=(
                "1. Victim submits swap with `amountOutMin=0`.\n"
                "2. MEV bot front-runs: buys token A, price rises.\n"
                "3. Victim's swap executes at terrible price.\n"
                "4. MEV bot back-runs: sells for profit. Victim receives near-zero output."
            ),
            remediation=(
                "Always compute and pass a meaningful `minOut`:\n"
                "```solidity\n"
                "uint256 minOut = expectedOut * (10000 - slippageBps) / 10000;\n"
                "ISwapRouter.ExactInputSingleParams({\n"
                "    amountOutMinimum: minOut,  // e.g. 0.5% slippage\n"
                "    deadline: block.timestamp + 300,\n"
                "    ...\n"
                "});\n"
                "```"
            ),
            references=["Solodit: slippage-missing", "https://eigenphi.io/mev/ethereum/sandwich", "Sherlock: slippage-vulnerability"],
            language="solidity",
        ))


def _block_timestamp(file_ctx, content, issues):
    """SOL-HIGH-010: block.timestamp used for critical randomness or precise timing."""
    # Only flag if block.timestamp is used for randomness or as an entropy source
    # NOT for deadline checks (legitimate use)
    rand_pattern = re.compile(
        r'block\.timestamp\s*%|keccak256\s*\([^)]*block\.timestamp'
        r'|block\.timestamp\s*\^\s*|uint\s*\(\s*block\.timestamp\s*\)',
        re.MULTILINE
    )
    for m in rand_pattern.finditer(content):
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-HIGH-010",
            title="`block.timestamp` Used as Randomness or Entropy Source",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "`block.timestamp` is **miner-manipulable** (up to ~15 seconds on PoW, "
                "and validators on PoS can influence it). Using it as randomness or in "
                "modular arithmetic creates predictable or manipulable outcomes.\n\n"
                "Note: Using `block.timestamp` for deadlines is acceptable."
            ),
            exploit_scenario="A miner/validator adjusts `block.timestamp` to influence the modular outcome, winning a lottery or gaming a time-based distribution.",
            remediation=(
                "Use Chainlink VRF for on-chain randomness:\n"
                "```solidity\n"
                "// Request randomness via Chainlink VRF v2\n"
                "uint256 requestId = COORDINATOR.requestRandomWords(keyHash, subId, 3, 100000, 1);\n"
                "```"
            ),
            references=["SWC-116", "https://docs.chain.link/vrf", "https://swcregistry.io/docs/SWC-116"],
            language="solidity",
        ))


def _rounding_error(file_ctx, content, issues):
    """SOL-HIGH-011: Division before multiplication causing precision loss."""
    # x / y * z pattern — division truncates before multiply amplifies error
    pattern = re.compile(
        r'(\w+)\s*/\s*(\w+)\s*\*\s*(\w+)',
        re.MULTILINE
    )
    mul_div_safe = re.compile(r'(mulDiv|FullMath|PRBMath|muldiv)', re.IGNORECASE)
    for m in pattern.finditer(content):
        if mul_div_safe.search(content):
            continue
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-HIGH-011",
            title="Divide-Before-Multiply: Precision Loss Leading to Incorrect Calculation",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "Integer division truncates remainders. Performing division before "
                "multiplication discards precision. For financial math, this causes "
                "systematic rounding errors that can be exploited or cause incorrect payouts.\n\n"
                "Example: `(100 / 3) * 3 = 99` (loses 1 unit)"
            ),
            exploit_scenario="Small rounding errors per transaction accumulate over millions of operations, draining the protocol or giving attackers more than entitled.",
            remediation=(
                "Multiply before dividing, or use `Math.mulDiv()`:\n"
                "```solidity\n"
                "// ❌ Bad: (a / b) * c\n"
                "// ✅ Good: (a * c) / b  — or use:\n"
                "uint256 result = Math.mulDiv(a, c, b);  // OZ Math library\n"
                "```"
            ),
            references=["Slither: divide-before-multiply", "Solodit: rounding-errors", "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/Math.sol"],
            language="solidity",
        ))


def _governance_flashloan(file_ctx, content, issues):
    """SOL-HIGH-012: Governance vote using token balance (flash loan governance attack)."""
    has_governance = bool(re.search(r'(Governor|Governance|vote|propose|castVote|quorum)', content, re.IGNORECASE))
    if not has_governance:
        return
    # Check if voting power is based on current balance (not snapshot/checkpoint)
    snapshot_guard = re.compile(r'(getPastVotes|getPastTotalSupply|snapshot|checkpoint|Votes\.getVotes)', re.IGNORECASE)
    balanceof_vote = re.compile(r'(balanceOf|getVotes|votingPower)\s*\(\s*msg\.sender', re.IGNORECASE)
    if snapshot_guard.search(content):
        return
    if balanceof_vote.search(content):
        m = balanceof_vote.search(content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-HIGH-012",
            title="Flash Loan Governance Attack: Voting Power Based on Spot Balance",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                "Governance voting power is derived from current token balance rather than "
                "a historical snapshot. An attacker can flash-borrow a massive amount of "
                "governance tokens, pass a malicious proposal, and repay — all in one transaction.\n\n"
                "**Real incidents:** Beanstalk ($182M), Tornado Cash governance attack."
            ),
            exploit_scenario=(
                "1. Attacker flash-borrows 51% of governance tokens.\n"
                "2. Votes to pass malicious proposal (e.g. drain treasury).\n"
                "3. Executes proposal immediately (no timelock).\n"
                "4. Repays flash loan. Protocol drained."
            ),
            remediation=(
                "Use vote snapshots (ERC20Votes/ERC20Snapshot) and mandatory timelocks:\n"
                "```solidity\n"
                "// Use getPastVotes — historical snapshot, immune to flash loans\n"
                "uint256 votes = token.getPastVotes(account, block.number - 1);\n"
                "// Add a TimelockController with minimum delay of 24-48 hours\n"
                "```"
            ),
            references=["https://rekt.news/beanstalk-rekt/", "ERC20Votes", "https://docs.openzeppelin.com/contracts/4.x/governance"],
            language="solidity",
        ))


def _unprotected_initialize(file_ctx, content, issues):
    """SOL-HIGH-013: Non-proxy contracts with initialize() that can be called multiple times."""
    is_upgradeable = bool(re.search(r'(Initializable|UUPSUpgradeable|_disableInitializers)', content))
    if is_upgradeable:
        return  # Already caught by SOL-CRIT-007
    init_pattern = re.compile(r'function\s+initialize\s*\([^)]*\)\s*(public|external)([^{]*)\{', re.MULTILINE)
    for m in init_pattern.finditer(content):
        attrs = m.group(2)
        if re.search(r'(initializer|onlyOwner|onlyAdmin|require)', attrs):
            continue
        func_start = m.end()
        depth = 1; i = func_start
        while i < len(content) and depth > 0:
            if content[i] == '{': depth += 1
            elif content[i] == '}': depth -= 1
            i += 1
        body = content[func_start:i]
        if re.search(r'require', body):
            continue  # Has some internal check
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-HIGH-013",
            title="Unprotected `initialize()` — Can Be Called Multiple Times",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                "The `initialize()` function has no guard preventing repeated calls. "
                "Anyone can re-initialize the contract at any time, overwriting the owner, "
                "resetting balances, or corrupting state."
            ),
            exploit_scenario="Attacker calls `initialize(attackerAddress)` after deployment, taking ownership.",
            remediation=(
                "Add a one-time guard:\n"
                "```solidity\n"
                "bool private _initialized;\n"
                "function initialize(...) external {\n"
                "    require(!_initialized, 'Already initialized');\n"
                "    _initialized = true;\n"
                "    ...\n"
                "}\n"
                "```\n"
                "Or use OpenZeppelin's `Initializable` contract."
            ),
            references=["SWC-118", "Solodit: unprotected-initializer"],
            language="solidity",
        ))

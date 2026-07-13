"""
SELF — Protocol-Specific Pack: AMM / DEX
Detectors derived from 4 years of Code4rena, Sherlock, and Immunefi AMM findings.

Real incidents encoded:
- Uniswap V2/V3 fork bugs (Code4rena 2022-2024)
- Balancer math precision (Rekt: Balancer $20M)
- Curve invariant manipulation
- TWAMM time-weighted math bugs
- Price impact calculation errors
- LP token accounting issues

Sources: Code4rena AMM contests, Sherlock AMM audits, DeFiHackLabs AMM PoCs,
         Uniswap security advisories, Balancer post-mortems
"""
import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext


def detect(file_ctx: FileContext) -> List[Issue]:
    content = file_ctx.content
    # Only run on files that look like AMM/DEX contracts
    is_amm = bool(re.search(
        r'(swap|reserve0|reserve1|getReserves|addLiquidity|removeLiquidity'
        r'|kLast|_update|token0|token1|sqrtPrice|liquidity|tick\b|Pool|Pair)',
        content, re.IGNORECASE
    ))
    if not is_amm:
        return []

    issues = []
    _k_invariant_check(file_ctx, content, issues)
    _price_impact_no_limit(file_ctx, content, issues)
    _lp_inflation_attack(file_ctx, content, issues)
    _fee_on_transfer_unhandled(file_ctx, content, issues)
    _reserve_manipulation(file_ctx, content, issues)
    _sqrt_precision_loss(file_ctx, content, issues)
    _liquidity_lock_bypass(file_ctx, content, issues)
    return issues


def _k_invariant_check(file_ctx, content, issues):
    """
    AMM-CRIT-001: xy=k invariant not checked after swap.
    Code4rena finding: Multiple Uniswap V2 forks skip the final invariant check.
    """
    has_swap = bool(re.search(r'function\s+swap\s*\(', content))
    if not has_swap:
        return
    # Look for k-invariant check pattern: balance0 * balance1 >= reserve0 * reserve1
    has_k_check = bool(re.search(
        r'(balance0Adjusted\s*\*\s*balance1Adjusted'
        r'|require\s*\([^)]*reserve0\s*\*[^)]*reserve1'
        r'|_k\s*>=|invariant|checkK)',
        content
    ))
    if not has_k_check:
        m = re.search(r'function\s+swap\s*\(', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="AMM-CRIT-001",
            title="AMM: xy=k Invariant Not Verified After Swap",
            severity=Severity.CRITICAL, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=5),
            description=(
                "The `swap()` function does not verify the xy=k constant-product invariant "
                "after execution. Without this check, an attacker can drain the pool by "
                "manipulating reserve balances without maintaining the invariant.\n\n"
                "**Real incidents:** Multiple Uniswap V2 fork drains (Code4rena 2022-2023) "
                "where forks removed or skipped the invariant check to 'save gas'."
            ),
            exploit_scenario=(
                "1. Attacker calls swap() with manipulated amounts.\n"
                "2. Reserves updated incorrectly — invariant violated.\n"
                "3. Attacker extracts more tokens than entitled.\n"
                "4. Pool drained over multiple transactions."
            ),
            remediation=(
                "```solidity\n"
                "// At end of swap(), verify the invariant holds:\n"
                "uint256 balance0Adjusted = balance0 * 1000 - amount0In * 3;\n"
                "uint256 balance1Adjusted = balance1 * 1000 - amount1In * 3;\n"
                "require(\n"
                "    balance0Adjusted * balance1Adjusted >= uint256(reserve0) * reserve1 * 1e6,\n"
                "    'K invariant violated'\n"
                ");\n"
                "```"
            ),
            references=["Uniswap V2 whitepaper", "https://rekt.news/", "Code4rena: AMM-invariant"],
            language="solidity",
        ))


def _price_impact_no_limit(file_ctx, content, issues):
    """
    AMM-HIGH-001: No maximum price impact / slippage protection in swap.
    Sherlock finding: Missing price impact cap allows massive single-tx slippage.
    """
    has_swap = bool(re.search(r'function\s+swap\w*\s*\(', content, re.IGNORECASE))
    if not has_swap:
        return
    has_impact_limit = bool(re.search(
        r'(maxPriceImpact|priceImpactLimit|MAX_PRICE_IMPACT'
        r'|amountOutMin|minAmountOut|minOut)',
        content, re.IGNORECASE
    ))
    if not has_impact_limit:
        m = re.search(r'function\s+swap\w*\s*\(', content, re.IGNORECASE)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="AMM-HIGH-001",
            title="AMM: No Price Impact Limit — Susceptible to Large Slippage",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                "The AMM swap function lacks a maximum price impact check. "
                "Large swaps can move the price by an arbitrary amount — "
                "enabling sandwich attacks and allowing whale manipulation of small pools."
            ),
            exploit_scenario="MEV bot detects large pending swap. Front-runs to push price, lets victim swap at terrible rate, back-runs to profit.",
            remediation=(
                "Add a price impact limit:\n"
                "```solidity\n"
                "uint256 priceImpact = (amountIn * 10000) / reserveIn;\n"
                "require(priceImpact <= MAX_PRICE_IMPACT_BPS, 'Price impact too high');\n"
                "```"
            ),
            references=["Sherlock: AMM-slippage", "Uniswap V3 tick spacing"],
            language="solidity",
        ))


def _lp_inflation_attack(file_ctx, content, issues):
    """
    AMM-HIGH-002: LP token minting without minimum liquidity lock.
    Classic first-depositor inflation attack on AMM pools.
    """
    has_mint = bool(re.search(r'(mintLP|_mint|mint\s*\(|_mintLP)', content))
    has_min_liquidity = bool(re.search(
        r'(MINIMUM_LIQUIDITY|minimumLiquidity|MIN_LIQUIDITY|1000\s*\))',
        content
    ))
    has_totalSupply_zero = bool(re.search(r'totalSupply\s*==\s*0', content))

    if has_mint and has_totalSupply_zero and not has_min_liquidity:
        m = re.search(r'totalSupply\s*==\s*0', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="AMM-HIGH-002",
            title="AMM: LP Token Inflation Attack — No Minimum Liquidity Lock",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=5),
            description=(
                "The first LP depositor can manipulate the LP token price via share inflation. "
                "Without locking `MINIMUM_LIQUIDITY` (1000 LP tokens) to address(dead), "
                "an attacker can be the first depositor and exploit the rounding to steal "
                "subsequent depositors' funds.\n\n"
                "**Real incidents:** Multiple Code4rena AMM fork findings (2022-2023). "
                "Uniswap V2 solves this by burning 1000 LP tokens on first deposit."
            ),
            exploit_scenario=(
                "1. Attacker is first depositor: deposits 1 wei token A and 1 wei token B → gets 1 LP.\n"
                "2. Attacker donates 1e18 token A to the pool directly.\n"
                "3. pricePerShare = 1e18. Victim deposits 1e18 tokens → gets 0 LP (rounds to 0).\n"
                "4. Attacker redeems 1 LP for all assets."
            ),
            remediation=(
                "```solidity\n"
                "if (totalSupply == 0) {\n"
                "    liquidity = Math.sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY;\n"
                "    _mint(address(0xdead), MINIMUM_LIQUIDITY);  // Lock forever\n"
                "}\n"
                "```"
            ),
            references=["Uniswap V2 whitepaper Section 3.4", "Code4rena: lp-inflation"],
            language="solidity",
        ))


def _fee_on_transfer_unhandled(file_ctx, content, issues):
    """
    AMM-HIGH-003: transferFrom without accounting for fee-on-transfer tokens.
    Sherlock/Code4rena: Protocols assume amount transferred == amount specified.
    """
    has_transfer_from = bool(re.search(r'\.transferFrom\s*\(', content))
    if not has_transfer_from:
        return
    has_fot_handling = bool(re.search(
        r'(balanceBefore|balanceAfter|balance.*before|balance.*after'
        r'|actualReceived|received\s*=)',
        content, re.IGNORECASE
    ))
    if not has_fot_handling:
        m = re.search(r'\.transferFrom\s*\(', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="AMM-HIGH-003",
            title="AMM: Fee-On-Transfer Tokens Not Handled — Balance Accounting Error",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "The contract uses `transferFrom(from, to, amount)` and assumes the received "
                "amount equals `amount`. Fee-on-transfer tokens (USDT in some deployments, "
                "SAFEMOON, REFLECT tokens) deduct a fee, so the actual received amount is less.\n\n"
                "This causes accounting inflation — the contract credits more than it received."
            ),
            exploit_scenario="Attacker deposits FoT token. Contract records `amount` but only receives `amount * 0.99`. Over time the pool becomes insolvent.",
            remediation=(
                "Check actual received amount:\n"
                "```solidity\n"
                "uint256 balBefore = IERC20(token).balanceOf(address(this));\n"
                "IERC20(token).transferFrom(msg.sender, address(this), amount);\n"
                "uint256 actualReceived = IERC20(token).balanceOf(address(this)) - balBefore;\n"
                "// Use actualReceived, not amount\n"
                "```"
            ),
            references=["Sherlock: fee-on-transfer", "Code4rena: fot-token", "https://github.com/d-xo/weird-erc20"],
            language="solidity",
        ))


def _reserve_manipulation(file_ctx, content, issues):
    """
    AMM-CRIT-002: Reserves updated from balanceOf instead of tracking deposits.
    Allows direct token donation to manipulate price.
    """
    has_sync = bool(re.search(r'(function\s+sync|_update\s*\(|sync\s*\(\))', content))
    uses_balanceof_for_reserve = bool(re.search(
        r'reserve\w*\s*=\s*\w+\.balanceOf\s*\(address\s*\(this\)\)',
        content
    ))
    if has_sync and uses_balanceof_for_reserve:
        m = re.search(r'reserve\w*\s*=\s*\w+\.balanceOf', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="AMM-CRIT-002",
            title="AMM: Reserves Derived from `balanceOf` — Donation Manipulation",
            severity=Severity.CRITICAL, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                "Pool reserves are set directly from `token.balanceOf(address(this))`. "
                "An attacker can donate tokens directly to the pool (without going through "
                "swap/addLiquidity) to manipulate the reserve ratio and thus the price, "
                "enabling profitable arbitrage or oracle manipulation.\n\n"
                "**Real incidents:** Multiple AMM donation attacks (2022-2023)."
            ),
            exploit_scenario=(
                "1. Attacker donates large amount of token0 directly to pool.\n"
                "2. sync() is called — reserves updated to inflated balances.\n"
                "3. Price of token0 is artificially deflated.\n"
                "4. Attacker uses other protocols that read this pool as price oracle."
            ),
            remediation="Track deposited amounts internally rather than relying on `balanceOf`. Or use TWAP to prevent single-block manipulation.",
            references=["Code4rena: reserve-manipulation", "Uniswap V2 lock mechanism"],
            language="solidity",
        ))


def _sqrt_precision_loss(file_ctx, content, issues):
    """
    AMM-MED-001: sqrt() used in liquidity calculation without precision guard.
    Sherlock: Truncated sqrt causes LP share minting to be off by 1, accumulates.
    """
    sqrt_in_liquidity = bool(re.search(
        r'(Math\.sqrt|_sqrt|sqrt\s*\()\s*\([^)]*\*[^)]*\)',
        content
    ))
    if not sqrt_in_liquidity:
        return
    has_precision_guard = bool(re.search(r'(mulDiv|FullMath|PRBMath|+ 1|rounding)', content))
    if not has_precision_guard:
        m = re.search(r'(Math\.sqrt|sqrt\s*\()', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="AMM-MED-001",
            title="AMM: `sqrt()` Precision Loss in Liquidity Calculation",
            severity=Severity.MEDIUM, confidence=Confidence.LOW,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "`sqrt()` truncates the result. When used in liquidity minting calculations, "
                "small rounding errors accumulate over millions of LP operations, "
                "causing the protocol to issue slightly fewer shares than correct — "
                "or slightly more, which can be exploited."
            ),
            exploit_scenario="Systematic rounding in favor of the pool — users receive slightly fewer LP tokens than entitled on every deposit. Over time, significant value extracted.",
            remediation="Use `FullMath.mulDiv()` for intermediate calculations before `sqrt()`. Consider rounding direction explicitly (floor vs ceiling).",
            references=["Uniswap V3 FullMath library", "Sherlock: sqrt-precision"],
            language="solidity",
        ))


def _liquidity_lock_bypass(file_ctx, content, issues):
    """
    AMM-HIGH-004: removeLiquidity without checking minimum time lock.
    Flash loan + addLiquidity + removeLiquidity in same block to drain fees.
    """
    has_remove = bool(re.search(r'function\s+(removeLiquidity|burnLP)\s*\(', content))
    if not has_remove:
        return
    has_time_lock = bool(re.search(
        r'(block\.timestamp\s*-\s*\w*[Tt]ime|lockTime|lastDeposit|MIN_LOCK'
        r'|depositBlock|block\.number\s*-)',
        content
    ))
    if not has_time_lock:
        m = re.search(r'function\s+(removeLiquidity|burnLP)\s*\(', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="AMM-HIGH-004",
            title="AMM: No Liquidity Lock — Flash Loan LP Attack Possible",
            severity=Severity.HIGH, confidence=Confidence.LOW,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                "Liquidity can be added and removed in the same transaction with no time lock. "
                "An attacker can flash-loan tokens, add liquidity (capturing fees), "
                "and immediately remove liquidity — extracting fees without any capital commitment.\n\n"
                "**Real incident:** Multiple AMM yield protocols (2022)."
            ),
            exploit_scenario=(
                "1. Flash loan large amount of tokens.\n"
                "2. Add liquidity — temporarily become majority LP.\n"
                "3. Remove liquidity in same tx — collect fee share proportional to share.\n"
                "4. Repay flash loan. Net profit = fees stolen from honest LPs."
            ),
            remediation=(
                "Add minimum deposit duration:\n"
                "```solidity\n"
                "mapping(address => uint256) public lastDepositBlock;\n"
                "require(block.number > lastDepositBlock[msg.sender] + MIN_LOCK_BLOCKS, 'Locked');\n"
                "```"
            ),
            references=["Sherlock: flash-lp-attack", "Code4rena: liquidity-lock"],
            language="solidity",
        ))

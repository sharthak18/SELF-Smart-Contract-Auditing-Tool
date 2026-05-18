"""
SELF — Protocol-Specific Pack: Lending / Borrowing
Detectors from 4 years of Code4rena, Sherlock, and Immunefi lending protocol findings.

Real incidents encoded:
- Aave, Compound forks (Code4rena 2022-2024)
- Euler Finance ($197M) — donation + liquidation manipulation
- Hundred Finance ($7M) — cToken inflation
- CREAM Finance ($130M) — reentrancy + oracle
- Mango Markets ($117M) — oracle + governance
- BonqDAO ($120M) — oracle manipulation

Sources: Sherlock lending audits, Code4rena Aave/Compound contests,
         Euler post-mortem, Immunefi lending bounties, Trail of Bits
"""
import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext


def detect(file_ctx: FileContext) -> List[Issue]:
    content = file_ctx.content
    is_lending = bool(re.search(
        r'(borrow|repay|collateral|liquidat|healthFactor|ltv|LTV'
        r'|interest|accrue|cToken|aToken|debtToken|interestRate'
        r'|utilization|lending|Lend)',
        content, re.IGNORECASE
    ))
    if not is_lending:
        return []

    issues = []
    _liquidation_threshold(file_ctx, content, issues)
    _interest_accrual_missing(file_ctx, content, issues)
    _ctoken_inflation(file_ctx, content, issues)
    _bad_debt_socialization(file_ctx, content, issues)
    _self_liquidation(file_ctx, content, issues)
    _collateral_manipulation(file_ctx, content, issues)
    _borrow_cap_missing(file_ctx, content, issues)
    return issues


def _liquidation_threshold(file_ctx, content, issues):
    """
    LEND-CRIT-001: Liquidation threshold == collateral factor (no buffer).
    Position can go bad-debt instantly — protocol is insolvent.
    """
    has_liquidation = bool(re.search(r'(liquidat|healthFactor)', content, re.IGNORECASE))
    if not has_liquidation:
        return
    # Both LTV and liquidation threshold defined — check if they're equal
    ltv_m = re.search(r'(LTV|ltv|collateralFactor)\s*=\s*(\d+)', content, re.IGNORECASE)
    liq_m = re.search(r'(liquidationThreshold|LIQUIDATION_THRESHOLD)\s*=\s*(\d+)', content, re.IGNORECASE)
    if ltv_m and liq_m:
        if ltv_m.group(2) == liq_m.group(2):
            line = content[:liq_m.start()].count('\n') + 1
            issues.append(Issue(
                id="LEND-CRIT-001",
                title="Lending: Liquidation Threshold == LTV — Zero Buffer, Instant Bad Debt",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description=(
                    f"Liquidation threshold ({liq_m.group(2)}) equals collateral factor LTV "
                    f"({ltv_m.group(2)}). There is no buffer between 'max borrowable' and "
                    "'liquidatable'. Any price move, however small, causes positions to skip "
                    "the liquidation window and go directly to bad debt — making the protocol insolvent."
                ),
                exploit_scenario="Asset price drops 0.01%. All max-leveraged positions instantly become bad debt. No time for liquidators to act. Protocol is insolvent.",
                remediation="Set liquidation threshold > LTV. Aave uses LTV=80% and liquidation threshold=85%. The gap allows liquidators to act before bad debt.",
                references=["Aave risk parameters", "Euler Finance post-mortem", "Code4rena: lending-threshold"],
                language="solidity",
            ))


def _interest_accrual_missing(file_ctx, content, issues):
    """
    LEND-HIGH-001: borrow/repay/liquidate called without accruing interest first.
    Code4rena #1 finding in lending protocols — stale index causes wrong calculations.
    """
    is_lending_contract = bool(re.search(r'(borrowIndex|interestIndex|accrueInterest|accrue)', content))
    if not is_lending_contract:
        return

    critical_fns = ['borrow', 'repay', 'liquidate', 'withdraw', 'redeem']
    accrue_pattern = re.compile(r'accrueInterest\s*\(\)|_accrue\s*\(|accrue\s*\(\)', re.MULTILINE)

    for fn_name in critical_fns:
        fn_pattern = re.compile(
            rf'function\s+{fn_name}\w*\s*\([^)]*\)\s*(?:public|external)[^{{]*\{{',
            re.MULTILINE
        )
        for m in fn_pattern.finditer(content):
            func_start = m.end(); depth = 1; i = func_start
            while i < len(content) and depth > 0:
                if content[i] == '{': depth += 1
                elif content[i] == '}': depth -= 1
                i += 1
            body = content[func_start:i]
            if not accrue_pattern.search(body[:200]):  # Should be first call
                line = content[:m.start()].count('\n') + 1
                issues.append(Issue(
                    id="LEND-HIGH-001",
                    title=f"Lending: `{fn_name}()` Doesn't Accrue Interest Before Execution",
                    severity=Severity.HIGH, confidence=Confidence.HIGH,
                    file=file_ctx.relative_path, line=line,
                    snippet=file_ctx.get_snippet(line, context=4),
                    description=(
                        f"`{fn_name}()` does not call `accrueInterest()` before executing. "
                        "Without accrual, the borrow/collateral indices are stale — users can "
                        "borrow more than allowed, repay less than owed, or liquidate positions "
                        "that should not yet be liquidatable.\n\n"
                        "**This is the most common High/Medium finding in Code4rena lending audits (2022-2024).**"
                    ),
                    exploit_scenario=(
                        f"1. Interest has accrued since last interaction — indices are stale.\n"
                        f"2. Attacker calls `{fn_name}()` without triggering accrual.\n"
                        f"3. Stale index is used — attacker borrows at lower-than-actual rate.\n"
                        f"4. Protocol loses interest revenue or user gets undercollateralized loan."
                    ),
                    remediation=(
                        f"```solidity\n"
                        f"function {fn_name}(...) external {{\n"
                        f"    accrueInterest();  // ← Always first\n"
                        f"    // ... rest of logic\n"
                        f"}}\n"
                        f"```"
                    ),
                    references=["Compound V2 architecture", "Code4rena: accrue-interest-missing", "Sherlock: lending-stale-index"],
                    language="solidity",
                ))
                break


def _ctoken_inflation(file_ctx, content, issues):
    """
    LEND-CRIT-002: cToken/share inflation attack (Compound fork).
    Hundred Finance ($7M), Midas Capital ($600K) — same attack vector.
    """
    is_ctoken = bool(re.search(r'(cToken|CToken|exchangeRate|exchangeRateCurrent|mint.*share|share.*mint)', content))
    if not is_ctoken:
        return
    has_min_shares = bool(re.search(r'(MINIMUM_SHARES|minShares|MIN_SHARES|dead.*address|burn.*1000)', content))
    has_total_supply_check = bool(re.search(r'totalSupply\s*==\s*0', content))

    if has_total_supply_check and not has_min_shares:
        m = re.search(r'totalSupply\s*==\s*0', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="LEND-CRIT-002",
            title="Lending: cToken Share Inflation Attack — First Depositor Exploit",
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=5),
            description=(
                "This cToken/lending vault is vulnerable to the first-depositor share inflation attack. "
                "An attacker can:\n"
                "1. Mint 1 cToken share (deposit 1 wei)\n"
                "2. Donate large amount of underlying directly to the contract\n"
                "3. exchangeRate skyrockets — subsequent depositors get 0 shares (rounds down)\n\n"
                "**Real incidents:** Hundred Finance ($7M, 2023), Midas Capital ($600K, 2023), "
                "multiple Compound forks on Code4rena."
            ),
            exploit_scenario=(
                "1. Attacker mints 1 share by depositing 1 wei — totalSupply = 1.\n"
                "2. Attacker donates 1e18 underlying tokens directly to market.\n"
                "3. exchangeRate = (1e18 + 1) / 1 ≈ 1e18 per share.\n"
                "4. Victim deposits 1e18 tokens → receives (1e18 * 1) / (1e18 + 1) = 0 shares.\n"
                "5. Attacker redeems 1 share for all underlying."
            ),
            remediation=(
                "Lock minimum shares on first deposit (Compound V3 approach):\n"
                "```solidity\n"
                "if (totalSupply == 0) {\n"
                "    shares = depositAmount - MINIMUM_SHARES;\n"
                "    _mint(address(0xdead), MINIMUM_SHARES);  // Burned permanently\n"
                "}\n"
                "// Or use virtual shares: totalAssets += 1; totalShares += 1e3;\n"
                "```"
            ),
            references=["https://rekt.news/hundred-finance-rekt2/", "ERC-4626: inflation-attack", "Code4rena: ctoken-inflation"],
            language="solidity",
        ))


def _bad_debt_socialization(file_ctx, content, issues):
    """
    LEND-HIGH-002: No bad debt handling — insolvent positions can brick protocol.
    """
    has_liquidation = bool(re.search(r'function\s+liquidat\w*\s*\(', content))
    if not has_liquidation:
        return
    has_bad_debt = bool(re.search(r'(badDebt|socialize|insuranceFund|badDebtRealized|shortfall)', content))
    if not has_bad_debt:
        m = re.search(r'function\s+liquidat\w*\s*\(', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="LEND-HIGH-002",
            title="Lending: No Bad Debt Socialization Mechanism",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "The protocol has no mechanism to handle bad debt (positions where debt > collateral). "
                "When a position becomes undercollateralized faster than liquidators can act, "
                "the resulting bad debt is silently absorbed by the protocol — making it insolvent "
                "and preventing other users from withdrawing.\n\n"
                "**Real incidents:** Euler Finance — bad debt not socialized caused $197M exploit impact."
            ),
            exploit_scenario="Flash crash causes positions to skip liquidation threshold and accumulate bad debt. Protocol becomes insolvent — withdrawals bricked.",
            remediation=(
                "Implement bad debt tracking and socialization:\n"
                "```solidity\n"
                "// On liquidation, if collateral < debt:\n"
                "uint256 badDebt = debt - collateralValue;\n"
                "totalBadDebt += badDebt;\n"
                "// Socialize: reduce all lenders' shares proportionally\n"
                "```\n"
                "Or maintain an insurance fund to cover bad debt."
            ),
            references=["Euler Finance post-mortem", "Aave bad debt handling", "Sherlock: bad-debt"],
            language="solidity",
        ))


def _self_liquidation(file_ctx, content, issues):
    """
    LEND-HIGH-003: Self-liquidation — user can liquidate their own position,
    collecting the liquidation bonus on themselves (Sherlock finding).
    """
    has_liquidation = bool(re.search(r'function\s+liquidat\w*\s*\([^)]*\)', content))
    if not has_liquidation:
        return
    has_self_check = bool(re.search(
        r'require\s*\([^)]*borrower\s*!=\s*msg\.sender|liquidator\s*!=\s*borrower',
        content
    ))
    if not has_self_check:
        m = re.search(r'function\s+liquidat\w*\s*\(', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="LEND-HIGH-003",
            title="Lending: Self-Liquidation — User Collects Own Liquidation Bonus",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                "The liquidation function does not prevent a borrower from liquidating "
                "their own position. A user can take a loan, make their position liquidatable "
                "(e.g., via price manipulation), then liquidate themselves — collecting the "
                "liquidation bonus at the expense of the protocol or other users."
            ),
            exploit_scenario=(
                "1. User borrows to 99% LTV.\n"
                "2. User flash-loans to briefly drop collateral value below threshold.\n"
                "3. User (via second address) liquidates own position, collecting 5-10% bonus.\n"
                "4. Repays flash loan. Net profit = liquidation bonus."
            ),
            remediation=(
                "```solidity\n"
                "function liquidate(address borrower, ...) external {\n"
                "    require(msg.sender != borrower, 'Cannot self-liquidate');\n"
                "    ...\n"
                "}\n"
                "```"
            ),
            references=["Sherlock: self-liquidation", "Code4rena: lending-self-liquidate"],
            language="solidity",
        ))


def _collateral_manipulation(file_ctx, content, issues):
    """
    LEND-HIGH-004: Collateral price fetched from manipulable source in borrow/liquidate.
    """
    has_borrow = bool(re.search(r'function\s+borrow\w*\s*\(', content))
    if not has_borrow:
        return
    # Uses spot price (balanceOf/getReserves) for collateral valuation
    spot_in_collateral = bool(re.search(
        r'(getPrice|collateralValue|getCollateralValue)[^{]*'
        r'(balanceOf|getReserves|reserve0|reserve1)',
        content, re.DOTALL
    ))
    if spot_in_collateral:
        m = re.search(r'(getPrice|collateralValue)', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="LEND-HIGH-004",
            title="Lending: Collateral Valuation Uses Manipulable Spot Price",
            severity=Severity.CRITICAL, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                "Collateral value is calculated using spot AMM price (via `getReserves()` or `balanceOf()`). "
                "An attacker can manipulate this price within a single transaction using flash loans, "
                "borrow at inflated collateral value, then let price return to normal.\n\n"
                "**Real incidents:** Cream Finance ($130M), BonqDAO ($120M), Mango Markets ($117M)."
            ),
            exploit_scenario=(
                "1. Attacker flash-loans tokens to inflate collateral asset price.\n"
                "2. Calls borrow() — collateral valued at manipulated price.\n"
                "3. Borrows far more than legitimate collateral allows.\n"
                "4. Repays flash loan. Keeps excess borrowed funds."
            ),
            remediation="Use Chainlink oracles or Uniswap V3 TWAP for all collateral valuation. Never use spot AMM prices.",
            references=["https://rekt.news/cream-rekt-2/", "https://rekt.news/mango-markets-rekt/", "Solodit: oracle-manipulation"],
            language="solidity",
        ))


def _borrow_cap_missing(file_ctx, content, issues):
    """
    LEND-MED-001: No borrow cap per asset — single asset can drain entire protocol.
    """
    has_borrow = bool(re.search(r'function\s+borrow\w*\s*\(', content))
    if not has_borrow:
        return
    has_borrow_cap = bool(re.search(r'(borrowCap|maxBorrow|BORROW_CAP|totalBorrows.*<=)', content))
    if not has_borrow_cap:
        m = re.search(r'function\s+borrow\w*\s*\(', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="LEND-MED-001",
            title="Lending: No Borrow Cap — Single Asset Can Drain Protocol",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "There is no borrow cap limiting how much of any single asset can be borrowed. "
                "If a vulnerable asset is listed, an attacker can drain the entire liquidity "
                "for that market in one transaction."
            ),
            exploit_scenario="Attacker provides minimal collateral and borrows 100% of the USDC market — draining all depositors.",
            remediation=(
                "```solidity\n"
                "require(totalBorrows[asset] + amount <= borrowCap[asset], 'Borrow cap exceeded');\n"
                "```\n"
                "Aave V3 implements per-asset borrow caps for this reason."
            ),
            references=["Aave V3 risk parameters", "Compound V3 borrow caps", "Sherlock: borrow-cap"],
            language="solidity",
        ))

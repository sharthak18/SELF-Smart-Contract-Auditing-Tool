"""
SELF — HIGH severity detectors: Oracle, Overflow, Flash Loan, Access Control
SOL-HIGH-001 through SOL-HIGH-005
Sources: Rekt.news, Solodit, SWC, Immunefi, Sherlock, Code4rena
Low-FP: multi-signal checks, skip if mitigations detected
"""
import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext


def detect(file_ctx: FileContext) -> List[Issue]:
    issues = []
    content = file_ctx.content
    _oracle_spot_price(file_ctx, content, issues)
    _integer_overflow(file_ctx, content, issues)
    _unchecked_math(file_ctx, content, issues)
    _flash_loan_no_guard(file_ctx, content, issues)
    _missing_access_control(file_ctx, content, issues)
    return issues


def _oracle_spot_price(file_ctx, content, issues):
    """SOL-HIGH-001: Spot price oracle — balanceOf/getReserves used as price without TWAP."""
    # Must use getReserves/balanceOf for price AND no TWAP/Chainlink/Time check
    spot_price = re.compile(
        r'(getReserves\s*\(\)|\.reserve0\b|\.reserve1\b'
        r'|balanceOf\s*\(address\s*\(this\)\)'
        r'|token\d?\.balanceOf\s*\()',
        re.MULTILINE
    )
    twap_guard = re.compile(
        r'(TWAP|twap|timeWeighted|consult\s*\(|observe\s*\('
        r'|AggregatorV3|latestRoundData|priceFeed|Chainlink'
        r'|slot0\s*\(\)|getSqrtTwapX96)', re.IGNORECASE
    )
    if not spot_price.search(content):
        return
    if twap_guard.search(content):
        return
    m = spot_price.search(content)
    line = content[:m.start()].count('\n') + 1
    issues.append(Issue(
        id="SOL-HIGH-001",
        title="Oracle Manipulation: Spot Price Used Without TWAP Protection",
        severity=Severity.HIGH, confidence=Confidence.MEDIUM,
        file=file_ctx.relative_path, line=line,
        snippet=file_ctx.get_snippet(line, context=4),
        description=(
            "The contract reads spot price directly from a DEX (via `getReserves()`, "
            "`balanceOf()`) without using a TWAP or Chainlink oracle. Spot prices can be "
            "manipulated within a single transaction using flash loans.\n\n"
            "**Real incidents:** Cream Finance ($130M), Mango Markets ($117M), "
            "Harvest Finance ($34M), Euler Finance ($197M)."
        ),
        exploit_scenario=(
            "1. Attacker takes a flash loan of asset X.\n"
            "2. Dumps X into the pool — spot price of Y skyrockets.\n"
            "3. Uses inflated Y price as collateral to borrow protocol funds.\n"
            "4. Repays flash loan; keeps stolen funds."
        ),
        remediation=(
            "Use a TWAP oracle (Uniswap V3 `OracleLibrary.consult()`) or Chainlink:\n"
            "```solidity\n"
            "(int224 value, uint32 timestamp) = IUniswapV3Pool(pool).observe(...);\n"
            "// OR\n"
            "(, int256 answer,,,) = priceFeed.latestRoundData();\n"
            "```"
        ),
        references=["https://rekt.news/cream-rekt-2/", "Solodit: oracle-manipulation", "https://docs.uniswap.org/contracts/v3/reference/core/libraries/OracleLibrary"],
        language="solidity",
    ))


def _integer_overflow(file_ctx, content, issues):
    """SOL-HIGH-002: Integer overflow/underflow in pre-0.8 contracts (no SafeMath)."""
    version_m = re.search(r'pragma\s+solidity\s+\^?(\d+)\.(\d+)', content)
    if not version_m:
        return
    major, minor = int(version_m.group(1)), int(version_m.group(2))
    if major > 0 or minor >= 8:
        return  # 0.8+ has built-in checks
    has_safemath = bool(re.search(r'(SafeMath|using\s+SafeMath)', content))
    has_unchecked_arith = bool(re.search(r'(\w+\s*\+\s*\w+|\w+\s*\*\s*\w+|\w+\s*-\s*\w+)', content))
    if has_unchecked_arith and not has_safemath:
        line = version_m.start() and content[:version_m.start()].count('\n') + 1 or 1
        issues.append(Issue(
            id="SOL-HIGH-002",
            title="Integer Overflow/Underflow: Pre-0.8 Solidity Without SafeMath",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=2),
            description=(
                "This contract uses Solidity <0.8 without SafeMath. Arithmetic operations "
                "silently wrap on overflow/underflow. For example, `uint256(0) - 1` wraps "
                "to `2^256 - 1`.\n\n**Real incidents:** batchOverflow (2018) — $1B+ in tokens created."
            ),
            exploit_scenario="An attacker passes values that cause `balances[attacker]` to overflow to near-max uint256.",
            remediation="Upgrade to Solidity >=0.8.0 or use OpenZeppelin SafeMath for all arithmetic.",
            references=["SWC-101", "https://swcregistry.io/docs/SWC-101"],
            language="solidity",
        ))


def _unchecked_math(file_ctx, content, issues):
    """SOL-HIGH-003: Risky arithmetic inside unchecked{} block in 0.8+."""
    version_m = re.search(r'pragma\s+solidity\s+\^?(\d+)\.(\d+)', content)
    if not version_m:
        return
    major, minor = int(version_m.group(1)), int(version_m.group(2))
    if major == 0 and minor < 8:
        return  # Already caught by SOL-HIGH-002
    unchecked_blocks = re.finditer(r'\bunchecked\s*\{([^}]+)\}', content, re.DOTALL)
    for m in unchecked_blocks:
        body = m.group(1)
        # Risky: multiplication, subtraction of user-controlled vars (not simple loop increments)
        risky = re.search(r'(\w+\s*\*\s*\w+|\w+\s*-\s*\w+)', body)
        # Skip if it's only `++i` / `i++` (common gas optimization)
        only_increment = re.fullmatch(r'\s*\+\+\w+\s*|\s*\w\+\+\s*', body.strip())
        if risky and not only_increment:
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="SOL-HIGH-003",
                title="Unsafe Arithmetic in `unchecked{}` Block",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=4),
                description=(
                    "Non-trivial arithmetic (multiplication or subtraction) is performed inside "
                    "an `unchecked{}` block, disabling Solidity 0.8's overflow protection. "
                    "If values are user-controlled or unbounded, this can overflow silently."
                ),
                exploit_scenario="Attacker passes a large value causing `amount * price` to overflow to a small number inside `unchecked{}`.",
                remediation="Only use `unchecked{}` for proven-safe operations (e.g. loop counters). Add explicit bounds checks before unchecked arithmetic.",
                references=["Solodit: unchecked-arithmetic", "https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic"],
                language="solidity",
            ))


def _flash_loan_no_guard(file_ctx, content, issues):
    """SOL-HIGH-004: Flash loan callback without sender/initiator validation."""
    callback_pattern = re.compile(
        r'function\s+(executeOperation|onFlashLoan|uniswapV[23]?FlashCallback'
        r'|pancakeCall|hookCall|flashCallback)\s*\(([^)]*)\)[^{]*\{',
        re.MULTILINE
    )
    for m in callback_pattern.finditer(content):
        fname = m.group(1)
        func_start = m.end()
        depth = 1; i = func_start
        while i < len(content) and depth > 0:
            if content[i] == '{': depth += 1
            elif content[i] == '}': depth -= 1
            i += 1
        body = content[func_start:i]
        # Check if initiator/sender is validated
        has_validation = bool(re.search(
            r'(require\s*\(\s*(msg\.sender|initiator|sender)\s*==|'
            r'if\s*\(\s*(msg\.sender|initiator)\s*!=)', body
        ))
        if not has_validation:
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="SOL-HIGH-004",
                title=f"Flash Loan Callback `{fname}()` Missing Caller Validation",
                severity=Severity.HIGH, confidence=Confidence.HIGH,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=4),
                description=(
                    f"The flash loan callback `{fname}()` does not validate that "
                    "`msg.sender` is the trusted lending pool and `initiator` is this contract. "
                    "Any external contract can call this callback directly, bypassing the "
                    "flash loan mechanism and executing privileged logic."
                ),
                exploit_scenario=(
                    f"1. Attacker calls `{fname}()` directly with crafted parameters.\n"
                    "2. No sender check — callback executes privileged operations.\n"
                    "3. Attacker drains funds without repaying any flash loan."
                ),
                remediation=(
                    "```solidity\n"
                    f"function {fname}(...) external override {{\n"
                    "    require(msg.sender == address(LENDING_POOL), 'Untrusted caller');\n"
                    "    require(initiator == address(this), 'Untrusted initiator');\n"
                    "    ...\n"
                    "}}\n"
                    "```"
                ),
                references=["Solodit: flash-loan-callback", "https://docs.aave.com/developers/guides/flash-loans"],
                language="solidity",
            ))


def _missing_access_control(file_ctx, content, issues):
    """
    SOL-HIGH-005: Critical functions (mint, burn, setOwner, withdraw, pause, upgrade)
    without any access control modifier or require(msg.sender...) check.
    Low-FP: only flag if function is public/external AND has no auth whatsoever.
    """
    critical_fn = re.compile(
        r'function\s+(mint|burn|setOwner|transferOwnership|withdraw|pause|unpause'
        r'|upgrade|upgradeTo|emergencyWithdraw|setFee|setTreasury|drainFunds'
        r'|sweep|rescueTokens)\s*\([^)]*\)\s*(public|external)([^{]*)\{',
        re.MULTILINE
    )
    auth_pattern = re.compile(
        r'(onlyOwner|onlyAdmin|onlyRole|onlyMinter|onlyGovernance|onlyOperator'
        r'|require\s*\(\s*msg\.sender|hasRole\s*\(|_checkRole|AccessControl'
        r'|Ownable|whenNotPaused)', re.IGNORECASE
    )
    for m in critical_fn.finditer(content):
        fname = m.group(1)
        attrs = m.group(3)
        func_start = m.end()
        depth = 1; i = func_start
        while i < len(content) and depth > 0:
            if content[i] == '{': depth += 1
            elif content[i] == '}': depth -= 1
            i += 1
        body = content[func_start:i]
        # Check attrs line AND first few lines of body
        check_zone = attrs + body[:200]
        if not auth_pattern.search(check_zone):
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="SOL-HIGH-005",
                title=f"Missing Access Control on Critical Function `{fname}()`",
                severity=Severity.HIGH, confidence=Confidence.HIGH,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=4),
                description=(
                    f"`{fname}()` is `public`/`external` but has no access control "
                    "modifier or `require(msg.sender == ...)` check. Any address can call "
                    "this critical function.\n\n"
                    "**Real incidents:** Nomad Bridge ($190M), Ronin Bridge ($625M) — "
                    "both had missing/broken access control."
                ),
                exploit_scenario=f"Attacker directly calls `{fname}()` with attacker-controlled parameters, draining or taking over the protocol.",
                remediation=(
                    f"```solidity\n"
                    f"// Option A: OpenZeppelin Ownable\n"
                    f"function {fname}(...) external onlyOwner {{ ... }}\n\n"
                    f"// Option B: Role-based (recommended for complex protocols)\n"
                    f"function {fname}(...) external {{\n"
                    f"    require(hasRole(ADMIN_ROLE, msg.sender), 'Not admin');\n"
                    f"    ...\n"
                    f"}}\n"
                    f"```"
                ),
                references=["SWC-105", "https://swcregistry.io/docs/SWC-105", "https://rekt.news/nomad-rekt/"],
                language="solidity",
            ))

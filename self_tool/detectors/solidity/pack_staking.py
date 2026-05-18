"""
SELF — Protocol-Specific Pack: Staking / Yield / Vault
Detectors from Code4rena staking contests, Sherlock yield audits, and real exploits.

Real incidents:
- Compound reward distribution bug ($80M over-distributed)
- Convex/Curve reward manipulation
- Yield aggregator reentrancy during harvest
- Staking reward index manipulation
- Vault share price manipulation during deposit
- Fee-on-deposit sandwich attacks
- ERC-4626 related bugs from Code4rena 2023-2024

Sources: Code4rena staking/yield contests, Sherlock vault audits,
         OpenZeppelin defender findings, Immunefi yield bounties
"""
import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext


def detect(file_ctx: FileContext) -> List[Issue]:
    content = file_ctx.content
    is_staking = bool(re.search(
        r'(stake|unstake|reward|harvest|yield|Vault|vault'
        r'|rewardPerToken|rewardIndex|rewardDebt|pendingReward'
        r'|totalStaked|lastUpdateTime|rewardRate)',
        content, re.IGNORECASE
    ))
    if not is_staking:
        return []

    issues = []
    _reward_before_balance_update(file_ctx, content, issues)
    _reward_index_overflow(file_ctx, content, issues)
    _sandwich_deposit(file_ctx, content, issues)
    _harvest_reentrancy(file_ctx, content, issues)
    _reward_token_as_staking_token(file_ctx, content, issues)
    _locked_rewards_on_exit(file_ctx, content, issues)
    return issues


def _reward_before_balance_update(file_ctx, content, issues):
    """
    STAKE-CRIT-001: Reward checkpoint not updated before balance changes.
    Classic Synthetix/Compound staking bug — rewards calculated on wrong balances.
    """
    has_update_reward = bool(re.search(r'(updateReward|_updateReward|checkpoint)', content))
    if not has_update_reward:
        return
    # Find stake/unstake functions
    stake_fns = re.compile(
        r'function\s+(stake|deposit|withdraw|unstake|exit)\s*\([^)]*\)\s*(?:public|external)[^{]*\{',
        re.MULTILINE
    )
    update_pattern = re.compile(r'(updateReward|_updateReward|checkpoint)\s*\(', re.MULTILINE)

    for m in stake_fns.finditer(content):
        fname = m.group(1)
        func_start = m.end(); depth = 1; i = func_start
        while i < len(content) and depth > 0:
            if content[i] == '{': depth += 1
            elif content[i] == '}': depth -= 1
            i += 1
        body = content[func_start:i]

        has_update = bool(update_pattern.search(body))
        has_modifier = bool(re.search(r'updateReward', m.group(0)))  # modifier form

        if not has_update and not has_modifier:
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="STAKE-CRIT-001",
                title=f"Staking: `{fname}()` Doesn't Checkpoint Rewards Before Balance Change",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=4),
                description=(
                    f"`{fname}()` changes user balance without first calling `updateReward()`. "
                    "This means accumulated rewards are calculated on the **new** balance instead "
                    "of the balance at the time of accrual — users can either steal rewards "
                    "or lose them entirely.\n\n"
                    "**Pattern:** This is the #1 staking vulnerability across Code4rena 2022-2024."
                ),
                exploit_scenario=(
                    f"1. User has been staking — rewards accumulate but aren't checkpointed.\n"
                    f"2. Attacker deposits a huge amount before rewards are distributed.\n"
                    f"3. `rewardPerToken` calculated on new (inflated) total supply.\n"
                    f"4. Attacker receives disproportionate share of rewards."
                ),
                remediation=(
                    "```solidity\n"
                    "modifier updateReward(address account) {\n"
                    "    rewardPerTokenStored = rewardPerToken();\n"
                    "    lastUpdateTime = lastTimeRewardApplicable();\n"
                    "    if (account != address(0)) {\n"
                    "        rewards[account] = earned(account);\n"
                    "        userRewardPerTokenPaid[account] = rewardPerTokenStored;\n"
                    "    }\n"
                    "    _;\n"
                    "}\n\n"
                    f"function {fname}(...) external updateReward(msg.sender) {{ ... }}\n"
                    "```"
                ),
                references=["Synthetix staking rewards", "Code4rena: staking-reward-checkpoint", "Sherlock: reward-manipulation"],
                language="solidity",
            ))
            break


def _reward_index_overflow(file_ctx, content, issues):
    """
    STAKE-HIGH-001: Reward per token accumulator can overflow, resetting to 0.
    """
    has_reward_index = bool(re.search(r'(rewardPerTokenStored|rewardIndex|accRewardPerShare)', content))
    if not has_reward_index:
        return
    has_overflow_guard = bool(re.search(r'(SafeMath|checked|unchecked.*overflow|type.*max)', content))
    version_m = re.search(r'pragma\s+solidity\s+\^?(\d+)\.(\d+)', content)
    is_safe_version = version_m and int(version_m.group(2)) >= 8 if version_m else False

    # Only flag if pre-0.8 without SafeMath OR using unchecked blocks
    has_unchecked = bool(re.search(r'unchecked', content))
    if (not is_safe_version and not has_overflow_guard) or (is_safe_version and has_unchecked):
        m = re.search(r'(rewardPerTokenStored|rewardIndex|accRewardPerShare)', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="STAKE-HIGH-001",
            title="Staking: Reward Accumulator May Overflow — Rewards Reset to Zero",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "The reward-per-token accumulator can overflow if not using Solidity 0.8+ "
                "overflow protection or SafeMath. An overflow resets the index to 0, "
                "making all pending rewards uncollectable — users lose all accumulated rewards."
            ),
            exploit_scenario="Over time, accumulator grows past uint256 max → wraps to 0. All users' pending rewards calculated as 0. Funds locked forever.",
            remediation="Ensure accumulator uses checked arithmetic. Solidity 0.8+ handles this automatically unless `unchecked{}` is used.",
            references=["Code4rena: reward-overflow", "Compound reward distribution"],
            language="solidity",
        ))


def _sandwich_deposit(file_ctx, content, issues):
    """
    STAKE-HIGH-002: Vault/staking deposit can be sandwiched during reward distribution.
    Front-run the reward distribution → deposit → collect → withdraw.
    """
    has_notify_reward = bool(re.search(r'(notifyRewardAmount|addReward|distributeReward|harvest)', content))
    has_stake = bool(re.search(r'function\s+(stake|deposit)\s*\(', content))
    if not (has_notify_reward and has_stake):
        return
    has_lock = bool(re.search(r'(lockPeriod|minStakeDuration|stakingEndTime|lockTime)', content))
    if not has_lock:
        m = re.search(r'(notifyRewardAmount|addReward|distributeReward)', content)
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="STAKE-HIGH-002",
            title="Staking: Reward Sandwich Attack — Deposit Before Distribution, Withdraw After",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "Rewards are distributed via `notifyRewardAmount()` without a minimum "
                "staking duration. An attacker can:\n"
                "1. Front-run `notifyRewardAmount` with a large deposit.\n"
                "2. Collect disproportionate rewards.\n"
                "3. Immediately withdraw.\n\n"
                "Net result: attacker extracts value from honest long-term stakers."
            ),
            exploit_scenario="MEV bot detects `notifyRewardAmount()` in mempool. Front-runs with massive stake. Collects proportional rewards. Back-runs unstake.",
            remediation="Implement minimum staking duration or a lock period. Alternatively, use a checkpoint-based reward system that accounts for time-weighted positions.",
            references=["Sherlock: staking-sandwich", "Code4rena: reward-distribution-timing"],
            language="solidity",
        ))


def _harvest_reentrancy(file_ctx, content, issues):
    """
    STAKE-CRIT-002: Harvest/claim function sends rewards before updating state.
    """
    harvest_pattern = re.compile(
        r'function\s+(harvest|claim|claimReward|getReward|collectReward)\s*\([^)]*\)\s*(?:public|external)[^{]*\{',
        re.MULTILINE
    )
    for m in harvest_pattern.finditer(content):
        fname = m.group(1)
        func_start = m.end(); depth = 1; i = func_start
        while i < len(content) and depth > 0:
            if content[i] == '{': depth += 1
            elif content[i] == '}': depth -= 1
            i += 1
        body = content[func_start:i]

        has_guard = bool(re.search(r'(nonReentrant|ReentrancyGuard|_status)', body + m.group(0)))

        # Find external call position vs state update position
        ext_call_pos = -1
        state_update_pos = -1
        ext_m = re.search(r'(\.transfer\(|\.call\{|safeTransfer\()', body)
        state_m = re.search(r'(rewards\[.*\]\s*=\s*0|userReward.*=\s*0|pending.*=\s*0)', body)

        if ext_m and state_m:
            ext_call_pos = ext_m.start()
            state_update_pos = state_m.start()

        if ext_call_pos != -1 and state_update_pos != -1 and ext_call_pos < state_update_pos and not has_guard:
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="STAKE-CRIT-002",
                title=f"Staking: Reentrancy in `{fname}()` — Rewards Sent Before State Reset",
                severity=Severity.CRITICAL, confidence=Confidence.HIGH,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=5),
                description=(
                    f"`{fname}()` transfers reward tokens before resetting `rewards[user]` to 0. "
                    "With an ERC-777 reward token or ETH transfer, an attacker can re-enter "
                    f"`{fname}()` and claim rewards multiple times.\n\n"
                    "**Real incidents:** Multiple yield aggregator drains via harvest reentrancy."
                ),
                exploit_scenario=f"1. Attacker calls `{fname}()`. 2. Reward token's hook fires before `rewards[attacker] = 0`. 3. Re-enters `{fname}()`. 4. Claims same rewards again. Repeat until pool drained.",
                remediation=(
                    "```solidity\n"
                    f"function {fname}() external nonReentrant {{\n"
                    "    uint256 reward = rewards[msg.sender];\n"
                    "    rewards[msg.sender] = 0;  // ← Reset FIRST (CEI)\n"
                    "    rewardToken.safeTransfer(msg.sender, reward);\n"
                    "}}\n"
                    "```"
                ),
                references=["SWC-107", "Code4rena: harvest-reentrancy"],
                language="solidity",
            ))


def _reward_token_as_staking_token(file_ctx, content, issues):
    """
    STAKE-HIGH-003: Reward token is same as staking token — accounting breaks.
    """
    stake_token = re.search(r'(stakingToken|STAKING_TOKEN)\s*=\s*(\w+)', content)
    reward_token = re.search(r'(rewardToken|REWARD_TOKEN)\s*=\s*(\w+)', content)
    if stake_token and reward_token:
        if stake_token.group(2) == reward_token.group(2):
            line = content[:reward_token.start()].count('\n') + 1
            issues.append(Issue(
                id="STAKE-HIGH-003",
                title="Staking: Reward Token == Staking Token — Balance Accounting Breaks",
                severity=Severity.HIGH, confidence=Confidence.HIGH,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description=(
                    "The reward token and staking token are the same contract. "
                    "When rewards are distributed (added to staked balance), "
                    "the `totalSupply` used for reward calculation includes undistributed "
                    "rewards — causing compounding over-distribution or under-distribution."
                ),
                exploit_scenario="Reward distribution inflates staked balance → next reward calculation uses wrong totalSupply → infinite mint-like effect or reward theft.",
                remediation="Use separate tokens for staking and rewards. If same token must be used, carefully track 'reward balance' vs 'staked balance' separately.",
                references=["Code4rena: reward-token-staking-token", "Sherlock: same-token-stake-reward"],
                language="solidity",
            ))


def _locked_rewards_on_exit(file_ctx, content, issues):
    """
    STAKE-MED-001: Rewards not claimed on emergency exit / forced unstake.
    Users lose unclaimed rewards when forced out.
    """
    has_emergency = bool(re.search(r'(emergencyWithdraw|forceUnstake|emergencyExit)', content))
    if not has_emergency:
        return
    m = re.search(r'(emergencyWithdraw|forceUnstake|emergencyExit)', content)
    func_start_m = re.search(
        rf'function\s+{m.group(1)}\s*\([^)]*\)[^{{]*\{{',
        content
    )
    if not func_start_m:
        return
    fs = func_start_m.end(); depth = 1; i = fs
    while i < len(content) and depth > 0:
        if content[i] == '{': depth += 1
        elif content[i] == '}': depth -= 1
        i += 1
    body = content[fs:i]
    # Emergency withdraw should also give rewards
    claims_rewards = bool(re.search(r'(reward|harvest|claim)', body))
    if not claims_rewards:
        line = content[:func_start_m.start()].count('\n') + 1
        issues.append(Issue(
            id="STAKE-MED-001",
            title=f"Staking: `{m.group(1)}()` Does Not Claim Pending Rewards — User Loses Rewards",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                f"`{m.group(1)}()` withdraws staked tokens but does not distribute pending rewards. "
                "Users who are forced to emergency-exit (e.g., when protocol is paused) "
                "permanently lose all their accumulated rewards."
            ),
            exploit_scenario="Protocol pauses. Admin calls emergencyWithdraw for users. All pending rewards are lost — users get principal only.",
            remediation=(
                "```solidity\n"
                f"function {m.group(1)}() external {{\n"
                "    // Claim pending rewards first\n"
                "    uint256 pending = rewards[msg.sender];\n"
                "    if (pending > 0) { rewardToken.safeTransfer(msg.sender, pending); }\n"
                "    rewards[msg.sender] = 0;\n"
                "    // Then withdraw principal\n"
                "    stakingToken.safeTransfer(msg.sender, balances[msg.sender]);\n"
                "    balances[msg.sender] = 0;\n"
                "}}\n"
                "```"
            ),
            references=["Code4rena: emergency-withdraw-rewards", "Sherlock: lost-rewards"],
            language="solidity",
        ))

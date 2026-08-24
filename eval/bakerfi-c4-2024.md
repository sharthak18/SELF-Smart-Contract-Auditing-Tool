# Blind replay: BakerFi Code4rena invitational (May 2024)

SELF v2.4.0 was pointed at the **exact pre-audit snapshot** wardens reviewed, then scored against the **published C4 report**. Nothing was tuned to this repo first.

| | |
|---|---|
| Platform | [Code4rena invitational](https://code4rena.com/reports/2024-05-bakerfi) (5 wardens, judge `0xleastwood`) |
| Source | [`code-423n4/2024-05-bakerfi`](https://github.com/code-423n4/2024-05-bakerfi) @ contest `main` |
| Scope | 33 Solidity files, 1,683 nSLOC (`scope.txt`) |
| Official result | **4 High, 8 Medium**, 3 Low/NC |
| SELF commands | `self contracts` and `self autonomous contracts --no-docs` |
| Date of this replay | 2026-08-25 |

This is a **recall test**, not a claim that SELF replaces a contest. A hit means SELF surfaced the same *class* on the same surface. Protocol-specific leftover-accounting bugs are expected misses.

## Official High / Medium scorecard

| C4 ID | Official title | SELF result | What fired | Notes |
|---|---|---|---|---|
| **H-01** | `ETHOracle.getLatestPrice` does not scale 8-dec Chainlink to the contract’s 1e18 precision | **MISS** | Related only: `AUTO-L2-SEQUENCER`, `SOL-HIGH-001` | SELF never asks “does `getPrecision()` match `answer` decimals?” That is a protocol-math bug, not a generic oracle-spot class. |
| **H-02** | Vault first-depositor / donation share inflation | **HIT** | `AUTO-FIRST-DEPOSITOR` (`Vault.sol:149`), `PATH-INFLATION`, static `SOL-MED-010` | Exact class the brain was trained on (Sherlock/C4 2024–25 + BakerFi itself in `incidents.json`). Share math is `assets * totalSupply / totalAssets` via `Rebase.toBase` with no virtual offset. |
| **H-03** | Harvest leftover collateral locked in the strategy (quoter fee-tier 500 vs configured pool; self-transfer of dust) | **MISS** | — | Integration invariant: leftover after `exactOutputSingle` is not re-supplied to Aave. No playbook encodes “quoter fee ≠ swap fee”. |
| **H-04** | Multiple swaps lack slippage protection (`amountOutMinimum: 0`, `sqrtPriceLimitX96: 0`) | **HIT** | Static `SOL-HIGH-009` on `UseSwapper.sol:72/75/92` | Autonomous `AV-SLIPPAGE` did **not** fire: project-wide `deadline` / `amountOutMin` tokens in Uniswap/Aave *interfaces* cleared `missing_slippage`. The static detector still caught the `0` min-out. |
| **M-01** | WETH supplied to Aave as deposit is irrecoverable | **MISS** | — | Strategy-specific asset-flow bug. |
| **M-02** | Vault can be DoS | **MISS** | — | Not the generic unbounded-loop class. |
| **M-03** | `StrategyLeverage.harvest` ignores flash-loan fee | **MISS** | — | One-line fee omission in harvest math. |
| **M-04** | `deposit()` `afterDeposit` formula is wrong | **PARTIAL** | `AUTO-ROUNDING-DIRECTION` | SELF flagged div-before-mul / rounding, not the specific `balanceOf * tokenPerETH` wallet-cap formula. |
| **M-05** | Protocol receives less harvest fee than intended | **MISS** | — | Fee-share formula after harvest. |
| **M-06** | Chainlink `minAnswer` / `maxAnswer` never checked | **PARTIAL** | `AUTO-L2-SEQUENCER`, `uses_chainlink_like` | SELF checks sequencer / heartbeat, not aggregator min/max bounds. |
| **M-07** | `flashFee` rounds down and can revert the loan | **PARTIAL** | `AUTO-ROUNDING-DIRECTION` | Same coarse rounding playbook; not pinned to `flashFee`. |
| **M-08** | `BalancerFlashLender.receiveFlashLoan` does not bind `originalCallData` | **HIT** | `AUTO-CALLBACK-UNVALIDATED`, `AUTO-FLASHLOAN-CALLBACK`, `PATH-CALLBACK-DEPUTY` at `BalancerFlashLender.sol:35` | Caller *is* checked (`msg.sender == vault`). SELF still correctly flagged an untrusted callback / userdata surface. |

### Headline numbers (High + Medium only)

| | Count | Rate |
|---|---:|---:|
| Official unique High/Med | 12 | — |
| **HIT** (same class, same surface) | **3** (H-02, H-04, M-08) | **25%** |
| **PARTIAL** (right theme, wrong bug) | **3** (M-04, M-06, M-07) | 25% |
| **MISS** | **6** (H-01, H-03, M-01, M-02, M-03, M-05) | 50% |
| High-only HIT | 2 / 4 | 50% |

Wardens found these by reading leverage + harvest + oracle precision as one system. SELF’s hits are the **generic classes** it was trained on: empty-vault inflation, zero slippage, flash-loan callback hygiene.

## What SELF actually emitted

### Autonomous (usable)

12 findings (6 Critical, 6 High) + 4 exploit paths. Mapped:

| SELF ID | Verdict vs C4 |
|---|---|
| `AUTO-FIRST-DEPOSITOR` + `PATH-INFLATION` | **True positive** (H-02) |
| `AUTO-CALLBACK-UNVALIDATED` / `AUTO-FLASHLOAN-CALLBACK` + `PATH-CALLBACK-DEPUTY` | **True positive** (M-08) |
| `AUTO-ROUNDING-DIRECTION` | Weak partial (M-04 / M-07) |
| `AUTO-LST-EXRATE` | Adjacent (wstETH rate exists; not H-01) |
| `AUTO-L2-SEQUENCER` | Adjacent (M-06 / Arbitrum) |
| `AUTO-ORACLE-SPOT` + `PATH-ORACLE-FLASH` | **False positive** as “AMM spot”; they price via Chainlink/Pyth |
| `AUTO-CLAMM-TICK` + `PATH-TICK-DOUBLE-COUNT` | **False positive** — `sqrtPriceLimitX96` substring-matched `sqrtP` |
| `AUTO-ACCESS-MISSING` on `Constants.sol` | **False positive** |
| `AUTO-STORAGE-COLLISION` | **False positive** (file already has `__gap`) |
| `AUTO-FEE-ON-TRANSFER` | Not in the C4 report |
| `AUTO-LIQUIDATION-SELF` on Aave `DataTypes.sol` | **False positive** (interface) |

Autonomous precision against the C4 High/Med set: **~2–4 / 12 findings** are contest-relevant.

### Static `self contracts` (noisy)

173 findings after `--severity medium`, then **exit 3** because four detector runtimes crashed (`NoneType.start` in `low_info_detectors` / `pack_staking` on `Settings.sol`, `Vault.sol`, `StrategyLeverage.sol`).

Top IDs were corpus false positives: 83× `SOL-CRIT-EXPLOIT-007` (“read-only reentrancy via token balance hooks”), 14× `SOL-CRIT-EXPLOIT-004` (“2-of-5 multisig”), 22× `SOL-HIGH-EXPLOIT-007` (“liquidate own position”). Those are not BakerFi bugs.

Useful static needles that *did* match the report: `SOL-MED-010` (4626 inflation), `SOL-HIGH-009` (zero slippage).

**Do not treat the static Critical count (118) as a contest score.** Use the autonomous table.

## Evidence on the two clean hits

H-02 lives in `Vault.deposit` / `convertToShares`:

```203:227: /tmp/bakerfi-c4/contracts/core/Vault.sol
        Rebase memory total = Rebase(_totalAssets(maxPriceAge), totalSupply());
        ...
        shares = total.toBase(amount, false);
        _mint(receiver, shares);
```

No virtual shares, no dead shares. Official writeup: [findings#39](https://github.com/code-423n4/2024-05-bakerfi-findings/issues/39).

H-04 is literal zero min-out in the Uni v3 adapter:

```67:76:/tmp/bakerfi-c4/contracts/core/hooks/UseSwapper.sol
            amountOut = _uniRouter.exactInputSingle(
                IV3SwapRouter.ExactInputSingleParams({
                    ...
                    amountOutMinimum: 0,
                    ...
                    sqrtPriceLimitX96: 0
                })
            );
```

## What this says about the brain

1. **Generic, well-encoded classes fire on real contest code.** First-depositor inflation and “swap with `amountOutMinimum = 0`” are not toy-fixture only.
2. **Protocol-specific logic is still the gap.** H-01 (8 vs 18 decimals), H-03 (quoter fee-tier ≠ pool fee + leftover self-transfer), M-01/M-03/M-05 are exactly the Immunefi 2025 point: remaining losses are business logic, not regex.
3. **Project-wide facts are too coarse.** One `deadline` in an interface suppresses `AV-SLIPPAGE` for the whole repo. One `sqrtPriceLimitX96` can trip the Kyber tick playbook.
4. **The static exploit-corpus pack is too eager** on a 1.6k-nSLOC vault and drowns the two real hits.

## Suggested follow-ups (not done in this replay)

Those four items were implemented in the ten-contest patch (see `eval/c4-replay-10.md`). Re-score of this same snapshot after the patch:

| C4 ID | After patch |
|---|---|
| **H-01** | **HIT** — `AUTO-ORACLE-DECIMALS` at `oracles/EthOracle.sol:31` |
| **H-02** | **HIT** — unchanged |
| **H-03** | **MISS** — still protocol leftover / fee-tier math |
| **H-04** | **HIT** — now also `AUTO-SLIPPAGE` (not only static `SOL-HIGH-009`) |
| High-only | **3 / 4** (was 2 / 4) |

`AUTO-CLAMM-TICK`, `AUTO-ORACLE-SPOT`, `AUTO-STORAGE-COLLISION`, and the Hardhat advisory flood are gone on this repo.

## Re-run

```bash
git clone --depth 1 https://github.com/code-423n4/2024-05-bakerfi.git /tmp/bakerfi-c4
SELF_DATA_DIR=/tmp/self-bakerfi-data self autonomous /tmp/bakerfi-c4/contracts --no-docs -o /tmp/bakerfi-eval/auto.md --json
```

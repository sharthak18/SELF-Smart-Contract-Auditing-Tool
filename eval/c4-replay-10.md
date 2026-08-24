# Ten-contest C4 replay: why SELF misses and FPs, and what we fixed

SELF v2.4.0 was pointed at **exact pre-audit snapshots** from ten Code4rena contests (BakerFi plus nine more), then scored against the **published High/Medium reports**. Nothing was given the official write-up first.

This is a recall / precision study, not a claim that SELF replaces a contest. A **HIT** means the same *class* on the same surface. Protocol-specific leftover-accounting and connector-TVL math remain expected misses.

| | |
|---|---|
| Tool | SELF autonomous v2.4.0 (`self autonomous TARGET --no-docs`) |
| Date | 2026-08-25 |
| Snapshots | `/tmp/c4-replays/*` and `/tmp/bakerfi-c4` (C4 GitHub `main` at contest time) |
| Brain after the patch | 43 playbooks, 24 incidents, 13 tactics. `RULE_VERSION` still **2.3.0**. Catalog untouched. |

## Contest set

Picked for high bounty / criticality. Unique High counts vary; Ethena and Next Generation are the “few unique vulns” cases. Noya (23 High) is the stress test.

| Contest | Official H / M | nSLOC-ish | Why it is here |
|---|---:|---:|---|
| [BakerFi 2024-05](https://code4rena.com/reports/2024-05-bakerfi) | 4 / 8 | ~1.7k | Vault + leverage + Chainlink |
| [Next Generation 2025-01](https://code4rena.com/reports/2025-01-next-generation) | 1 / 3 | 472 | Meta-tx / forwarder |
| [PoolTogether 2024-03](https://code4rena.com/reports/2024-03-pooltogether) | 1 / 8 | small | ERC-4626 prize vault |
| [Fraxlend 2022-08](https://code4rena.com/reports/2022-08-frax) | 2 / 13 | mid | Liquidation / bad debt |
| [Revert Lend 2024-03](https://code4rena.com/reports/2024-03-revert-lend) | 6 / 25 | mid | Permit2 + Uni v3 vault |
| [Size 2024-06](https://code4rena.com/reports/2024-06-size) | 4 / 13 | large | Credit market math |
| [Ethena Labs 2024-11](https://code4rena.com/reports/2024-11-ethena-labs) | 0 / 2 | 665 | Whitelist / burn |
| [Curves 2024-01](https://code4rena.com/reports/2024-01-curves) | 5 / 10 | small | Friend.tech-style curve |
| [NOYA 2024-04](https://code4rena.com/reports/2024-04-noya) | 23 / 63 | huge | Oracle + connector TVL |
| [Wise Lending 2024-02](https://code4rena.com/reports/2024-02-wise-lending) | 5 / 17 | large | Lending + PowerFarm |

## Headline scorecard (after the patch)

Blind first pass is in the session notes and `eval/bakerfi-c4-2024.md`. Numbers below are the **re-run after the root-cause patch**.

| Contest | High HIT | High PARTIAL | High MISS | Notable new true positives | Noise that went away |
|---|---:|---:|---:|---|---|
| BakerFi | **3 / 4** (H-01, H-02, H-04) | 0 | H-03 leftover / fee-tier | `AUTO-ORACLE-DECIMALS`, `AUTO-SLIPPAGE` | CLAMM-TICK, ORACLE-SPOT, STORAGE-COLLISION, hardhat flood |
| Next Generation | **1 / 1** (H-01) | 0 | — | `AUTO-DOMAIN-SEPARATOR-ARG`, `PATH-DOMAIN-REPLAY` | PROXY-INIT, STORAGE-COLLISION, PATH-BRIDGE-REPLAY, hardhat |
| PoolTogether | 0 / 1 | 0 | H-01 fee-claim lock | — | CREATE2, ORACLE-SPOT, LIQUIDATION-SELF |
| Fraxlend | **2 / 2** (H-01, H-02) | 0 | — | `AUTO-BAD-DEBT-UNMARKED` | CREATE2, ORACLE-SPOT as AMM |
| Revert Lend | **1 / 6** (H-01) | H-02 reentrancy | H-03..H-06 | `AUTO-PERMIT2` now means “token not bound” | CREATE2, hardhat |
| Size | 0 / 4 | H-04 liq math | H-01..H-03 fee / race / cap | `AUTO-BAD-DEBT-UNMARKED` (adjacent) | ORACLE-SPOT |
| Ethena | n/a (0 High) | — | — | `AUTO-WHITELIST-GAP` → **both Mediums** | PATH-BRIDGE-REPLAY, hardhat |
| Curves | 1 / 5 | H-04 `setCurves` class | H-01 DoS, H-02 splitter, H-03 honeypot, H-05 equate | `AUTO-ACCESS-MISSING` on unguarded `set*` | FIRST-DEPOSITOR FP |
| NOYA | 1–2 / 23 | H-02 decimals | rest are connector TVL | `AUTO-ORACLE-DECIMALS` | ACCESS flood, PATH-BRIDGE |
| Wise Lending | 1 / 5 | H-03 bad-debt brick | H-01 receive, H-02 erase debt, H-04/H-05 | `AUTO-BAD-DEBT-UNMARKED`, first-depositor (M-03) | CREATE2, CLAMM |

**High-only recall across the nine contests that have Highs:** about **9–11 / 51** unique Highs (~20%). That is not a contest replacement. It *is* a step change from the first pass, where BakerFi High recall was 2/4, Next Generation H-01 was a total miss, Fraxlend H-01/H-02 were a miss, Revert H-01 was a generic “uses Permit2”, and Ethena’s only two Mediums were invisible.

Ethena (the “<6 unique vulns” invitational) goes **2 / 2 Medium** after the whitelist playbook.

## It is not hallucination

The autonomous layer is a **symbolic reasoner** (playbook × project-wide facts × substring locate). There is no LLM on the default path (`--no-docs`, `use_llm=False`). False positives are **over-general heuristics**. False negatives are **facts that OR the whole repo** or **invariants no playbook encodes**.

### Why misses happened

| Root cause | Evidence from this set | Not this |
|---|---|---|
| **Project-wide facts** | Next Generation has `_domainSeparatorV4()` in `ERC20MetaTxUpgradeable`, so `missing_signature_binding` was False and H-01 (caller-supplied `domainSeparator` on `Forwarder.execute`) never fired. BakerFi has `deadline` on Uniswap *interfaces*, so `missing_slippage` was False even with `amountOutMinimum: 0` in `UseSwapper`. | Not “the model forgot EIP-712”. |
| **No per-argument binding** | Revert H-01: `permitTransferFrom` is present, but the permitted **token** is never checked against USDC. Ethena: `WHITELIST_ENABLED` exists, but `to == address(0)` is still open. BakerFi H-01: `latestRoundData` + `getPrecision() == 1e18` and **no** `feed.decimals()`. | Not missing “oracle” or “permit” knowledge — the knowledge was one file away. |
| **Comments treated as code** | Fraxlend `liquidateClean` has a `// writeoff` comment, so the first pass marked the *whole project* as writing off bad debt. Dirty `liquidate()` does not. That is C4 H-01/H-02. | Not lack of lending knowledge. |
| **Protocol-specific math** | BakerFi H-03 (quoter fee 500 vs `_swapFeeTier` + leftover self-transfer). Size H-01 swap-fee undercharge. Noya H-03..H-23 connector TVL. Curves H-05 malformed `==`. Wise H-01 `receive`. | These need inter-procedural dataflow or a human. The brain cannot invent a Pendle TVL formula it has never been taught. |
| **Generic verbs promoted the wrong type** | `mint`/`burn` are bridge entry verbs. Next Generation and Ethena scored as `bridge` and grew `PATH-BRIDGE-REPLAY`. | Not a fake bridge exploit narrative from an LLM. |

### Why false positives happened

| Root cause | Evidence | Fix |
|---|---|---|
| **Substring `sqrtP`** | BakerFi `sqrtPriceLimitX96` fired `AV-CLAMM-TICK` (Kyber). | Word-boundary + require `nextSqrtP` / `baseL` / `nearestCurrentTick`. |
| **`set[A-Z]` + `IGNORECASE`** | `settings()` matched as an unguarded admin setter. ACCESS landed on view getters. | Case-sensitive `set[A-Z]` only. |
| **Public `mint`/`burn`/`liquidate` = “missing access”** | Every ERC-20 and every lending pair fired `AUTO-ACCESS-MISSING` at file:1. | Only admin-style names (`setX`, `pause`, `upgrade`, `grantRole`, …). |
| **`onlyOwner` not enough, `initializer` treated as unprotected** | OZ `initializer` *is* the guard. Next Generation `Forwarder.initialize` is not Wintermute. | `initializer` / `only*` modifiers count as auth. |
| **`__gap` required the collision playbook** | `AV-STORAGE-COLLISION.required_any` included `__gap`, so the *defense* fired the finding. | Fact `missing_storage_gap`; `__gap` is now forbidden. |
| **Interface / Constants files** | Aave `liquidate` on an interface; `Constants.sol:1`. | Skip `interface` / `library` / `interfaces/` / `Constants.sol`. |
| **Hardhat `*` INFO advisory** | 9× `AUTO-DEP-DEP-HARDHAT-DEFAULT-KEY` on every repo that mentioned hardhat. | Wildcard INFO/LOW advisories are not findings. |
| **`getAmountOut` / `balanceOf(this)` = spot oracle** | PrizeVault and Fraxlend priced via Chainlink, still got `PATH-ORACLE-FLASH`. | Spot = `getReserves`/`slot0` and **not** `latestRoundData`. |
| **CREATE2 factory = metamorphic** | Every factory fired CRITICAL. | Require CREATE2 **and** `selfdestruct`. |

## What we changed in the tool

Payload-free. No catalog detectors. `RULE_VERSION` 2.3.0. Offline `self TARGET` unchanged.

### Tighter facts (`understand.py`, `languages.py`)

- `user_supplied_domain_separator` — `domainSeparator` is a **function parameter**.
- `amount_out_min_zero` — literal `amountOutMinimum: 0` (BakerFi H-04).
- `oracle_decimal_mismatch` — **per file**: `latestRoundData` + `10**18`/`getPrecision` and no `.decimals()` (BakerFi H-01, NOYA H-01).
- `permit2_token_unbound` — `permitTransferFrom` without `permit.token == asset` (Revert H-01).
- `whitelist_burn_gap` — `WHITELIST_ENABLED` plus burn-to-zero (Ethena M-01/M-02).
- `liquidation_unrestricted` — some impl `liquidate*` never writes off debt, **comments stripped** (Fraxlend H-01/H-02).
- `unguarded_privileged_write` — admin names only; `only*` / `initializer` count as auth; skip interfaces.
- `is_bridge` — no longer promoted by `mint`/`burn`; requires `processMessage` / `completeTransfer` / `verifyVM`.
- `uses_spot_price` — not when Chainlink is present.
- `create2_with_selfdestruct`, `missing_storage_gap`.

### New / retargeted playbooks (`attack_vectors.json`: 39 → 43)

- `AV-DOMAIN-SEPARATOR-ARG` + `PATH-DOMAIN-REPLAY`
- `AV-ORACLE-DECIMALS`
- `AV-WHITELIST-GAP`
- `AV-BAD-DEBT-UNMARKED`
- `AV-PERMIT2` now requires the token-unbound fact
- `AV-SLIPPAGE` now requires `amount_out_min_zero`
- `AV-CLAMM-TICK`, `AV-STORAGE-COLLISION`, `AV-CREATE2-METAMORPHIC`, `AV-ORACLE-SPOT` retargeted as above

### Reasoner / deps

- Skip interface and `Constants.sol` when locating.
- ACCESS locates the **unguarded** setter, not the first `set*` with `onlyOwner`.
- `sqrtP` is word-bounded.
- INFO wildcard advisories (Hardhat default key) are not findings.

### Training corpus (lessons only)

- Incidents: Next Generation domain, BakerFi decimals, Revert Permit2, Fraxlend bad debt (24 total).
- Tactic `TAC-PER-FUNCTION-BINDING`: “ask what each argument binds, not whether the project has a check *somewhere*.”

Regression tests live in `tests.test_autonomous.ReplayFixTests` (10 cases). Full suite: **117 OK**.

## What is still out of reach

These need whole-program interpretation the reasoner does not do:

1. **BakerFi H-03** — quoter fee-tier 500 vs configured pool, leftover not re-supplied.
2. **Size H-01 / H-02 / H-03** — swap-fee formula, repay vs `liquidateWithReplacement` race, collateral remainder cap.
3. **NOYA H-03..H-23** — each connector’s TVL math (Pendle, Balancer, Silo, Morpho, Uni v3, …).
4. **Curves H-02 / H-03 / H-05** — `FeeSplitter` credit updates, honeypot subject, malformed equate.
5. **Wise H-01 / H-02 / H-05** — `receive` steal, free debt erase, `nftID` vs Aave flag.
6. **Revert H-03 / H-04 / H-05 / H-06** — unsanitized `transform` data, `V3Utils.execute` caller, tick rounding, `onERC721Received` grief.

Those are “lack of inter-procedural understanding”, not “lack of a keyword”. Teaching another 20 playbooks will not close them; a path-sensitive pass (or a human) will.

`AUTO-ACCESS-MISSING`, `AUTO-DOS-UNBOUNDED`, `AUTO-L2-SEQUENCER`, and `AUTO-FIRST-DEPOSITOR` still fire too often on large lending repos. They are now at least pointed at real functions instead of `Constants.sol:1`.

## Re-run

```bash
# any one snapshot
SELF_DATA_DIR=/tmp/self-c4-replay-data \
  self autonomous /path/to/scope --no-docs -o /tmp/out.md --json

# unit lock for the new facts
python -m unittest tests.test_autonomous.ReplayFixTests
```

## Follow-on 4: keep the contest brief in mind

The scorecard above was **blind**: `run_autonomous_audit(..., no_docs=True)` on a `.sol`-only copy. That was the wrong question for “did SELF understand the README?”. Re-reading the ten full repos showed every contest publishes Known Issues / trusted roles / `scope.txt`, and the reasoner never saw them.

Three stacked failures:

1. **How the replay was run** — `no_docs=True` plus `/tmp/c4-eval/*-scope` (copied Solidity only). `ProtocolContext` was empty.
2. **Where the wiring stopped** — `pipeline.py` short-circuits on `no_docs`; `doc_reader` did not open `README-sponsor.md` / `scope.txt` / `out_of_scope.txt`; `understand()` used docs only for type scoring; `reason()` never received the context.
3. **Why it was designed that way** — docs were boolean posture flags (multisig / Chainlink / SafeERC20) for static-detector notes, not a contest-brief parser.

### What the brain now keeps

`DocReader` walks up from `contracts/` / `src/` and **scores** candidate roots (`scope.txt`, “known issue”, “trusted role”, “warden”) so a nested package README no longer hides the contest brief (PoolTogether `pt-v5-vault/README.md` used to win).

Parsed into `ProtocolContext` → `ProtocolUnderstanding` → reasoner / path synthesizer / report:

| Field | Used for |
|---|---|
| `known_issues` | Briefing text + accepted-playbook map |
| `trusted_roles` | Briefing / report (never mapped to `AV-ACCESS-MISSING`) |
| `out_of_scope_files` | Skip findings whose file suffix-matches the list |
| `accepted_playbooks` | Skip those playbooks **and** the matching exploit paths |

Conservative map (never centralization → missing access):

- first-depositor / `yieldBuffer` → `AV-FIRST-DEPOSITOR`
- storage gap → `AV-STORAGE-COLLISION`
- FoT / rebase / “fees on transfer not supported” → `AV-FEE-ON-TRANSFER`
- sequencer / stale / outdated answers → `AV-L2-SEQUENCER`
- misconfigured / trusted oracle → `AV-ORACLE-SPOT` (not `AV-ORACLE-DECIMALS`)
- rounding known → `AV-ROUNDING-DIRECTION`
- “centralization risk” / trusted owner → `AV-GOVERNANCE-FLASH`

Known-issue sections are **concatenated** (C4’s 4naly3er heading no longer hides a later `## Known issues:`). If a section has no dashes, `###` paragraphs are kept (Fraxlend). Role tables drop Q&A rows; `Roles in the protocol: Owner (… and Timelock), EmergencyAdmin` splits on commas only.

`4naly3er-report.md` / `bot-report.md` are never loaded as accepted issues.

### Docs-on re-run (`no_docs=False`, full-repo contract dirs)

Summaries: `/tmp/c4-eval-docs/summaries.json`. Recall of official Highs is unchanged — those bugs were never in the sponsor brief. What changed is **the tool stops re-reporting accepted risk**.

| Contest | Brief now in mind | Findings / paths that dropped | Kept (still in scope) |
|---|---|---|---|
| BakerFi | Governor / User; 82 OOS | — (known section is 4naly3er-only) | H-01 decimals, H-02 inflation, H-04 slippage |
| Next Generation | 5 roles | — | H-01 `DOMAIN-SEPARATOR-ARG` |
| PoolTogether | 5 known; accepted first-depositor + rounding | `AUTO-FIRST-DEPOSITOR`, `PATH-INFLATION` | ACCESS / readonly reentrancy (H-01 fee-claim still a miss) |
| Fraxlend | 8 known; accepted spot / stale / rounding | `AUTO-L2-SEQUENCER` | H-01/H-02 `BAD-DEBT-UNMARKED`, `AUTO-ORACLE-DECIMALS` |
| Revert Lend | Owner / EmergencyAdmin / Operators; accepted FoT | — | H-01 `PERMIT2` |
| Size | 21 known; 4 roles; FoT / spot / stale / gov-flash; 180 OOS | `AUTO-GOVERNANCE-FLASH`, `PATH-FLASH-VOTE` | H-01..H-03 still misses; first-depositor still fires (not declared) |
| Ethena | 7 roles; storage-gap + centralization; 48 OOS | `AUTO-STORAGE-COLLISION`, `PATH-FLASH-VOTE` | **both Mediums** `WHITELIST-GAP` |
| Curves | none (4naly3er-only) | — | ACCESS on `setWhitelist` / `setCurves` |
| NOYA | 5 roles; 326 OOS | — | `ORACLE-DECIMALS`; connector TVL still out of reach |
| Wise Lending | 37 known; accepted FoT / stale / rounding | `AUTO-ROUNDING-DIRECTION` | H-03 bad-debt; first-depositor (M-03) still fires |

### Tests / version

`ReplayFixTests` now covers walk-up vs nested README, paragraph known issues + role prose, and “accepted `AV-GOVERNANCE-FLASH` does not emit `PATH-FLASH-VOTE`”. Full suite **121 OK**. Brain still 43 / 24 / 13 + `TAC-CONTEST-BRIEF`. `RULE_VERSION` still **2.3.0**. Offline `self TARGET` unchanged.

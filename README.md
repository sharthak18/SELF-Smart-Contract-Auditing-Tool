# SELF — Smart Contract Auditing Tool
### *The Devil That Kills All Evil*

[![Python](https://img.shields.io/badge/Python-3.8+-blue)](https://python.org)
[![Version](https://img.shields.io/badge/Version-2.0.0-red)](.)
[![Languages](https://img.shields.io/badge/Languages-5-orange)](.)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

A **zero-cloud, intelligent smart contract security auditing tool** for security researchers and auditors.

Reads your protocol's docs → understands its intent → scans for 95+ vulnerability patterns → produces professional audit reports. Optional local LLM analysis via Ollama for false-positive filtering.

**No cloud. No API keys. No compiler needed. Runs on Intel i3 + 4GB RAM.**

---

## Install

```bash
git clone https://github.com/YOUR_USERNAME/self-auditor.git
cd self-auditor/self_tool
pip install -e .
```

Verify:
```bash
self --version   # Should print SELF v2.0.0
self --list-detectors
```

---

## Usage

```bash
# Scan a project (reads docs + NatSpec automatically)
self .
self /path/to/protocol

# Scan a single file
self src/Vault.sol

# Common options
self . --severity high          # Only High and Critical
self . --no-info                # Hide Info findings
self . --output report.md       # Custom report path
self . --json                   # Also export JSON (CI/CD)
self . --show-suppressed        # Show what docs suppressed and why
self . --no-docs                # Skip doc reading (pure static mode)

# AI-assisted analysis (requires Ollama — see below)
self . --ai                     # AI reviews Critical+High findings
self . --ai --ai-all            # AI reviews everything
self . --ai --ai-model qwen2.5-coder:7b
self . --ai --ai-timeout 60     # Skip if LLM takes >60s

# List all built-in detectors
self --list-detectors
```

---

## Real-World Test Results

Tested on **Damn Vulnerable DeFi** (30 contracts, 2,283 lines):

| Metric | Result |
|--------|--------|
| Scan time | **0.18 seconds** |
| Files scanned | 30 |
| Critical findings | 13 |
| High findings | 21 |
| Medium findings | 13 |
| Context-suppressed | 7 |

**Known vulnerabilities correctly caught:**
- ✅ `TrusterLenderPool` — arbitrary external call
- ✅ `SelfiePool` — flash loan + governance attack
- ✅ `PuppetV2Pool` — spot price oracle manipulation
- ✅ `FreeRiderNFTMarketplace` — reentrancy + flash loan
- ✅ `ClimberVault` — access control bypass
- ✅ `SideEntranceLenderPool` — flash loan LP attack
- ✅ `TheRewarderPool` — reward sandwich attack
- ✅ AMM xy=k invariant violations

---

## What It Detects (~95 Patterns)

### Critical (10 detectors)
Reentrancy (classic, cross-function, read-only/Curve), unchecked `.call()`, arbitrary `delegatecall`, unprotected `selfdestruct`, uninitialized proxy, proxy storage collision, `tx.origin` auth, signature replay.

### High (13 detectors)
Oracle spot price (no TWAP), integer overflow, unchecked math blocks, flash loan no validation, missing access control, ERC20 approval race, unbounded loop DoS, unchecked ERC20 transfer, zero slippage (MEV sandwich), `block.timestamp` randomness, divide-before-multiply, flash loan governance, unprotected `initialize()`.

### Protocol Packs (auto-detected)
| Pack | Trigger | Key Patterns |
|------|---------|-------------|
| **AMM** | swap/reserve keywords | xy=k invariant, LP inflation, FoT tokens, slippage |
| **Lending** | borrow/collateral/liquidate | Accrual missing, cToken inflation, self-liquidation |
| **Bridge** | bridge/crossChain/LayerZero | Message replay, validator threshold, zero root |
| **Staking** | stake/reward/harvest | Checkpoint missing, harvest reentrancy, sandwich |

### Medium/Low/Info
Centralization risk, zero-address checks, missing deadline, stale Chainlink, ERC777 hooks, missing events, unsafe downcast, ERC-4626 inflation, floating pragma, outdated compiler, hardcoded addresses, missing NatSpec.

### Multi-Language Support
| Language | Detectors | Frameworks |
|----------|-----------|-----------|
| Solidity | 44+ | Foundry, Hardhat, Truffle, Brownie |
| Vyper | 5 | Foundry, Brownie |
| Rust/Anchor | 6 | Anchor (Solana) |
| Huff | 4 | Foundry |
| Move | 5 | Aptos, Sui |

---

## Intelligence Layer

### Doc Reader (runs automatically)
SELF reads before scanning:
- `README.md`, `WHITEPAPER.md`, `SECURITY.md`, `docs/*.md`
- `audits/*.md` (previous audit reports)
- NatSpec: `@dev`, `@notice`, `@custom:security`
- Import statements (SafeERC20, ReentrancyGuard, etc.)

**Suppression examples:**
```
"Gnosis Safe" in README    → centralization_risk severity reduced
"TWAP oracle" in docs      → oracle_spot_price suppressed
SafeERC20 import detected  → unchecked_transfer suppressed
@dev permissionless        → access_control suppressed for that function
```

Use `--show-suppressed` to see everything that was suppressed and why.

### Local LLM via Ollama (optional)
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull model (4GB, works on 8GB RAM)
ollama pull deepseek-coder:6.7b    # Recommended
# OR
ollama pull qwen2.5-coder:7b       # Also excellent

# Run with AI
self . --ai
```

LLM sees: `[protocol docs] + [flagged code] + [finding]`  
Returns: `CONFIRMED / LIKELY_FALSE_POSITIVE / UNCERTAIN` + reasoning

Without Ollama, SELF works perfectly — `--ai` shows a helpful skip message.

---

## Custom Detectors (Query DSL)

Write custom rules in plain Python:

```python
# self_tool/detectors/solidity/my_custom.py
from self_tool.query import Q

def detect(file_ctx):
    return (
        Q(file_ctx)
        .functions()
        .visibility('external', 'public')
        .has_pattern(r'\.call\s*\{')
        .not_has_pattern(r'nonReentrant')
        .as_issues(
            id='CUSTOM-001',
            title='Unchecked external call in {fname}()',
            severity='HIGH',
            confidence='MEDIUM',
            description='...',
            exploit_scenario='...',
            remediation='...',
        )
    )
```

SELF auto-discovers it — no registration needed.

---

## Auditor Workflow

### First time on a new protocol:
```bash
# 1. Clone or download the protocol
git clone https://github.com/protocol/contracts.git target

# 2. Run SELF (reads their docs automatically)
self target/ --output target-audit.md

# 3. Review the report (check Critical+High first)
# The "Protocol Intelligence" section shows what signals were found in docs

# 4. If you have Ollama running, add AI review:
self target/ --output target-audit.md --ai

# 5. Check what was suppressed (verify suppression is correct)
self target/ --output target-audit.md --show-suppressed

# 6. For CI/CD pipelines:
self target/ --severity high --json --quiet
echo "Exit code: $?"  # 0=clean, 1=high, 2=critical
```

### NatSpec suppression tags (add to your contracts):
```solidity
/// @dev permissionless by design
function openFunction() external { ... }

/// @custom:security no reentrancy risk — all state settled before external call
function safeWithdraw() external { ... }

/// @dev deadline checked in the router, not here
function swap() external { ... }
```

---

## Report Structure

Every report includes:
1. **Protocol Intelligence** — signals from docs, what was suppressed
2. **Summary table** — active vs suppressed counts per severity  
3. **Findings index** — clickable table with AI verdict column (if `--ai`)
4. **Detailed findings** — description + code snippet + exploit scenario + remediation + references
5. **AI analysis block** per finding (if `--ai`)
6. **Suppressed findings** (if `--show-suppressed`)
7. **Files scanned** table

---

## Exit Codes (CI/CD)

| Code | Meaning |
|------|---------|
| `0` | No Critical or High findings |
| `1` | High severity finding present |
| `2` | Critical severity finding present |

GitHub Actions example:
```yaml
- name: SELF Security Scan
  run: |
    pip install -e ./self_tool
    self src/ --severity high --json --quiet
```

---

## Project Structure

```
self_tool/
├── self.py                      # CLI entry point
├── query.py                     # Glider-inspired Query DSL
├── requirements.txt
├── pyproject.toml
├── core/
│   ├── issue.py                 # Finding data model
│   ├── scanner.py               # File discovery + framework detection
│   ├── detector_engine.py       # Orchestrator + doc suppression
│   ├── reporter.py              # Markdown report generator
│   ├── doc_reader.py            # Documentation intelligence
│   ├── protocol_context.py      # Intent context + suppression rules
│   └── llm_analyzer.py          # Ollama local LLM integration
├── parsers/
│   └── solidity_parser.py
├── detectors/
│   ├── solidity/                # 44+ detectors + 4 protocol packs
│   │   ├── reentrancy.py
│   │   ├── dangerous_calls.py
│   │   ├── proxy_and_auth.py
│   │   ├── high_oracle_overflow_access.py
│   │   ├── high_misc.py
│   │   ├── medium_detectors.py
│   │   ├── low_info_detectors.py
│   │   ├── taint_tracker.py
│   │   ├── pack_amm.py
│   │   ├── pack_lending.py
│   │   ├── pack_bridge.py
│   │   └── pack_staking.py
│   ├── vyper/
│   ├── rust/
│   ├── huff/
│   └── move/
└── knowledge/
    └── exploit_patterns.json
```

---

## Known Limitations

| Issue | Details |
|-------|---------|
| False positives on interfaces | `SOL-CRIT-003` can fire on interface function declarations that contain `transfer` — verify manually |
| No symbolic execution | Deep math overflow in complex formulas may be missed |
| No inter-contract analysis | Cross-contract call chains not fully tracked yet |
| Protocol-specific logic | Business logic bugs require manual review |

**SELF is a first-pass tool. Always follow up with manual review.**

---

## Sources

Detectors sourced from real incidents and research:

| Source | Used For |
|--------|---------|
| Rekt.news | Real exploit patterns |
| Code4rena / Sherlock | Contest findings (2021-2025) |
| Trail of Bits | Vulnerability classes |
| OpenZeppelin | ERC standards, proxy patterns |
| Pashov Audit Group | Methodology |
| Immunefi / Spearbit | Bug bounty patterns |
| SWC Registry | Weakness classification |
| Neodyme / Soteria | Solana/Anchor security |
| DeFiHackLabs | PoC exploit database |

---

*Built for Web3 security researchers. Zero cloud. Zero tracking. Runs on your machine.*

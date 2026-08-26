# SELF — Smart Contract Exploit & Logic Finder

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![Version](https://img.shields.io/badge/Version-2.5.0-red)](VERSION)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Offline](https://img.shields.io/badge/Scans-Offline-blueviolet)](SECURITY.md)
[![Repo](https://img.shields.io/badge/Repo-GitHub-black)](https://github.com/sharthak18/SELF-Smart-Contract-Auditing-Tool)

SELF is a **local, deterministic, offline-first** smart-contract auditor for
Solidity, Vyper, Huff, Rust/Anchor, Move, and (in autonomous mode) Cairo,
Sway, and Tact. It is designed to be the first pass a security researcher
runs before opening a Foundry test, an Echidna campaign, a Slither run, or
a manual review.

v2.4 adds an **autonomous AI auditor** (`self autonomous` / `self agent`)
that reads the entire project, trains a local knowledge index on real
exploit data, reasons about business logic / math / on-chain behaviour,
walks multi-hop exploit paths, and checks dependency versions. An optional
`--llm` flag can refine that pass with OpenAI, Anthropic, or Ollama. The
original `self TARGET` scan stays offline, deterministic, and LLM-free.

SELF ships:

- A deterministic, parser-backed detector engine that runs **without** a
  Solidity or Rust compiler, without RPC, without a cloud LLM, and without
  network access.
- A strict one-to-one mapping between every detector ID and a hardcoded
  **deep-review profile** containing the proof obligation a human auditor
  must establish for that finding.
- A **project semantic graph** that resolves imports, inheritance, modifier
  guards, internal calls, low-level calls, and writes across files, then
  emits project-level findings (`PROJECT-ACCESS-001`, `PROJECT-PROXY-001`,
  `PROJECT-REENTRANCY-001`, `PROJECT-AUTH-001`, `PROJECT-ORACLE-001`,
  `PROJECT-UNRESOLVED-001`) when cross-contract hazards appear.
- A **local persistent feedback store** (`~/.self-auditor/feedback.sqlite3`)
  with fingerprint-scoped suppression: changed source code or a new rule
  version automatically re-surfaces a finding.
- A **deterministic calibration corpus** (`self calibrate`) that produces
  per-detector precision, recall, and false-positive rates so the
  detector table can be audited like any other benchmark.
- An isolated, **metadata-only signed-manifest updater** (`self update`)
  that pulls pinned advisory metadata from OWASP Smart Contract Security,
  OpenZeppelin, Vyper, GHSA, and NVD. Nothing downloaded is ever executed;
  nothing silently mutates a detector.
- An **X-ray pre-audit report** (`self --xray`) that maps entry points,
  state writes, modifiers, external calls, and NatSpec predicates without
  compiling anything.
- A **structural fuzzer** (`self --fuzz`) that runs Hypothesis-based
  property tests on parsed contract structure and a modeled
  state-machine sequence fuzzer.
- A **PoC harness generator** (`self --poc`) that emits runnable Foundry
  test files for every exploit-class detector that fires, with output
  paths confined to the scan target directory.
- An **autonomous AI auditor** (`self autonomous`) that trains on the
  real-incident corpus, reads the whole repository, reasons about
  business logic / math / on-chain behaviour, synthesizes exploit
  paths, and checks dependency versions. Optional `--llm` refinement.

SELF does **not** claim to replace a manual audit. It is a triage tool. The
question it answers is "which lines of code deserve a closer look, and what
must a human prove before declaring them safe?". It can drive false
positives toward zero through calibration and explicit feedback; it can
never reach zero.

---

## Table of Contents

1. [Install](#install)
2. [Quickstart](#quickstart)
3. [Command reference](#command-reference)
4. [Output formats](#output-formats)
5. [Detection model](#detection-model)
6. [Autonomous AI auditor](#autonomous-ai-auditor)
7. [Project semantic graph](#project-semantic-graph)
8. [Feedback store](#feedback-store)
9. [Calibration](#calibration)
10. [Advisory updater](#advisory-updater)
11. [X-ray pre-audit](#x-ray-pre-audit)
12. [Fuzzing](#fuzzing)
13. [PoC generation](#poc-generation)
14. [Custom rules](#custom-rules)
15. [Configuration and storage](#configuration-and-storage)
16. [Exit codes](#exit-codes)
17. [CI integration](#ci-integration)
18. [Limits and honest boundaries](#limits-and-honest-boundaries)
19. [Contributing](#contributing)
20. [License](#license)

---

## Install

```bash
git clone https://github.com/sharthak18/SELF-Smart-Contract-Auditing-Tool.git
cd SELF-Smart-Contract-Auditing-Tool
python3 -m pip install -e .
```

Verify:

```bash
self --version              # 2.5.0
self --list-detectors       # full detector catalog
self --knowledge-status     # OWASP coverage + knowledge sources
```

Optional, only if you intend to use the structural fuzzer:

```bash
python3 -m pip install hypothesis
```

`hypothesis` is the only optional runtime dependency. It is required for
`self --fuzz`; scans without `--fuzz` work without it.

---

## Quickstart

```bash
# Scan a directory or a single file. Exit code reflects severity.
self .

# Generate a Markdown report + JSON sidecar.
self src/Vault.sol -o reports/vault.md --json

# Project semantic graph (human-readable Markdown).
self graph .

# Project semantic graph (canonical JSON, for tooling).
self graph . --json --output reports/graph.json

# Pre-audit X-ray report alongside the normal findings.
self . --xray --xray-output reports/xray.md

# Property-based fuzzing on parsed structure.
self . --fuzz

# Generate Foundry PoC harnesses for every exploit-class finding.
self . --poc --poc-dir poc/

# Run the deterministic calibration corpus.
self calibrate

# Pull the latest pinned advisory metadata.
self update --manifest-url https://scs.owasp.org/feed.json

# Autonomous AI audit: read the whole project, reason, check deps.
self autonomous .
self autonomous src/ --json -o reports/autonomous.md

# Train / refresh the local knowledge index on the bundled
# exploit corpus, or on extra audit-report JSON you provide.
self train
self train extra-exploits.json
self train --status

# List, add, export, import local feedback entries.
self feedback list .
self feedback add . --finding sf_xxx --type false_positive --reason "uses SafeERC20"
self feedback export ./feedback.json
self feedback import ./feedback.json
```

Every command runs without network access except `self update`,
`self intelligence rollback`, the opt-in `self autonomous --llm`,
and the opt-in `self autonomous --online` (fetch inventoried doc links
+ OSV dependency lookup). See [SECURITY.md](SECURITY.md).

---

## Command reference

```text
self TARGET                                 # scan
self [TARGET] --list-detectors              # catalog
self [TARGET] --knowledge-status            # knowledge provenance
self graph TARGET [--json] [-o FILE]        # project semantic graph
self update --manifest-url URL [--dry-run]  # pull advisory metadata
self intelligence status                    # list installed snapshots
self intelligence rollback SNAPSHOT_ID      # activate a previous snapshot
self feedback add TARGET --finding FP --type {confirmed|false_positive|accepted_risk|fixed} --reason "..."
self feedback list TARGET [--include-inactive]
self feedback remove FEEDBACK_ID
self feedback export FILE                    # write local store as JSON
self feedback import FILE [--replace]       # merge or replace local store
self calibrate [--root DIR] [--json]        # confusion-matrix report
self autonomous TARGET [--llm] [--online] [--json]  # autonomous AI audit
self agent TARGET                           # alias of autonomous
self train [EXTRA.json ...] [--status]      # train local knowledge index
```

### Scan flags

| Flag | Description |
|---|---|
| `-s`, `--severity` | Minimum severity to report: `critical|high|medium|low|info`. |
| `-o`, `--output` | Markdown report path. Default: `self-report.md` next to the target. |
| `--json` | Also write `self-report.json`. |
| `-l`, `--lang` | Force a language (`solidity|vyper|huff|rust|move|typescript`). |
| `--no-info` | Drop `INFO`-severity findings. |
| `--quiet` | Suppress banner and progress; print only the summary. |
| `--no-docs` | Skip documentation/NatSpec context collection. |
| `--show-suppressed` | Include suppressed findings in the report. |
| `--trust-doc-suppressions` | **Unsafe.** Allow README / NatSpec claims to mark findings suppressed. Off by default. |
| `--xray` | Write a pre-audit X-ray report. |
| `--xray-output` | X-ray path. Default: `self-xray.md` next to the target. |
| `--poc` | Emit Foundry PoC harnesses for every exploit-class finding. |
| `--poc-dir` | Output directory for PoCs (must be a relative path under the scan target). Default: `poc/`. |
| `--fuzz` | Run Hypothesis-based fuzzing after the scan. |
| `--fuzz-mode` | `stateless`, `stateful`, or `both` (default). |
| `--fuzz-iters` | Max Hypothesis examples per (target, invariant). Default: `32`. |
| `--fuzz-seqs` | Number of action sequences for stateful fuzzing. Default: `32`. |
| `--fuzz-seq-len` | Maximum sequence length. Default: `6`. |
| `--fuzz-seed` | Pin the RNG for reproducibility. |

Suppressions from the local feedback store are **off by default**. To apply
them, pass the runtime flag in your scan (see
[Feedback store](#feedback-store)) or run `self --apply-suppressions` if
your build of SELF exposes it; the catalog/rule-version of every
suppression is recorded so a rule-version bump or a source-code edit
automatically re-surfaces the finding.

---

## Output formats

### Terminal summary

```
SELF v2.5.0  scan of  /home/auditor/repo
CRITICAL findings   : 1
HIGH      findings   : 4
MEDIUM    findings   : 9
LOW       findings   : 13
INFO      findings   : 6
suppressed by docs   : 2
fuzz findings        : 1
exit code            : 2 (>= 1 critical)
```

### Markdown report

The Markdown report contains:

- An executive summary table.
- A findings table with `id`, severity, confidence, location, snippet,
  review status (`STATIC_MATCH | CONTEXT_REQUIRED | MANUAL_PROOF |
  INFORMATIONAL`), proof obligation, and regression-test recipe.
- A suppressed findings appendix (when `--show-suppressed` is on).
- An optional documentation-signals section.
- Optional X-ray and fuzz subsections.

### JSON report

```json
{
  "version": "2.5.0",
  "target": "/home/auditor/repo",
  "framework": "foundry",
  "project_fingerprint": "pf_…",
  "issues": [
    {
      "id": "SOL-CRIT-001",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "title": "Reentrancy in withdraw()",
      "file": "src/Vault.sol",
      "line": 42,
      "snippet": "(bool ok,) = msg.sender.call{value: bal}(\"\");",
      "description": "…",
      "exploit_scenario": "…",
      "remediation": "…",
      "evidence_paths": [{"file": "src/Vault.sol", "start_line": 42, "end_line": 48, "text_hash": "sh_…", "relation": "writes"}],
      "suppression_state": "none",
      "review_status": "CONTEXT_REQUIRED",
      "proof_obligation": "…",
      "regression_recipe": "forge test --match-test reentrancy"
    }
  ]
}
```

---

## Detection model

SELF combines five detection layers:

1. **Regex pattern matching** for syntactic invariants (re-entrancy guards,
   low-level call shape, signature replay surface, etc.).
2. **Lightweight, comment-stripping parsers** for each supported language
   that produce contracts, functions, modifiers, state variables, events,
   modifiers, NatSpec, and assembly blocks. See `self_tool/parsers/`.
3. **The project semantic graph** that merges per-file facts across files
   and resolves imports, inheritance, modifier guards, internal calls,
   low-level calls, and writes.
4. **Project-level detectors** that emit findings when graph edges span
   multiple contracts (`PROJECT-*`).
5. **The exploit corpus** (`self_tool/knowledge/exploits/exploits.json`),
   a JSON catalog of real-world exploits that compiles to detectors on
   startup. Adding a new entry to `exploits.json` teaches the auditor.

Every detector ID is paired with a hardcoded review profile in
`self_tool/core/builtin_reviewer.py`. Startup fails if a detector is
unpaired or a profile is orphaned. The `self --list-detectors` table is
the authoritative source of truth.

### Languages covered

| Language | Per-file | Project-level | Notes |
|---|---|---|---|
| Solidity | yes | yes | reentrancy, access, low-level calls, signatures, proxy init, oracle, arithmetic, tokens, DoS, AMM/lending/bridge/staking |
| Vyper | yes | — | raw_call, send, storage layout, default visibility, reentrancy |
| Huff | yes | — | macros, opcodes |
| Rust / Anchor | yes | — | missing signer, owner, arbitrary CPI, PDA canonical bump, unchecked arithmetic, stale account read, duplicate mutable accounts, broken `has_one`, account lifecycle, token-vs-Token-2022 confusion, spoofable sysvars |
| Move | yes | — | capability, signer, resource invariants |
| TypeScript | scanner matches | — | reserved for Hardhat scripts (no detectors yet) |

Cairo (Starknet), Sway (Fuel), and Tact (TON) are ingested and reasoned
about in `self autonomous`. They do not yet have per-file detector
packs. Stylus is covered through the Rust parser. Contributions welcome.

---

## Autonomous AI auditor

```bash
self autonomous .
self agent src/Vault.sol --json
self autonomous . --llm --llm-provider ollama
self train
self train reports/extra-exploits.json
self train --status
```

`self autonomous` (alias `self agent`) is a project-wide reasoning pass
on top of the deterministic engine. It is **not** imported by `self .`,
so a normal scan stays offline and free of optional AI code.

What it does:

1. **Reads the entire project** — source in Solidity, Vyper, Huff,
   Rust/Anchor, Move, plus Cairo / Sway / Tact in this mode; README,
   docs, Foundry/Hardhat/Anchor/Move/Cargo/npm manifests and lockfiles.
2. **Understands the protocol** — type (AMM, lending, vault, bridge,
   governance, …), contract roles, token flows, privileged vs
   permissionless surfaces, extracted guards, and matched math models
   (`x*y=k`, ERC-4626 shares, health factor, funding, …).
3. **Trains on real data** — `self train` builds a local retrieval
   index from the bundled exploit corpus, attack-vector playbooks,
   language semantics, business-logic invariants, on-chain behaviours,
   recent public incident post-mortems (`incidents.json`: Euler,
   KyberSwap, Prisma, Penpie, Cetus, Immunefi 2025 shift, …), expert
   review tactics (`expert_tactics.json`: Trail of Bits, Pashov,
   Spearbit, OpenZeppelin, Sherlock/C4, Immunefi, Solodit), and
   optional extra JSON. Confirmed / false-positive feedback reweights
   playbooks. First `self autonomous` run trains automatically if no
   index exists. Prefer new incidents/tactics over new `exploits.json`
   detectors so catalog ↔ review-profile parity stays intact.
4. **Reasons about exploitability** — trained playbooks fire only when
   language, protocol type, source patterns, and computed facts all
   agree. Static detector hits corroborate and raise confidence.
5. **Walks multi-hop paths** — reentrancy drains, flash-loan oracle
   manipulation, first-depositor inflation, initialize takeovers,
   bridge replays, sandwiches, flash-loaned governance, Euler-style
   donate-then-self-liquidate, Penpie-style fake-market harvest, Prisma
   zap callbacks, and Kyber-style tick double-counts.
6. **Checks dependency versions** against a local advisory brain
   (Vyper compiler ranges, OpenZeppelin GHSA windows, Anchor, solmate,
   SPL token, …). Metadata only; nothing is executed.
7. **Acknowledges project documentation** — README links, `audits/*.pdf`,
   Spearbit/OpenZeppelin markdown, `scope.txt`. Those facts stay in the
   briefing even when offline. `self autonomous --online` then fetches
   the inventoried `https://` links (SSRF-safe, size-capped) and queries
   [OSV.dev](https://osv.dev) for pinned npm / PyPI / crates.io versions.

The default reasoner is symbolic and fully offline. `--online` and
`--llm` are separate opt-in flags. `--llm` requires `OPENAI_API_KEY`,
`ANTHROPIC_API_KEY`, or `OLLAMA_HOST`. LLM findings are labelled
`AUTO-LLM-*`, confidence Low, and must cite a file that actually exists
in the project.

Report: `self-autonomous.md` (and `.json` with `--json`). Finding IDs
use the `AUTO-*` prefix and do not go through the detector catalog —
they carry their own proof obligation.

---

## Project semantic graph

```bash
self graph .
self graph . --json --output graph.json
```

The graph is built deterministically from the parser facts of every
supported file in the scan target. It contains:

- **Nodes**: files, contracts, interfaces, libraries, abstract contracts,
  functions, modifiers, state variables.
- **Edges**: `imports`, `inherits`, `implements`, `calls_internal`,
  `calls_external`, `delegatecall`, `reads`, `writes`, `guards`,
  `uses_library`, `declared_in`.
- **Unresolved edges**: edges the builder could not close (cross-file
  import under remappings, library call attachment, dynamic dispatch
  through an interface variable). These flow to `PROJECT-UNRESOLVED-001`
  rather than being guessed.

The project fingerprint is the canonical SHA-256 of `(framework, sorted
node ids, sorted edge kinds)`. Two identical projects produce identical
fingerprints; renaming a file or splitting a contract produces a new
fingerprint and re-surfaces suppressed findings.

---

## Feedback store

Local, append-only, reversible. Stores at
`~/.self-auditor/feedback.sqlite3`.

```bash
# Add a suppression. --finding is the semantic_fingerprint printed by the
# JSON report or `self graph . --json` output.
self feedback add . --finding sf_xxx \
    --type false_positive \
    --reason "uses SafeERC20.transfer (reentrancy not reachable)"

# List current entries for a target.
self feedback list .

# Export / import for sharing across a research team.
self feedback export ./team-feedback.json
self feedback import ./team-feedback.json --replace
```

Dispositions:

- `confirmed` — annotate, never suppress.
- `false_positive` — suppress only when `--apply-suppressions` is on.
- `accepted_risk` — suppress with explicit reason, visible under
  `--show-suppressed`.
- `fixed` — annotate.

Suppression requires exact match of
`(project_fingerprint, detector_id, semantic_fingerprint, source_hash,
rule_version)`. Changed source code or a new rule version automatically
re-surfaces the finding. Every change is logged to
`~/.self-auditor/audit.log.jsonl`.

---

## Calibration

```bash
self calibrate                        # Markdown confusion matrix
self calibrate --json                 # machine-readable
self calibrate --root tests/fixtures/calibration
```

SELF ships a deterministic calibration corpus under
`tests/fixtures/calibration/{positive,negative}/`. Each fixture is a tiny
contract that triggers (or does not trigger) exactly one detector. The
runner reports per-detector precision, recall, false-positive rate,
confidence calibration, fixture coverage, and unresolved-edge rate.

Candidate rules live under `self_tool/knowledge/rules/candidates/` and
are excluded from production until they pass calibration thresholds. No
candidate is silently removed from production based on feedback alone.

---

## Advisory updater

```bash
self update --manifest-url https://scs.owasp.org/feed.json --dry-run
self update --manifest-url https://scs.owasp.org/feed.json
self intelligence status
self intelligence rollback snap-2026-07-28-001
```

`self update` is the only command that opens a network connection during
normal operation. It:

1. Connects to an HTTPS host in the hardcoded allowlist (OWASP Smart
   Contract Security, OpenZeppelin, Vyper, GHSA, NVD).
2. Caps responses at 2 MB and uses 15 s connect / 30 s read timeouts.
3. Refuses redirects to non-allowlisted hosts.
4. Verifies SHA-256 hashes against the manifest before activating any
   snapshot.
5. Stores snapshots at `~/.self-auditor/intelligence/<snapshot_id>/`
   with atomic activation via a `latest` symlink.

Downloaded content is **defensive metadata only**. It is never executed,
never instantiated as Python, and never silently mutates a detector. It
feeds the calibration corpus and a human-reviewed candidate queue.

See [SECURITY.md](SECURITY.md) for the full threat model.

---

## X-ray pre-audit

```bash
self . --xray
self . --xray --xray-output reports/xray.md
```

The X-ray report is a deterministic, parser-backed attack-surface map. It
includes:

- State-changing `public` / `external` entry points.
- `receive()` and `fallback()` entry points.
- Permissionless / role-gated / owner-restricted classification.
- Value direction, external calls, state writes, reentrancy guards.
- Extracted `require` / `assert` predicates as invariant candidates.
- Fuzz and invariant test posture.
- High-churn files and security-relevant git commit subjects.
- Independent review lenses for access, economics, execution, math, and
  trust gaps.

These are static leads. A guard candidate is not proof that a protocol
invariant holds across calls or contracts.

---

## Fuzzing

```bash
self . --fuzz
self . --fuzz --fuzz-seed 0xC0FFEE
self . --fuzz --fuzz-mode stateful --fuzz-seqs 256 --fuzz-seq-len 10
```

Two fuzzers run after the static pass:

- **Stateless**: Hypothesis-based property testing on parsed contract
  structure (numerical bounds, enum coverage, signature replay).
- **Stateful**: Modeled state-machine sequence fuzzer that drives the
  x-ray entry points with synthesized action sequences.

Fuzz findings are emitted as `fuzz-` prefixed `Issue` objects with the
same review path as static findings. Pin the seed for reproducibility.

---

## PoC generation

```bash
self . --poc
self . --poc --poc-dir poc/
```

For every exploit-class finding (`SOL-CRIT/HIGH-EXPLOIT-*`,
`VYP-CRIT/HIGH-EXPLOIT-*`), SELF writes a runnable Foundry test harness
under `<target>/poc/`. The harness asserts the documented invariant
violation against a stub target; replace the stub with the audited
contract's bytecode-equivalent in a real audit.

`--poc-dir` must be a relative path under the scan target. SELF refuses
absolute paths or `..` components.

---

## Custom rules

Drop a module under `self_tool/detectors/<language>/`. The catalog
discovers any literal `Issue(...)` or `.as_issues(...)` rule metadata
and binds it to a review profile in
`self_tool/core/builtin_reviewer.py`. Strict parity is enforced.

```python
from self_tool.query import Q
from self_tool.core.issue import Severity, Confidence


def detect(file_ctx):
    return (
        Q(file_ctx)
        .functions()
        .visibility("external", "public")
        .has_pattern(r"\.call\s*\{")
        .not_has_pattern(r"nonReentrant")
        .as_issues(
            id="CUSTOM-001",
            title="External call in {fname}()",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="Review the external-call ordering in {fname}().",
            exploit_scenario="A callback may observe or modify inconsistent state.",
            remediation="Apply checks-effects-interactions and a suitable guard.",
        )
    )
```

Then register a review profile:

```python
REVIEW_PROFILES["CUSTOM-001"] = ReviewProfile(
    lens="external-call-ordering",
    proof_obligation="Show that every external call in {fname}() is preceded by a state-finalizing write and followed by no further reads of the affected storage.",
    regression_recipe="forge test --match-contract Vault -vvvv",
)
```

Startup fails if the catalog and profile table drift apart.

---

## Configuration and storage

| Path | Purpose |
|---|---|
| `~/.self-auditor/feedback.sqlite3` | Local feedback store. |
| `~/.self-auditor/audit.log.jsonl` | Append-only event log (install, rollback, feedback, suppression). |
| `~/.self-auditor/intelligence/<snapshot_id>/` | Installed advisory snapshots. |
| `~/.self-auditor/intelligence/latest` | Active snapshot pointer (symlink or text). |
| `~/.self-auditor/brain/index.json` | Trained autonomous knowledge index. |

Override the data directory with `SELF_DATA_DIR`.

---

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | No active Critical or High findings. |
| `1` | At least one active High finding. |
| `2` | At least one active Critical finding. |
| `3` | Detector import or runtime failure; the audit is incomplete. |
| `4` | No supported source files found. |

---

## CI integration

GitHub Actions:

```yaml
name: self
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install -e .
      - run: self src --severity high --json --quiet
```

A `Severity: high` step fails the build on High or Critical findings.

---

## Limits and honest boundaries

- Most rules are heuristic and can produce false positives. SELF reports
  per-detector precision from the calibration corpus and lets humans
  apply `false_positive` and `accepted_risk` suppressions explicitly.
  **No system can guarantee zero false positives.**
- Regex and lightweight parsing do not replace a compiler-backed AST.
  Solana/Anchor semantic checks run against a parser-backed schema of
  `#[derive(Accounts)]` structs and instruction handlers; they improve
  precision over file-wide regex but do not perform whole-program type
  resolution.
- Cross-contract reasoning is parser-backed and conservative. The
  project semantic graph resolves imports, inheritance, library calls,
  and writes through a deterministic symbol index and surfaces
  unresolved edges as `PROJECT-UNRESOLVED-001` findings. Symbolic
  execution and cross-crate Rust compilation are not implemented.
- Business logic and economic safety require protocol-specific
  invariants.
- The X-ray state-write mapper resolves direct writes, not arbitrary
  inherited or interprocedural effects.
- New attack classes require maintained rules, tests, and source review.

SELF is offline by default. Network access is explicit and opt-in:
`self update` / `self intelligence rollback` (allowlisted advisory
snapshots), `self autonomous --online` (project-doc links + OSV), and
`self autonomous --llm` (user-configured model endpoint).

The fuzzing pass is structural: Hypothesis-based property testing on
parsed contract structure and a modeled state-machine sequence fuzzer.
It is **not** equivalent to Foundry `forge fuzz`, Echidna, or Mollusk
and it does not execute arbitrary EVM bytecode or Solana BPF programs.
A clean SELF scan is a useful triage signal; it is **not** a
substitute for manual protocol-invariant review and a top-tier manual
audit.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New detectors must:

1. Live under `self_tool/detectors/<language>/` and expose a `detect`
   function.
2. Emit `Issue` records with literal `id=` (so the catalog scanner can
   discover them).
3. Add a matching `REVIEW_PROFILES[id]` entry with a real proof
   obligation and a regression-test recipe.
4. Ship positive and negative fixtures under
   `tests/fixtures/calibration/{positive,negative}/`.
5. Pass `self calibrate` without flagging the negative fixtures.

Bug reports and detector ideas: open an issue.

---

## License

MIT. See [LICENSE](LICENSE).
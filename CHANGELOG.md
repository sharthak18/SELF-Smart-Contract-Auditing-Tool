# Changelog

All notable changes to SELF are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Invariant-first protocol-math lens (`self_tool/autonomous/invariants.py`).
  Five new understanding facts name accounting properties the code fails to
  enforce: `missing_accrue_on_value_path`, `missing_share_invariant`,
  `missing_k_invariant`, `missing_health_check`, and
  `tstore_delete_poison`. A conversion formula such as
  `assets * totalSupply() / totalAssets()` is deliberately *not* treated as an
  invariant — it prices a share without constraining one — and a bare `tstore`
  is not poison unless the same function also `delete`s or `.pop()`s the entry
  it describes.
- `propose_hypotheses()` emits targeted Foundry invariant handler sketches
  (`INV-SHARE-BACKING`, `INV-EMPTY-VAULT`, `INV-K`, `INV-ACCRUE-FIRST`,
  `INV-HEALTH`, `INV-VIEW-LOCK`, `INV-TSTORE-CLEAR`, `INV-SIG-BIND`) gated on
  the detected protocol shape. They are surfaced as
  `ProtocolUnderstanding.hypotheses`, in the JSON `to_dict()`, in the
  retrieval `briefing()`, and in a new report section,
  "Must-hold invariants (hypotheses, not proofs)".
- Second-order reentrancy fact in the deep pass: a public function that writes
  value state *after* delegating to a helper performing a low-level `.call`.
  Skipped when either function carries a reentrancy guard, or when the public
  function makes the call itself (that case is first-order and already
  covered). Reported as `AV-SECOND-ORDER-REENTRANCY` with exploit path
  `PATH-SECOND-ORDER-REENTRANCY`.
- Brain playbooks `AV-SECOND-ORDER-REENTRANCY`, `AV-MISSING-ACCRUE`,
  `AV-MISSING-SHARE-INVARIANT`, `AV-MISSING-K`, `AV-TSTORE-DELETE-POISON`, and
  expert tactic `TAC-INVARIANT-FIRST`.

No new catalog detector IDs; `RULE_VERSION` stays `2.3.0` and catalog ↔
review-profile parity is unchanged at 161 rules. Nothing wraps an external
scanner — the invariant lens is SELF's own reasoning. Test suite is 175
(24 new in `tests/test_invariants.py`).

## [2.4.0] — 2026-08-25

### Added

- Autonomous AI auditor (`self autonomous` / `self agent`): full-project
  ingestion, protocol understanding, trained playbook reasoning, multi-hop
  exploit paths, and dependency-advisory matching.
- `self train` builds a local retrieval index from the bundled exploit
  corpus, attack-vector / math / business-logic / on-chain brain, recent
  public incidents, expert review tactics, optional extra JSON, and
  feedback-store weights. Index schema is `2` so older indexes rebuild.
- Bundled knowledge brain under `self_tool/knowledge/brain/` covering
  attack vectors, language semantics (including Cairo, Sway, Tact),
  DeFi math models, protocol business-logic invariants, on-chain
  behaviours, known dependency version ranges, 2023–2026 incident
  post-mortems (`incidents.json`), and expert tactics from Trail of
  Bits, Pashov, Spearbit, OpenZeppelin, Sherlock/Code4rena, Immunefi,
  and Solodit (`expert_tactics.json`). New lessons train retrieval
  without minting catalog detectors.
- Recent protocol-logic playbooks: donation-skips-health (Euler),
  permissionless market + harvest delta (Penpie), unauthenticated
  zap callback (Prisma), CLAMM tick double-count (KyberSwap Elastic),
  LST exchange-rate oracles, Uniswap v4 hooks, Permit2, ERC-7540
  async vaults, and ERC-4337 validation.
- Optional `--llm` refinement (OpenAI, Anthropic, Ollama) that is never
  imported by the default `self TARGET` scan.
- Local inventory of README links, `audits/*.pdf`, and prior-audit
  markdown so the reasoner acknowledges them offline. Opt-in
  `self autonomous --online` fetches those https links (SSRF-safe) and
  queries OSV.dev for pinned npm / PyPI / crates.io versions.
- Autonomous findings use `AUTO-*` IDs with their own proof obligations
  and do not disturb catalog ↔ review-profile parity.

### Changed

- Package version bumped to 2.4.0. `RULE_VERSION` stays `2.3.0` so
  existing fingerprint-scoped suppressions remain valid.

## [2.3.0] — 2026-07-28

### Added

- Project semantic graph (Phase 1) with deterministic Solidity extractor,
  imports / inheritance / modifier / call / write resolver, unresolved-edge
  surfaces, and a stable `project_fingerprint`.
- Project-level detectors (Phase 2): `PROJECT-ACCESS-001`,
  `PROJECT-PROXY-001`, `PROJECT-REENTRANCY-001`, `PROJECT-AUTH-001`,
  `PROJECT-ORACLE-001`, `PROJECT-UNRESOLVED-001`. Each ships with a
  hardcoded review profile enforcing strict catalog ↔ profile parity.
- Local persistent feedback store (Phase 3) under
  `~/.self-auditor/feedback.sqlite3` with fingerprint-scoped suppression.
  Dispositions: `confirmed`, `false_positive`, `accepted_risk`, `fixed`.
- Deterministic calibration corpus (Phase 4) with per-detector
  precision / recall / false-positive rate reporting.
- Isolated advisory updater (Phase 5) behind `self update`:
  HTTPS-only, host-allowlisted (OWASP Smart Contract Security,
  OpenZeppelin, Vyper, GHSA, NVD), 2 MB response cap, 15 s connect /
  30 s read timeout, SHA-256 hash verification, atomic
  snapshot activation, explicit rollback.
- CLI subcommands: `self graph`, `self feedback {add,list,remove,export,import}`,
  `self intelligence {status,rollback}`, `self update`, `self calibrate`.
- Append-only audit log at `~/.self-auditor/audit.log.jsonl`.
- Foundry PoC harness generator (`--poc`) confined to the scan target.
- Markdown pipe-escaping in the suppressed-findings table.

### Changed

- `DetectorEngine._framework_for` now uses `scanner.detect_framework`
  instead of synthesizing a `FrameworkInfo` from `files[0]`. Project
  fingerprints now match CLI fingerprints.
- Feedback-suppression failures now record a `DetectorDiagnostic`
  instead of silently returning.
- `write` edges skip line-comment content (`//`) before pattern
  extraction, so commented-out assignments no longer become graph
  edges.
- Severity counts in the fuzz summary use `Counter` keyed by
  `Severity.ORDER` for deterministic ordering.
- Package metadata: explicit `pyproject.toml` URLs (homepage, repo,
  issues, changelog, security), full Python version classifiers,
  `knowledge/exploits/*.json` included in `package-data`.
- Version bumped to 2.3.0 (matches `RULE_VERSION`).

### Fixed

- `PROJECT-ORACLE-001` no longer reads the never-set `_body_hint`
  attribute; it now uses `Graph.body_for(node_id)` populated by the
  builder.
- `PROJECT-AUTH-001` no longer short-circuits on `nonReentrant`-only
  functions with no other modifier set.
- `state_var` symbols are now indexed by the resolver, so `writes`
  edges resolve correctly.
- Subcommand dispatch goes through a single `main()` entry point with
  native Click help (the previous `CliRunner` shim swallowed
  `--help`).
- Pre-existing `from self_tool import audit_log` in the intelligence
  CLI now correctly imports `from self_tool.core import audit_log`.

### Security

- Documented offline-by-default model, host allowlist, content-hash
  verification, and audit-log surface in `SECURITY.md`.
- Verified offline guard: a subprocess-level test asserts that no
  `self_tool.intelligence.*` module is imported during a scan.

## [2.2.0] — 2026-06

### Added

- 95 explicit built-in review profiles: one for every detector ID.
- Every finding includes a hardcoded proof obligation and regression-test
  recipe.
- Startup fails when a detector lacks a review profile or a profile
  has no detector.
- Detector import and runtime failures always exit with code `3`;
  strict mode is the default.
- Unreadable source or documentation files fail the audit instead of
  being skipped.
- `--knowledge-status` proves review-profile coverage alongside OWASP
  coverage.
- Removed the optional model/Ollama path and all model fallback
  behavior.

## [2.1.x] — 2026

- Parser, detector-health, documentation safety, x-ray, OWASP
  knowledge-base upgrades.

[2.4.0]: https://github.com/sharthak18/SELF-Smart-Contract-Auditing-Tool/releases/tag/v2.4.0
[2.3.0]: https://github.com/sharthak18/SELF-Smart-Contract-Auditing-Tool/releases/tag/v2.3.0
[2.2.0]: https://github.com/sharthak18/SELF-Smart-Contract-Auditing-Tool/releases/tag/v2.2.0

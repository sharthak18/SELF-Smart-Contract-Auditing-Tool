# Changelog

All notable changes to SELF are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/).

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

[2.3.0]: https://github.com/sharthak18/SELF-Smart-Contract-Auditing-Tool/releases/tag/v2.3.0
[2.2.0]: https://github.com/sharthak18/SELF-Smart-Contract-Auditing-Tool/releases/tag/v2.2.0

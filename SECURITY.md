# Security Policy

## Reporting a Vulnerability

Please do not open a public issue for an unpatched vulnerability in SELF.

Send a private report through GitHub's security-advisory interface for this
repository. Include:

- Affected version and component
- Reproduction steps using a harmless local fixture
- Security impact
- Suggested remediation, if known

Do not include real credentials, stolen data, mainnet exploitation steps, or
targets you are not authorized to test.

## Scope

Security reports may cover SELF's parser, detector engine, report generation,
dependency handling, built-in review profiles, and CI behavior. False negatives in
individual heuristic rules are welcome as normal bug reports unless they create
a broader integrity problem such as silently disabling a detector family.

## Threat Model and Honest Boundaries

SELF is a **local, offline-by-default, heuristic** auditor. Scans do
not fetch data from networks, do not call RPC nodes, do not compile
contracts, and do not invoke cloud LLMs. The fuzzing pass runs
property-based tests on parsed Solidity structure and a modeled
state-machine sequence fuzzer; it does **not** execute arbitrary EVM
bytecode or Solana BPF programs.

### Network access (opt-in, metadata only)

Only `self update` and `self intelligence rollback` open a network
connection, and only when the user explicitly invokes them. Both:

- Require HTTPS with a hardcoded host allowlist
  (OWASP Smart Contract Security, OpenZeppelin advisories, Vyper
  advisories, GHSA, NVD)
- Cap responses at 2 MB and use 15 s connect / 30 s read timeouts
- Refuse redirects to non-allowlisted hosts
- Verify SHA-256 hashes against a pinned manifest before activating
  any downloaded snapshot
- Store snapshots under `~/.self-auditor/intelligence/<snapshot_id>/`
  with atomic activation via a `latest` symlink and explicit rollback

Downloaded content is defensive metadata only. It is never executed
as Python, never instantiated, never compiled, and never silently
mutates detector rules. It feeds the local calibration corpus and a
human-reviewed candidate queue.

### Project reasoning

Cross-contract reasoning is parser-backed and conservative. The
project semantic graph resolves imports, inheritance, library calls,
and writes through a deterministic symbol index; unresolvable edges
are surfaced as `PROJECT-UNRESOLVED-001` findings rather than
guessed. Confidence is downgraded, never inflated, when a graph edge
cannot be resolved.

### Feedback suppression

`self feedback add|list|remove|export|import` writes to a local SQLite
store at `~/.self-auditor/feedback.sqlite3`. Suppression requires an
exact match of `(project_fingerprint, detector_id,
semantic_fingerprint, source_hash, rule_version)`. Source-code or
rule-version changes automatically re-surface a finding. Entries are
append-only, reversible, and visible under `--show-suppressed`. The
`--apply-suppressions` flag defaults to off.

### Auditability

Every intelligence install, rollback, feedback change, and suppression
application appends an event to `~/.self-auditor/audit.log.jsonl`.

A clean SELF scan is not equivalent to a manual security audit. Manual
protocol-invariant discovery, formal verification, and economic attack
modelling remain required for production deployments. SELF is intended
as a fast, deterministic triage tool that augments — never replaces —
human review. No system can guarantee zero false positives.

## Disclosure

Please allow reasonable time for validation and a coordinated fix before public
disclosure. Confirmed reporters will be credited unless they prefer anonymity.

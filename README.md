# SELF - Smart Contract Security Auditor

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![Version](https://img.shields.io/badge/Version-2.2.0-red)](.)
[![Rules](https://img.shields.io/badge/Rules-95-orange)](.)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

SELF is a local, open-source first-pass security auditor for smart contracts. It
combines deterministic vulnerability rules, one hardcoded deep-review profile
per detector, documentation context, and a Solidity pre-audit "x-ray" report.

It runs without cloud APIs, API keys, model servers, network access, or a
Solidity compiler. It is not a replacement for manual review, fuzzing, formal
verification, or an independent professional audit.

## What's New in 2.2

- Removed the optional model/Ollama path and all model fallback behavior.
- Added 95 explicit built-in review profiles: one for every detector ID.
- Every finding now includes a hardcoded proof obligation and regression-test recipe.
- Startup fails when a detector lacks a review profile or a profile has no detector.
- Detector import and runtime failures always exit with code `3`; strict mode is the default.
- Unreadable source or documentation files fail the audit instead of being skipped.
- JSON and Markdown reports always include deterministic review results.
- `--knowledge-status` proves review-profile coverage alongside OWASP coverage.

Version 2.2 includes the 2.1 package, parser, detector-health, documentation
safety, x-ray, and OWASP knowledge-base upgrades.

The x-ray and review-lens design is informed by the current
[Pashov Audit Group skills](https://github.com/pashov/skills), including its
June 4, 2026 v3 attacker-framing and gap-hunter update. SELF implements a
deterministic local workflow rather than copying its multi-agent prompts.

## Install

```bash
git clone https://github.com/sharthak18/SELF-Smart-Contract-Auditing-Tool.git
cd SELF-Smart-Contract-Auditing-Tool
python3 -m pip install -e .
```

Verify the installation:

```bash
self --version
self --list-detectors
self --knowledge-status
```

## Scan

```bash
# Project or single file
self .
self src/Vault.sol

# Reporting and CI
self . --severity high
self . --output audit.md --json
self . --no-info
self . --quiet

# Include documentation context without trusting it as proof
self .

# Legacy opt-in: allow documentation claims to suppress findings
self . --trust-doc-suppressions --show-suppressed
```

Project scans skip common generated, dependency, test, and mock directories.
Passing a test fixture as the direct target still scans that file.

## X-Ray

Generate a deterministic pre-audit map alongside the normal findings report:

```bash
self . --xray
self . --xray --xray-output reports/protocol-xray.md
```

The x-ray report includes:

- State-changing `public` and `external` entry points
- `receive()` and `fallback()` entry points
- Permissionless, caller-restricted, role-gated, and admin classification
- Value direction, external calls, state writes, and reentrancy guards
- Extracted `require` and `assert` predicates as invariant candidates
- Fuzz and invariant test posture
- High-churn files and security-relevant git commit subjects
- Independent review lenses for access, economics, execution, math, and trust gaps

These are static leads. A guard candidate is not proof that a protocol invariant
holds across calls or contracts.

## Rule Coverage

SELF currently discovers 95 unique rule IDs directly from detector source:

| Language | Rules |
|---|---:|
| Solidity and EVM protocol packs | 75 |
| Rust / Solana / Anchor | 6 |
| Move | 5 |
| Vyper | 5 |
| Huff | 4 |

Solidity coverage includes reentrancy, access control, low-level calls,
signatures, proxy initialization and storage, oracle use, arithmetic, token
handling, DoS, and protocol-specific AMM, lending, bridge, and staking patterns.

Run `self --list-detectors` for the implementation-derived catalog.

At startup, SELF compares that catalog with the hardcoded review-profile table.
Missing and extra IDs are fatal configuration errors, so detector and review
coverage cannot quietly drift apart.

## Knowledge Base

`self_tool/knowledge/security_knowledge.json` stores defensive metadata:

- OWASP Smart Contract Top 10: 2026 categories and detector mappings
- Active official standards and advisory sources
- Community incident-fixture sources with constrained ingestion rules
- Legacy source status, including the SWC Registry
- A policy excluding secrets, stolen data, weaponized payloads, and bulk copies
  of third-party reports

Inspect it with:

```bash
self --knowledge-status
```

The database is designed for provenance and reviewability. It does not claim to
contain every historical or future exploit, and it does not automatically
download proof-of-concept attack code.

## Documentation Context

SELF reads project documentation, NatSpec, imports, and framework configuration
before scanning. Signals such as SafeERC20, Chainlink, TWAP, timelocks,
multisigs, upgradeability, and emergency pause mechanisms are attached to
findings as **unverified context**.

By default, a README sentence cannot make a code finding disappear. The
`--trust-doc-suppressions` option exists for compatibility but should not be
used as a CI quality gate without human review.

## Built-In Deep Review

Deep review runs on every finding with no flag and no external service. Each
detector ID has an explicit, source-controlled profile containing:

- The security lens to apply
- The proof obligation a reviewer must establish
- A focused adversarial or regression-test recipe
- A deterministic status: `STATIC_MATCH`, `CONTEXT_REQUIRED`, `MANUAL_PROOF`,
  or `INFORMATIONAL`

`STATIC_MATCH` means the detector found its coded pattern with high confidence.
It does not claim that exploitability has been proven. Findings remain visible
until a human verifies the code and the suggested test.

## Custom Rules

Rules can use the local query DSL:

```python
from self_tool.query import Q


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
            severity="HIGH",
            confidence="MEDIUM",
            description="Review the external call ordering in {fname}().",
            exploit_scenario="A callback may observe or modify inconsistent state.",
            remediation="Apply checks-effects-interactions and a suitable guard.",
        )
    )
```

Place the module under the appropriate `self_tool/detectors/<language>/`
directory. SELF discovers modules automatically, and the AST catalog discovers
literal `Issue(...)` and `.as_issues(...)` rule metadata.

Also add the new detector ID to `REVIEW_PROFILES` in
`self_tool/core/builtin_reviewer.py`. SELF intentionally refuses to start when
detector IDs and hardcoded review profiles do not match exactly.

## Exit Codes

| Code | Meaning |
|---:|---|
| `0` | No active Critical or High findings |
| `1` | At least one active High finding |
| `2` | At least one active Critical finding |
| `3` | Detector import or runtime failure; the audit is incomplete |
| `4` | No supported source files found |

GitHub Actions example:

```yaml
- name: Install SELF
  run: python3 -m pip install -e .

- name: Audit contracts
  run: self src --severity high --json --quiet
```

## Development

The regression suite uses the Python standard library:

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
python3 -m compileall -q self_tool
python3 -m pip wheel . --no-deps --no-build-isolation -w /tmp/self-wheel
```

The deliberately vulnerable fixture at
`tests/contracts/VulnerableVault.sol` verifies detector execution and report
generation. Never deploy it.

## Limits

- Most rules are heuristic and can produce false positives.
- Regex and lightweight parsing do not replace a compiler-backed AST.
- Cross-contract call graphs and symbolic execution are not implemented.
- Business logic and economic safety require protocol-specific invariants.
- The x-ray state-write mapper resolves direct writes, not arbitrary inherited
  or interprocedural effects.
- New attack classes require maintained rules, tests, and source review.

## Primary References

- [OWASP Smart Contract Security](https://scs.owasp.org/)
- [OWASP Smart Contract Top 10: 2026](https://scs.owasp.org/Top10/)
- [Solidity Security Considerations](https://docs.soliditylang.org/en/latest/security-considerations.html)
- [Ethereum Improvement Proposals](https://eips.ethereum.org/)
- [OpenZeppelin security advisories](https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories)
- [Vyper security advisories](https://github.com/vyperlang/vyper/security/advisories)
- [Pashov Audit Group skills](https://github.com/pashov/skills)

Community incident material is used only as defensive metadata or isolated test
fixtures and must be independently verified before becoming a detector.

## License

MIT. See [LICENSE](LICENSE).

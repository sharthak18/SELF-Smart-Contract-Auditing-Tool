---
name: Feature request
about: Suggest a new detector, language, CLI flag, or report capability.
title: "[feature] "
labels: enhancement
assignees: []
---

## Motivation

What gap in SELF prompted this request? Reference the README or
`SECURITY.md` section that currently does not cover it.

## Proposal

The user-facing behavior you want. Be specific:

- New subcommand? Its flags and exit codes.
- New detector ID? Its scope, severity, confidence, and a one-line
  description of the proof obligation.
- New language? Its parser strategy (regex / handwritten / tree-sitter).

## Alternatives

What you have already tried. Mention detectors in other tools
(Slither, Mythril, Certora, Securify, …) and how SELF should differ.

## Acceptance criteria

How will we know this is done? For a detector, this usually means:

- `tests/test_<scope>.py` covers both a positive and a negative fixture.
- `tests/fixtures/calibration/{positive,negative}/` covers the new rule.
- `self calibrate` reports `precision=1.0, recall=1.0` for the rule.
- A matching `REVIEW_PROFILES[id]` entry exists.
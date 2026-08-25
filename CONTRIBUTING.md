# Contributing to SELF

Thanks for your interest in SELF. Contributions of detector rules,
parser improvements, review profiles, calibration fixtures, and bug
fixes are all welcome.

## Ground rules

1. **SELF is offline by default.** Every change is reviewed under the
   assumption that the auditor must run on a locked-down CI box with no
   network access. New code paths may not import any module under
   `self_tool/intelligence/*` during a normal scan. The
   `tests/test_offline_guard.py` test enforces this and must continue
   to pass.
2. **The catalog and review-profile table must stay in lockstep.**
   `validate_review_profiles` in `self_tool/core/builtin_reviewer.py`
   fails startup if a detector ID has no profile or a profile has no
   detector. Every new detector ships with a profile that contains a
   real proof obligation and a regression-test recipe (e.g. a `forge
   test --match-test` invocation).
3. **No silent mutators.** Suppressions must be fingerprint-scoped and
   reversible. Detector rules may not be auto-deleted based on
   feedback.
4. **Determinism.** Re-running `self .` twice produces identical
   `Issue.line`, `Issue.semantic_fingerprint`, and `project_fingerprint`
   values. Hashing the file ordering or the RNG state is a bug.
5. **One PR per concern.** Bundled fixes are hard to review and hard to
   bisect.

## Adding a detector

1. Place the module under `self_tool/detectors/<language>/`. Use
   `Issue(id=..., ...)` with a literal `id=` so the AST catalog scanner
   can discover it. Avoid ternary `Issue(id="X" if cond else "Y", ...)`
   if you can; if you must, also call `Issue(id=..., ...)` in a comment
   for each branch so the scanner picks both up.
2. Add the matching entry in
   `self_tool/core/builtin_reviewer.py::REVIEW_PROFILES`. The entry
   must include a non-empty `lens`, `proof_obligation`, and
   `regression_recipe`. Naked strings are not acceptable.
3. Add at least one positive and one negative fixture under
   `tests/fixtures/calibration/{positive,negative}/` for your detector.
4. Run `self calibrate --root tests/fixtures/calibration` and confirm
   the new detector appears with `precision=1.0` and `recall=1.0`
   against your fixtures.
5. Add a test under `tests/test_<lang>_detectors.py` covering the
   happy path and one regression case.

## Extending the autonomous brain

Playbooks live under `self_tool/knowledge/brain/`. A new attack vector
is a JSON object with `id`, `title`, `severity`, language/protocol
filters, source patterns, fact predicates, and a real-incident list.
Run `self train` after editing so the local index picks it up. Keep
payload-free: describe the class, not a weaponized exploit.

**Prefer brain JSON over `exploits.json` for new real-world lessons.**
Appending `exploits.json` mints a catalog detector and a review
profile. Recent post-mortems, contest findings, and auditor tactics
belong in `incidents.json` or `expert_tactics.json` so they train
retrieval and playbook weights without breaking catalog parity.

`self_tool/autonomous/` must not be imported from `DetectorEngine` or
the default scan path. `tests/test_autonomous.py` enforces this.

## Adding a project-level detector

1. Place the module under `self_tool/detectors/project/`. Implement
   `detect_project(ctx: ProjectContext)` instead of `detect(file_ctx)`.
2. The detector may consume `ctx.graph.edges_from`, `ctx.graph.by_kind`,
   `ctx.graph.body_for(node_id)`, and unresolved edges from
   `ctx.graph.unresolved`.
3. Follow the same catalog/profile/fixture workflow as a per-file
   detector. Project-level IDs follow the `PROJECT-*-001` convention.

## Updating the exploit corpus

1. Append an entry to `self_tool/knowledge/exploits/exploits.json`.
   Required fields: `id`, `name`, `target`, `chain`, `date`,
   `loss_usd`, `root_cause_class`, `severity`, `confidence`,
   `detector_id`, `title`, `description`, and at least one
   `code_signatures[].pattern`.
2. The schema validator (`validate_corpus`) runs at load time and
   refuses duplicates, missing required fields, or unknown
   signature types.
3. If `root_cause_class` is new, add a template to
   `self_tool/knowledge/poc_generator.py::_TEMPLATE` or accept the
   generic `logic-bypass` template.

## Commit messages

Use the form `<scope>: <one-line summary>`. Scope is one of `detectors`,
`parsers`, `graph`, `feedback`, `calibration`, `intelligence`, `cli`,
`docs`, `tests`, `ci`, or `core`.

## Running tests locally

```bash
python3 -m compileall -q self_tool
python3 -m unittest discover -s tests -p "test_*.py"
```

For full coverage of the fuzz tests, also install `hypothesis`:

```bash
python3 -m pip install -e ".[fuzz]"  # when an extras group exists
```

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md). Please do not open a public issue for
an unpatched vulnerability in SELF.

## Code of conduct

By participating, you agree to abide by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
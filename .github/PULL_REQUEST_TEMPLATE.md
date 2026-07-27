## Summary

One-paragraph description of what this PR does and why.

## Type of change

- [ ] Bug fix (non-breaking, fixes an issue)
- [ ] New detector (new rule ID with proof obligation and review profile)
- [ ] New language support (parser + detectors)
- [ ] New project-level detector (consumes the project semantic graph)
- [ ] Documentation / metadata only
- [ ] CI / release plumbing

## Linked issues

- Fixes #...
- Relates to #...

## Test plan

Describe the commands you ran locally and their outcome. For new
detectors this should include:

- [ ] `python3 -m unittest discover -s tests -p "test_*.py"` passes locally
- [ ] `self calibrate` reports the new detector against the fixtures
- [ ] A `REVIEW_PROFILES[id]` entry exists with proof obligation and
      regression-test recipe
- [ ] The strict catalog ↔ profile parity check passes

## Offline guarantee

This PR does not import any `self_tool.intelligence.*` module during a
normal scan. Confirm by running `tests/test_offline_guard.py`.

## Security implications

- [ ] None
- [ ] Touches the fetcher / manifest verifier (requires review by a
      maintainer)
- [ ] Touches the project fingerprint / suppression store (requires
      review by a maintainer)

## Checklist

- [ ] I have read [CONTRIBUTING.md](../CONTRIBUTING.md) and
      [SECURITY.md](../SECURITY.md).
- [ ] I have not committed any secrets, credentials, or live exploit
      payloads.
- [ ] I have added a `CHANGELOG.md` entry under the next release heading.
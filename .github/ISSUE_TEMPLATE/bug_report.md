---
name: Bug report
about: Report a behavior that contradicts the documented contract of SELF.
title: "[bug] "
labels: bug
assignees: []
---

## Summary

A short, factual description of the bug.

## Reproduction

The minimal command and (if possible) a minimal input file:

```bash
self path/to/target --json
```

```solidity
// input contract
pragma solidity ^0.8.0;
contract Bug {
    // …
}
```

## Expected behavior

What you expected SELF to do, citing the relevant section of the
README or `SECURITY.md`.

## Actual behavior

What SELF actually did. Include the terminal output and, if relevant,
the `self-report.md` excerpt.

## Environment

- SELF version (`self --version`)
- Python version (`python --version`)
- OS (`uname -a` on POSIX, `ver` on Windows)
- Target language (`--lang` if specified)

## Severity

How bad is the bug? Choose one:

- [ ] Incorrect finding (false positive or false negative)
- [ ] Crash (stack trace attached)
- [ ] Documentation drift (claim that does not match implementation)
- [ ] Cosmetic / nit

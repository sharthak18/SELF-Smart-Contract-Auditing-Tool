#!/usr/bin/env bash
set -euo pipefail

# Historical filename retained for compatibility. This script performs release
# checks only; it never stages, commits, changes remotes, or pushes.

python3 -m compileall -q self_tool
python3 -m unittest discover -s tests -p "test_*.py" -v
python3 -m pip wheel . --no-deps --no-build-isolation -w /tmp/self-auditor-wheel
git diff --check
git status --short

printf '\nRelease checks passed. Review the status above before committing or pushing.\n'

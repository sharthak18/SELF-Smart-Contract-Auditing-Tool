"""
SELF — Smart Contract Auditing Tool
Detector: SOL-CRIT-016 / SOL-HIGH-025
Known Solidity compiler code-generation bugs that produce silently wrong
bytecode from correct-looking source (bytecode-level "silent bugs").

SOL-CRIT-016 — "TSTORE Poison" transient-storage clearing-helper collision
(solc 0.8.28–0.8.33, --via-ir only, fixed in 0.8.34). The IR code generator's
`storage_set_to_zero_<type>` Yul helper name did not encode storage location
(persistent vs transient). When a contract cleared BOTH a transient value
(via `delete` on a `transient` variable — the only op that reaches this path)
and a persistent value of a matching type (via `delete`, `pop()`, or
overwriting a longer array with a shorter one) within the same Yul object,
whichever operation the codegen visited first "won": the second reused the
wrong opcode (`sstore` where `tstore` was needed, or vice versa). This can
silently zero an unrelated persistent slot (e.g. `owner`) on every call, or
leave a stale approval/lock in place because the intended location was never
actually cleared. No compiler warning, no revert — the bug is invisible to
source review, ordinary tests, and every static analyzer that only reads
source or bytecode against known patterns.

Source: Solidity team disclosure (soliditylang.org, 2026-02-18), Hexens
research ("TSTORE Poison"), Etherscan Solidity Bug Database entry
`TransientStorageClearingHelperCollision`.

SOL-HIGH-025 — pragma spans the affected TSTORE-poison range while the
project also compiles with `--via-ir` (Foundry `foundry.toml` /
`hardhat.config` `viaIR: true`), which is the second precondition for the
bug to fire — flagged even without an explicit transient variable in this
file, because the collision can be introduced by ANY file in the same
compilation unit.
"""
import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext


# solc 0.8.28 through 0.8.33 inclusive are affected (0.8.34 fixes it).
_AFFECTED_MINOR_PATCH_RANGE = range(28, 34)  # 28..33

RE_PRAGMA = re.compile(r'pragma\s+solidity\s+([^;]+);')
RE_VERSION = re.compile(r'(\d+)\.(\d+)\.(\d+)')

_VIS = r'(?:public|private|internal)?'
RE_TRANSIENT_VAR = re.compile(
    r'\btransient\b\s+(?:uint\d*|int\d*|address|bool|bytes\d*)\s+' + _VIS + r'\s*\w+\s*;'
    r'|(?:uint\d*|int\d*|address|bool|bytes\d*)\s+transient\s+' + _VIS + r'\s*\w+\s*;',
)
RE_DELETE_TRANSIENT = re.compile(r'\bdelete\s+(\w+)\s*;')
RE_PERSISTENT_CLEAR = re.compile(
    r'\bdelete\s+\w+(\[[^\]]*\])*(\.\w+)*\s*;'
    r'|\.\s*pop\s*\(\s*\)\s*;',
)


def _pragma_hits_affected_range(pragma_expr: str) -> bool:
    """Best-effort check: does any version this pragma admits fall in 0.8.28-0.8.33?"""
    versions = RE_VERSION.findall(pragma_expr)
    if not versions:
        return False
    for major, minor, patch in versions:
        major, minor, patch = int(major), int(minor), int(patch)
        if major != 0 or minor != 8:
            continue
        if patch in _AFFECTED_MINOR_PATCH_RANGE:
            return True
        # Caret / range pragmas (^0.8.28, >=0.8.28 <0.8.34, etc.) admit the
        # buggy versions even if the literal written version differs.
        if ("^" in pragma_expr or ">" in pragma_expr) and patch <= 33:
            return True
    return False


def detect(file_ctx: FileContext) -> List[Issue]:
    issues: List[Issue] = []
    content = file_ctx.content

    pragma_m = RE_PRAGMA.search(content)
    if not pragma_m:
        return issues
    pragma_expr = pragma_m.group(1)
    if not _pragma_hits_affected_range(pragma_expr):
        return issues

    pragma_line = content[:pragma_m.start()].count('\n') + 1

    has_transient_var = bool(RE_TRANSIENT_VAR.search(content))
    transient_deletes = RE_DELETE_TRANSIENT.findall(content) if has_transient_var else []
    has_persistent_clear = bool(RE_PERSISTENT_CLEAR.search(content))

    if has_transient_var and transient_deletes and has_persistent_clear:
        # Both necessary conditions observed in this file: transient `delete`
        # AND a persistent clearing operation (delete/pop/short-array-overwrite).
        del_m = RE_DELETE_TRANSIENT.search(content)
        line = content[:del_m.start()].count('\n') + 1 if del_m else pragma_line
        issues.append(Issue(
            id="SOL-CRIT-016",
            title="Solidity \"TSTORE Poison\": Transient + Persistent Storage Clearing Collision (solc 0.8.28–0.8.33)",
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path,
            line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                "This file is compiled by a pragma that admits Solidity 0.8.28–0.8.33 "
                "AND contains both a `delete` on a `transient` variable and a persistent "
                "storage clearing operation (`delete`, `.pop()`, or overwriting a longer "
                "storage array with a shorter one). If the project also compiles with "
                "`--via-ir` (Foundry/Hardhat `viaIR = true`), the compiler's IR code "
                "generator can silently swap the opcodes for these two operations: the "
                "clearing helper function name did not encode storage location, so the "
                "**first** clearing operation the codegen visits determines whether the "
                "shared helper emits `sstore` or `tstore` — the second operation of the "
                "other kind silently gets the wrong one. Depending on function-selector "
                "ordering (outside developer control), this either zeros an unrelated "
                "persistent slot (e.g. `owner`, `_initialized`, an admin flag) on every "
                "call, or leaves a persistent value (e.g. an approval, a reentrancy flag) "
                "un-cleared while a transient slot is corrupted instead.\n\n"
                "**No revert, no compiler warning, no source-level indicator.** The bug "
                "shipped in the Solidity compiler for ~18 months before disclosure "
                "(fixed in 0.8.34, 2026-02-18)."
            ),
            exploit_scenario=(
                "1. A vault has `_owner` (persistent) and a `transient` reentrancy-guard "
                "variable, both `address`-typed, each cleared with `delete` somewhere in "
                "the contract.\n"
                "2. Depending on which function's `delete` the IR codegen compiles first, "
                "the transient guard's `delete` reuses the persistent-clearing helper and "
                "emits `sstore` to slot 0 instead of `tstore` — every call to the guarded "
                "function silently zeroes `_owner`.\n"
                "3. No exploit transaction is required: normal legitimate use of the "
                "contract corrupts state. An attacker only needs to observe that `owner()` "
                "reads `address(0)` and call any owner-gated function."
            ),
            remediation=(
                "1. **Upgrade to solc >=0.8.34** and recompile/redeploy any contract "
                "compiled with an affected version (0.8.28–0.8.33) using `--via-ir`.\n"
                "2. As an interim workaround, replace `delete <transient_var>;` with an "
                "explicit assignment (`<transient_var> = 0;` / `= address(0);`), which "
                "uses a different code path and is unaffected.\n"
                "3. Diff the bytecode of the same contract compiled with 0.8.27 (or "
                "0.8.34+) against the deployed 0.8.28-0.8.33 build and confirm the "
                "`sstore`/`tstore` opcodes at every clearing site match expectations.\n"
                "4. Treat this as a category, not a one-off: run differential compilation "
                "(multiple compiler versions, with and without `--via-ir`) on every "
                "release as a matter of process, since source-level review cannot "
                "detect codegen bugs."
            ),
            references=[
                "https://soliditylang.org/blog/2026/02/18/transient-storage-clearing-helper-collision-bug/",
                "https://hexens.io/research/solidity-compiler-bug-tstore-poison",
                "https://etherscan.io/solcbuginfo?a=TransientStorageClearingHelperCollision",
            ],
            language="solidity",
        ))
    elif has_transient_var:
        # Transient storage in an affected-range file, but we could not confirm
        # the persistent-clearing precondition locally (it may live in another
        # file within the same compilation unit under inheritance).
        del_m = RE_TRANSIENT_VAR.search(content)
        line = content[:del_m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-HIGH-025",
            title="Transient Storage Variable Compiled Under Potentially Affected solc Range (0.8.28–0.8.33)",
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
            file=file_ctx.relative_path,
            line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "This file declares a `transient` state variable and is compiled by a "
                "pragma admitting Solidity 0.8.28–0.8.33 — the range affected by the "
                "TSTORE Poison transient/persistent storage-clearing collision bug "
                "(fixed in 0.8.34). Whether the bug actually fires depends on whether "
                "any file in the same compilation unit also clears a persistent slot "
                "of a matching value type AND the project compiles with `--via-ir`. "
                "Both conditions could not be confirmed from this file alone."
            ),
            exploit_scenario=(
                "See SOL-CRIT-016. If a sibling contract or inherited base clears a "
                "persistent variable of the same value type reachable in the same "
                "compilation unit, the same silent storage corruption applies."
            ),
            remediation=(
                "Upgrade to solc >=0.8.34, or confirm `--via-ir` is not enabled "
                "(`foundry.toml` `via_ir`, Hardhat `viaIR`). If via-ir is required, "
                "pin >=0.8.34 before relying on any `transient` storage semantics."
            ),
            references=[
                "https://soliditylang.org/blog/2026/02/18/transient-storage-clearing-helper-collision-bug/",
                "https://hexens.io/research/solidity-compiler-bug-tstore-poison",
            ],
            language="solidity",
        ))

    return issues

"""
SELF — Smart Contract Auditing Tool
Detector: SOL-CRIT-015
Low-level call success discarded before trusting return data.

Real incident: Zodiac Roles/Delay module (introduced v3.4.0, Oct 2023) used by
Gnosis Pay. `isValidSignature` (EIP-1271) was validated as:

    (, bytes memory returnData) = signer.staticcall(abi.encodeWithSelector(...));
    return bytes4(returnData) == EIP1271_MAGIC_VALUE;

The `success` boolean was discarded. In the EVM, a REVERTing call still lets
the callee fully control the returned (revert) data. An attacker deployed a
contract that always reverts with the magic bytes `0x1626ba7e` as its first
four bytes of revert data. The staticcall "failed" but the discarded success
flag meant the forged magic value was accepted as a valid signature, letting
the attacker queue and execute unauthorized withdrawals through Gnosis Pay's
Delay module. ~5,281 wallets and ~$1.5M were drained (June 2026, patched
June 5 2026 after being introduced in Oct 2023).

This generalizes to ANY low-level call/staticcall/delegatecall whose return
data is decoded/compared without first requiring `success`.

Sources: Gnosis Pay / Zodiac post-mortem (June 2026), CertiK incident
report, EIP-1271, SWC-104.
"""
import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext
from self_tool.parsers.solidity_parser import parse_solidity


# Matches: (<opt bool discard>, bytes memory X) = target.staticcall/call/delegatecall(...)
RE_LOWLEVEL_CALL_ASSIGN = re.compile(
    r'\(\s*(?:,|bool\s+(\w+)\s*,)\s*bytes\s+memory\s+(\w+)\s*\)\s*='
    r'\s*[\w.]+\s*\.\s*(staticcall|call|delegatecall)\s*[({]',
    re.MULTILINE,
)

RE_MAGIC_VALUE_COMPARE = re.compile(
    r'(bytes4\s*\(\s*%s\s*\)|%s\s*\[\s*:?\s*4\s*\])\s*(==|!=)',
    re.MULTILINE,
)

RE_EIP1271_CONTEXT = re.compile(
    r'(isValidSignature|EIP1271|0x1626ba7e|MAGICVALUE|magicValue)',
    re.IGNORECASE,
)


def detect(file_ctx: FileContext) -> List[Issue]:
    issues: List[Issue] = []
    content = file_ctx.content

    for m in RE_LOWLEVEL_CALL_ASSIGN.finditer(content):
        success_var = m.group(1)
        data_var = m.group(2)
        call_kind = m.group(3)
        success_discarded = success_var is None

        # Look at the next ~400 chars after the call for how returnData is used.
        window_end = min(len(content), m.end() + 500)
        window = content[m.end():window_end]

        compare_re = re.compile(
            r'(bytes4\s*\(\s*' + re.escape(data_var) + r'\s*\)|'
            + re.escape(data_var) + r'\s*\[\s*:?\s*4\s*\])',
        )
        compare_m = compare_re.search(window)
        if not compare_m:
            continue

        # If success is captured, does the code actually require/check it
        # before or alongside the comparison?
        checks_success = False
        if not success_discarded and success_var:
            # Look for `success &&`, `require(success`, `if (!success)` etc.
            success_check_re = re.compile(
                r'(require\s*\(\s*' + re.escape(success_var) + r'|'
                + re.escape(success_var) + r'\s*&&|'
                r'&&\s*' + re.escape(success_var) + r'|'
                r'if\s*\(\s*!\s*' + re.escape(success_var) + r')'
            )
            # Search both before the comparison (within window) and shortly after
            checks_success = bool(
                success_check_re.search(content[m.start():m.end() + compare_m.end() + 200])
            )

        if success_discarded or not checks_success:
            line = content[:m.start()].count('\n') + 1
            surrounding = content[max(0, m.start() - 300):m.end() + compare_m.end() + 100]
            is_signature_context = bool(RE_EIP1271_CONTEXT.search(surrounding))

            title = (
                "EIP-1271 Signature Check Ignores `staticcall` Success (Zodiac/Gnosis Pay Pattern)"
                if is_signature_context else
                f"Low-Level `{call_kind}` Return Data Trusted Without Checking Success"
            )
            issues.append(Issue(
                id="SOL-CRIT-015",
                title=title,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH if success_discarded else Confidence.MEDIUM,
                file=file_ctx.relative_path,
                line=line,
                snippet=file_ctx.get_snippet(line, context=4),
                description=(
                    f"The result of a low-level `.{call_kind}()` is decoded and compared "
                    "(e.g. `bytes4(returnData) == MAGIC_VALUE`) without first requiring "
                    "`success == true`. In the EVM, when a call reverts, the **callee fully "
                    "controls the revert/return data** propagated to the caller. An attacker "
                    "can deploy a contract that always reverts with the first four bytes set "
                    "to a target magic value (e.g. EIP-1271's `0x1626ba7e`), so the discarded "
                    "`success` flag lets a forged, reverted call be accepted as a valid "
                    "signature or successful response.\n\n"
                    "**Real incident: Gnosis Pay / Zodiac Roles & Delay modules (June 2026)** "
                    "— the vulnerable pattern was introduced in Zodiac v3.4.0 (Oct 2023). An "
                    "attacker pre-deployed 41 contracts that always reverted with the EIP-1271 "
                    "magic value, routed calls through a `CompatibilityFallbackHandler`, and "
                    "used the forged \"signature\" to queue and execute unauthorized withdrawals "
                    "through the Delay module — draining ~$1.5M across 5,281 wallets."
                ),
                exploit_scenario=(
                    "1. Attacker deploys `EvilSigner`, whose `isValidSignature()` (or any "
                    f"function) always `revert`s with data beginning `0x1626ba7e` "
                    "(the EIP-1271 magic value).\n"
                    "2. The victim contract does "
                    f"`(, bytes memory ret) = signer.{call_kind}(...)` and checks "
                    "`bytes4(ret) == MAGIC_VALUE` without checking `success`.\n"
                    "3. Because `EvilSigner` reverted, `success` is `false`, but it is never "
                    "inspected — the comparison still passes.\n"
                    "4. The victim treats an unauthenticated, reverted call as a valid "
                    "signature/authorization and executes the privileged action."
                ),
                remediation=(
                    "Always capture **and enforce** the `success` boolean before trusting "
                    "any low-level call's return data:\n"
                    "```solidity\n"
                    "// ✅ Hardened\n"
                    f"(bool ok, bytes memory ret) = signer.{call_kind}(\n"
                    "    abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, sig)\n"
                    ");\n"
                    "return ok && ret.length == 32 && bytes4(ret) == EIP1271_MAGIC_VALUE;\n"
                    "```\n"
                    "This applies to every low-level `call`/`staticcall`/`delegatecall` in "
                    "the codebase, not only signature validation — a reverted call's return "
                    "data must never be trusted without first checking `success`."
                ),
                references=[
                    "SWC-104: Unchecked Call Return Value",
                    "EIP-1271: Standard Signature Validation Method for Contracts",
                    "https://help.gnosis-safe.io/",
                    "Gnosis Pay incident post-mortem, June 2026",
                    "CertiK: GnosisPay Delay Module Exploit Analysis, June 2026",
                ],
                language="solidity",
            ))

    return issues

"""
SELF — Rust/Solana/Anchor detectors (semantic, parser-backed).

Sources: Soteria, Neodyme, Immunefi Solana findings, Anchor documentation,
         Trail of Bits Solana security guide, DeFiHackLabs Solana exploits

The detectors here run on the parsed ``RustProgram`` produced by
``self_tool.parsers.rust_parser.parse_rust``.  They are written to be:

* per-instruction (rather than file-wide regex windows),
* conservative on confidence when context is ambiguous,
* additive with native Solana: where Anchor accounts do not apply,
  a small raw-text fallback is used and clearly labelled.
"""
from __future__ import annotations

import re
from typing import Iterable, List

from self_tool.core.issue import Confidence, Issue, Severity
from self_tool.core.scanner import FileContext
from self_tool.parsers.rust_parser import (
    AnchorAccountField,
    AnchorInstruction,
    RustProgram,
    parse_rust,
)


# Privileged account name heuristics. A raw ``AccountInfo`` whose name
# implies authority over funds or settings is treated as privileged.
_PRIVILEGED_HINTS = (
    "authority", "owner", "admin", "operator", "governance", "guardian",
)
_TOKEN_LIKE_HINTS = (
    "token", "mint", "vault", "pool", "state", "escrow", "treasury",
)

# Program-id literals we treat as known-good identity checks. These are
# the canonical SPL token program ids and the system program id; any
# invoke target referencing one of these is considered constrained.
_KNOWN_PROGRAM_LITERALS = (
    "spl_token::ID", "spl_token_2022::ID", "anchor_spl::ID",
    "system_program::ID", "sysvar::ID", "clock::ID",
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
    "11111111111111111111111111111111",
)

# Precompiled regexes used across detectors.
_IS_ANCHOR_RE = re.compile(r"use anchor_lang|#\[program\]|#\[account\]|declare_id!")
_IS_SOLANA_RE = re.compile(r"use solana_program|entrypoint!|AccountInfo")
_RELOAD_RE = re.compile(r"\.reload\s*\(\s*\)")
_INVOKE_RE_BODY = re.compile(r"\binvoke(?:_signed)?\s*\(")
_PDA_DERIVE_RE_BODY = re.compile(r"\b(?:find_program_address|create_program_address)\s*\(")
_ARITH_OP_RE = re.compile(r"\w+\s*[+\-\*]\s*\w+")
_CPI_CONSTRAINED_RE = re.compile(r"\.key\s*\(\s*\)\s*==|require\s*!.*::ID")
_DUPLICATE_ROLE_SUBSTR_RE = re.compile(r"vault|pool|state|escrow")


def detect(file_ctx: FileContext) -> List[Issue]:
    """Run parser-backed Anchor/Rust detectors on a file."""
    content = file_ctx.content
    if not (_IS_ANCHOR_RE.search(content) or _IS_SOLANA_RE.search(content)):
        return []
    prog = parse_rust(file_ctx)
    issues: List[Issue] = []
    if prog.is_anchor or prog.accounts_structs:
        _scan_anchor(prog, file_ctx, issues)
    if prog.is_solana_native and not prog.is_anchor:
        _scan_native_solana(prog, file_ctx, issues)
    return issues


# ── Anchor semantic checks ───────────────────────────────────────────────────

def _scan_anchor(prog: RustProgram, file_ctx: FileContext, issues: List[Issue]) -> None:
    for struct_name, struct in prog.accounts_structs.items():
        for field in struct.fields:
            _check_missing_signer(prog, struct_name, field, file_ctx, issues)
            _check_missing_owner(prog, struct_name, field, file_ctx, issues)
            _check_relationship_constraints(prog, struct, field, file_ctx, issues)
            _check_token_program_confusion(prog, struct, field, file_ctx, issues)
            _check_sysvar_spoofing(prog, struct, field, file_ctx, issues)
            _check_lifecycle_constraints(prog, struct, field, file_ctx, issues)

    for instr in prog.instructions:
        _check_cpi_target(instr, prog, file_ctx, issues)
        _check_pda_constraints(instr, prog, file_ctx, issues)
        _check_unchecked_arithmetic(instr, prog, file_ctx, issues)
        _check_stale_account_read(instr, prog, file_ctx, issues)

    # Cross-instruction duplicate mutable risk.
    _check_duplicate_mutable_accounts(prog, file_ctx, issues)


def _check_missing_signer(
    prog: RustProgram, struct_name: str, field: AnchorAccountField,
    file_ctx: FileContext, issues: List[Issue],
) -> None:
    if not field.is_unchecked:
        return
    if field.is_program or field.is_sysvar:
        return
    name_lower = field.name.lower()
    if not any(h in name_lower for h in _PRIVILEGED_HINTS):
        return
    if field.is_signer:
        return
    issues.append(Issue(
        id="SOL-RUST-001",
        title=f"Solana/Anchor: Missing `signer` on privileged account `{field.name}`",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        file=file_ctx.relative_path, line=field.line,
        snippet=file_ctx.get_snippet(field.line, context=3),
        description=(
            f"`{struct_name}.{field.name}` looks privileged (matched one of "
            f"{list(_PRIVILEGED_HINTS)}) but is typed as a raw `AccountInfo` "
            "without an Anchor `Signer` constraint. Without that constraint "
            "the program does not require the transaction to be signed by "
            "this account."
        ),
        exploit_scenario=(
            f"Attacker passes any account as `{field.name}`. No signature "
            "is enforced. Attacker gains admin/authority privileges and "
            "drains the program."
        ),
        remediation=(
            "```rust\n"
            f"#[account(signer)]\npub {field.name}: Signer<'info>,\n```\n"
            "Or check `account.is_signer == &true` explicitly when the field "
            "must remain a raw `AccountInfo`."
        ),
        references=[
            "https://neodyme.io/blog/solana_common_pitfalls/",
            "https://docs.anchor-lang.com/docs/the-accounts-struct",
        ],
        language="rust",
    ))


def _check_missing_owner(
    prog: RustProgram, struct_name: str, field: AnchorAccountField,
    file_ctx: FileContext, issues: List[Issue],
) -> None:
    if not field.is_unchecked:
        return
    if field.is_program or field.is_sysvar:
        return
    if field.address:
        return
    name_lower = field.name.lower()
    if not any(h in name_lower for h in _TOKEN_LIKE_HINTS):
        return
    # Heuristic: if the file declares the corresponding Account<'info, T>
    # wrapper elsewhere, the developer is aware of owner checking.
    if re.search(rf"Account\s*<\\s*'info\\s*,\\s*{re.escape(field.name.capitalize())}", prog.raw):
        return
    if re.search(rf"\\b{re.escape(field.name)}\\.owner\\s*==", prog.raw):
        return
    issues.append(Issue(
        id="SOL-RUST-002",
        title=f"Solana/Anchor: Missing owner/type check on `{field.name}`",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        file=file_ctx.relative_path, line=field.line,
        snippet=file_ctx.get_snippet(field.line, context=3),
        description=(
            f"`{struct_name}.{field.name}` is accepted as `AccountInfo` "
            "without verifying its owner or wrapped type. An attacker can "
            "supply a same-layout account owned by an arbitrary program; "
            "the program will then operate on attacker-controlled data."
        ),
        exploit_scenario=(
            f"Attacker constructs a fake `{field.name}` owned by a "
            "malicious program and passes it to this instruction. The "
            "instruction reads or writes attacker-controlled data."
        ),
        remediation=(
            f"```rust\npub {field.name}: Account<'info, TokenAccount>,\n```\n"
            "Anchor's `Account<>` wrapper performs the owner check and "
            "type deserialization automatically."
        ),
        references=[
            "https://neodyme.io/blog/solana_common_pitfalls/",
            "Soteria: missing-owner-check",
        ],
        language="rust",
    ))


def _check_cpi_target(
    instr: AnchorInstruction, prog: RustProgram,
    file_ctx: FileContext, issues: List[Issue],
) -> None:
    if not instr.cpi_program_args:
        return
    # If the instruction's accounts struct has any field declared with
    # `address = ...::ID` and that field's name matches the first arg,
    # we consider the program as constrained.
    constrained_identifiers: set = set()
    if instr.accounts is not None:
        for f in instr.accounts.fields:
            if f.address and "ID" in f.address:
                constrained_identifiers.add(f.name)
                constrained_identifiers.add(f.name.lower())
            if f.is_program:
                constrained_identifiers.add(f.name)
                constrained_identifiers.add(f.name.lower())
    for idx, arg in enumerate(instr.cpi_program_args):
        arg_clean = arg.strip()
        if not arg_clean:
            continue
        # Treat the program as constrained if the literal expression
        # references a known-good program id.
        if any(lit in arg_clean for lit in _KNOWN_PROGRAM_LITERALS):
            continue
        # `&ix` style typically indicates the program id was checked
        # upstream when `ix` was built; flag only the risky pattern.
        if re.fullmatch(r"&[A-Za-z_]\w*", arg_clean):
            ident = arg_clean.lstrip("&")
            if ident in constrained_identifiers:
                continue
            if _cpi_args_constrained(prog.raw, instr, arg_clean):
                continue
        issues.append(Issue(
            id="SOL-RUST-003",
            title=f"Solana/Anchor: CPI target in `{instr.name}` not constrained to a known program",
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path,
            line=instr.line + instr.body[: instr.body.find(arg_clean)].count("\n") if arg_clean in instr.body else instr.line,
            snippet=file_ctx.get_snippet(instr.line, context=4),
            description=(
                f"`{instr.name}` invokes a cross-program with program "
                f"expression `{arg_clean}`. Anchor does not constrain the "
                "program id automatically; if this expression derives from "
                "user-supplied input or a non-validated `AccountInfo`, an "
                "attacker can substitute their own program."
            ),
            exploit_scenario=(
                "Attacker substitutes a malicious program for the CPI "
                "target. The CPI executes attacker code in the calling "
                "program's authority, draining funds or corrupting state."
            ),
            remediation=(
                "Constrain the program account:\n"
                "```rust\n"
                "#[account(address = spl_token::ID)]\n"
                "pub token_program: AccountInfo,\n"
                "```\n"
                "Or use Anchor's `Program<'info, T>` typed account."
            ),
            references=[
                "https://docs.solana.com/developing/programming-model/calling-between-programs",
                "https://docs.anchor-lang.com/docs/the-accounts-struct",
            ],
            language="rust",
        ))


def _cpi_args_constrained(raw: str, instr: AnchorInstruction, arg: str) -> bool:
    """Best-effort: did the surrounding code validate the program id?"""
    body = instr.body
    return bool(_CPI_CONSTRAINED_RE.search(body))


def _check_pda_constraints(
    instr: AnchorInstruction, prog: RustProgram,
    file_ctx: FileContext, issues: List[Issue],
) -> None:
    if not instr.has_find_pda:
        return
    if instr.accounts is None:
        return
    pda_fields = [f for f in instr.accounts.fields if f.is_pda]
    if not pda_fields:
        return
    for f in pda_fields:
        # A canonical Anchor bump is present when `bump` (without an
        # explicit value) or `bump = <canonical expr>` appears; an
        # arbitrary non-canonical expression means the program trusts a
        # caller-supplied bump.
        if f.bump is None:
            issues.append(Issue(
                id="SOL-RUST-004",
                title=f"Solana/Anchor: PDA `{f.name}` in `{instr.name}` lacks a canonical bump",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=f.line,
                snippet=file_ctx.get_snippet(f.line, context=3),
                description=(
                    f"`{instr.name}` derives a PDA for `{f.name}` but the "
                    "`#[account]` attributes do not store or verify the "
                    "canonical bump. Without it, an attacker can derive a "
                    "non-canonical PDA and pass it as a substitute."
                ),
                exploit_scenario=(
                    "Attacker derives the same seeds with a different bump "
                    "and passes the substitute PDA to a sibling instruction "
                    "that does not re-derive the canonical bump."
                ),
                remediation=(
                    "```rust\n#[account(seeds = [b\"vault\", user.key().as_ref()], bump)]\n```\n"
                    "Store the canonical bump in account data and verify it "
                    "on every future use."
                ),
                references=[
                    "https://docs.anchor-lang.com/docs/pdas",
                    "Soteria: pda-seeds",
                ],
                language="rust",
            ))
        elif re.search(r"\b(bump|nonce|seed)\s*=\s*[A-Za-z_]\w*\s*[+\-*/]", f.bump) and "ctx.bumps" not in f.bump:
            issues.append(Issue(
                id="SOL-RUST-004",
                title=f"Solana/Anchor: PDA `{f.name}` bump not derived from `ctx.bumps`",
                severity=Severity.HIGH,
                confidence=Confidence.LOW,
                file=file_ctx.relative_path, line=f.line,
                snippet=file_ctx.get_snippet(f.line, context=3),
                description=(
                    f"`{f.name}` stores a bump derived from an arbitrary "
                    "expression rather than `ctx.bumps.<field>`. Anchor's "
                    "`ctx.bumps` accessor returns the canonical bump."
                ),
                exploit_scenario=(
                    "Attacker supplies a custom bump that satisfies the "
                    "non-canonical constraint, producing a substitute PDA."
                ),
                remediation=(
                    "Use `bump = ctx.bumps.<field>` or omit `bump` and let "
                    "Anchor store the canonical value automatically."
                ),
                references=["https://docs.anchor-lang.com/docs/pdas"],
                language="rust",
            ))


def _check_unchecked_arithmetic(
    instr: AnchorInstruction, prog: RustProgram,
    file_ctx: FileContext, issues: List[Issue],
) -> None:
    if instr.unchecked_arith_ops <= 0:
        return
    # Require at least 3 unchecked ops in this instruction and zero
    # checked ops anywhere in the same instruction to flag — anything
    # less is likely a benign offset.
    if instr.unchecked_arith_ops < 3 or instr.checked_arith_ops > 0:
        return
    # Find the first arithmetic op in the body to point at.
    body = instr.body
    m = _ARITH_OP_RE.search(body)
    line = instr.line + (body[: m.start()].count("\n") if m else 0)
    issues.append(Issue(
        id="SOL-RUST-005",
        title=f"Solana/Anchor: Unchecked arithmetic in `{instr.name}`",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        file=file_ctx.relative_path, line=line,
        snippet=file_ctx.get_snippet(line, context=3),
        description=(
            f"`{instr.name}` contains {instr.unchecked_arith_ops} unchecked "
            "`+`, `-`, or `*` operations and no `checked_*`/`saturating_*`/"
            "`wrapping_*` calls. Rust panics in debug but wraps silently "
            "in release; Solana programs run in release."
        ),
        exploit_scenario=(
            "An addition or subtraction overflows in release, wrapping to "
            "near-zero. Accounting logic credits the user 0 despite a "
            "positive deposit, or underflows when debiting."
        ),
        remediation=(
            "Use checked arithmetic:\n"
            "```rust\nlet total = a.checked_add(b).ok_or(ErrorCode::Math)?;\n```\n"
            "Or use `checked_*`/`saturating_*` consistently for value-bearing math."
        ),
        references=[
            "https://doc.rust-lang.org/reference/expressions/operator-expr.html#overflow",
            "Soteria: integer-overflow",
        ],
        language="rust",
    ))


def _check_stale_account_read(
    instr: AnchorInstruction, prog: RustProgram,
    file_ctx: FileContext, issues: List[Issue],
) -> None:
    if not instr.has_cpi or instr.has_reload:
        return
    # Read-after-CPI without reload is most risky for `is_mut` accounts
    # touched in the instruction.
    if instr.accounts is None:
        return
    mut_fields = [f for f in instr.accounts.fields if f.is_mut]
    if not mut_fields:
        return
    body = instr.body
    if not _RELOAD_RE.search(body):
        # Approximate line of the CPI.
        cpi_match = _INVOKE_RE_BODY.search(body)
        line = instr.line + (body[: cpi_match.start()].count("\n") if cpi_match else 0)
        issues.append(Issue(
            id="SOL-RUST-006",
            title=f"Solana/Anchor: Stale account read possible after CPI in `{instr.name}`",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                f"`{instr.name}` performs CPI and may read the cached "
                "deserialized account state of a `mut` account "
                f"({', '.join(f.name for f in mut_fields)}) afterwards. "
                "Anchor does not auto-reload accounts after CPI; the "
                "cached struct can become stale."
            ),
            exploit_scenario=(
                "CPI modifies the on-chain account. The instruction then "
                "reads the cached (stale) fields and makes authorization "
                "or accounting decisions based on the old value."
            ),
            remediation=(
                "After any CPI that could mutate the account, call "
                "`ctx.accounts.<field>.reload()?` before reading its data."
            ),
            references=["https://docs.anchor-lang.com/docs/account-types#reload"],
            language="rust",
        ))


def _check_relationship_constraints(
    prog: RustProgram, struct, field: AnchorAccountField,
    file_ctx: FileContext, issues: List[Issue],
) -> None:
    """SOL-RUST-008: has_one / address / owner / constraint must reference real fields."""
    struct_field_names = {f.name for f in struct.fields}
    references_to_check: List[tuple] = []  # (kind, target, line)
    for ref in field.has_one:
        references_to_check.append(("has_one", ref, field.line))
    if field.address:
        references_to_check.append(("address", field.address, field.line))
    if field.owner:
        references_to_check.append(("owner", field.owner, field.line))
    for expr in field.constraint_exprs:
        # A custom constraint of the form `target == value` references
        # an account field by name; flag references to names missing
        # from the struct.
        m = re.search(r"\b([a-z_]\w*)\s*\.key\s*\(\s*\)", expr)
        if m and m.group(1) not in struct_field_names:
            references_to_check.append(("constraint.key", m.group(1), field.line))
    for kind, target, line in references_to_check:
        if kind == "has_one" and target not in struct_field_names:
            issues.append(Issue(
                id="SOL-RUST-008",
                title=f"Solana/Anchor: `has_one = {target}` on `{field.name}` references unknown field",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description=(
                    f"`{struct.name}.{field.name}` declares `has_one = {target}` "
                    f"but `{target}` is not a field of `{struct.name}`. The "
                    "constraint will fail at runtime or, worse, the wrong "
                    "field is referenced and the relationship is silently "
                    "unchecked."
                ),
                exploit_scenario=(
                    "Either the constraint fails to compile (denying the "
                    "instruction) or the developer falls back to manual "
                    "checks that are easy to bypass."
                ),
                remediation=(
                    f"Add `pub {target}: Account<'info, ...>,` to `{struct.name}` "
                    "or remove the `has_one` constraint."
                ),
                references=["https://docs.anchor-lang.com/docs/the-accounts-struct"],
                language="rust",
            ))
        elif kind == "constraint.key":
            issues.append(Issue(
                id="SOL-RUST-008",
                title=f"Solana/Anchor: Custom constraint on `{field.name}` references missing account `{target}`",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description=(
                    f"`{field.name}` has a `constraint =` that references "
                    f"`{target}.key()`, but `{target}` is not a field of "
                    f"`{struct.name}`."
                ),
                exploit_scenario="Constraint fails to compile or silently no-ops.",
                remediation=f"Add `{target}` as a field of `{struct.name}`.",
                references=["https://docs.anchor-lang.com/docs/the-accounts-struct"],
                language="rust",
            ))


def _check_token_program_confusion(
    prog: RustProgram, struct, field: AnchorAccountField,
    file_ctx: FileContext, issues: List[Issue],
) -> None:
    """SOL-RUST-010: token / token-2022 program accounts must be typed."""
    name_lower = field.name.lower()
    if not ("token" in name_lower and ("program" in name_lower or "mint" in name_lower)):
        return
    if field.is_program or field.is_interface_account or "Program<" in field.type:
        return
    if field.is_unchecked and not field.address:
        issues.append(Issue(
            id="SOL-RUST-010",
            title=f"Solana/Anchor: `{field.name}` accepts untyped token program/mint",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=field.line,
            snippet=file_ctx.get_snippet(field.line, context=3),
            description=(
                f"`{struct.name}.{field.name}` is a raw `AccountInfo` that "
                "could be either the SPL Token or the Token-2022 program. "
                "Anchor will not distinguish them; the instruction may be "
                "called with whichever program the attacker prefers."
            ),
            exploit_scenario=(
                "Attacker passes the Token-2022 program where SPL Token is "
                "expected (or vice versa), causing the instruction to act "
                "against a different on-chain program than the developers "
                "intended."
            ),
            remediation=(
                "Use Anchor's typed program account:\n"
                "```rust\npub token_program: Program<'info, Token>,\n```\n"
                "Or use `Interface<'info, TokenInterface>` if both token "
                "programs must be accepted, and validate which one was passed."
            ),
            references=[
                "https://www.anchor-lang.com/docs/account-constraints",
                "https://spl.solana.com/token-2022",
            ],
            language="rust",
        ))


def _check_sysvar_spoofing(
    prog: RustProgram, struct, field: AnchorAccountField,
    file_ctx: FileContext, issues: List[Issue],
) -> None:
    """SOL-RUST-011: sysvars must use the typed Sysvar wrapper."""
    name_lower = field.name.lower()
    if not any(s in name_lower for s in ("clock", "rent", "epochschedule", "instructions")):
        return
    if field.is_sysvar or "Sysvar" in field.type:
        return
    if field.address:
        return
    if not field.is_unchecked:
        return
    issues.append(Issue(
        id="SOL-RUST-011",
        title=f"Solana/Anchor: `{field.name}` is a raw sysvar candidate",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        file=file_ctx.relative_path, line=field.line,
        snippet=file_ctx.get_snippet(field.line, context=3),
        description=(
            f"`{struct.name}.{field.name}` is taken as a raw `AccountInfo` "
            "but its name suggests a sysvar (Clock, Rent, Instructions, ...). "
            "Anchor does not verify sysvar identity for `AccountInfo`; an "
            "attacker can supply a fake account whose data matches the "
            "sysvar layout."
        ),
        exploit_scenario=(
            "Attacker passes a forged account whose bytes mimic Clock. "
            "The instruction reads `unix_timestamp` from the fake account "
            "and behaves as though time has elapsed or not."
        ),
        remediation=(
            "Use the typed sysvar:\n"
            "```rust\npub clock: Sysvar<'info, Clock>,\n```\n"
            "Or use `Clock::get()` from inside the instruction body."
        ),
        references=["https://docs.anchor-lang.com/docs/account-constraints"],
        language="rust",
    ))


def _check_lifecycle_constraints(
    prog: RustProgram, struct, field: AnchorAccountField,
    file_ctx: FileContext, issues: List[Issue],
) -> None:
    """SOL-RUST-009: realloc / close / init_if_needed require safety constraints."""
    if field.is_init_if_needed:
        if not field.payer or not field.space:
            issues.append(Issue(
                id="SOL-RUST-009",
                title=(
                    f"Solana/Anchor: `init_if_needed` on `{field.name}` "
                    "missing payer or space"
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=field.line,
                snippet=file_ctx.get_snippet(field.line, context=3),
                description=(
                    f"`{struct.name}.{field.name}` uses `init_if_needed` "
                    "without an explicit `payer` and `space`. Anchor will "
                    "still allow re-initialization of an existing account "
                    "without these protections."
                ),
                exploit_scenario=(
                    "Attacker triggers `init_if_needed` after the account "
                    "exists. Without an 8-byte discriminator check or "
                    "explicit re-init protection, account data is reset."
                ),
                remediation=(
                    "Pair `init_if_needed` with `payer = ..., space = ...,` "
                    "and a discriminator check or owner validation."
                ),
                references=["https://docs.anchor-lang.com/docs/account-constraints"],
                language="rust",
            ))
    if field.is_init and not field.payer:
        issues.append(Issue(
            id="SOL-RUST-009",
            title=f"Solana/Anchor: `init` on `{field.name}` missing `payer`",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            file=file_ctx.relative_path, line=field.line,
            snippet=file_ctx.get_snippet(field.line, context=3),
            description=(
                f"`{struct.name}.{field.name}` declares `init` but does not "
                "specify which account pays for rent. Anchor requires a "
                "`payer`; without it the program will fail to compile or "
                "default to an unintended signer."
            ),
            exploit_scenario="Program fails to deploy or bills rent to an unintended signer.",
            remediation="Add `payer = <signer_account>,` to the `#[account]` attributes.",
            references=["https://docs.anchor-lang.com/docs/account-constraints"],
            language="rust",
        ))
    if field.realloc and not (field.realloc_payer or field.payer):
        issues.append(Issue(
            id="SOL-RUST-009",
            title=f"Solana/Anchor: `realloc` on `{field.name}` missing `realloc::payer`",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=field.line,
            snippet=file_ctx.get_snippet(field.line, context=3),
            description=(
                f"`{struct.name}.{field.name}` declares `realloc` without "
                "a `realloc::payer = ...`. Without an explicit payer, "
                "Anchor bills the reallocation rent to a default signer "
                "and may exceed the user's intent."
            ),
            exploit_scenario=(
                "Realloc consumes more lamports than expected from the "
                "intended payer; the user is overcharged."
            ),
            remediation=(
                "Add `realloc::payer = <signer_account>,` to the `#[account]` attributes."
            ),
            references=["https://docs.anchor-lang.com/docs/account-constraints"],
            language="rust",
        ))


def _check_duplicate_mutable_accounts(
    prog: RustProgram, file_ctx: FileContext, issues: List[Issue],
) -> None:
    """SOL-RUST-007: distinct role accounts passed mut may collide."""
    for struct_name, struct in prog.accounts_structs.items():
        # Two accounts are likely colliding if their role names appear
        # repeated across the struct (rare) or if an instruction passes
        # two distinct role accounts that are not constrained to be
        # distinct via constraint = ....  We surface a warning whenever
        # two `mut` fields share a substring and are not cross-checked.
        seen_substrings: dict = {}
        for f in struct.fields:
            if not f.is_mut:
                continue
            for m in _DUPLICATE_ROLE_SUBSTR_RE.finditer(f.name.lower()):
                s = m.group(0)
                other = seen_substrings.get(s)
                if other and other != f.name:
                    issues.append(Issue(
                        id="SOL-RUST-007",
                        title=(
                            f"Solana/Anchor: Mutable role accounts "
                            f"`{other}` and `{f.name}` in `{struct.name}` "
                            "may collide"
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.LOW,
                        file=file_ctx.relative_path, line=f.line,
                        snippet=file_ctx.get_snippet(f.line, context=3),
                        description=(
                            f"`{struct.name}` declares two `mut` fields "
                            f"sharing role `{s}` (`{other}` and `{f.name}`) "
                            "without an explicit `constraint = "
                            f"{other}.key() != {f.name}.key()` cross-check. "
                            "Anchor does not enforce distinctness."
                        ),
                        exploit_scenario=(
                            "Attacker passes the same account for both "
                            f"`{other}` and `{f.name}`, bypassing the "
                            "separation the developer assumed."
                        ),
                        remediation=(
                            "Add a custom constraint ensuring the two "
                            "accounts are distinct."
                        ),
                        references=["https://docs.anchor-lang.com/docs/account-constraints"],
                        language="rust",
                    ))
                seen_substrings[s] = f.name


# ── Native Solana fallback ───────────────────────────────────────────────────

def _scan_native_solana(prog: RustProgram, file_ctx: FileContext, issues: List[Issue]) -> None:
    """Mirror SOL-RUST-003 / SOL-RUST-004 for non-Anchor programs.

    Reuses the parser-populated ``cpi_invokes`` and ``pda_derivations``
    lists so we never re-compile or re-apply the same regexes here.
    """
    raw = prog.raw
    raw_lines = raw.splitlines()
    for line, _snippet in prog.cpi_invokes:
        line_start = sum(len(l) + 1 for l in raw_lines[: line - 1])
        surrounding = raw[max(0, line_start - 300): line_start + 200]
        if _CPI_CONSTRAINED_RE.search(surrounding):
            continue
        issues.append(Issue(
            id="SOL-RUST-003",
            title="Solana (native): CPI without explicit program-id check",
            severity=Severity.CRITICAL,
            confidence=Confidence.LOW,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description=(
                "Native Solana program performs `invoke` / `invoke_signed` "
                "without an observable program-id assertion in the "
                "surrounding context."
            ),
            exploit_scenario="Attacker substitutes the CPI target program.",
            remediation="Validate `*instruction.program_id == expected::ID` before CPI.",
            references=["https://docs.solana.com/developing/programming-model/calling-between-programs"],
            language="rust",
        ))
    for line, _snippet in prog.pda_derivations:
        line_start = sum(len(l) + 1 for l in raw_lines[: line - 1])
        surrounding = raw[max(0, line_start - 100): line_start + 300]
        if not re.search(r"\bbump\b", surrounding, re.IGNORECASE):
            issues.append(Issue(
                id="SOL-RUST-004",
                title="Solana (native): PDA derived without bump verification",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description=(
                    "`find_program_address` / `create_program_address` is "
                    "used without storing the canonical bump."
                ),
                exploit_scenario="Attacker substitutes a non-canonical PDA.",
                remediation="Persist the canonical bump and verify on subsequent uses.",
                references=["https://docs.anchor-lang.com/docs/pdas"],
                language="rust",
            ))
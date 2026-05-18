"""
SELF — Rust/Solana/Anchor detectors
Sources: Soteria, Neodyme, Immunefi Solana findings, Anchor documentation,
         Trail of Bits Solana security guide, DeFiHackLabs Solana exploits
"""
import re
from typing import List
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext


def detect(file_ctx: FileContext) -> List[Issue]:
    # Only process Rust files that look like Solana/Anchor programs
    content = file_ctx.content
    is_anchor = bool(re.search(r'(use anchor_lang|#\[program\]|#\[account\]|declare_id!)', content))
    is_solana = bool(re.search(r'(use solana_program|entrypoint!|AccountInfo)', content))
    if not is_anchor and not is_solana:
        return []
    issues = []
    _missing_signer_check(file_ctx, content, issues)
    _missing_owner_check(file_ctx, content, issues)
    _arbitrary_cpi(file_ctx, content, issues)
    _pda_seeds_unchecked(file_ctx, content, issues)
    _integer_overflow_rust(file_ctx, content, issues)
    _account_reloading(file_ctx, content, issues)
    return issues


def _missing_signer_check(file_ctx, content, issues):
    """SOL-RUST-001: Account not validated as signer."""
    # Anchor: AccountInfo used but not Signer<> type or .is_signer not checked
    account_info = re.compile(r'pub\s+(\w+)\s*:\s*AccountInfo', re.MULTILINE)
    for m in account_info.finditer(content):
        acct_name = m.group(1)
        # Skip if it's typed as Signer
        if re.search(rf'pub\s+{re.escape(acct_name)}\s*:\s*Signer', content):
            continue
        # Check if .is_signer is verified anywhere
        if re.search(rf'{re.escape(acct_name)}\.is_signer', content):
            continue
        if 'authority' in acct_name.lower() or 'owner' in acct_name.lower() or 'admin' in acct_name.lower():
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="SOL-RUST-001",
                title=f"Solana: Missing Signer Check on `{acct_name}`",
                severity=Severity.CRITICAL, confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=4),
                description=(
                    f"`{acct_name}` appears to be a privileged account (authority/owner/admin) "
                    "but is typed as `AccountInfo` instead of `Signer<'info>`. This means "
                    "any account can be passed — the program never verifies the caller signed "
                    "the transaction.\n\n"
                    "**Real incidents:** Wormhole ($320M), Solend ($1.26M) — missing signer checks."
                ),
                exploit_scenario=f"Attacker passes any account as `{acct_name}`. No signature required. Attacker gains admin privileges and drains the program.",
                remediation=(
                    "Use Anchor's `Signer` constraint:\n"
                    "```rust\n"
                    "#[derive(Accounts)]\n"
                    "pub struct MyContext<'info> {\n"
                    f"    pub {acct_name}: Signer<'info>,  // ✅ enforces signature\n"
                    "}\n"
                    "```"
                ),
                references=["https://neodyme.io/blog/solana_common_pitfalls/", "https://docs.anchor-lang.com/docs/the-accounts-struct"],
                language="rust",
            ))


def _missing_owner_check(file_ctx, content, issues):
    """SOL-RUST-002: Account owner not verified — allows attacker-controlled accounts."""
    account_info = re.compile(r'pub\s+(\w+)\s*:\s*AccountInfo', re.MULTILINE)
    for m in account_info.finditer(content):
        acct_name = m.group(1)
        # Check if owner is verified
        if re.search(rf'{re.escape(acct_name)}\.owner', content):
            continue
        # Check for Anchor Account<> wrapper (handles ownership)
        if re.search(rf'pub\s+{re.escape(acct_name)}\s*:\s*Account<', content):
            continue
        if any(k in acct_name.lower() for k in ['token', 'mint', 'vault', 'pool', 'state']):
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="SOL-RUST-002",
                title=f"Solana: Missing Owner Check on `{acct_name}`",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=4),
                description=(
                    f"`{acct_name}` is accepted as `AccountInfo` without verifying its owner. "
                    "An attacker can pass a fake account owned by a malicious program, "
                    "tricking the program into operating on attacker-controlled data."
                ),
                exploit_scenario=f"Attacker creates a fake `{acct_name}` account owned by attacker's program. Passes it to your program — your program reads/writes attacker-controlled data.",
                remediation=(
                    "Use Anchor's `Account<'info, T>` which automatically checks ownership:\n"
                    "```rust\n"
                    f"pub {acct_name}: Account<'info, TokenAccount>,  // owner verified\n"
                    "// Or manually: require!({acct_name}.owner == &token_program::ID)\n"
                    "```"
                ),
                references=["https://neodyme.io/blog/solana_common_pitfalls/", "Soteria: missing-owner-check"],
                language="rust",
            ))


def _arbitrary_cpi(file_ctx, content, issues):
    """SOL-RUST-003: Arbitrary CPI — program_id not validated before invoke."""
    cpi_pattern = re.compile(r'invoke\s*\(|invoke_signed\s*\(', re.MULTILINE)
    for m in cpi_pattern.finditer(content):
        surrounding = content[max(0, m.start()-300):m.start()+200]
        # Check if program key is validated
        if re.search(r'(program_id\s*==|require.*program|check.*program|\.key\(\)\s*==)', surrounding):
            continue
        line = content[:m.start()].count('\n') + 1
        issues.append(Issue(
            id="SOL-RUST-003",
            title="Solana: Arbitrary CPI — Program ID Not Validated",
            severity=Severity.CRITICAL, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=4),
            description=(
                "A Cross-Program Invocation (CPI) is made without validating that the "
                "target `program_id` matches the expected program. An attacker can pass "
                "a malicious program that executes arbitrary code in the CPI context."
            ),
            exploit_scenario="Attacker passes their own program as the CPI target. CPI executes attacker code — drains accounts or corrupts state.",
            remediation=(
                "Always validate program ID before CPI:\n"
                "```rust\n"
                "require!(token_program.key() == spl_token::ID, ErrorCode::InvalidProgram);\n"
                "invoke(&instruction, &[account1, account2])\n"
                "```"
            ),
            references=["https://docs.solana.com/developing/programming-model/calling-between-programs", "Neodyme: arbitrary-cpi"],
            language="rust",
        ))


def _pda_seeds_unchecked(file_ctx, content, issues):
    """SOL-RUST-004: PDA created/used without bump seed verification."""
    pda_pattern = re.compile(r'(find_program_address|create_program_address)\s*\(', re.MULTILINE)
    for m in pda_pattern.finditer(content):
        surrounding = content[max(0,m.start()-100):m.start()+300]
        if not re.search(r'bump|canonical_bump|seeds.*bump', surrounding, re.IGNORECASE):
            line = content[:m.start()].count('\n') + 1
            issues.append(Issue(
                id="SOL-RUST-004",
                title="Solana: PDA Without Canonical Bump Seed Verification",
                severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                file=file_ctx.relative_path, line=line,
                snippet=file_ctx.get_snippet(line, context=3),
                description="PDA derivation without storing and verifying the canonical bump seed can allow multiple valid PDAs with different bumps — enabling account substitution attacks.",
                exploit_scenario="Attacker derives a PDA with a non-canonical bump and passes it as a valid PDA — program accepts it and operates on attacker-controlled account.",
                remediation=(
                    "Store and verify the canonical bump:\n"
                    "```rust\n"
                    "let (pda, bump) = Pubkey::find_program_address(&[b'seed'], program_id);\n"
                    "// Store bump in account data, verify on future calls\n"
                    "```"
                ),
                references=["https://docs.anchor-lang.com/docs/pdas", "Soteria: pda-seeds"],
                language="rust",
            ))


def _integer_overflow_rust(file_ctx, content, issues):
    """SOL-RUST-005: Unchecked arithmetic in Rust (debug builds catch, release doesn't)."""
    # Direct + * - on numeric types without checked_add/checked_mul etc.
    pattern = re.compile(r'(\w+)\s*\+\s*(\w+)(?!\s*checked)', re.MULTILINE)
    checked = re.compile(r'(checked_add|checked_mul|checked_sub|saturating_add|overflow)', re.MULTILINE)
    if checked.search(content):
        return  # File already uses safe math
    dangerous_ops = len(re.findall(r'\w+\s*[+\-\*]\s*\w+', content))
    if dangerous_ops > 5:
        m = re.search(r'\w+\s*[+\-\*]\s*\w+', content)
        line = content[:m.start()].count('\n') + 1 if m else 1
        issues.append(Issue(
            id="SOL-RUST-005",
            title="Solana/Rust: Unchecked Arithmetic — Overflow in Release Build",
            severity=Severity.HIGH, confidence=Confidence.MEDIUM,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description="Rust's arithmetic operators panic on overflow in debug builds but **wrap silently in release builds**. Solana programs run in release mode — overflows are silent.",
            exploit_scenario="Amount addition overflows in release — wrapped to near-zero. User credited 0 tokens despite depositing 2^64.",
            remediation=(
                "Use checked arithmetic:\n"
                "```rust\n"
                "let total = amount.checked_add(fee).ok_or(ErrorCode::MathOverflow)?;\n"
                "```"
            ),
            references=["https://doc.rust-lang.org/reference/expressions/operator-expr.html#overflow", "Soteria: integer-overflow"],
            language="rust",
        ))


def _account_reloading(file_ctx, content, issues):
    """SOL-RUST-006: Account data read after CPI without reload — stale data."""
    has_cpi = bool(re.search(r'invoke\s*\(|invoke_signed\s*\(|cpi::', content))
    has_reload = bool(re.search(r'\.reload\s*\(\)', content))
    if has_cpi and not has_reload:
        m = re.search(r'invoke\s*\(|invoke_signed\s*\(|cpi::', content)
        line = content[:m.start()].count('\n') + 1 if m else 1
        issues.append(Issue(
            id="SOL-RUST-006",
            title="Solana: Account Data Read After CPI Without `.reload()`",
            severity=Severity.MEDIUM, confidence=Confidence.LOW,
            file=file_ctx.relative_path, line=line,
            snippet=file_ctx.get_snippet(line, context=3),
            description="After a CPI call, account data cached in Anchor's `Account<>` struct may be stale. Reading it without calling `.reload()` can lead to logic errors based on outdated values.",
            exploit_scenario="CPI modifies token balance. Program reads cached (old) balance — logic based on wrong value.",
            remediation="Call `account.reload()?` after any CPI that modifies the account's data.",
            references=["https://docs.anchor-lang.com/docs/account-types#reload"],
            language="rust",
        ))

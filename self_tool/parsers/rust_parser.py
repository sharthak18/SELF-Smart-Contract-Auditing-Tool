"""
SELF — Smart Contract Exploit & Logic Finder
Rust/Anchor regex-based parser: extracts program structure from .rs files.

Anchor syntax is attribute-driven.  We focus on:
  * `#[program]` module — instruction handlers (functions taking `Context<T>`)
  * `#[derive(Accounts)]` structs — fields and constraints (Signer, Account<>,
    seeds, bump, has_one, owner, close, realloc, address)
  * AccountInfo vs Signer usage
  * `find_program_address` / `create_program_address` (PDA derivations)
  * `invoke` / `invoke_signed` (CPI)
  * CPI module-level `declare_program!` / `cpi::` calls

Limitations: no full Rust syntax tree (would require syn/tree-sitter).
We parse line- and attribute-level structure only — sufficient for the
20+ Anchor detector rules in rust_detectors.py.
"""
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple


@dataclass
class AnchorConstraint:
    """One Anchor constraint on an account field, e.g. ``seeds = [b"vault"]``."""
    kind: str                   # signer, mut, init, seeds, bump, has_one, owner, address, close, realloc, constraint
    raw: str                    # original attribute text
    line: int


@dataclass
class AnchorAccountField:
    """One field inside a ``#[derive(Accounts)]`` struct."""
    name: str
    type: str                       # "AccountInfo", "Signer<'info>", "Account<'info, TokenAccount>", ...
    is_signer: bool = False
    is_mut: bool = False
    is_init: bool = False
    is_init_if_needed: bool = False
    is_pda: bool = False            # derives a PDA (seeds or find_program_address)
    seeds: List[str] = field(default_factory=list)
    bump: Optional[str] = None
    has_one: List[str] = field(default_factory=list)
    owner: Optional[str] = None
    address: Optional[str] = None
    close: Optional[str] = None
    realloc: Optional[str] = None
    realloc_payer: Optional[str] = None
    realloc_zero: Optional[str] = None
    payer: Optional[str] = None
    space: Optional[str] = None
    raw_constraints: List[str] = field(default_factory=list)
    constraint_exprs: List[str] = field(default_factory=list)
    line: int = 0
    is_unchecked: bool = False
    is_program: bool = False
    is_sysvar: bool = False
    is_token_account: bool = False
    is_mint: bool = False
    is_interface_account: bool = False
    is_token_2022: bool = False


@dataclass
class AnchorAccountsStruct:
    """A ``#[derive(Accounts)]`` struct used by an instruction handler."""
    name: str
    fields: List[AnchorAccountField] = field(default_factory=list)
    line: int = 0


@dataclass
class AnchorInstruction:
    """One instruction handler inside a ``#[program]`` mod."""
    name: str
    accounts_struct: Optional[str]           # the generic of Context<...>, e.g. "Deposit"
    accounts: Optional[AnchorAccountsStruct] = None
    params: List[Tuple[str, str]] = field(default_factory=list)   # (name, type)
    body: str = ""
    line: int = 0
    has_cpi: bool = False                    # invokes invoke/invoke_signed/cpi::
    cpi_calls: List[str] = field(default_factory=list)
    cpi_program_args: List[str] = field(default_factory=list)  # first arg of each CPI
    has_find_pda: bool = False
    has_pda_creation: bool = False
    has_close: bool = False
    has_realloc: bool = False
    has_reload: bool = False                 # .reload() observed after a CPI
    unchecked_arith_ops: int = 0             # rough count of + - *
    checked_arith_ops: int = 0               # rough count of checked_/saturating_/wrapping_


@dataclass
class RustProgram:
    """Parsed representation of one Anchor program (file)."""
    path: str
    is_anchor: bool = False                  # uses anchor_lang / #[program]
    is_solana_native: bool = False           # uses solana_program only
    declare_id: Optional[str] = None
    program_mod: Optional[str] = None        # name of the #[program] module
    instructions: List[AnchorInstruction] = field(default_factory=list)
    accounts_structs: Dict[str, AnchorAccountsStruct] = field(default_factory=dict)
    cpi_invokes: List[Tuple[int, str]] = field(default_factory=list)  # (line, snippet)
    pda_derivations: List[Tuple[int, str]] = field(default_factory=list)
    raw: str = ""


# ── helpers ─────────────────────────────────────────────────────────────────
_STRUCT_HDR_RE = re.compile(
    r"#\[derive\(Accounts\)\]\s*\n\s*pub\s+struct\s+(\w+)\s*(?:<[^>]+>)?\s*\{",
    re.MULTILINE,
)
_PROGRAM_MOD_RE = re.compile(
    r"#\[program\]\s*\n\s*(?:pub\s+)?mod\s+(\w+)",
    re.MULTILINE,
)
_DECLARE_ID_RE = re.compile(r"declare_id!\s*\(\s*\"([1-9A-HJ-NP-Za-km-z]+)\"\s*\)")
_INSTRUCTION_RE = re.compile(
    r"pub\s+fn\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*[^\{]+)?\s*\{",
    re.MULTILINE,
)
_CONTEXT_TYPE_RE = re.compile(r"Context\s*<\s*(\w+)\s*>")
_USE_ANCHOR_RE = re.compile(r"use\s+anchor_lang")
_USE_SOLANA_RE = re.compile(r"use\s+solana_program")
_INVOKE_RE = re.compile(r"\binvoke(?:_signed)?\s*\(|\bcpi::")
_PDA_DERIVE_RE = re.compile(r"\b(?:find_program_address|create_program_address)\s*\(")
_BLANK_OR_COMMENT = re.compile(r"^\s*(?://.*)?$")
_FIELD_RE = re.compile(
    r"^\s*(?P<annots>(?:#\[[^\]]+\]\s*)*)\s*pub\s+(?P<name>\w+)\s*:\s*(?P<type>[^,\n]+?)\s*,?\s*$",
    re.MULTILINE,
)
_CONSTRAINT_KINDS = {
    "Signer": "signer",
    "AccountInfo": "account_info",
    "Account<": "account",
    "SystemAccount<": "system_account",
    "Program<": "program",
    "UncheckedAccount<": "unchecked_account",
    "Signer<'info>": "signer",
}


def _strip_comments(content: str) -> str:
    out = []
    for line in content.splitlines():
        in_block = False
        i = 0
        while i < len(line):
            if line[i:i+2] == "//":
                line = line[:i]
                break
            i += 1
        out.append(line)
    return "\n".join(out)


def _strip_strings(line: str) -> str:
    """Strip Rust string literals so attribute matching isn't fooled by 'text'."""
    return re.sub(r'"(?:[^"\\]|\\.)*"', '""', line)


def _parse_constraint_blob(blob: str) -> List[AnchorConstraint]:
    """Parse one attribute blob like ``#(accounts = ..., has_one = pool)``."""
    constraints: List[AnchorConstraint] = []
    text = _strip_strings(blob)
    # Match `key = value` pairs where value can be a simple ident or expr
    for m in re.finditer(r"\b(signer|init_if_needed|seeds|bump|has_one|owner|address|close|realloc|constraint|payer|space|lamports|rent)\b\s*=", text):
        kind = m.group(1)
        constraints.append(AnchorConstraint(kind=kind, raw=m.group(0), line=0))
    if re.search(r"\bsigner\b(?!\s*=)", text) and not any(c.kind == "signer" for c in constraints):
        constraints.append(AnchorConstraint(kind="signer", raw="signer", line=0))
    if re.search(r"\bmut\b(?!\s*=)", text) and not any(c.kind == "mut" for c in constraints):
        constraints.append(AnchorConstraint(kind="mut", raw="mut", line=0))
    if re.search(r"\bbump\b(?!\s*=)", text) and not any(c.kind == "bump" for c in constraints):
        constraints.append(AnchorConstraint(kind="bump", raw="bump", line=0))
    if re.search(r"\binit(?!_if_needed|\s*=)\b", text) and not any(c.kind == "init" for c in constraints):
        constraints.append(AnchorConstraint(kind="init", raw="init", line=0))
    if re.search(r"\binit_if_needed\b(?!\s*=)", text) and not any(c.kind == "init_if_needed" for c in constraints):
        constraints.append(AnchorConstraint(kind="init_if_needed", raw="init_if_needed", line=0))
    # `realloc = N, realloc::payer = X, realloc::zero = bool`
    for m in re.finditer(r"\brealloc::(payer|zero)\s*=\s*([^\s,\]\)]+)", text):
        kind = f"realloc::{m.group(1)}"
        if not any(c.kind == kind for c in constraints):
            constraints.append(AnchorConstraint(kind=kind, raw=m.group(0), line=0))
    # Custom constraint expressions
    for m in re.finditer(r"\bconstraint\s*=\s*([^,\n\]]+)", text):
        constraints.append(AnchorConstraint(kind="constraint", raw=f"constraint = {m.group(1).strip()}", line=0))
    return constraints


def _parse_accounts_struct(name: str, body: str, start_line: int) -> AnchorAccountsStruct:
    """Parse a ``#[derive(Accounts)] pub struct Foo<'info> { ... }`` body."""
    struct = AnchorAccountsStruct(name=name, line=start_line)
    lines = body.splitlines()
    i = 0
    n = len(lines)
    # A pending attribute blob that should be applied to the *next*
    # `pub ...` field declaration we encounter.
    pending_attr_lines: List[str] = []
    pending_attr_start: int = -1
    while i < n:
        ln = lines[i]
        stripped = ln.strip()
        if not stripped or stripped.startswith("//") or stripped == "{" or stripped == "}":
            i += 1
            continue
        if stripped.startswith("#"):
            # New attribute block — starts collecting until bracket depth
            # returns to zero. Capture the start line for diagnostics.
            if not pending_attr_lines:
                pending_attr_start = i
            pending_attr_lines.append(ln)
            depth = ln.count("[") - ln.count("]")
            i += 1
            while depth > 0 and i < n:
                pending_attr_lines.append(lines[i])
                depth += lines[i].count("[") - lines[i].count("]")
                i += 1
            continue
        if stripped.startswith("pub "):
            attr_blob = "\n".join(pending_attr_lines)
            constraint_text = attr_blob + " " + ln
            m = re.match(
                r"^\s*(?:#\[[^\]]+\]\s*)*pub\s+(\w+)\s*:\s*(.+?)\s*,?\s*$",
                ln,
            )
            field_line_idx = i
            if m:
                fname = m.group(1)
                ftype = _strip_strings(m.group(2).strip()).rstrip(",")
                # Anchor constraints — parse from attribute text
                constraints = _parse_constraint_blob(constraint_text)
                is_signer = any(c.kind == "signer" for c in constraints) or "Signer" in ftype
                is_mut = any(c.kind == "mut" for c in constraints)
                is_init = any(c.kind == "init" for c in constraints)
                is_init_if_needed = any(c.kind == "init_if_needed" for c in constraints)
                is_pda = any(c.kind == "seeds" for c in constraints)
                seeds = []
                bump = None
                has_one = []
                owner = None
                address = None
                close = None
                realloc = None
                realloc_payer = None
                realloc_zero = None
                payer = None
                space = None
                constraint_exprs = []
                raw_constraints = []
                for c in constraints:
                    raw_constraints.append(c.raw)
                    if c.kind == "seeds":
                        seed_m = re.search(r"seeds\s*=\s*\[([^\]]*)\]", attr_blob)
                        if seed_m:
                            seeds = [s.strip() for s in seed_m.group(1).split(",") if s.strip()]
                    elif c.kind == "bump":
                        bump_m = re.search(r"\bbump(?:\s*=\s*([\w.]+))?", attr_blob)
                        if bump_m:
                            bump = bump_m.group(1) or ""
                    elif c.kind == "has_one":
                        ho_m = re.findall(r"has_one\s*=\s*(\w+)", attr_blob)
                        has_one = ho_m
                    elif c.kind == "owner":
                        o_m = re.search(r"owner\s*=\s*([^,\]\)]+)", attr_blob)
                        if o_m:
                            owner = o_m.group(1).strip()
                    elif c.kind == "address":
                        a_m = re.search(r"address\s*=\s*([^,\]\)]+)", attr_blob)
                        if a_m:
                            address = a_m.group(1).strip()
                    elif c.kind == "close":
                        cl_m = re.search(r"close\s*=\s*(\w+)", attr_blob)
                        if cl_m:
                            close = cl_m.group(1)
                    elif c.kind == "realloc":
                        r_m = re.search(r"realloc\s*=\s*([^,\]\)]+)", attr_blob)
                        if r_m:
                            realloc = r_m.group(1).strip()
                    elif c.kind == "realloc::payer":
                        rp_m = re.search(r"realloc::payer\s*=\s*([^,\]\)]+)", attr_blob)
                        if rp_m:
                            realloc_payer = rp_m.group(1).strip()
                    elif c.kind == "realloc::zero":
                        rz_m = re.search(r"realloc::zero\s*=\s*([^,\]\)]+)", attr_blob)
                        if rz_m:
                            realloc_zero = rz_m.group(1).strip()
                    elif c.kind == "payer":
                        p_m = re.search(r"(?<!realloc::)payer\s*=\s*([^,\]\)]+)", attr_blob)
                        if p_m:
                            payer = p_m.group(1).strip()
                    elif c.kind == "space":
                        sp_m = re.search(r"space\s*=\s*([^,\]\)]+)", attr_blob)
                        if sp_m:
                            space = sp_m.group(1).strip()
                    elif c.kind == "constraint":
                        expr = re.sub(r"^constraint\s*=\s*", "", c.raw).strip()
                        if expr and expr not in constraint_exprs:
                            constraint_exprs.append(expr)
                type_lower = ftype.lower()
                struct.fields.append(AnchorAccountField(
                    name=fname, type=ftype,
                    is_signer=is_signer, is_mut=is_mut, is_init=is_init,
                    is_init_if_needed=is_init_if_needed,
                    is_pda=is_pda, seeds=seeds, bump=bump,
                    has_one=has_one, owner=owner, address=address,
                    close=close, realloc=realloc,
                    realloc_payer=realloc_payer, realloc_zero=realloc_zero,
                    payer=payer, space=space,
                    raw_constraints=raw_constraints,
                    constraint_exprs=constraint_exprs,
                    line=start_line + field_line_idx,
                    is_unchecked="accountinfo" in type_lower or "uncheckedaccount" in type_lower,
                    is_program="program<" in type_lower or "interface<" in type_lower,
                    is_sysvar="sysvar<" in type_lower or any(name in type_lower for name in ("clock", "rent", "instructions")),
                    is_token_account="tokenaccount" in type_lower,
                    is_mint=bool(re.search(r"\bmint\b", type_lower)),
                    is_interface_account="interfaceaccount" in type_lower,
                    is_token_2022="token2022" in type_lower or "token_2022" in type_lower,
                ))
            # Consume the pending attribute block; it was applied to this
            # field regardless of whether the field matched our regex.
            pending_attr_lines = []
            pending_attr_start = -1
            i += 1
            continue
        # Anything else: reset pending attribute block and advance.
        pending_attr_lines = []
        pending_attr_start = -1
        i += 1
    return struct


def _find_matching_brace(text: str, open_pos: int) -> int:
    """Return index of matching `}` for the `{` at open_pos."""
    depth = 0
    i = open_pos
    while i < len(text):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _find_function_body(text: str, header_end: int) -> Tuple[str, int, int]:
    """Find the body of a function ``fn name(...) { ... }`` starting at header_end."""
    lines = text.splitlines()
    cum = 0
    header_line_idx = 0
    for i, ln in enumerate(lines):
        if cum + len(ln) + 1 > header_end:
            header_line_idx = i
            break
        cum += len(ln) + 1
    body_start = header_line_idx + 1
    body = "\n".join(lines[body_start:body_start + 80])  # heuristic cap
    return body, body_start + 1, body_start + 80


def parse_rust(file_ctx) -> RustProgram:
    """Parse a Rust/Anchor source file."""
    raw = file_ctx.content
    stripped = _strip_comments(raw)
    prog = RustProgram(path=file_ctx.relative_path, raw=raw)

    prog.is_anchor = bool(_USE_ANCHOR_RE.search(raw)) or bool(re.search(r"#\[program\]|#\[account\]|declare_id!", raw))
    prog.is_solana_native = bool(_USE_SOLANA_RE.search(raw)) and not prog.is_anchor

    # declare_id!
    m = _DECLARE_ID_RE.search(raw)
    if m:
        prog.declare_id = m.group(1)

    # #[program] mod name
    m = _PROGRAM_MOD_RE.search(stripped)
    if m:
        prog.program_mod = m.group(1)
        # Walk all #[derive(Accounts)] structs globally (they live in
        # the same crate, not necessarily inside the mod)
    for sm in _STRUCT_HDR_RE.finditer(stripped):
        name = sm.group(1)
        start_line = stripped[:sm.start()].count("\n") + 1
        brace_open = stripped.find("{", sm.end() - 1)
        brace_close = _find_matching_brace(stripped, brace_open)
        if brace_close == -1:
            continue
        body = stripped[brace_open + 1: brace_close]
        struct = _parse_accounts_struct(name, body, start_line)
        prog.accounts_structs[name] = struct

    # Instructions inside the #[program] mod
    if prog.program_mod:
        # Find the program mod body
        mod_match = re.search(rf"#\[program\]\s*\n\s*(?:pub\s+)?mod\s+{re.escape(prog.program_mod)}\s*\{{", stripped)
        if mod_match:
            brace_open = stripped.find("{", mod_match.end() - 1)
            brace_close = _find_matching_brace(stripped, brace_open)
            if brace_close != -1:
                mod_body = stripped[brace_open + 1: brace_close]
                mod_line_start = stripped[:brace_open].count("\n") + 1
                for im in _INSTRUCTION_RE.finditer(mod_body):
                    iname = im.group(1)
                    params = im.group(2).strip()
                    # Extract Context<T>
                    ctx_match = _CONTEXT_TYPE_RE.search(params)
                    struct_name = ctx_match.group(1) if ctx_match else None
                    # Extract other params (skip Context<T>)
                    other_params = re.sub(r"ctx:\s*Context<[^>]+>\s*,?", "", params)
                    other_params = re.sub(r"^\s*,|,\s*$", "", other_params).strip()
                    parsed_params: List[Tuple[str, str]] = []
                    for p in other_params.split(","):
                        p = p.strip()
                        if not p:
                            continue
                        pm = re.match(r"(\w+)\s*:\s*(.+)", p)
                        if pm:
                            parsed_params.append((pm.group(1), pm.group(2).strip()))
                    # Find function body
                    body_open = mod_body.find("{", im.end() - 1)
                    body_close = _find_matching_brace(mod_body, body_open)
                    body = mod_body[body_open + 1: body_close] if body_close != -1 else ""
                    line = mod_line_start + mod_body[:im.start()].count("\n")
                    instr = AnchorInstruction(
                        name=iname,
                        accounts_struct=struct_name,
                        accounts=prog.accounts_structs.get(struct_name) if struct_name else None,
                        params=parsed_params,
                        body=body,
                        line=line,
                    )
                    instr.has_cpi = bool(_INVOKE_RE.search(body))
                    instr.cpi_calls = _INVOKE_RE.findall(body)
                    instr.has_find_pda = bool(_PDA_DERIVE_RE.search(body))
                    instr.has_close = "::close" in body or ".close(" in body
                    instr.has_realloc = "realloc" in body
                    # Capture each CPI call's first argument (program id
                    # expression) for program-id analysis.
                    instr.cpi_program_args = []
                    for cpi_m in _INVOKE_RE.finditer(body):
                        # Search forward for the matching '(' then split
                        # arguments at the comma nearest the top level.
                        open_idx = body.find("(", cpi_m.end() - 1)
                        if open_idx == -1:
                            continue
                        depth = 0
                        close_idx = -1
                        for i in range(open_idx, len(body)):
                            ch = body[i]
                            if ch == "(":
                                depth += 1
                            elif ch == ")":
                                depth -= 1
                                if depth == 0:
                                    close_idx = i
                                    break
                        if close_idx == -1:
                            continue
                        args_text = body[open_idx + 1 : close_idx]
                        # First top-level comma separates program from rest.
                        depth = 0
                        first_split = len(args_text)
                        for i, ch in enumerate(args_text):
                            if ch in "([{":
                                depth += 1
                            elif ch in ")]}":
                                depth -= 1
                            elif ch == "," and depth == 0:
                                first_split = i
                                break
                        instr.cpi_program_args.append(args_text[:first_split].strip())
                    # Per-instruction reload detection
                    instr.has_reload = bool(re.search(r"\.reload\s*\(\s*\)", body))
                    instr.unchecked_arith_ops = len(re.findall(r"\w+\s*[+\-\*]\s*\w+", body))
                    instr.checked_arith_ops = len(re.findall(r"\b(?:checked|saturating|wrapping)_(?:add|sub|mul)\s*\(", body))
                    prog.instructions.append(instr)

    # Global CPA/PDA usage (for non-#[program] files)
    for m in _INVOKE_RE.finditer(stripped):
        line = stripped[:m.start()].count("\n") + 1
        snippet = stripped.split("\n")[line - 1].strip() if line - 1 < len(stripped.split("\n")) else ""
        prog.cpi_invokes.append((line, snippet))
    for m in _PDA_DERIVE_RE.finditer(stripped):
        line = stripped[:m.start()].count("\n") + 1
        snippet = stripped.split("\n")[line - 1].strip() if line - 1 < len(stripped.split("\n")) else ""
        prog.pda_derivations.append((line, snippet))

    return prog
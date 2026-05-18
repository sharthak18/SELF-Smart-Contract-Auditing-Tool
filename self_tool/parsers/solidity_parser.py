"""
SELF — Smart Contract Exploit & Logic Finder
Solidity regex-based parser: extracts structured info from .sol files.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict


@dataclass
class SolFunction:
    name: str
    line: int
    visibility: str          # public, external, internal, private
    mutability: str          # payable, view, pure, ""
    modifiers: List[str]
    params: str
    body: str                # Raw function body
    body_start_line: int
    body_end_line: int
    is_constructor: bool = False
    is_fallback: bool = False
    is_receive: bool = False


@dataclass
class SolStateVar:
    name: str
    type: str
    line: int
    visibility: str
    is_immutable: bool
    is_constant: bool


@dataclass
class SolEvent:
    name: str
    line: int


@dataclass
class SolModifier:
    name: str
    line: int
    body: str


@dataclass
class SolContract:
    name: str
    kind: str               # contract, interface, library, abstract
    line: int
    inherits: List[str]
    functions: List[SolFunction]
    state_vars: List[SolStateVar]
    events: List[SolEvent]
    modifiers: List[SolModifier]
    is_upgradeable: bool = False


@dataclass
class SolidityFileInfo:
    pragma_version: str
    imports: List[str]
    contracts: List[SolContract]
    raw_lines: List[str]
    has_assembly: bool
    compiler_major: int      # 0 = unknown, 4,5,6,7,8
    compiler_minor: int


# ─── Regex Patterns ───────────────────────────────────────────────────────────

RE_PRAGMA = re.compile(r'pragma\s+solidity\s+([^;]+);')
RE_IMPORT = re.compile(r'import\s+[^;]+;')
RE_CONTRACT = re.compile(
    r'^\s*(abstract\s+)?(contract|interface|library)\s+(\w+)'
    r'(?:\s+is\s+([^{]+))?\s*\{',
    re.MULTILINE
)
RE_FUNCTION = re.compile(
    r'function\s+(\w+)\s*\(([^)]*)\)\s*([^{;]*)',
    re.MULTILINE
)
RE_CONSTRUCTOR = re.compile(r'constructor\s*\(([^)]*)\)\s*([^{;]*)', re.MULTILINE)
RE_MODIFIER_DEF = re.compile(r'modifier\s+(\w+)\s*\(([^)]*)\)', re.MULTILINE)
RE_STATE_VAR = re.compile(
    r'^\s*([\w\[\]<>,\s]+?)\s+(public|private|internal|external)?\s*'
    r'(immutable\s+|constant\s+)?(\w+)\s*[=;]',
    re.MULTILINE
)
RE_EVENT = re.compile(r'event\s+(\w+)\s*\(', re.MULTILINE)
RE_ASSEMBLY = re.compile(r'\bassembly\b\s*\{')
RE_VISIBILITY = re.compile(r'\b(public|external|internal|private)\b')
RE_MUTABILITY = re.compile(r'\b(payable|view|pure)\b')
RE_MODIFIER_USE = re.compile(r'\b(onlyOwner|onlyRole|onlyAdmin|nonReentrant|whenNotPaused|initializer|[\w]+)\b')


def parse_solidity(file_ctx) -> SolidityFileInfo:
    """Parse a Solidity file into structured SolidityFileInfo."""
    content = file_ctx.content
    lines = file_ctx.lines

    # Pragma
    pragma_version = ""
    compiler_major, compiler_minor = 0, 0
    pragma_match = RE_PRAGMA.search(content)
    if pragma_match:
        pragma_version = pragma_match.group(1).strip()
        ver_m = re.search(r'(\d+)\.(\d+)', pragma_version)
        if ver_m:
            compiler_major = int(ver_m.group(1))
            compiler_minor = int(ver_m.group(2))

    # Imports
    imports = [m.group(0) for m in RE_IMPORT.finditer(content)]

    # Assembly usage
    has_assembly = bool(RE_ASSEMBLY.search(content))

    # Strip comments for cleaner analysis (but keep line numbers)
    clean_content, comment_ranges = _strip_comments(content)
    clean_lines = clean_content.splitlines()

    # Parse contracts
    contracts = _parse_contracts(content, clean_content, lines)

    return SolidityFileInfo(
        pragma_version=pragma_version,
        imports=imports,
        contracts=contracts,
        raw_lines=lines,
        has_assembly=has_assembly,
        compiler_major=compiler_major,
        compiler_minor=compiler_minor,
    )


def _strip_comments(content: str) -> Tuple[str, List[Tuple[int, int]]]:
    """Remove // and /* */ comments, preserving line structure."""
    result = []
    ranges = []
    i = 0
    in_string = False
    string_char = None
    in_block = False

    while i < len(content):
        if in_block:
            if content[i:i+2] == '*/':
                result.append('  ')
                i += 2
                in_block = False
            else:
                result.append(' ' if content[i] != '\n' else '\n')
                i += 1
        elif in_string:
            result.append(content[i])
            if content[i] == '\\':
                i += 1
                if i < len(content):
                    result.append(content[i])
            elif content[i] == string_char:
                in_string = False
            i += 1
        elif content[i] in ('"', "'"):
            in_string = True
            string_char = content[i]
            result.append(content[i])
            i += 1
        elif content[i:i+2] == '/*':
            in_block = True
            result.append('  ')
            i += 2
        elif content[i:i+2] == '//':
            # Line comment: blank until newline
            while i < len(content) and content[i] != '\n':
                result.append(' ')
                i += 1
        else:
            result.append(content[i])
            i += 1

    return ''.join(result), ranges


def _get_line_number(content: str, pos: int) -> int:
    """Get 1-indexed line number from character position."""
    return content[:pos].count('\n') + 1


def _extract_braces_body(content: str, start_pos: int) -> Tuple[str, int, int]:
    """Extract content between matching braces starting from start_pos (at '{')."""
    depth = 0
    i = start_pos
    in_string = False
    string_char = None
    body_start = -1

    while i < len(content):
        c = content[i]
        if in_string:
            if c == '\\':
                i += 2
                continue
            elif c == string_char:
                in_string = False
        elif c in ('"', "'"):
            in_string = True
            string_char = c
        elif c == '{':
            if depth == 0:
                body_start = i
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                body = content[body_start:i+1]
                end_line = _get_line_number(content, i)
                return body, body_start, i
        i += 1
    return "", -1, -1


def _parse_contracts(raw: str, clean: str, raw_lines: List[str]) -> List[SolContract]:
    contracts = []

    for m in RE_CONTRACT.finditer(clean):
        is_abstract = bool(m.group(1))
        kind = m.group(2)
        if is_abstract:
            kind = "abstract"
        name = m.group(3)
        inherits_raw = m.group(4) or ""
        inherits = [x.strip() for x in inherits_raw.split(',') if x.strip()]
        line = _get_line_number(clean, m.start())

        # Extract contract body
        brace_pos = clean.find('{', m.start())
        if brace_pos == -1:
            continue
        body, body_start, body_end = _extract_braces_body(clean, brace_pos)
        if not body:
            continue

        contract_raw_body = raw[brace_pos:body_end+1] if body_end < len(raw) else body

        # Detect upgradeability
        is_upgradeable = bool(re.search(
            r'(Initializable|UUPSUpgradeable|TransparentUpgradeableProxy|initialize\s*\()',
            contract_raw_body
        ))

        # Parse functions in body
        functions = _parse_functions(contract_raw_body, brace_pos, raw)
        modifiers = _parse_modifiers(contract_raw_body, brace_pos, raw)
        state_vars = _parse_state_vars(contract_raw_body, line)
        events = _parse_events(contract_raw_body, brace_pos, raw)

        contracts.append(SolContract(
            name=name,
            kind=kind,
            line=line,
            inherits=inherits,
            functions=functions,
            state_vars=state_vars,
            events=events,
            modifiers=modifiers,
            is_upgradeable=is_upgradeable,
        ))

    return contracts


def _parse_functions(body: str, offset: int, full_raw: str) -> List[SolFunction]:
    funcs = []

    for m in RE_FUNCTION.finditer(body):
        fname = m.group(1)
        params = m.group(2)
        attrs = m.group(3) or ""

        # Find visibility
        vis_m = RE_VISIBILITY.search(attrs)
        visibility = vis_m.group(1) if vis_m else "internal"

        # Find mutability
        mut_m = RE_MUTABILITY.search(attrs)
        mutability = mut_m.group(1) if mut_m else ""

        # Find modifiers (everything that's not a keyword)
        keywords = {"public", "external", "internal", "private", "payable", "view",
                    "pure", "returns", "virtual", "override", "memory", "storage",
                    "calldata"}
        modifier_words = [
            w for w in re.findall(r'\b\w+\b', attrs)
            if w not in keywords and not w[0].isupper() or w in ("onlyOwner",)
        ]
        modifiers = modifier_words

        # Find function body
        func_pos = m.start()
        brace_pos = body.find('{', func_pos + len(m.group(0)))
        func_body = ""
        body_start_line = 0
        body_end_line = 0
        if brace_pos != -1:
            fb, fb_start, fb_end = _extract_braces_body(body, brace_pos)
            func_body = fb
            abs_start = offset + brace_pos
            body_start_line = full_raw[:abs_start].count('\n') + 1
            abs_end = offset + fb_end if fb_end != -1 else abs_start
            body_end_line = full_raw[:abs_end].count('\n') + 1

        abs_pos = offset + func_pos
        line = full_raw[:abs_pos].count('\n') + 1

        funcs.append(SolFunction(
            name=fname,
            line=line,
            visibility=visibility,
            mutability=mutability,
            modifiers=modifiers,
            params=params,
            body=func_body,
            body_start_line=body_start_line,
            body_end_line=body_end_line,
        ))

    # Constructors
    for m in RE_CONSTRUCTOR.finditer(body):
        params = m.group(1)
        attrs = m.group(2) or ""
        abs_pos = offset + m.start()
        line = full_raw[:abs_pos].count('\n') + 1
        brace_pos = body.find('{', m.start())
        func_body = ""
        if brace_pos != -1:
            fb, _, _ = _extract_braces_body(body, brace_pos)
            func_body = fb
        funcs.append(SolFunction(
            name="constructor",
            line=line,
            visibility="public",
            mutability="",
            modifiers=[],
            params=params,
            body=func_body,
            body_start_line=line,
            body_end_line=line,
            is_constructor=True,
        ))

    return funcs


def _parse_modifiers(body: str, offset: int, full_raw: str) -> List[SolModifier]:
    mods = []
    for m in RE_MODIFIER_DEF.finditer(body):
        name = m.group(1)
        abs_pos = offset + m.start()
        line = full_raw[:abs_pos].count('\n') + 1
        brace_pos = body.find('{', m.start())
        mod_body = ""
        if brace_pos != -1:
            mb, _, _ = _extract_braces_body(body, brace_pos)
            mod_body = mb
        mods.append(SolModifier(name=name, line=line, body=mod_body))
    return mods


def _parse_state_vars(body: str, contract_line: int) -> List[SolStateVar]:
    """Simple heuristic extraction of state variables."""
    vars_ = []
    # Match lines that look like state variable declarations
    pattern = re.compile(
        r'^\s{4}((?:mapping\s*\([^)]+\)|[\w\[\]]+(?:\s*\[\s*\])?(?:\s+\w+)?'
        r'(?:\s*<[^>]+>)?)\s+)?(public|private|internal|external)?\s*'
        r'(immutable|constant)?\s+(\w+)\s*[=;]',
        re.MULTILINE
    )
    for m in pattern.finditer(body):
        typ = (m.group(1) or "").strip()
        visibility = m.group(2) or "internal"
        special = m.group(3) or ""
        name = m.group(4)
        if name in ("function", "event", "modifier", "struct", "enum", "mapping"):
            continue
        vars_.append(SolStateVar(
            name=name,
            type=typ,
            line=contract_line,
            visibility=visibility,
            is_immutable="immutable" in special,
            is_constant="constant" in special,
        ))
    return vars_


def _parse_events(body: str, offset: int, full_raw: str) -> List[SolEvent]:
    events = []
    for m in RE_EVENT.finditer(body):
        abs_pos = offset + m.start()
        line = full_raw[:abs_pos].count('\n') + 1
        events.append(SolEvent(name=m.group(1), line=line))
    return events


# ─── Utility helpers for detectors ───────────────────────────────────────────

def find_pattern_lines(content: str, pattern: re.Pattern) -> List[Tuple[int, str]]:
    """Return list of (line_number, matched_line) for all regex matches."""
    results = []
    for m in pattern.finditer(content):
        line_num = content[:m.start()].count('\n') + 1
        line_content = content.splitlines()[line_num - 1] if line_num <= len(content.splitlines()) else ""
        results.append((line_num, line_content))
    return results


def get_function_at_line(contracts: List[SolContract], line: int) -> Optional[SolFunction]:
    """Find which function a given line number belongs to."""
    for contract in contracts:
        for func in contract.functions:
            if func.body_start_line <= line <= func.body_end_line:
                return func
    return None

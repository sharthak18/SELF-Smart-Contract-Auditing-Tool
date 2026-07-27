"""
SELF — Smart Contract Exploit & Logic Finder
Vyper regex-based parser: extracts structured info from .vy files.

Vyper syntax is whitespace-significant (like Python), so we lean on
indentation to find function bodies. We support Vyper >=0.3.0 (current
syntax) with backward compatibility for the Curve-era 0.2.x.
"""
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict


@dataclass
class VyperFunction:
    name: str
    line: int
    visibility: str          # external, public, internal, default
    mutability: str          # nonpayable, payable, view, pure, "", default
    decorators: List[str]    # @nonreentrant, @view, @payable, @external, @internal, @public
    params: str
    body: str
    body_start_line: int
    body_end_line: int
    is_constructor: bool = False   # __init__
    is_default: bool = False       # __default__


@dataclass
class VyperStateVar:
    name: str
    type: str
    line: int
    is_constant: bool = False
    is_immutable: bool = False
    is_public: bool = False


@dataclass
class VyperContract:
    name: str
    version: Optional[str]          # from "# @version"
    functions: List[VyperFunction] = field(default_factory=list)
    state_vars: List[VyperStateVar] = field(default_factory=list)
    raw: str = ""
    imports: List[str] = field(default_factory=list)
    interfaces: List[str] = field(default_factory=list)


@dataclass
class VyperFileInfo:
    path: str
    contracts: List[VyperContract] = field(default_factory=list)
    raw: str = ""
    version: Optional[str] = None


# ── helpers ──────────────────────────────────────────────────────────────
_VERSION_RE = re.compile(r"#\s*@version\s+([\d.]+)")
_INTERFACE_RE = re.compile(r"^interface\s+([A-Za-z_]\w*)\s*:", re.MULTILINE)
_IMPORT_RE = re.compile(r"^from\s+(\S+)\s+import\s+(.+)$", re.MULTILINE)
# State variables: type at line start, optional "public", variable name
# Vyper 0.3.x:  counter: public(uint256)   ← name then `public(type)`
# Vyper 0.2.x:  counter: uint256(public)   ← type then `name(public)`
# Also plain:    counter: uint256            (no public)
_STATE_VAR_RE = re.compile(
    r"^(?P<lhs>[A-Za-z_][\w\[\],()\s]*?)\s*:\s*"
    r"(?:public\((?P<pub_type>[^)]+)\)|(?P<rhs>[^=\n]+?)(?:\s*=\s*[^#\n]+)?)"
    r"\s*$",
    re.MULTILINE,
)
# Function header:
#   @external
#   @nonreentrant
#   @view
#   def foo(arg1: uint256, arg2: address) -> uint256:
_FUNC_HEADER_RE = re.compile(
    r"^(?:@(?P<deco>\w+)\s*\n)*"
    r"def\s+(?P<name>__init__|__default__|[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*"
    r"(?:->\s*(?P<ret>[^:]+))?\s*:",
    re.MULTILINE,
)
_BLANK_OR_COMMENT = re.compile(r"^\s*(#.*)?$")


def _strip_comments(content: str) -> str:
    """Remove # comments — Vyper has no block comments, only `#`."""
    out = []
    for line in content.splitlines():
        # Strip trailing comment, but not inside strings
        in_str = False
        for i, ch in enumerate(line):
            if ch == '"':
                in_str = not in_str
            elif ch == "#" and not in_str:
                line = line[:i]
                break
        out.append(line)
    return "\n".join(out)


def _find_function_body(text: str, header_end: int) -> tuple[str, int, int]:
    """Vyper uses indentation. Find the body of the function starting
    at the *next* line after `header_end` (which is the line of `:`).

    Returns (body_text, start_line, end_line).
    """
    lines = text.splitlines()
    # Find which line index `header_end` is on
    cum = 0
    header_line_idx = 0
    for i, ln in enumerate(lines):
        if cum + len(ln) + 1 > header_end:
            header_line_idx = i
            break
        cum += len(ln) + 1
    body_start = header_line_idx + 1
    if body_start >= len(lines):
        return "", body_start + 1, body_start + 1
    # Next non-blank line determines indentation
    base_idx = body_start
    while base_idx < len(lines) and _BLANK_OR_COMMENT.match(lines[base_idx]):
        base_idx += 1
    if base_idx >= len(lines):
        return "", body_start + 1, body_start + 1
    indent = len(lines[base_idx]) - len(lines[base_idx].lstrip())
    # Body continues while lines are at indent >= base indent OR are blank
    i = base_idx
    while i < len(lines):
        ln = lines[i]
        if _BLANK_OR_COMMENT.match(ln):
            i += 1
            continue
        cur_indent = len(ln) - len(ln.lstrip())
        if cur_indent < indent:
            break
        i += 1
    body_end = i
    body = "\n".join(lines[body_start:body_end])
    return body, body_start + 1, body_end  # line numbers are 1-indexed


def _parse_vyper_contract(content: str, name: str, version: Optional[str]) -> VyperContract:
    contract = VyperContract(name=name, version=version, raw=content)
    stripped = _strip_comments(content)

    # Imports
    for m in _IMPORT_RE.finditer(stripped):
        contract.imports.append(m.group(1))

    # Interfaces
    for m in _INTERFACE_RE.finditer(stripped):
        contract.interfaces.append(m.group(1))

    # State vars (skip lines inside function bodies — we only catch top-level)
    # Heuristic: state vars are at column 0, no `def` keyword, and the `lhs`
    # should be a single identifier (not a multi-word phrase from a docstring).
    for m in _STATE_VAR_RE.finditer(stripped):
        line = m.group(0)
        if "def " in line:
            continue
        lhs = m.group("lhs").strip()
        # State-var name must be a single identifier (no spaces, no commas)
        if not re.match(r"^[A-Za-z_]\w*$", lhs):
            continue
        pub_type = m.group("pub_type")
        rhs = m.group("rhs")
        if pub_type is not None:
            # Form: `name: public(type)` — lhs is the var name
            var_name = lhs
            clean_type = pub_type.strip()
            is_public = True
        elif rhs is not None:
            # Form: `name: type` or `name: type(public)` — lhs is the var name
            rhs = rhs.strip()
            m2 = re.match(r"^(.+?)\s*\(\s*public\s*\)\s*$", rhs)
            if m2:
                var_name = lhs
                clean_type = m2.group(1).strip()
                is_public = True
            else:
                var_name = lhs
                clean_type = re.split(r"\s*=\s*", rhs)[0].strip()
                is_public = False
        else:
            continue
        if not var_name or not clean_type:
            continue
        is_constant = clean_type.startswith("constant ") or clean_type.startswith("constant(")
        is_immutable = clean_type.startswith("immutable ") or clean_type.startswith("immutable(")
        clean_type = re.sub(r"^(constant|immutable)\s*\(*", "", clean_type).rstrip(")")
        line_no = stripped[: m.start()].count("\n") + 1
        contract.state_vars.append(VyperStateVar(
            name=var_name, type=clean_type, line=line_no,
            is_constant=is_constant, is_immutable=is_immutable, is_public=is_public,
        ))

    # Functions
    lines_list = stripped.splitlines()
    for m in _FUNC_HEADER_RE.finditer(stripped):
        decorators = []
        # m.start() may be at the first @decorator or at `def`. The regex
        # captures the LAST decorator on the line immediately before `def`.
        # Walk forward collecting @decorator lines until we hit `def`.
        prefix = stripped[:m.start()]
        line_idx = prefix.count("\n")
        # Collect decorator lines starting at line_idx (could be @external or def)
        # If line_idx's line is a decorator, that's our starting point
        first_line = lines_list[line_idx] if line_idx < len(lines_list) else ""
        if first_line.lstrip().startswith("@"):
            # Scan forward through contiguous decorator lines
            i = line_idx
            while i < len(lines_list):
                ln = lines_list[i]
                stripped_ln = ln.strip()
                if stripped_ln.startswith("@") and not stripped_ln.startswith("#"):
                    m_deco = re.match(r"@(\w+)", stripped_ln)
                    if m_deco:
                        decorators.append(m_deco.group(1))
                    i += 1
                else:
                    break
        decorators = list(dict.fromkeys(decorators))  # dedupe, preserve order
        fname = m.group("name")
        params = m.group("params").strip()
        header_end = m.end()
        body, body_start, body_end = _find_function_body(stripped, header_end)

        # Derive visibility from decorators
        if "external" in decorators:
            visibility = "external"
        elif "internal" in decorators:
            visibility = "internal"
        elif "public" in decorators:
            visibility = "public"
        elif fname in ("__init__", "__default__"):
            visibility = "default"
        else:
            visibility = "default"  # Vyper 0.2.x: default = public for top-level

        # Derive mutability
        if "view" in decorators or "pure" in decorators:
            mutability = "view" if "view" in decorators else "pure"
        elif "payable" in decorators:
            mutability = "payable"
        elif "nonpayable" in decorators:
            mutability = "nonpayable"
        else:
            mutability = ""

        line_no = stripped[: m.start()].count("\n") + 1
        is_ctor = fname == "__init__"
        is_default = fname == "__default__"
        contract.functions.append(VyperFunction(
            name=fname, line=line_no, visibility=visibility,
            mutability=mutability, decorators=decorators,
            params=params, body=body,
            body_start_line=body_start, body_end_line=body_end,
            is_constructor=is_ctor, is_default=is_default,
        ))
    return contract


def parse_vyper(file_ctx) -> VyperFileInfo:
    """Parse a Vyper source file. `file_ctx` is a FileContext with
    `.content` and `.relative_path` attributes.
    """
    content = file_ctx.content
    version_m = _VERSION_RE.search(content)
    version = version_m.group(1) if version_m else None

    info = VyperFileInfo(path=file_ctx.relative_path, raw=content, version=version)
    # Vyper files (unlike Solidity) typically define one contract per file
    # at the top level. We use the filename as the contract name.
    from pathlib import Path
    name = Path(file_ctx.relative_path).stem
    contract = _parse_vyper_contract(content, name, version)
    info.contracts.append(contract)
    return info

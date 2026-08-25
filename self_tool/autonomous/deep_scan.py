"""Per-function deep pass — Slither/Aderyn-class sinks without a compiler IR.

SELF already ships 161 static detectors. This module exists so the
autonomous reasoner can *name* the same high-signal classes those tools
are famous for, using extracted function bodies instead of OR-ing the
whole repo.

No catalog detectors. Facts and location only.
"""

from __future__ import annotations

import re
from typing import Dict, Optional, Sequence, Tuple

from self_tool.autonomous.models import ExtractedContract, ExtractedFunction


AUTH_RE = re.compile(
    r"msg\.sender\s*==|require\s*\(\s*msg\.sender|onlyOwner|onlyRole|hasRole|"
    r"onlyAdmin|onlyGovernance|_checkOwner|_msgSender\s*\(\s*\)\s*==|"
    r"get_caller_address|msg_sender\s*\(",
    re.IGNORECASE,
)
TRANSFER_FROM_RE = re.compile(
    r"\.(?:safe)?transferFrom\s*\(\s*([^,\s]+)\s*,",
    re.IGNORECASE,
)
ETH_SEND_RE = re.compile(
    r"(?:payable\s*\(\s*([^)]+)\s*\)\s*\.(?:transfer|send)\s*\(|"
    r"([^.\s(]+)\s*\.call\s*\{[^}]*value\s*:)",
    re.IGNORECASE,
)
MSG_SENDER_ETH_RE = re.compile(
    r"payable\s*\(\s*msg\.sender\s*\)|msg\.sender\.transfer|msg\.sender\.call\s*\{",
    re.IGNORECASE,
)
MSG_VALUE_LOOP_RE = re.compile(
    r"for\s*\((?:[^()]|\([^()]*\)){0,240}\)[^{]{0,80}\{[\s\S]{0,1200}?msg\.value",
    re.IGNORECASE,
)
ENCODE_PACKED_RE = re.compile(
    r"abi\.encodePacked\s*\(([^)]{0,400})\)",
    re.IGNORECASE,
)
UNCHECKED_CALL_RE = re.compile(
    r"(?:\.call\s*\{|\.call\s*\(|\.send\s*\()[^;]{0,240};",
    re.IGNORECASE,
)
CHECKED_CALL_RE = re.compile(
    r"require\s*\(\s*!?\s*(?:ok|success|sent|result)\s*\)|"
    r"if\s*\(\s*!?\s*(?:ok|success|sent|result)\s*\)|"
    r"assert\s*\(\s*(?:ok|success|sent|result)\s*\)",
    re.IGNORECASE,
)
BALANCE_EQ_RE = re.compile(
    r"(?:==|!=)\s*(?:address\s*\(\s*this\s*\)\s*\.balance|balanceOf\s*\()|"
    r"(?:address\s*\(\s*this\s*\)\s*\.balance|balanceOf\s*\([^)]*\))\s*(?:==|!=)",
)
ETH_OUT_RE = re.compile(
    r"call\s*\{[^}]*value|\.send\s*\(|payable\s*\([^)]*\)\s*\.(?:transfer|send)\s*\(",
    re.IGNORECASE,
)
WITHDRAW_NAME_RE = re.compile(
    r"function\s+(withdraw|rescue|sweep|claim|harvest|undeploy|cashout)\b",
    re.IGNORECASE,
)
RECEIVE_RE = re.compile(
    r"receive\s*\(\s*\)\s*external\s+payable|fallback\s*\(\s*\)\s*external\s+payable|"
    r"function\s+receive\s*\(",
    re.IGNORECASE,
)
STRUCT_RE = re.compile(r"struct\s+(\w+)\s*\{([^}]*)\}", re.DOTALL)
MAPPING_TO_RE = re.compile(
    r"mapping\s*\([^)]*?=>\s*(\w+)\s*\)\s*(?:public|private|internal|external)?\s*(\w+)",
)
DELETE_INDEX_RE = re.compile(r"\bdelete\s+(\w+)\s*\[")
_SKIP_FUNCS = {"constructor", "receive", "fallback", "__default__", "__init__"}


def deep_facts(contracts: Sequence[ExtractedContract], combined: str) -> Dict[str, bool]:
    functions = [func for contract in contracts for func in contract.functions]
    public = [func for func in functions if _is_public(func) and func.name.lower() not in _SKIP_FUNCS]
    unauth = [func for func in public if not _is_authed(func)]

    return {
        "arbitrary_erc20_from": any(_arbitrary_transfer_from(func) for func in unauth),
        "arbitrary_eth_receiver": any(_arbitrary_eth_send(func) for func in unauth),
        "msg_value_in_loop": any(MSG_VALUE_LOOP_RE.search(func.body or "") for func in public)
            or bool(MSG_VALUE_LOOP_RE.search(combined)),
        "locked_ether": _locked_ether(combined, functions),
        "encode_packed_collision": any(_packed_collision(func) for func in functions)
            or _packed_collision_text(combined),
        "unchecked_lowlevel_call": any(_unchecked_call(func) for func in public),
        "balance_strict_eq": any(BALANCE_EQ_RE.search(func.body or "") for func in public),
        "mapping_delete_struct": _mapping_delete(combined, functions),
    }


def locate_deep(
    contracts: Sequence[ExtractedContract],
    fact: str,
    combined: str = "",
) -> Optional[Tuple[str, int, str, str]]:
    """Return (file, line, language, Contract.fn) for the first function matching *fact*."""
    functions = [func for contract in contracts for func in contract.functions]
    public = [func for func in functions if _is_public(func) and func.name.lower() not in _SKIP_FUNCS]
    unauth = [func for func in public if not _is_authed(func)]

    checkers = {
        "arbitrary_erc20_from": (unauth, _arbitrary_transfer_from),
        "arbitrary_eth_receiver": (unauth, _arbitrary_eth_send),
        "msg_value_in_loop": (public, lambda f: bool(MSG_VALUE_LOOP_RE.search(f.body or ""))),
        "encode_packed_collision": (functions, _packed_collision),
        "unchecked_lowlevel_call": (public, _unchecked_call),
        "balance_strict_eq": (public, lambda f: bool(BALANCE_EQ_RE.search(f.body or ""))),
        "mapping_delete_struct": (functions, lambda f: _mapping_delete(combined, [f])),
        "locked_ether": (
            functions,
            lambda f: f.name.lower() in {"receive", "fallback"} or bool(RECEIVE_RE.search(f.body or "")),
        ),
    }
    pool, pred = checkers.get(fact, ((), None))
    if pred is None:
        return None
    for func in pool:
        if pred(func):
            return func.file, func.line, func.language, f"{func.contract}.{func.name}"
    return None


def _is_public(func: ExtractedFunction) -> bool:
    return func.visibility in {"public", "external", "default", ""} or func.language in {
        "rust", "move", "cairo", "sway", "tact", "huff",
    }


def _is_authed(func: ExtractedFunction) -> bool:
    mods = {item.lower() for item in func.modifiers}
    if any(item.startswith("only") or item.endswith("auth") or item.endswith("role") for item in mods):
        return True
    blob = f"{func.params}\n{func.body}"
    return bool(AUTH_RE.search(blob))


def _param_names(func: ExtractedFunction) -> set:
    names = set()
    cleaned = (func.params or "").replace(" memory", " ").replace(" calldata", " ").replace(" storage", " ")
    for piece in cleaned.split(","):
        tokens = piece.strip().split()
        if not tokens:
            continue
        name = tokens[-1].lstrip("_")
        if re.match(r"^[A-Za-z_]\w*$", name):
            names.add(name)
            names.add(tokens[-1])
    return names


def _typed_params(func: ExtractedFunction) -> Dict[str, str]:
    out: Dict[str, str] = {}
    cleaned = (func.params or "").replace(" memory", " ").replace(" calldata", " ").replace(" storage", " ")
    for piece in cleaned.split(","):
        tokens = piece.strip().split()
        if len(tokens) < 2:
            continue
        name = tokens[-1]
        out[name] = tokens[0]
        out[name.lstrip("_")] = tokens[0]
    return out


def _arbitrary_transfer_from(func: ExtractedFunction) -> bool:
    params = _param_names(func)
    if not params:
        return False
    for match in TRANSFER_FROM_RE.finditer(func.body or ""):
        source = match.group(1).strip()
        if source in {"msg.sender", "_msgSender()", "address(this)", "address (this)"}:
            continue
        bare = source.split(".")[0].strip().lstrip("_")
        if bare in params or source in params or source.lstrip("_") in params:
            return True
    return False


def _arbitrary_eth_send(func: ExtractedFunction) -> bool:
    params = _param_names(func)
    body = func.body or ""
    if not params:
        return False
    if MSG_SENDER_ETH_RE.search(body) and not ETH_SEND_RE.search(body):
        return False
    for match in ETH_SEND_RE.finditer(body):
        target = (match.group(1) or match.group(2) or "").strip()
        if not target or target in {"msg.sender", "address(this)", "owner", "_owner"}:
            continue
        bare = target.split(".")[0].strip()
        if bare in params or target.lstrip("_") in params:
            return True
    return False


def _packed_collision(func: ExtractedFunction) -> bool:
    if _packed_collision_text(func.body or ""):
        return True
    types = _typed_params(func)
    dynamic = {name for name, typ in types.items() if typ.lower() in {"string", "bytes"}}
    if len(dynamic) < 2:
        return False
    for match in ENCODE_PACKED_RE.finditer(func.body or ""):
        args = match.group(1)
        used = [name for name in dynamic if re.search(rf"\b{re.escape(name)}\b", args)]
        if len(set(used)) >= 2:
            return True
    return False


def _packed_collision_text(text: str) -> bool:
    for match in ENCODE_PACKED_RE.finditer(text or ""):
        if len(re.findall(r"\b(?:string|bytes)\b", match.group(1), re.IGNORECASE)) >= 2:
            return True
    return False


def _unchecked_call(func: ExtractedFunction) -> bool:
    body = func.body or ""
    if not UNCHECKED_CALL_RE.search(body):
        return False
    if CHECKED_CALL_RE.search(body):
        return False
    return True


def _locked_ether(combined: str, functions: Sequence[ExtractedFunction]) -> bool:
    if not RECEIVE_RE.search(combined):
        return False
    if WITHDRAW_NAME_RE.search(combined):
        return False
    if ETH_OUT_RE.search(combined):
        return False
    for func in functions:
        if ETH_OUT_RE.search(func.body or ""):
            return False
    return True


def _mapping_delete(combined: str, functions: Sequence[ExtractedFunction]) -> bool:
    structs_with_map = set()
    for match in STRUCT_RE.finditer(combined or ""):
        if re.search(r"\bmapping\s*\(", match.group(2)):
            structs_with_map.add(match.group(1))
    if not structs_with_map:
        return False
    map_names = {
        match.group(2)
        for match in MAPPING_TO_RE.finditer(combined or "")
        if match.group(1) in structs_with_map
    }
    if not map_names:
        return False
    for func in functions:
        for match in DELETE_INDEX_RE.finditer(func.body or ""):
            if match.group(1) in map_names:
                return True
    return any(re.search(rf"\bdelete\s+{re.escape(name)}\s*\[", combined or "") for name in map_names)

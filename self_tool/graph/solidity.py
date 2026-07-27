"""Solidity facts for the project semantic graph.

This extractor only emits edges it can support with source evidence.
Dynamic calls (``address(x).call`` or a call through an unresolved
interface variable) are marked unresolved by the builder.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from self_tool.core.fingerprints import source_context_hash
from self_tool.core.scanner import FileContext
from self_tool.graph.model import Edge, EvidenceLink, Node, UnresolvedEdge
from self_tool.parsers.solidity_parser import parse_solidity


_IMPORT_PATH_RE = re.compile(r'import\s+(?:[^"\']+\s+from\s+)?["\']([^"\']+)["\']\s*;')
_MEMBER_CALL_RE = re.compile(r'\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(')
_DIRECT_CALL_RE = re.compile(r'(?<!\.)\b([A-Za-z_]\w*)\s*\(')
_LOW_LEVEL = {"call", "delegatecall", "staticcall", "send", "transfer"}
_IGNORE_CALLS = {
    "require", "assert", "revert", "keccak256", "abi", "type", "emit",
    "if", "for", "while", "return", "new", "delete", "unchecked",
}
_WRITE_RE = re.compile(
    r'(?<![\w.])([A-Za-z_]\w*)(?:\s*\[[^\]]*\])?\s*(?:\+?=|-=|\*=|\/=|<<=|\|=|\^=|&=)'
)


def _strip_line_comments(body: str) -> str:
    """Replace // comments with spaces while preserving line numbers.

    Block comments are not stripped here — the parser already passes
    comment-stripped bodies for analysis at higher levels. This is a
    conservative backstop so a single-line ``// foo = bar`` cannot
    become a write edge.
    """
    out = []
    i = 0
    while i < len(body):
        if body[i:i+2] == "//":
            j = body.find("\n", i)
            if j == -1:
                out.append(" " * (len(body) - i))
                break
            out.append(" " * (j - i))
            i = j
        else:
            out.append(body[i])
            i += 1
    return "".join(out)


def node_id(file: str, kind: str, name: str) -> str:
    safe = file.replace("\\", "/")
    return f"{kind}:{safe}:{name}"


def _evidence(ctx: FileContext, start: int, end: int, snippet: str) -> EvidenceLink:
    return EvidenceLink(
        file=ctx.relative_path,
        start_line=start,
        end_line=end,
        text_hash=source_context_hash(ctx.relative_path, start, end, snippet),
        snippet=snippet.strip()[:240],
    )


@dataclass
class SolidityFacts:
    nodes: List[Node] = field(default_factory=list)
    edges: List[Edge] = field(default_factory=list)
    imports: List[Tuple[str, str, int]] = field(default_factory=list)
    inherits: List[Tuple[str, str, str, int]] = field(default_factory=list)
    calls: List[Tuple[str, str, str, str, int]] = field(default_factory=list)
    writes: List[Tuple[str, str, int]] = field(default_factory=list)
    function_bodies: Dict[str, str] = field(default_factory=dict)
    fn_namespace: Dict[str, Set[str]] = field(default_factory=dict)


def extract_solidity_facts(ctx: FileContext) -> SolidityFacts:
    info = parse_solidity(ctx)
    facts = SolidityFacts()
    if ctx.language != "solidity":
        return facts
    file_node = node_id(ctx.relative_path, "file", ctx.relative_path)
    facts.nodes.append(Node(file_node, "file", ctx.relative_path, ctx.relative_path, (1, ctx.line_count)))

    for raw in info.imports:
        path_match = _IMPORT_PATH_RE.search(raw)
        if path_match:
            line = ctx.content[:ctx.content.find(raw)].count("\n") + 1
            facts.imports.append((file_node, path_match.group(1), line))

    contract_ids: Dict[str, str] = {}
    for contract in info.contracts:
        cid = node_id(ctx.relative_path, contract.kind, contract.name)
        contract_ids[contract.name] = cid
        facts.nodes.append(Node(
            cid, contract.kind, contract.name, ctx.relative_path, (contract.line, contract.line),
            {
                "inherits": list(contract.inherits),
                "is_upgradeable": contract.is_upgradeable,
            },
        ))
        facts.edges.append(Edge(
            "declared_in", cid, file_node, 1.0,
            (_evidence(ctx, contract.line, contract.line, ctx.get_line(contract.line)),),
        ))
        for base in contract.inherits:
            facts.inherits.append((cid, base.split("(", 1)[0].strip(), ctx.relative_path, contract.line))

        # Build a name set that includes both this contract's functions
        # and every other contract in the same file. Cross-contract calls
        # in the same file can resolve to inherited functions.
        fn_names: Set[str] = {fn.name for fn in contract.functions}
        all_in_file = {
            fn.name for other in info.contracts for fn in other.functions
        }
        cross_names = all_in_file - fn_names
        facts.fn_namespace[cid] = fn_names | cross_names

        for fn in contract.functions:
            signature = _function_signature(fn.name, fn.params)
            fid = node_id(ctx.relative_path, "function", f"{contract.name}.{signature}")
            facts.nodes.append(Node(
                fid, "function", fn.name, ctx.relative_path,
                (fn.line, max(fn.body_end_line, fn.line)),
                {
                    "contract": contract.name,
                    "signature": signature,
                    "visibility": fn.visibility,
                    "mutability": fn.mutability,
                    "modifiers": list(fn.modifiers),
                    "is_constructor": fn.is_constructor,
                    "is_fallback": fn.is_fallback,
                    "is_receive": fn.is_receive,
                },
            ))
            facts.edges.append(Edge(
                "declared_in", fid, cid, 1.0,
                (_evidence(ctx, fn.line, fn.line, ctx.get_line(fn.line)),),
            ))
            facts.function_bodies[fid] = fn.body
            _extract_call_facts(
                ctx, facts, fid, fn.body,
                fn.body_start_line or fn.line,
                facts.fn_namespace.get(cid, fn_names),
            )

            for modifier in fn.modifiers:
                mid = node_id(ctx.relative_path, "modifier", f"{contract.name}.{modifier}")
                facts.calls.append((fid, "guards", mid, modifier, fn.line))

            effective_body = _strip_line_comments(fn.body)
            for match in _WRITE_RE.finditer(effective_body):
                line = _line_for(fn.body, fn.body_start_line or fn.line, match.start())
                facts.writes.append((fid, match.group(1), line))

        for modifier in contract.modifiers:
            mid = node_id(ctx.relative_path, "modifier", f"{contract.name}.{modifier.name}")
            facts.nodes.append(Node(
                mid, "modifier", modifier.name, ctx.relative_path,
                (modifier.line, modifier.line), {"contract": contract.name},
            ))
            facts.edges.append(Edge("declared_in", mid, cid, 1.0))

        for var in contract.state_vars:
            sid = node_id(ctx.relative_path, "state_var", f"{contract.name}.{var.name}")
            facts.nodes.append(Node(
                sid, "state_var", var.name, ctx.relative_path, (var.line, var.line),
                {
                    "contract": contract.name, "type": var.type,
                    "visibility": var.visibility, "immutable": var.is_immutable,
                    "constant": var.is_constant,
                },
            ))
            facts.edges.append(Edge("declared_in", sid, cid, 1.0))

    return facts


def _function_signature(name: str, params: str) -> str:
    types: List[str] = []
    for raw in params.split(","):
        part = raw.strip()
        if not part:
            continue
        tokens = [t for t in part.split() if t not in {"memory", "storage", "calldata", "payable"}]
        if tokens:
            types.append(tokens[0])
    return f"{name}({','.join(types)})"


def _line_for(body: str, body_start_line: int, offset: int) -> int:
    return body_start_line + body[:offset].count("\n")


def _extract_call_facts(ctx: FileContext, facts: SolidityFacts, fid: str,
                        body: str, body_start_line: int, local_names: Set[str]) -> None:
    for match in _MEMBER_CALL_RE.finditer(body):
        receiver, method = match.groups()
        line = _line_for(body, body_start_line, match.start())
        if method in _LOW_LEVEL:
            kind = "delegatecall" if method == "delegatecall" else "calls_external"
            facts.calls.append((fid, kind, "", f"{receiver}.{method}", line))
        else:
            facts.calls.append((fid, "calls_external", "", f"{receiver}.{method}", line))

    for match in _DIRECT_CALL_RE.finditer(body):
        name = match.group(1)
        if name in _IGNORE_CALLS or name in _LOW_LEVEL:
            continue
        if name in local_names:
            line = _line_for(body, body_start_line, match.start())
            facts.calls.append((fid, "calls_internal", "", name, line))

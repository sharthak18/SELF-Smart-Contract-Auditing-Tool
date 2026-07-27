"""Compose per-file facts into a project :class:`Graph`."""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence

from self_tool.core.fingerprints import canonical_json, project_fingerprint, source_context_hash
from self_tool.core.scanner import FileContext
from self_tool.graph import solidity
from self_tool.graph.model import Edge, EvidenceLink, Graph, Node, UnresolvedEdge
from self_tool.graph.resolution import (
    build_symbol_index,
    choose_symbol,
    normalize_import,
)


def build_project_graph(
    files: Sequence[FileContext],
    framework: str = "unknown",
) -> Graph:
    """Build a deterministic project graph for ``files``.

    Files whose ``language`` is not ``"solidity"`` are ignored at the
    graph layer; project-level detectors can still walk them via
    ``FileContext``. ``framework`` participates in the project
    fingerprint so that two projects in different frameworks do not
    collide.
    """
    all_nodes: List[Node] = []
    unresolved: List[UnresolvedEdge] = []
    edges: List[Edge] = []
    imports_by_file: List[tuple] = []
    inherits: List[tuple] = []
    calls: List[tuple] = []

    file_paths = {ctx.relative_path for ctx in files}
    writes: List[tuple] = []

    for ctx in files:
        if ctx.language != "solidity":
            continue
        facts = solidity.extract_solidity_facts(ctx)
        all_nodes.extend(facts.nodes)
        imports_by_file.extend(facts.imports)
        inherits.extend(facts.inherits)
        calls.extend(facts.calls)
        writes.extend(facts.writes)

    symbol_index = build_symbol_index(all_nodes)

    for src_fn, var_name, line in writes:
        target = choose_symbol(symbol_index, var_name, kind="state_var")
        if target is not None:
            edges.append(Edge(
                "writes", src_fn, target.id, 0.9,
                (EvidenceLink(file="", start_line=line, end_line=line,
                              text_hash=source_context_hash("", line, line, var_name)),),
            ))

    for src_file_node, import_path, line in imports_by_file:
        target = normalize_import(src_file_node.replace("file:", "", 1), import_path)
        resolved = _resolve_import_path(target, file_paths)
        if resolved:
            edges.append(Edge(
                "imports", src_file_node, solidity.node_id(resolved, "file", resolved),
                1.0, (EvidenceLink(file=src_file_node.replace("file:", "", 1), start_line=line,
                                   end_line=line, text_hash=source_context_hash(
                                       src_file_node.replace("file:", "", 1), line, line, import_path)),
                      ),
            ))
        else:
            unresolved.append(UnresolvedEdge(
                "imports", src_file_node, import_path,
                file=src_file_node.replace("file:", "", 1),
                line=line,
                reason=f"unresolved import {import_path}",
            ))

    for src_contract_id, base_name, file, line in inherits:
        target = choose_symbol(symbol_index, base_name, file_hint=file)
        if target is not None:
            edges.append(Edge(
                "inherits", src_contract_id, target.id, 1.0,
                (EvidenceLink(file=file, start_line=line, end_line=line,
                              text_hash=source_context_hash(file, line, line, base_name)),),
            ))
        else:
            unresolved.append(UnresolvedEdge(
                "inherits", src_contract_id, base_name, file=file, line=line,
                reason=f"unresolved base {base_name}",
            ))

    for src_fn, kind, _, raw_target, line in calls:
        relation, dst_hint = (raw_target.split(".", 1) + [""])[:2] if "." in raw_target else ("", raw_target)
        target_node = _resolve_call(symbol_index, dst_hint or raw_target, kind, line)
        if target_node is not None:
            edges.append(Edge(
                kind, src_fn, target_node.id, 0.7 if "." in raw_target else 1.0,
                (EvidenceLink(file="", start_line=line, end_line=line,
                              text_hash=source_context_hash("", line, line, raw_target)),),
            ))
        elif kind == "calls_internal":
            # Cross-contract internal-style call: treat as cross-file external call;
            # still emit unresolved so detectors know it was uncertain.
            edges.append(Edge(
                "calls_external", src_fn,
                f"function:unknown:{dst_hint or raw_target}",
                0.4,
                (EvidenceLink(file="", start_line=line, end_line=line,
                              text_hash=source_context_hash("", line, line, raw_target)),),
            ))
            unresolved.append(UnresolvedEdge(
                kind, src_fn, raw_target, file="", line=line,
                reason=f"cross-contract internal call {raw_target}",
            ))
        else:
            unresolved.append(UnresolvedEdge(
                kind, src_fn, raw_target, file="", line=line,
                reason=f"unresolved call {raw_target}",
            ))

    fingerprint = project_fingerprint({
        "framework": framework,
        "nodes": sorted(n.id for n in all_nodes),
        "edges": sorted((e.kind, e.src, e.dst) for e in edges),
    })
    return Graph(
        project_fingerprint=fingerprint,
        nodes=tuple(all_nodes),
        edges=tuple(edges),
        unresolved=tuple(unresolved),
        function_bodies=tuple(sorted(facts.function_bodies.items())),
    )


def _resolve_import_path(target: str, files: Iterable[str]) -> Optional[str]:
    for path in files:
        if path == target:
            return path
    return None


def _resolve_call(index, name: str, kind: str, line: int) -> Optional[Node]:
    target_kind = "function" if kind in {"calls_internal", "calls_external"} else None
    node = choose_symbol(index, name, kind=target_kind)
    if node is not None:
        return node
    # Best-effort: a bare method name could resolve to a contract modifier.
    return choose_symbol(index, name, kind="modifier")

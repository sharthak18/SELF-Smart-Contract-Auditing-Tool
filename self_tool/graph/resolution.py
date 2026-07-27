"""Best-effort resolver for project graph facts."""

from __future__ import annotations

import posixpath
from pathlib import PurePosixPath
from typing import Dict, Iterable, List, Optional, Tuple

from self_tool.graph.model import Node


def normalize_import(source_file: str, import_path: str) -> str:
    """Resolve a Solidity import relative to ``source_file``.

    Package imports (``@openzeppelin/...``) are retained as-is; they are
    usually outside the scanned scope and will become unresolved edges.
    """
    import_path = import_path.replace("\\", "/")
    if import_path.startswith(("./", "../")):
        base = str(PurePosixPath(source_file).parent)
        return posixpath.normpath(posixpath.join(base, import_path))
    return import_path


def build_symbol_index(nodes: Iterable[Node]) -> Dict[str, List[Node]]:
    index: Dict[str, List[Node]] = {}
    for node in nodes:
        if node.kind in {
            "contract", "interface", "library", "abstract",
            "function", "modifier", "state_var",
        }:
            index.setdefault(node.name, []).append(node)
    return index


def choose_symbol(index: Dict[str, List[Node]], name: str,
                  *, file_hint: Optional[str] = None,
                  kind: Optional[str] = None) -> Optional[Node]:
    candidates = index.get(name, [])
    if kind:
        candidates = [c for c in candidates if c.kind == kind]
    if file_hint:
        local = [c for c in candidates if c.file == file_hint]
        if len(local) == 1:
            return local[0]
    if len(candidates) == 1:
        return candidates[0]
    return None

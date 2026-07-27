"""Cross-contract project-level detectors.

Each module here exposes a ``detect_project(project_ctx)`` function
returning a list of :class:`Issue`. They run after per-file detectors
and operate on the ``ProjectContext`` graph.
"""

from __future__ import annotations

import importlib
from typing import List


_PACKAGE = "self_tool.detectors.project"
_KNOWN = {
    "cross_contract_access",
    "project_proxy",
    "project_reentrancy",
    "project_auth",
    "project_oracle",
    "project_unresolved",
}


def discover_project_detectors() -> List[object]:
    """Return all loaded project detector modules in deterministic order."""
    import pkgutil

    modules: List[object] = []
    for info in pkgutil.iter_modules(__path__):
        if info.name not in _KNOWN:
            continue
        try:
            modules.append(importlib.import_module(f"{_PACKAGE}.{info.name}"))
        except Exception:
            continue
    return modules
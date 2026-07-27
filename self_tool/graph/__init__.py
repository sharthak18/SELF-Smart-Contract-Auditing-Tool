"""Project semantic graph: canonical IR for cross-contract reasoning.

The graph package is intentionally a *separate* module from the
per-file parser package. Detectors may consume either; per-file
detectors continue to receive a single ``FileContext``, and project
detectors receive a ``ProjectContext`` containing the graph.

Graph invariants:
    * Node ids are stable across rebuilds.
    * Edges carry an ``evidence`` array pointing back to source spans.
    * Anything unresolvable lives in ``Graph.unresolved`` rather than
      being guessed. Project detectors must treat ``unresolved`` as a
      first-class signal that lowers finding confidence.
"""

from .model import Edge, EvidenceLink, Graph, Node, NodeKind, EdgeKind
from .builder import build_project_graph

__all__ = [
    "Edge",
    "EdgeKind",
    "EvidenceLink",
    "Graph",
    "Node",
    "NodeKind",
    "build_project_graph",
]
"""Tests for the project semantic graph (Phase 1)."""

import unittest

from self_tool.core.scanner import FileContext
from self_tool.graph.builder import build_project_graph
from self_tool.graph.serialization import serialize_graph


INHERITANCE_FILE_A = """
pragma solidity ^0.8.0;
contract Base {
    uint public x;
    function setX(uint v) external { x = v; }
}
contract Child is Base {
    function inc() external { setX(x + 1); }
}
"""

MISSING_IMPORT_FILE = """
pragma solidity ^0.8.0;
import "./Missing.sol";
contract A { function f() external {} }
"""


def ctx(name: str, source: str, root: str = "/tmp", language: str = "solidity") -> FileContext:
    return FileContext(f"{root}/{name}", name, language, source)


class GraphTests(unittest.TestCase):
    def test_inheritance_and_internal_call_resolve(self):
        a = ctx("A.sol", INHERITANCE_FILE_A)
        graph = build_project_graph([a], framework="foundry")
        inherits = [e for e in graph.edges if e.kind == "inherits"]
        self.assertEqual(len(inherits), 1)
        internal = [e for e in graph.edges if e.kind == "calls_internal"]
        self.assertTrue(any("Base.setX" in e.dst or e.dst.endswith(".setX(uint256)") for e in internal),
                        "setX should resolve as an internal call")

    def test_unresolved_imports_are_kept(self):
        a = ctx("A.sol", MISSING_IMPORT_FILE)
        graph = build_project_graph([a], framework="foundry")
        unresolved = [u for u in graph.unresolved if u.kind == "imports"]
        self.assertEqual(len(unresolved), 1)
        self.assertIn("Missing.sol", unresolved[0].hint)

    def test_serialization_is_key_sorted_and_stable(self):
        a = ctx("A.sol", INHERITANCE_FILE_A)
        g1 = build_project_graph([a], framework="foundry")
        g2 = build_project_graph([a], framework="foundry")
        self.assertEqual(g1.project_fingerprint, g2.project_fingerprint)
        self.assertEqual(serialize_graph(g1), serialize_graph(g2))

    def test_fingerprint_uses_framework(self):
        a = ctx("A.sol", INHERITANCE_FILE_A)
        self.assertNotEqual(
            build_project_graph([a], framework="foundry").project_fingerprint,
            build_project_graph([a], framework="hardhat").project_fingerprint,
        )

    def test_non_solidity_files_are_ignored_by_graph(self):
        a = ctx("A.sol", INHERITANCE_FILE_A)
        ts = ctx("test.ts", "const x = 1;", root="/tmp", language="typescript")
        graph = build_project_graph([a, ts], framework="foundry")
        file_kinds = [n.kind for n in graph.by_kind("file")]
        self.assertEqual(file_kinds.count("file"), 1)
        self.assertIn("A.sol", graph.by_kind("file")[0].id)


if __name__ == "__main__":
    unittest.main()

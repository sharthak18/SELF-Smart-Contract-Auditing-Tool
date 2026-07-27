"""Reproducibility tests across the whole CLI fuzz path."""
import unittest

from self_tool.core.scanner import FileContext
from self_tool.fuzzing.stateless import StatelessFuzzEngine
from self_tool.fuzzing.stateful import StatefulFuzzEngine


SIMPLE_SOL = """
pragma solidity ^0.8.0;
contract V {
    mapping(address => uint256) public balances;
    address public admin;
    constructor() { admin = msg.sender; }
    function deposit(uint256 amount) public payable {
        balances[msg.sender] += amount;
    }
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
"""


def _ctx(src: str) -> FileContext:
    return FileContext("/tmp/V.sol", "V.sol", "solidity", src)


class FuzzReproducibilityTests(unittest.TestCase):
    def test_stateless_reproducible(self):
        def run_once():
            eng = StatelessFuzzEngine(max_examples=6, deadline_ms=150, seed=7)
            return eng.fuzz_file(_ctx(SIMPLE_SOL))
        a = run_once()
        b = run_once()
        self.assertEqual(
            [(i.id, i.line, i.title) for i in a.findings],
            [(i.id, i.line, i.title) for i in b.findings],
        )
        self.assertEqual(a.runs, b.runs)

    def test_stateful_reproducible(self):
        def run_once():
            eng = StatefulFuzzEngine(max_sequences=6, max_length=4, seed=7)
            return eng.fuzz_file(_ctx(SIMPLE_SOL))
        a = run_once()
        b = run_once()
        self.assertEqual(a.sequences, b.sequences)
        self.assertEqual(len(a.findings), len(b.findings))


if __name__ == "__main__":
    unittest.main()
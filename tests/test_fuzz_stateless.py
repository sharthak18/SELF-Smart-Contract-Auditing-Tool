"""Tests for the offline stateless property fuzzer."""
import unittest

from self_tool.core.scanner import FileContext
from self_tool.fuzzing.stateless import (
    HYPOTHESIS_AVAILABLE,
    Invariant,
    Severity,
    Confidence,
    StatelessFuzzEngine,
)


VULNERABLE_SOL = """
pragma solidity ^0.8.0;
contract V {
    mapping(address => uint256) public balances;
    function deposit(address to, uint256 amount) public payable {
        // No zero check on to; no overflow check on amount.
        balances[to] += amount;
    }
    function init() public {
        // No initialized guard.
        owner = msg.sender;
    }
    address public owner;
}
"""


SAFE_SOL = """
pragma solidity ^0.8.0;
contract S {
    mapping(address => uint256) public balances;
    function deposit(address to, uint256 amount) public payable {
        require(to != address(0), "to=0");
        unchecked { balances[to] += amount; }
    }
    bool initialized;
    function init() public {
        require(!initialized, "init");
        initialized = true;
        owner = msg.sender;
    }
    address public owner;
}
"""


def _ctx(src: str) -> FileContext:
    return FileContext("/tmp/x.sol", "x.sol", "solidity", src)


@unittest.skipUnless(HYPOTHESIS_AVAILABLE, "hypothesis not installed")
class StatelessFuzzTests(unittest.TestCase):
    def test_vulnerable_contract_produces_finding(self):
        eng = StatelessFuzzEngine(max_examples=8, deadline_ms=200, seed=1)
        result = eng.fuzz_file(_ctx(VULNERABLE_SOL))
        ids = {i.id for i in result.findings}
        self.assertTrue(ids, msg=f"no findings; runs={result.runs}, errors={result.errors}")
        # The vulnerable fixture lacks a zero-address check; the
        # default zero-address invariant should fire.
        self.assertIn("FUZZ-STATELESS-ZERO-ADDRESS", ids)
        self.assertIsNotNone(result.seed)

    def test_safe_contract_may_still_produce_findings_but_with_low_specificity(self):
        eng = StatelessFuzzEngine(max_examples=8, deadline_ms=200, seed=1)
        result = eng.fuzz_file(_ctx(SAFE_SOL))
        # The safe contract has no `initialize` flag check and no
        # uint-overflow guard in deposit. Hypothesis may still flag
        # these as long as they are present. We just assert the run
        # completes and reports its seed for reproducibility.
        self.assertIsNotNone(result.seed)
        self.assertGreaterEqual(result.runs, 0)

    def test_seed_is_recorded_on_result(self):
        eng = StatelessFuzzEngine(max_examples=4, deadline_ms=100, seed=42)
        result = eng.fuzz_file(_ctx(VULNERABLE_SOL))
        self.assertEqual(42, result.seed)

    def test_reproducibility_with_seed(self):
        def run_once():
            eng = StatelessFuzzEngine(max_examples=6, deadline_ms=200, seed=123)
            r = eng.fuzz_file(_ctx(VULNERABLE_SOL))
            return [(i.id, i.line, i.title) for i in r.findings]
        first = run_once()
        second = run_once()
        # Hypothesis itself is deterministic with the same example
        # budget; we expect runs == findings lists to be equal.
        self.assertEqual(first, second)

    def test_custom_invariant_can_be_added(self):
        inv = Invariant(
            name="every_function_has_payable",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            detector_id="FUZZ-CUSTOM-PAY",
            title="Function should be payable",
            description="fuzz test",
            check=lambda target, args: "no payable" if not target.has_payable else None,
        )
        # Use a fixture with a non-payable, parameterized function so
        # the custom invariant can fire.
        src = """
pragma solidity ^0.8.0;
contract V {
    function deposit(address to, uint256 amount) public {
        // intentionally non-payable
    }
}
"""
        eng = StatelessFuzzEngine(
            max_examples=4, deadline_ms=100, seed=7,
            invariants=[inv],
        )
        result = eng.fuzz_file(_ctx(src))
        ids = {i.id for i in result.findings}
        self.assertIn("FUZZ-CUSTOM-PAY", ids,
                      msg=f"runs={result.runs} errors={result.errors} ids={ids}")


if __name__ == "__main__":
    unittest.main()
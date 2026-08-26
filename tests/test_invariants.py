"""Protocol-math invariants: unenforced accounting properties + second-order reentrancy.

Covers the invariant lens (self_tool.autonomous.invariants), the second-order
reentrancy fact in deep_scan, and how both surface through playbooks, exploit
paths, the model surface and the markdown report.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from self_tool.autonomous.brain import load_attack_vectors, load_expert_tactics
from self_tool.autonomous.deep_scan import deep_facts, locate_deep
from self_tool.autonomous.ingest import all_file_contexts, ingest_project
from self_tool.autonomous.invariants import invariant_facts, propose_hypotheses
from self_tool.autonomous.languages import extract_contracts
from self_tool.autonomous.pipeline import run_autonomous_audit
from self_tool.autonomous.reason import _DEEP_PLAYBOOK_FACTS
from self_tool.autonomous.report import render_markdown


def _project(source: str, name: str = "Case.sol"):
    """Ingest a single-file project and return (contracts, combined_source)."""
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    (root / name).write_text(source, encoding="utf-8")
    ingestion = ingest_project(str(root))
    contracts = extract_contracts(all_file_contexts(ingestion))
    return contracts, ingestion.combined_source, tmp


class SecondOrderReentrancyTests(unittest.TestCase):
    """Public fn writes value state after delegating to a helper that .call's."""

    def _fact(self, source: str):
        contracts, combined, tmp = _project(source)
        self.addCleanup(tmp.cleanup)
        return deep_facts(contracts, combined).get("second_order_reentrancy")

    def test_second_order_reentrancy_hit(self):
        src = """
        pragma solidity ^0.8.20;
        contract Broker {
            mapping(address => uint256) public balances;
            function withdraw(uint256 amount) external {
                _payout(msg.sender, amount);
                balances[msg.sender] -= amount;
            }
            function _payout(address to, uint256 amount) internal {
                (bool ok,) = to.call{value: amount}("");
                require(ok);
            }
        }
        """
        self.assertTrue(self._fact(src))

    def test_guarded_public_function_is_skipped(self):
        src = """
        pragma solidity ^0.8.20;
        contract Broker {
            mapping(address => uint256) public balances;
            modifier nonReentrant() { _; }
            function withdraw(uint256 amount) external nonReentrant {
                _payout(msg.sender, amount);
                balances[msg.sender] -= amount;
            }
            function _payout(address to, uint256 amount) internal {
                (bool ok,) = to.call{value: amount}("");
                require(ok);
            }
        }
        """
        self.assertFalse(self._fact(src))

    def test_guarded_helper_is_skipped(self):
        src = """
        pragma solidity ^0.8.20;
        contract Broker {
            mapping(address => uint256) public balances;
            modifier nonReentrant() { _; }
            function withdraw(uint256 amount) external {
                _payout(msg.sender, amount);
                balances[msg.sender] -= amount;
            }
            function _payout(address to, uint256 amount) internal nonReentrant {
                (bool ok,) = to.call{value: amount}("");
                require(ok);
            }
        }
        """
        self.assertFalse(self._fact(src))

    def test_call_in_public_function_is_first_order_not_second(self):
        # The .call sits directly in the public fn: already covered by
        # external_call_before_write, so this lens must stay quiet.
        src = """
        pragma solidity ^0.8.20;
        contract Broker {
            mapping(address => uint256) public balances;
            function withdraw(uint256 amount) external {
                (bool ok,) = msg.sender.call{value: amount}("");
                require(ok);
                balances[msg.sender] -= amount;
            }
            function _noop() internal {}
        }
        """
        self.assertFalse(self._fact(src))

    def test_write_before_helper_call_is_not_flagged(self):
        # Check-effects-interactions done right: the balance is settled first.
        src = """
        pragma solidity ^0.8.20;
        contract Broker {
            mapping(address => uint256) public balances;
            function withdraw(uint256 amount) external {
                balances[msg.sender] -= amount;
                _payout(msg.sender, amount);
            }
            function _payout(address to, uint256 amount) internal {
                (bool ok,) = to.call{value: amount}("");
                require(ok);
            }
        }
        """
        self.assertFalse(self._fact(src))

    def test_locate_deep_points_at_the_public_function(self):
        src = """
        pragma solidity ^0.8.20;
        contract Broker {
            mapping(address => uint256) public balances;
            function withdraw(uint256 amount) external {
                _payout(msg.sender, amount);
                balances[msg.sender] -= amount;
            }
            function _payout(address to, uint256 amount) internal {
                (bool ok,) = to.call{value: amount}("");
                require(ok);
            }
        }
        """
        contracts, combined, tmp = _project(src, "Broker.sol")
        self.addCleanup(tmp.cleanup)
        located = locate_deep(contracts, "second_order_reentrancy", combined)
        self.assertIsNotNone(located)
        self.assertEqual(located[3], "Broker.withdraw")


class InvariantFactTests(unittest.TestCase):
    """Accounting properties the code fails to enforce."""

    def _facts(self, source: str, types=("vault",), name: str = "Case.sol"):
        contracts, combined, tmp = _project(source, name)
        self.addCleanup(tmp.cleanup)
        return invariant_facts(contracts, combined, types)

    def test_missing_accrue_hit(self):
        src = """
        pragma solidity ^0.8.20;
        contract Vault {
            mapping(address => uint256) public shares;
            uint256 public totalAssets;
            function convertToShares(uint256 a) public view returns (uint256) {
                return a * 1e18 / totalAssets;
            }
            function deposit(uint256 amount) external {
                uint256 minted = convertToShares(amount);
                shares[msg.sender] += minted;
                totalAssets += amount;
            }
        }
        """
        self.assertTrue(self._facts(src)["missing_accrue_on_value_path"])

    def test_missing_accrue_miss(self):
        src = """
        pragma solidity ^0.8.20;
        contract Vault {
            mapping(address => uint256) public shares;
            uint256 public totalAssets;
            function convertToShares(uint256 a) public view returns (uint256) {
                return a * 1e18 / totalAssets;
            }
            function deposit(uint256 amount) external {
                accrueInterest();
                uint256 minted = convertToShares(amount);
                shares[msg.sender] += minted;
                totalAssets += amount;
            }
            function accrueInterest() internal { totalAssets += 1; }
        }
        """
        self.assertFalse(self._facts(src)["missing_accrue_on_value_path"])

    def test_accrue_through_internal_helper_counts(self):
        # deposit() -> _before() -> accrueInterest(): one level of indirection
        # still satisfies the obligation.
        src = """
        pragma solidity ^0.8.20;
        contract Vault {
            mapping(address => uint256) public shares;
            uint256 public totalAssets;
            function convertToShares(uint256 a) public view returns (uint256) {
                return a * 1e18 / totalAssets;
            }
            function deposit(uint256 amount) external {
                _before();
                uint256 minted = convertToShares(amount);
                shares[msg.sender] += minted;
            }
            function _before() internal { accrueInterest(); }
            function accrueInterest() internal { totalAssets += 1; }
        }
        """
        self.assertFalse(self._facts(src)["missing_accrue_on_value_path"])

    def test_missing_share_invariant_hit(self):
        # The conversion formula alone is NOT an invariant: it prices a share
        # without constraining one, so nothing enforces backing here.
        src = """
        pragma solidity ^0.8.20;
        contract Vault {
            uint256 public totalAssets;
            function totalSupply() public view returns (uint256) { return 1; }
            function convertToShares(uint256 a) public view returns (uint256) {
                return a * totalSupply() / totalAssets;
            }
        }
        """
        self.assertTrue(self._facts(src)["missing_share_invariant"])

    def test_missing_share_invariant_miss_when_backing_is_asserted(self):
        src = """
        pragma solidity ^0.8.20;
        contract Vault {
            uint256 public totalAssets;
            function totalSupply() public view returns (uint256) { return 1; }
            function convertToShares(uint256 a) public view returns (uint256) {
                return a * totalSupply() / totalAssets;
            }
            function _checkBacking() internal view {
                require(convertToShares(totalSupply()) <= totalAssets, "unbacked");
            }
        }
        """
        self.assertFalse(self._facts(src)["missing_share_invariant"])

    def test_missing_k_invariant_hit(self):
        src = """
        pragma solidity ^0.8.20;
        contract Pair {
            uint112 public reserve0;
            uint112 public reserve1;
            function getReserves() public view returns (uint112, uint112, uint32) {
                return (reserve0, reserve1, 0);
            }
            function swap(uint256 a0Out, uint256 a1Out, address to) external {
                reserve0 -= a0Out;
                reserve1 -= a1Out;
            }
        }
        """
        self.assertTrue(self._facts(src, types=("amm",), name="Pair.sol")["missing_k_invariant"])

    def test_missing_k_invariant_miss_with_product_check(self):
        src = """
        pragma solidity ^0.8.20;
        contract Pair {
            uint112 public reserve0;
            uint112 public reserve1;
            function getReserves() public view returns (uint112, uint112, uint32) {
                return (reserve0, reserve1, 0);
            }
            function swap(uint256 a0Out, uint256 a1Out, address to) external {
                uint112 r0 = reserve0;
                uint112 r1 = reserve1;
                reserve0 -= a0Out;
                reserve1 -= a1Out;
                require(
                    token0.balanceOf(address(this)) * token1.balanceOf(address(this))
                        >= uint256(r0) * uint256(r1),
                    "K"
                );
            }
        }
        """
        self.assertFalse(self._facts(src, types=("amm",), name="Pair.sol")["missing_k_invariant"])

    def test_missing_health_check_hit(self):
        src = """
        pragma solidity ^0.8.20;
        contract Lend {
            mapping(address => uint256) public debt;
            function borrow(uint256 amount) external {
                debt[msg.sender] += amount;
                token.transfer(msg.sender, amount);
            }
        }
        """
        self.assertTrue(self._facts(src, types=("lending",), name="Lend.sol")["missing_health_check"])

    def test_missing_health_check_miss(self):
        src = """
        pragma solidity ^0.8.20;
        contract Lend {
            mapping(address => uint256) public debt;
            function borrow(uint256 amount) external {
                debt[msg.sender] += amount;
                token.transfer(msg.sender, amount);
                require(healthFactor(msg.sender) > 1e18, "underwater");
            }
            function healthFactor(address a) public view returns (uint256) { return 1e18; }
        }
        """
        self.assertFalse(self._facts(src, types=("lending",), name="Lend.sol")["missing_health_check"])


class TransientPoisonTests(unittest.TestCase):
    """EIP-1153: transient data outliving the entry it describes."""

    def _fact(self, source: str):
        contracts, combined, tmp = _project(source, "Lock.sol")
        self.addCleanup(tmp.cleanup)
        return invariant_facts(contracts, combined, ("vault",))["tstore_delete_poison"]

    def test_tstore_with_delete_is_poison(self):
        src = """
        pragma solidity ^0.8.20;
        contract Lock {
            mapping(uint256 => bool) public used;
            function claim(uint256 id) external {
                assembly { tstore(id.slot, 1) }
                if (used[id]) { delete used[id]; }
            }
        }
        """
        self.assertTrue(self._fact(src))

    def test_bare_tstore_is_not_poison(self):
        # Normal EIP-1153 usage: nothing deletes the entry underneath the slot.
        src = """
        pragma solidity ^0.8.20;
        contract Lock {
            mapping(uint256 => bool) public used;
            function claim(uint256 id) external {
                assembly { tstore(id.slot, 1) }
                used[id] = true;
            }
        }
        """
        self.assertFalse(self._fact(src))

    def test_tstore_with_pop_is_poison(self):
        src = """
        pragma solidity ^0.8.20;
        contract Lock {
            uint256[] public queue;
            function claim(uint256 id) external {
                assembly { tstore(id.slot, 1) }
                queue.pop();
            }
        }
        """
        self.assertTrue(self._fact(src))


class HypothesisTests(unittest.TestCase):
    def test_eight_invariant_ids_proposed_and_gated(self):
        facts = {
            "is_share_vault": True,
            "is_lending": True,
            "has_view_price": True,
            "uses_transient_storage": True,
            "has_signature_auth": True,
            "missing_accrue_on_value_path": True,
        }
        proposed = list(propose_hypotheses(facts, ["vault", "lending", "amm"], ""))
        ids = [item.split(":", 1)[0] for item in proposed]
        self.assertEqual(ids, [
            "INV-SHARE-BACKING", "INV-EMPTY-VAULT", "INV-K", "INV-ACCRUE-FIRST",
            "INV-HEALTH", "INV-VIEW-LOCK", "INV-TSTORE-CLEAR", "INV-SIG-BIND",
        ])
        # Every entry is a Foundry handler sketch, not a bare label.
        for item in proposed:
            self.assertIn("invariant_", item)

        # Gating: a plain token with none of those signals gets no vault,
        # constant-product or solvency hypotheses.
        plain = list(propose_hypotheses({}, ["token"], "function transfer(address to, uint256 a) public {}"))
        plain_ids = {item.split(":", 1)[0] for item in plain}
        self.assertNotIn("INV-SHARE-BACKING", plain_ids)
        self.assertNotIn("INV-K", plain_ids)
        self.assertNotIn("INV-HEALTH", plain_ids)

    def test_hypotheses_exposed_on_model_surface(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "Vault.sol").write_text("""
        pragma solidity ^0.8.20;
        contract Vault {
            uint256 public totalAssets;
            function totalSupply() public view returns (uint256) { return 1; }
            function convertToShares(uint256 a) public view returns (uint256) {
                return a * totalSupply() / totalAssets;
            }
        }
        """, encoding="utf-8")
        audit = run_autonomous_audit(
            str(root), output=str(root / "out.md"), no_docs=True, index_root=root,
        )
        understanding = audit.understanding
        self.assertTrue(understanding.hypotheses)
        self.assertEqual(understanding.to_dict()["hypotheses"], list(understanding.hypotheses))
        self.assertIn("Must-hold invariants (hypotheses, not proofs)", understanding.briefing())


class InvariantBrainTests(unittest.TestCase):
    def test_invariant_playbooks_and_tactic_exist(self):
        ids = {item.id for item in load_attack_vectors()}
        for playbook_id in (
            "AV-SECOND-ORDER-REENTRANCY",
            "AV-MISSING-ACCRUE",
            "AV-MISSING-SHARE-INVARIANT",
            "AV-MISSING-K",
            "AV-TSTORE-DELETE-POISON",
        ):
            self.assertIn(playbook_id, ids)
        self.assertIn("TAC-INVARIANT-FIRST", {item["id"] for item in load_expert_tactics()})

    def test_deep_playbook_facts_map_the_five_new_avs(self):
        expected = {
            "AV-SECOND-ORDER-REENTRANCY": "second_order_reentrancy",
            "AV-MISSING-ACCRUE": "missing_accrue_on_value_path",
            "AV-MISSING-SHARE-INVARIANT": "missing_share_invariant",
            "AV-MISSING-K": "missing_k_invariant",
            "AV-TSTORE-DELETE-POISON": "tstore_delete_poison",
        }
        for playbook_id, fact in expected.items():
            self.assertEqual(_DEEP_PLAYBOOK_FACTS.get(playbook_id), fact)


BROKER_SRC = """
pragma solidity ^0.8.20;

interface IERC20 { function transferFrom(address,address,uint256) external returns (bool); }

contract Broker {
    IERC20 public token;
    mapping(address => uint256) public balances;
    uint256 public totalAssets;
    mapping(uint256 => bool) public used;

    function totalSupply() public view returns (uint256) { return 1; }

    function convertToShares(uint256 a) public view returns (uint256) {
        return a * totalSupply() / totalAssets;
    }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        uint256 minted = convertToShares(amount);
        balances[msg.sender] += minted;
        totalAssets += amount;
    }

    function withdraw(uint256 amount) external {
        _payout(msg.sender, amount);
        balances[msg.sender] -= amount;
    }

    function claim(uint256 id) external {
        assembly { tstore(id.slot, 1) }
        if (used[id]) { delete used[id]; }
    }

    function _payout(address to, uint256 amount) internal {
        (bool ok,) = to.call{value: amount}("");
        require(ok);
    }
}
"""


class InvariantAuditTests(unittest.TestCase):
    def _audit(self, source: str, name: str = "Broker.sol"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / name).write_text(source, encoding="utf-8")
        return run_autonomous_audit(
            str(root), output=str(root / "out.md"), no_docs=True, index_root=root,
        )

    def test_second_order_reentrancy_fires_finding_and_path(self):
        audit = self._audit(BROKER_SRC)
        facts = audit.understanding.facts
        self.assertTrue(facts.get("second_order_reentrancy"), facts)
        self.assertTrue(facts.get("tstore_delete_poison"), facts)
        ids = {item.id for item in audit.findings}
        self.assertIn("AUTO-SECOND-ORDER-REENTRANCY", ids, ids)
        self.assertIn("AUTO-TSTORE-DELETE-POISON", ids, ids)
        self.assertIn("AUTO-MISSING-ACCRUE", ids, ids)
        self.assertIn("AUTO-MISSING-SHARE-INVARIANT", ids, ids)
        self.assertTrue(
            any(path.id == "PATH-SECOND-ORDER-REENTRANCY" for path in audit.exploit_paths),
            [path.id for path in audit.exploit_paths],
        )


class InvariantReportTests(unittest.TestCase):
    def test_hypotheses_section_in_markdown_report(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "Broker.sol").write_text(BROKER_SRC, encoding="utf-8")
        audit = run_autonomous_audit(
            str(root), output=str(root / "out.md"), no_docs=True, index_root=root,
        )
        markdown = render_markdown(audit)
        self.assertIn("### Must-hold invariants (hypotheses, not proofs)", markdown)
        self.assertIn("INV-SHARE-BACKING", markdown)
        self.assertIn("INV-ACCRUE-FIRST", markdown)
        # The section must state that these are not proofs.
        self.assertIn("has not", markdown)


if __name__ == "__main__":
    unittest.main()

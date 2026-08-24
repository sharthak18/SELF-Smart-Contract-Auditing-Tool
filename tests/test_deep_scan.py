"""Per-function deep pass: Slither-class facts without new catalog detectors."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from self_tool.autonomous.brain import load_attack_vectors, load_expert_tactics
from self_tool.autonomous.pipeline import run_autonomous_audit


class DeepScanPlaybookTests(unittest.TestCase):
    def test_slither_class_playbooks_and_tactic_exist(self):
        ids = {item.id for item in load_attack_vectors()}
        for playbook_id in (
            "AV-ARBITRARY-ERC20-FROM",
            "AV-ARBITRARY-ETH-SEND",
            "AV-MSG-VALUE-LOOP",
            "AV-LOCKED-ETHER",
            "AV-ENCODEPACKED-COLLISION",
            "AV-UNCHECKED-CALL",
            "AV-BALANCE-EQ",
            "AV-MAPPING-DELETE",
        ):
            self.assertIn(playbook_id, ids)
        tactic_ids = {item["id"] for item in load_expert_tactics()}
        self.assertIn("TAC-SLITHER-CLASS", tactic_ids)


class DeepScanAuditTests(unittest.TestCase):
    def _audit(self, source: str, name: str = "Case.sol"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        path = root / name
        path.write_text(source, encoding="utf-8")
        return run_autonomous_audit(
            str(path), output=str(root / "out.md"), no_docs=True, index_root=root,
        )

    def test_arbitrary_transfer_from_argument(self):
        src = """
        pragma solidity ^0.8.20;
        interface IERC20 { function transferFrom(address,address,uint256) external returns (bool); }
        contract Pull {
            IERC20 public token;
            function pull(address from, uint256 amount) external {
                token.transferFrom(from, address(this), amount);
            }
        }
        """
        audit = self._audit(src, "Pull.sol")
        self.assertTrue(audit.understanding.facts.get("arbitrary_erc20_from"), audit.understanding.facts)
        ids = {item.id for item in audit.findings}
        self.assertIn("AUTO-ARBITRARY-ERC20-FROM", ids, ids)
        self.assertTrue(any(item.id == "PATH-ARBITRARY-SEND" for item in audit.exploit_paths))

    def test_transfer_from_msg_sender_is_not_arbitrary(self):
        src = """
        pragma solidity ^0.8.20;
        interface IERC20 { function transferFrom(address,address,uint256) external returns (bool); }
        contract Vault {
            IERC20 public token;
            function deposit(uint256 amount) external {
                token.transferFrom(msg.sender, address(this), amount);
            }
        }
        """
        audit = self._audit(src, "Vault.sol")
        self.assertFalse(audit.understanding.facts.get("arbitrary_erc20_from"))
        ids = {item.id for item in audit.findings}
        self.assertNotIn("AUTO-ARBITRARY-ERC20-FROM", ids, ids)

    def test_only_owner_transfer_from_is_not_arbitrary(self):
        src = """
        pragma solidity ^0.8.20;
        interface IERC20 { function transferFrom(address,address,uint256) external returns (bool); }
        contract Admin {
            IERC20 public token;
            address public owner;
            function collect(address from, uint256 amount) external {
                require(msg.sender == owner);
                token.transferFrom(from, address(this), amount);
            }
        }
        """
        audit = self._audit(src, "Admin.sol")
        self.assertFalse(audit.understanding.facts.get("arbitrary_erc20_from"))

    def test_arbitrary_eth_send_to_argument(self):
        src = """
        pragma solidity ^0.8.20;
        contract Pay {
            function pay(address to) external {
                payable(to).transfer(address(this).balance);
            }
        }
        """
        audit = self._audit(src, "Pay.sol")
        self.assertTrue(audit.understanding.facts.get("arbitrary_eth_receiver"), audit.understanding.facts)
        ids = {item.id for item in audit.findings}
        self.assertIn("AUTO-ARBITRARY-ETH-SEND", ids, ids)

    def test_withdraw_to_msg_sender_is_not_arbitrary_eth(self):
        src = """
        pragma solidity ^0.8.20;
        contract Wallet {
            mapping(address => uint256) public bal;
            function withdraw() external {
                uint256 amount = bal[msg.sender];
                bal[msg.sender] = 0;
                (bool ok,) = msg.sender.call{value: amount}("");
                require(ok);
            }
        }
        """
        audit = self._audit(src, "Wallet.sol")
        self.assertFalse(audit.understanding.facts.get("arbitrary_eth_receiver"))
        ids = {item.id for item in audit.findings}
        self.assertNotIn("AUTO-ARBITRARY-ETH-SEND", ids, ids)

    def test_msg_value_in_loop(self):
        src = """
        pragma solidity ^0.8.20;
        contract Batch {
            mapping(address => uint256) public credit;
            function fund(address[] calldata users) external payable {
                for (uint256 i = 0; i < users.length; i++) {
                    credit[users[i]] += msg.value;
                }
            }
        }
        """
        audit = self._audit(src, "Batch.sol")
        self.assertTrue(audit.understanding.facts.get("msg_value_in_loop"), audit.understanding.facts)
        ids = {item.id for item in audit.findings}
        self.assertIn("AUTO-MSG-VALUE-LOOP", ids, ids)

    def test_locked_ether_without_withdraw(self):
        src = """
        pragma solidity ^0.8.20;
        contract Piggy {
            event Ping();
            receive() external payable {}
            function ping() external { emit Ping(); }
        }
        """
        audit = self._audit(src, "Piggy.sol")
        self.assertTrue(audit.understanding.facts.get("locked_ether"), audit.understanding.facts)
        ids = {item.id for item in audit.findings}
        self.assertIn("AUTO-LOCKED-ETHER", ids, ids)

    def test_receive_plus_withdraw_is_not_locked(self):
        src = """
        pragma solidity ^0.8.20;
        contract Bank {
            address public owner;
            receive() external payable {}
            function withdraw() external {
                require(msg.sender == owner);
                payable(owner).transfer(address(this).balance);
            }
        }
        """
        audit = self._audit(src, "Bank.sol")
        self.assertFalse(audit.understanding.facts.get("locked_ether"))
        ids = {item.id for item in audit.findings}
        self.assertNotIn("AUTO-LOCKED-ETHER", ids, ids)

    def test_encode_packed_two_dynamic_types(self):
        src = """
        pragma solidity ^0.8.20;
        contract Commit {
            function digest(string calldata a, string calldata b) external pure returns (bytes32) {
                return keccak256(abi.encodePacked(a, b));
            }
        }
        """
        audit = self._audit(src, "Commit.sol")
        self.assertTrue(audit.understanding.facts.get("encode_packed_collision"), audit.understanding.facts)
        ids = {item.id for item in audit.findings}
        self.assertIn("AUTO-ENCODEPACKED-COLLISION", ids, ids)

    def test_encode_packed_static_types_is_safe(self):
        src = """
        pragma solidity ^0.8.20;
        contract Commit {
            function digest(bytes32 a, bytes32 b) external pure returns (bytes32) {
                return keccak256(abi.encodePacked(a, b));
            }
        }
        """
        audit = self._audit(src, "Commit.sol")
        self.assertFalse(audit.understanding.facts.get("encode_packed_collision"))
        ids = {item.id for item in audit.findings}
        self.assertNotIn("AUTO-ENCODEPACKED-COLLISION", ids, ids)

    def test_unchecked_lowlevel_call(self):
        src = """
        pragma solidity ^0.8.20;
        contract Sink {
            function dump(address to) external {
                to.call{value: 1}("");
            }
        }
        """
        audit = self._audit(src, "Sink.sol")
        self.assertTrue(audit.understanding.facts.get("unchecked_lowlevel_call"), audit.understanding.facts)
        ids = {item.id for item in audit.findings}
        self.assertIn("AUTO-UNCHECKED-CALL", ids, ids)

    def test_checked_call_is_not_unchecked(self):
        src = """
        pragma solidity ^0.8.20;
        contract Sink {
            function dump() external {
                (bool ok,) = msg.sender.call{value: 1}("");
                require(ok);
            }
        }
        """
        audit = self._audit(src, "Sink.sol")
        self.assertFalse(audit.understanding.facts.get("unchecked_lowlevel_call"))
        ids = {item.id for item in audit.findings}
        self.assertNotIn("AUTO-UNCHECKED-CALL", ids, ids)

    def test_balance_strict_equality(self):
        src = """
        pragma solidity ^0.8.20;
        contract Gate {
            function ready() external view returns (bool) {
                return address(this).balance == 0;
            }
        }
        """
        audit = self._audit(src, "Gate.sol")
        self.assertTrue(audit.understanding.facts.get("balance_strict_eq"), audit.understanding.facts)
        ids = {item.id for item in audit.findings}
        self.assertIn("AUTO-BALANCE-EQ", ids, ids)

    def test_mapping_delete_nested_struct(self):
        src = """
        pragma solidity ^0.8.20;
        contract Registry {
            struct User {
                uint256 balance;
                mapping(address => uint256) allowances;
            }
            mapping(address => User) public users;
            function reset(address who) external {
                delete users[who];
            }
        }
        """
        audit = self._audit(src, "Registry.sol")
        self.assertTrue(audit.understanding.facts.get("mapping_delete_struct"), audit.understanding.facts)
        ids = {item.id for item in audit.findings}
        self.assertIn("AUTO-MAPPING-DELETE", ids, ids)


if __name__ == "__main__":
    unittest.main()

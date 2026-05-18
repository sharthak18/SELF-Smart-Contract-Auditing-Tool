// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

// ================================================================
// SELF TEST CONTRACT — Deliberately Vulnerable
// This file is used to verify SELF detects all expected issues.
// DO NOT deploy this contract.
// ================================================================

contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // SOL-CRIT-001: Classic Reentrancy — external call before state update
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        (bool ok,) = msg.sender.call{value: amount}("");  // call BEFORE state update
        require(ok);
        balances[msg.sender] -= amount;  // state update AFTER call ❌
    }

    // SOL-CRIT-004: Unchecked .call() return value
    function sendReward(address recipient, uint256 amount) external {
        recipient.call{value: amount}("");  // return value ignored ❌
    }

    // SOL-CRIT-009: tx.origin authentication
    function adminWithdraw() external {
        require(tx.origin == owner, "Not owner");  // tx.origin auth ❌
        payable(owner).transfer(address(this).balance);
    }

    // SOL-CRIT-006: Unprotected selfdestruct
    function destroy() external {
        selfdestruct(payable(msg.sender));  // no access control ❌
    }

    // SOL-HIGH-005: Missing access control on critical function
    function mint(address to, uint256 amount) external {  // no onlyOwner ❌
        balances[to] += amount;
    }

    // SOL-HIGH-002: Integer overflow (Solidity 0.7 — no SafeMath)
    function unsafeAdd(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;  // can overflow ❌
    }

    // SOL-HIGH-007: Unbounded loop DoS
    address[] public users;

    function distributeAll(uint256 amount) external {
        for (uint256 i = 0; i < users.length; i++) {  // unbounded ❌
            payable(users[i]).transfer(amount);
        }
    }

    function addUser(address user) external {
        users.push(user);  // array grows without bound
    }

    // SOL-MED-002: Missing zero-address check
    function setOwner(address newOwner) external {
        // require(newOwner != address(0)); ← missing ❌
        owner = newOwner;
    }

    // SOL-MED-006: Missing event on state change
    function setFee(uint256 fee) external {
        // No emit event ❌
        // fee storage would go here
    }

    // SOL-LOW-001: Floating pragma (pragma solidity ^0.7.6 above)

    // SOL-INFO-003: External dependency
    // Uses hardcoded address (SOL-LOW-004)
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    receive() external payable {}
}

// SOL-HIGH-008: ERC20 transfer return value unchecked
interface IERC20Simple {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract UncheckedTransfer {
    function pay(address token, address recipient, uint256 amount) external {
        IERC20Simple(token).transfer(recipient, amount);  // return value ignored ❌
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SOL-HIGH-020: Missing __gap in upgradeable base contract
contract BaseUpgradeable {
    address public owner;
    bool public initialized;
    
    function init() public {
        require(!initialized);
        owner = msg.sender;
        initialized = true;
    }
    
    // Missing: uint256[50] private __gap;
}

contract ChildUpgradeable is BaseUpgradeable {
    uint256 public balance;
}

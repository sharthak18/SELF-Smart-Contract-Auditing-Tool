// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

// Fixed compiler version — outside the TSTORE Poison affected range.
contract VaultWithTransientLockFixed {
    address public owner;
    transient address internal _txSender;
    mapping(uint256 => address) public delegates;

    constructor() {
        owner = msg.sender;
    }

    function clearDelegate(uint256 id) external {
        delete delegates[id];
    }

    function guarded() external {
        _txSender = msg.sender;
        delete _txSender;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Models the "TSTORE Poison" transient/persistent storage clearing
// collision (solc 0.8.28-0.8.33, --via-ir). Both a transient `delete`
// and a persistent `delete` of a matching value type appear in the
// same compilation unit.
contract VaultWithTransientLock {
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
        // ... perform guarded logic ...
        delete _txSender;
    }
}

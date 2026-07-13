// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SignatureMalleability {
    mapping(bytes32 => bool) public usedSigs;

    // SOL-CRIT-014: Signature malleability
    function withdraw(bytes32 message, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 sigHash = keccak256(abi.encodePacked(message, v, r, s));
        require(!usedSigs[sigHash], "Sig used");
        usedSigs[sigHash] = true;
        
        address recovered = ecrecover(message, v, r, s);
        // Uses recovered address...
    }
    
    // SOL-HIGH-023: ecrecover zero
    function authenticate(bytes32 message, uint8 v, bytes32 r, bytes32 s) external view returns (bool) {
        address recovered = ecrecover(message, v, r, s);
        return recovered == msg.sender;
        // If recovered == 0, and msg.sender == 0...
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Models a forwarder that accepts the EIP-712 domain separator as a
// caller-supplied argument instead of deriving it on-chain.
contract UnsafeForwarder {
    function verify(
        bytes32 domainSeparator,
        bytes32 structHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external pure returns (address) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        return ecrecover(digest, v, r, s);
    }
}

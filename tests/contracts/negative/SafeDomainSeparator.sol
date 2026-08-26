// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SafeForwarder {
    bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;

    constructor() {
        _CACHED_DOMAIN_SEPARATOR = keccak256(
            abi.encode(block.chainid, address(this))
        );
    }

    function verify(bytes32 structHash, uint8 v, bytes32 r, bytes32 s) external view returns (address) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _CACHED_DOMAIN_SEPARATOR, structHash));
        return ecrecover(digest, v, r, s);
    }
}

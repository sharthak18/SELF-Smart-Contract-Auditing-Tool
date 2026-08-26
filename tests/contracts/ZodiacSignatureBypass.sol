// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Models the Zodiac Roles/Delay module pattern behind the June 2026
// Gnosis Pay exploit: the low-level staticcall's success flag is
// discarded before the magic value comparison.
contract ZodiacStyleModule {
    bytes4 internal constant EIP1271_MAGIC_VALUE = 0x1626ba7e;

    function isValidSignature(address signer, bytes32 hash, bytes memory signature)
        external
        view
        returns (bool)
    {
        (, bytes memory returnData) = signer.staticcall(
            abi.encodeWithSelector(0x1626ba7e, hash, signature)
        );
        return bytes4(returnData) == EIP1271_MAGIC_VALUE;
    }
}

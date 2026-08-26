// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SafeZodiacStyleModule {
    bytes4 internal constant EIP1271_MAGIC_VALUE = 0x1626ba7e;

    function isValidSignature(address signer, bytes32 hash, bytes memory signature)
        external
        view
        returns (bool)
    {
        (bool ok, bytes memory returnData) = signer.staticcall(
            abi.encodeWithSelector(0x1626ba7e, hash, signature)
        );
        return ok && bytes4(returnData) == EIP1271_MAGIC_VALUE;
    }
}

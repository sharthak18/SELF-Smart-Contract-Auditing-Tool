// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract Safe {
    uint256 public x;

    function set(uint256 v) external {
        x = v;
    }
}

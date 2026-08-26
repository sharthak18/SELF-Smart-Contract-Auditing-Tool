// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Models the Curve get_virtual_price() read-only reentrancy shape:
// an unguarded price view alongside a state-mutating function that
// makes an external call before finishing its own accounting.
contract CurveStylePool {
    uint256 public totalSupply;
    uint256 public poolBalance;

    function get_virtual_price() external view returns (uint256) {
        return poolBalance * 1e18 / totalSupply;
    }

    function remove_liquidity(uint256 amount) external {
        totalSupply -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        poolBalance -= amount;
    }
}

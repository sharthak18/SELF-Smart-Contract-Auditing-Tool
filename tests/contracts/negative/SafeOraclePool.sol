// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SafeCurveStylePool {
    uint256 public totalSupply;
    uint256 public poolBalance;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "reentrant");
        _locked = true;
        _;
        _locked = false;
    }

    function get_virtual_price() external view nonReentrant returns (uint256) {
        return poolBalance * 1e18 / totalSupply;
    }

    function remove_liquidity(uint256 amount) external nonReentrant {
        totalSupply -= amount;
        poolBalance -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}

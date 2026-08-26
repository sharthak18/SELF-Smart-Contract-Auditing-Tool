// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Permit {
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract PermitRouter {
    function supplyWithPermit(
        address token,
        address owner,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        IERC20Permit(token).permit(owner, address(this), value, deadline, v, r, s);
        IERC20Permit(token).transferFrom(owner, address(this), value);
    }
}

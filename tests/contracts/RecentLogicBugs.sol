// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// SELF fixture — recent protocol-logic classes (Euler / Penpie / Prisma).
// Do not deploy.

interface IMarket {
    function redeemRewards() external;
}

interface IERC20Lite {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract EulerishPool {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public reserves;

    function borrow(uint256 amount) external {
        debt[msg.sender] += amount;
    }

    function liquidate(address user) external {
        require(debt[user] > collateral[user], "healthy");
        collateral[user] = 0;
        debt[user] = 0;
    }

    // Euler 2023: donation skips the health check every other path uses.
    function donateToReserves(uint256 amount) external {
        collateral[msg.sender] -= amount;
        reserves += amount;
    }
}

contract PenpieishStaking {
    address[] public markets;
    mapping(address => uint256) public rewards;
    IERC20Lite public token;

    function registerMarket(address market) external {
        markets.push(market);
    }

    function harvest(address market) external {
        uint256 before = token.balanceOf(address(this));
        IMarket(market).redeemRewards();
        rewards[msg.sender] += token.balanceOf(address(this)) - before;
    }
}

contract PrismaishZap {
    function onFlashLoan(address trove, uint256 debt, bytes calldata data) external {
        // No caller / initiator bind — Prisma 2024 class.
        (bool ok,) = trove.call(data);
        require(ok);
        debt;
    }
}

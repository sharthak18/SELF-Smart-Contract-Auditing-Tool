// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MEVTarget {
    address public highestBidder;
    uint256 public highestBid;

    // SOL-HIGH-018: Predictable commit-reveal
    function commit(bytes32 commitment) external {
        // Expected commitment: keccak256(abi.encodePacked(bid))
        // Missing sender address
        bytes32 verify = keccak256(abi.encodePacked(commitment));
    }
    
    function reveal(uint256 bid) external {
        bytes32 hash = keccak256(abi.encodePacked(bid));
        // Verify commitment...
        if (bid > highestBid) {
            highestBid = bid;
            highestBidder = msg.sender;
        }
    }
    
    // SOL-HIGH-019: Slippage protection
    function executeSwap(address router, address tokenA, address tokenB, uint256 amount) external {
        // Call to a DEX router
        // Missing minAmountOut and strict deadline
        IRouter(router).swapExactTokensForTokens(
            amount,
            0, // minAmountOut = 0!
            getTokens(tokenA, tokenB),
            msg.sender,
            block.timestamp // Using block.timestamp as deadline!
        );
    }
    
    function getTokens(address a, address b) internal pure returns (address[] memory) {
        address[] memory path = new address[](2);
        path[0] = a; path[1] = b;
        return path;
    }
}

interface IRouter {
    function swapExactTokensForTokens(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external returns (uint[] memory amounts);
}

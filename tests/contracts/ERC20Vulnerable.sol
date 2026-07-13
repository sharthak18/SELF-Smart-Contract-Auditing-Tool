// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ERC20Vulnerable {
    mapping(address => mapping(address => uint256)) public allowance;

    // SOL-HIGH-014: ERC-20 approve race
    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    
    // SOL-HIGH-016: Dangerous transferFrom
    function purchaseNFT(address nft, uint256 id) external {
        // Assume NFT is an ERC721
        IERC721(nft).transferFrom(msg.sender, address(this), id);
    }
    
    // SOL-MED-014: Permit deadline
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        // Missing deadline validation against current block time
        // require(current_time <= deadline, "Expired");
        allowance[owner][spender] = value;
    }
}

interface IERC721 {
    function transferFrom(address from, address to, uint256 tokenId) external;
}

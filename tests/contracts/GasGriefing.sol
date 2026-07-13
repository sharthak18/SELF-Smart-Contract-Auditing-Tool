// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GasGriefing {
    
    // SOL-HIGH-024: Returndata Bomb
    function batchCall(address[] memory targets) external {
        for(uint i=0; i<targets.length; i++) {
            (bool success, bytes memory data) = targets[i].call("");
            // Implicit copy of return data into memory happens here
            // Attacker can return 10MB of data
            if(success) {
                // Do something
            }
        }
    }
    
    // SOL-CRIT-011: Transient storage
    function enter() external {
        assembly {
            tstore(1, 1) // lock
        }
        
        // Do something
        
        // No cleanup!
    }
    
    // SOL-CRIT-012: CREATE2 Reentrancy
    function deployAndCall(bytes memory code, bytes32 salt) external {
        address target;
        assembly {
            target := create2(0, add(code, 0x20), mload(code), salt)
        }
        // External call immediately after create2
        (bool ok, ) = target.call("");
        require(ok);
    }
    
    // SOL-LOW-009: Payable missing msg.value
    function deposit() external payable {
        // Doesn't use msg.value!
    }
    
    // SOL-LOW-008: WETH without fallback
    address public WETH;
    function unwrap() external {
        // WETH withdraw sends ETH to this contract, which will fail without a receiver method
        IWETH(WETH).withdraw(100);
    }
}

interface IWETH {
    function withdraw(uint256 wad) external;
}

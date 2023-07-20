// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

/// @notice this is the structure that a user will sign
struct OrderToSign {
    uint256 amountA;
    uint256 amountB;
    uint256 expirationTime;
    uint256 nonce;
    uint256 chainId;
    address tokenA;
    address tokenB;
    address verifyingContract;
}

/// @notice offline exchange will pass this to contract
struct OrderToVerify {
    uint256 amountA;
    uint256 amountB;
    uint256 expirationTime;
    address signer;
    bytes signature;
}

contract TokenA is ERC20Permit {
    constructor() ERC20Permit("TOKENA") ERC20("TOKENA", "TKA") {
        _mint(msg.sender, 1000 ether);
    }
}

contract TokenB is ERC20Permit {
    constructor() ERC20Permit("TOKENB") ERC20("TOKENB", "TKB") {
        _mint(msg.sender, 1000 ether);
    }
}

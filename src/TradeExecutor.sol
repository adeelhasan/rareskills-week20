// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./TradeHelpers.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract TradeExecutor {
    using ECDSA for bytes32;

    TokenA public immutable tokenA;
    TokenB public immutable tokenB;
    
    mapping(address => uint256) public nonces;

    constructor(address _tokenA, address _tokenB) {
        tokenA = TokenA(_tokenA);
        tokenB = TokenB(_tokenB);
    }

    /// @notice verifies orders by the off-chain exchange
    /// @dev recreate hash, then attempt to recover
    /// verify that the trader and signer are the same
    /// check that the allowances cover trade amounts involved
    function verifyOrder(OrderToVerify calldata order) public view returns (bool) {
        OrderToSign memory orderForHash = OrderToSign(
            order.amountA,
            order.amountB,
            order.expirationTime,
            nonces[order.signer],   //this limits the user to one order at a time
            getChainId(),
            address(tokenA),
            address(tokenB),
            address(this)
        );

        bytes32 orderHash = keccak256(abi.encode(orderForHash)).toEthSignedMessageHash();
        require(order.signer == orderHash.recover(order.signature), "signature didnt match");
        require(order.expirationTime > block.timestamp, "order expired");

        //allowance should have been granted by a pervious permit call
        require(tokenA.allowance(order.signer, address(this)) >= order.amountA, "inadequate allowance for A");
        require(tokenB.allowance(order.signer, address(this)) >= order.amountB, "inadequate allowance for B");

        return true;
    }

    function executeOrder(OrderToVerify calldata order1, OrderToVerify calldata order2) external {
        require(order1.signer != order2.signer, "cannot self-trade");
        require(verifyOrder(order1), "order 1 is not valid");
        require(verifyOrder(order2), "order 2 is not valid");

        nonces[order1.signer]++;
        nonces[order2.signer]++;

        //swap tokens and actually materialize the trade
        //not part of exercise


    }

    function getChainId() public view returns (uint256 result) {
        assembly {
            result := chainid()
        }
    }
}

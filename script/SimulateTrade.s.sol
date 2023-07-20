// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import "src/TradeHelpers.sol";
import "src/TradeExecutor.sol";
import "src/SigUtils.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SimulateTrade is Script {
    using ECDSA for bytes32;

    uint256 account1PK = uint256(bytes32("0xABCD"));
    uint256 account2PK = uint256(bytes32("0xDCBA"));
    address account1 = vm.addr(uint256(account1PK));
    address account2 = vm.addr(uint256(account2PK));

    TokenA tokenA;
    TokenB tokenB;
    TradeExecutor tradeExecutor;

    function setUp() public {
        tokenA = new TokenA();
        tokenB = new TokenB();
        tokenA.transfer(account1, 100);
        tokenA.transfer(account2, 50);
        tokenB.transfer(account1, 50);
        tokenB.transfer(account2, 25);
        tradeExecutor = new TradeExecutor(address(tokenA), address(tokenB));
    }

    /// @notice utility function since we will call it 4 times
    function signOrder(uint256 privateKey, OrderToSign memory order) internal pure returns (bytes memory signature) {
        bytes32 msgHash = keccak256(abi.encode(order)).toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        signature = abi.encodePacked(r, s, v);
        require(signature.length == 65);
    }

    /// @notice utility function since we will call this 4 times
    function signForPermit(uint256 pk, uint256 value, uint256 deadline, bool useTokenA) internal returns (uint8 v, bytes32 r, bytes32 s) {
        address accountToUse = vm.addr(pk);
        bytes32 domainSepatorToUse;
        uint256 nonce;
        if (useTokenA) {
            nonce = tokenA.nonces(accountToUse);
            domainSepatorToUse = tokenA.DOMAIN_SEPARATOR();
        } else {
            nonce = tokenB.nonces(accountToUse);
            domainSepatorToUse = tokenB.DOMAIN_SEPARATOR();
        }

        SigUtils.Permit memory permit = SigUtils.Permit({
            owner: accountToUse,
            spender: address(tradeExecutor),
            value: value,
            nonce: nonce,
            deadline: deadline
        });
        SigUtils sigUtils = new SigUtils(domainSepatorToUse);
        bytes32 digest = sigUtils.getTypedDataHash(permit);
        (v, r, s) = vm.sign(pk, digest);
    }

    /// @notice simulate the trading run
    function run() public {
        uint256 expirationTime = block.timestamp + 1000;
        
        // permits for account 1
        (uint8 v, bytes32 r, bytes32 s) = signForPermit(account1PK, 100, expirationTime, true);
        tokenA.permit(account1, address(tradeExecutor), 100, expirationTime, v, r, s);
        (v, r, s) = signForPermit(account1PK, 50, expirationTime, false);
        tokenB.permit(account1, address(tradeExecutor), 50, expirationTime, v, r, s);

        // permits for account 2
        (v, r, s) = signForPermit(account2PK, 100, expirationTime, true);
        tokenA.permit(account2, address(tradeExecutor), 100, expirationTime, v, r, s);
        (v, r, s) = signForPermit(account2PK, 50, expirationTime, false);
        tokenB.permit(account2, address(tradeExecutor), 50, expirationTime, v, r, s);

        OrderToSign memory orderA =
            OrderToSign(100, 50, expirationTime, tradeExecutor.nonces(account1), tradeExecutor.getChainId(), address(tokenA), address(tokenB), address(tradeExecutor));
        OrderToSign memory orderB =
            OrderToSign(50, 25, expirationTime, tradeExecutor.nonces(account1), tradeExecutor.getChainId(), address(tokenA), address(tokenB), address(tradeExecutor));

        bytes memory signature1 = signOrder(uint256(account1PK), orderA);
        bytes memory signature2 = signOrder(uint256(account2PK), orderB);

        OrderToVerify memory order1 = OrderToVerify(100, 50, expirationTime, account1, signature1);
        OrderToVerify memory order2 = OrderToVerify(50, 25, expirationTime, account2, signature2);
        tradeExecutor.executeOrder(order1, order2);

        //do the exchange...

        //vm.broadcast();
    }
}

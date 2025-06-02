// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {DfnsSmartAccount} from "../../src/DfnsSmartAccount.sol";

struct Operation {
    address to;          // 20 bytes
    uint256 value;       // 32 bytes
    bytes data;          // variable length
}

struct TestContext {
    address dfnsSmartAccount;
    address eoaOwner;
    uint256 eoaOwnerPrivateKey;
    Vm vm;
}

/**
 * @title DfnsTestUtils
 * @dev Library containing reusable utility functions for DfnsSmartAccount testing
 * This library helps reduce the size of test contracts by extracting commonly used functions
 */
library DfnsTestUtils {
    // Constants matching DfnsSmartAccount
    bytes32 private constant _STORAGE = 0x10ee8db8a0021e326896fcf9b44ce61becefe5f52e3dfd0bb294aee9b73bc000;
    bytes32 private constant _DOMAIN_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
    bytes32 private constant _HANDLEOPS_TYPEHASH = 0x4f8bb4631e6552ac29b9d6bacf60ff8b5481e2af7c2104fe0261045fa6988111;

    // Signature malleability protection constants
    uint256 private constant CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    uint256 private constant HALF_CURVE_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    /**
     * @dev Set up EIP-7702 delegation before each test that requires signature verification
     * This simulates the EOA delegating to the smart contract implementation
     */
    function setupEIP7702Delegation(TestContext memory ctx) internal {
        ctx.vm.signAndAttachDelegation(ctx.dfnsSmartAccount, ctx.eoaOwnerPrivateKey);
        
        // Verify delegation was successful
        bytes memory code = ctx.eoaOwner.code;
        require(code.length > 0, "EIP-7702 delegation failed - no code at EOA address");
    }

    /**
     * @dev Generate signature for userOps using EIP-7702 context
     * @param ctx Test context containing necessary addresses and keys
     * @param userOps Encoded user operations
     * @param nonce Current nonce for the operation
     * @return r The r component of the signature
     * @return vs The combined v and s components
     */
    function generateSignature(
        TestContext memory ctx,
        bytes memory userOps, 
        uint256 nonce
    ) internal returns (uint256 r, uint256 vs) {
        // In EIP-7702 context, the contract calculates digest using EOA address as address(this)
        bytes32 digest = simulateContractDigest(ctx, userOps, nonce, ctx.eoaOwner);
        
        // Sign with the EOA's private key
        (uint8 v, bytes32 rBytes, bytes32 s) = ctx.vm.sign(ctx.eoaOwnerPrivateKey, digest);
        
        // Apply malleability protection - ensure s is in lower half of curve order
        uint256 sValue = uint256(s);
        if (sValue > HALF_CURVE_ORDER) {
            sValue = CURVE_ORDER - sValue;
            // When we flip s, we also need to flip v
            v = v == 27 ? 28 : 27;
        }
        
        // Convert to the vs format used by the contract
        // The vs format: high bit indicates v parity, remaining 255 bits are s
        r = uint256(rBytes);
        
        // Ensure s fits in 255 bits (clear high bit) and set v bit
        sValue = sValue & 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
        vs = (v == 27 ? 0 : uint256(1 << 255)) | sValue;
    }

    /**
     * @dev Encode operations into userOps format
     * Format: to(20) + value(32) + dataLength(32) + data(variable)
     * @param operations Array of operations to encode
     * @return encoded Encoded operations in userOps format
     */
    function encodeOperations(Operation[] memory operations) internal pure returns (bytes memory) {
        bytes memory encoded;
        
        for (uint256 i = 0; i < operations.length; i++) {
            encoded = abi.encodePacked(
                encoded,
                operations[i].to,        // 20 bytes
                operations[i].value,     // 32 bytes  
                operations[i].data.length, // 32 bytes
                operations[i].data       // variable length
            );
        }
        
        return encoded;
    }

    /**
     * @dev Simulate signature validation exactly as the contract does in EIP-7702 context
     * @param ctx Test context
     * @param userOps Encoded user operations
     * @param nonce Current nonce
     * @param contractAddress Address to use as verifying contract
     * @return digest The calculated EIP-712 digest
     */
    function simulateContractDigest(
        TestContext memory ctx,
        bytes memory userOps, 
        uint256 nonce, 
        address contractAddress
    ) internal view returns (bytes32 digest) {
        // This simulates exactly what the contract does in handleOps()
        bytes32 domainSeparator = keccak256(abi.encode(_DOMAIN_TYPEHASH, block.chainid, contractAddress));
        bytes32 structHash = keccak256(abi.encode(_HANDLEOPS_TYPEHASH, keccak256(userOps), nonce));
        digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /**
     * @dev Generate EIP-712 data structure for DFNS API integration
     * @param ctx Test context
     * @param userOps Encoded User Ops
     * @param nonce The nonce value
     * @return dataHash The keccak256 hash of userOps (for EIP-712 message.data field)
     * @return digest The final EIP-712 digest that would be signed
     * @return domainSeparator The domain separator for verification
     */
    function generateEip712Data(
        TestContext memory ctx,
        bytes memory userOps, 
        uint256 nonce
    ) internal view returns (bytes32 dataHash, bytes32 digest, bytes32 domainSeparator) {
        // Calculate data hash for EIP-712 message
        dataHash = keccak256(userOps);
        
        // In EIP-7702, when the contract executes, address(this) will be the EOA address
        // because the EOA has delegated its code to the smart contract
        // So we use the EOA address as the verifying contract
        domainSeparator = keccak256(abi.encode(
            _DOMAIN_TYPEHASH,
            block.chainid,
            ctx.eoaOwner  // This will be address(this) when the contract executes via EIP-7702
        ));
        
        bytes32 structHash = keccak256(abi.encode(
            _HANDLEOPS_TYPEHASH,
            dataHash,
            nonce
        ));
        
        digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /**
     * @dev Call handleOps with proper EIP-7702 delegation context
     * @param ctx Test context
     * @param userOps Encoded user operations
     * @param r The r component of the signature
     * @param vs The combined v and s components
     */
    function callHandleOps(
        TestContext memory ctx,
        bytes memory userOps, 
        uint256 r, 
        uint256 vs
    ) internal {
        // Set up EIP-7702 delegation
        setupEIP7702Delegation(ctx);
        
        // Call the contract from the EOA context (EIP-7702 delegation)
        ctx.vm.startPrank(ctx.eoaOwner);
        
        // Get the contract instance at the EOA address (delegation simulation)
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(ctx.eoaOwner));
        delegatedContract.handleOps(userOps, r, vs);
        
        ctx.vm.stopPrank();
    }

    /**
     * @dev Safely attempt to call handleOps and return success status
     * @param ctx Test context
     * @param userOps The encoded user operations
     * @param r The r component of the signature
     * @param vs The combined v and s components
     * @return success True if the call succeeded, false if it reverted
     */
    function tryHandleOps(
        TestContext memory ctx,
        bytes memory userOps, 
        uint256 r, 
        uint256 vs
    ) internal returns (bool success) {
        // After EIP-7702 delegation, the EOA address behaves like the smart contract
        // We create a DfnsSmartAccount interface pointing to the EOA address
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(ctx.eoaOwner));
        
        ctx.vm.startPrank(ctx.eoaOwner);
        try delegatedContract.handleOps(userOps, r, vs) {
            success = true;
        } catch {
            success = false;
        }
        ctx.vm.stopPrank();
    }

    /**
     * @dev Custom signature validation function that mimics DfnsSmartAccount._isValidSignature
     * This allows us to test the signature validation logic independently
     * @param hash The hash to validate
     * @param r The r component of the signature
     * @param vs The combined v and s components
     * @param expectedSigner The expected signer address
     * @return isValid True if signature is valid
     */
    function simulateSignatureValidation(
        bytes32 hash, 
        uint256 r, 
        uint256 vs, 
        address expectedSigner
    ) internal pure returns (bool isValid) {
        unchecked {
            // Apply signature malleability protection as in the updated contract
            if (r == 0 || r >= CURVE_ORDER) return false;
            
            uint256 v = (vs >> 255) + 27;
            uint256 s = vs & 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
            
            // Ensure v is 27 or 28
            if (v != 27 && v != 28) return false;
            
            // Apply strict s validation for malleability protection
            if (s == 0 || s > HALF_CURVE_ORDER) return false;
            
            return expectedSigner == ecrecover(hash, uint8(v), bytes32(r), bytes32(s));
        }
    }

    /**
     * @dev Simulate hash calculation as done in DfnsSmartAccount.handleOps
     * @param userOps Encoded user operations
     * @param nonce Current nonce
     * @param verifyingContract Address of the verifying contract
     * @return hash The calculated hash
     */
    function simulateHashCalculation(
        bytes memory userOps, 
        uint256 nonce, 
        address verifyingContract
    ) internal view returns (bytes32 hash) {
        bytes32 domainSeparator = keccak256(abi.encode(_DOMAIN_TYPEHASH, block.chainid, verifyingContract));
        bytes32 structHash = keccak256(abi.encode(_HANDLEOPS_TYPEHASH, keccak256(userOps), nonce));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /**
     * @dev Validate operation format for edge case testing
     * @param userOps Encoded operations to validate
     * @return isValid True if format is valid
     */
    function validateOperationFormat(bytes memory userOps) internal pure returns (bool isValid) {
        if (userOps.length == 0) return true; // Empty operations are valid
        
        uint256 offset = 0;
        while (offset < userOps.length) {
            // Check if we have enough bytes for: address(20) + value(32) + dataLength(32)
            if (offset + 84 > userOps.length) return false;
            
            // Extract data length
            uint256 dataLength;
            assembly {
                dataLength := mload(add(add(userOps, 0x20), add(offset, 52)))
            }
            
            // Check if we have enough bytes for the data
            if (offset + 84 + dataLength > userOps.length) return false;
            
            // Move to next operation
            offset += 84 + dataLength;
        }
        
        return offset == userOps.length;
    }

    /**
     * @dev Create a test context for library functions
     * @param dfnsSmartAccount Address of the DfnsSmartAccount contract
     * @param eoaOwner Address of the EOA owner
     * @param eoaOwnerPrivateKey Private key of the EOA owner
     * @param vm Foundry VM instance
     * @return ctx The test context struct
     */
    function createTestContext(
        address dfnsSmartAccount,
        address eoaOwner,
        uint256 eoaOwnerPrivateKey,
        Vm vm
    ) internal pure returns (TestContext memory ctx) {
        ctx.dfnsSmartAccount = dfnsSmartAccount;
        ctx.eoaOwner = eoaOwner;
        ctx.eoaOwnerPrivateKey = eoaOwnerPrivateKey;
        ctx.vm = vm;
    }

    /**
     * @dev Create valid deployment userOps for CREATE2 testing
     * @param target Target address for the operation
     * @param value ETH value to send
     * @param data Encoded function call data
     * @return userOps Encoded user operations
     */
    function createValidDeploymentUserOps(
        address target,
        uint256 value,
        bytes memory data
    ) internal pure returns (bytes memory userOps) {
        return abi.encodePacked(
            uint256(84 + data.length), // Total length: 32 (length) + 20 (address) + 32 (value) + 32 (dataLength) + data.length
            target,                    // Target address (20 bytes)
            value,                     // ETH value (32 bytes)
            uint256(data.length),      // Data length (32 bytes)
            data                       // Encoded function call (variable length)
        );
    }

    /**
     * @dev Check if address is a contract
     * @param account Address to check
     * @return isContract True if address has code
     */
    function isContract(address account) internal view returns (bool isContract) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}

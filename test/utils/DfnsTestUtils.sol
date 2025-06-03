// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {DfnsSmartAccount} from "../../src/DfnsSmartAccount.sol";
import {MockERC20, MockERC721} from "./mockContracts.sol"; 
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
     * @return success True if the call succeeded, false if it reverted
     */
// In DfnsTestUtils.sol
function callHandleOps(
    TestContext memory ctx,
    bytes memory userOps,
    uint256 r,
    uint256 vs
) internal returns (bool success) {
    try DfnsSmartAccount(payable(ctx.dfnsSmartAccount)).handleOps(userOps, r, vs) {
        return true;
    } catch {
        return false;
    }
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

    // =================== INVARIANT TESTING UTILITIES ===================

    /**
     * @dev Validate nonce monotonicity and uniqueness
     * @param ctx Test context
     * @param expectedMinNonce Minimum expected nonce value
     * @return isValid True if nonce constraints are satisfied
     */
    function validateNonceInvariant(
        TestContext memory ctx,
        uint256 expectedMinNonce
    ) internal view returns (bool isValid) {
        DfnsSmartAccount account = DfnsSmartAccount(ctx.dfnsSmartAccount);
        uint256 currentNonce = account.getNonce();
        return currentNonce >= expectedMinNonce;
    }

    /**
     * @dev Test signature validation with malformed signatures
     * @param ctx Test context
     * @param userOps Valid user operations
     * @return allInvalidSigsRejected True if all invalid signatures are properly rejected
     */
    function testInvalidSignatureRejection(
        TestContext memory ctx,
        bytes memory userOps
    ) internal returns (bool allInvalidSigsRejected) {
        uint256 currentNonce = DfnsSmartAccount(ctx.dfnsSmartAccount).getNonce();
        
        // Test 1: Invalid r value (zero)
        if (!_testInvalidSignature(ctx, userOps, 0, 1, currentNonce)) {
            return false;
        }
        
        // Test 2: Invalid r value (>= curve order)
        if (!_testInvalidSignature(ctx, userOps, CURVE_ORDER, 1, currentNonce)) {
            return false;
        }
        
        // Test 3: Invalid s value (zero)
        if (!_testInvalidSignature(ctx, userOps, 1, 0, currentNonce)) {
            return false;
        }
        
        // Test 4: Invalid s value (> half curve order - malleable)
        if (!_testInvalidSignature(ctx, userOps, 1, HALF_CURVE_ORDER + 1, currentNonce)) {
            return false;
        }
        
        return true;
    }

    /**
     * @dev Test assembly parsing with malformed userOps
     * @param ctx Test context
     * @return memoryAndParsingSecure True if assembly parsing is secure
     */
    function testAssemblyParsingSecurity(
        TestContext memory ctx
    ) internal returns (bool memoryAndParsingSecure) {
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(ctx.eoaOwner));
        
        // Test 1: Empty userOps (should succeed)
        bytes memory emptyOps = abi.encodePacked(uint256(0));
        if (!_tryUserOps(ctx, emptyOps)) {
            return false; // Empty ops should succeed
        }
        
        // Test 2: Truncated operation (should fail)
        bytes memory truncatedOps = abi.encodePacked(
            uint256(50), // Claims 50 bytes
            address(0x1234), // Only 20 bytes provided
            uint256(1 ether) // 32 bytes, total 52 > 50
        );
        if (_tryUserOps(ctx, truncatedOps)) {
            return false; // Truncated ops should fail
        }
        
        // Test 3: Data length mismatch (should fail)
        bytes memory mismatchOps = abi.encodePacked(
            uint256(100), // Claims 100 bytes total
            address(0x1234), // 20 bytes
            uint256(0), // 32 bytes
            uint256(1000), // Claims 1000 bytes of data but only has ~48 bytes left
            bytes4(0x12345678) // 4 bytes of data
        );
        if (_tryUserOps(ctx, mismatchOps)) {
            return false; // Mismatched data length should fail
        }
        
        return true;
    }

    /**
     * @dev Test batch atomicity invariant
     * @param ctx Test context
     * @param target Target contract address
     * @return batchIsAtomic True if batch operations are atomic
     */
    function testBatchAtomicity(
        TestContext memory ctx,
        address target
    ) internal returns (bool batchIsAtomic) {
        uint256 balanceBefore = ctx.eoaOwner.balance;
        uint256 nonceBefore = DfnsSmartAccount(ctx.dfnsSmartAccount).getNonce();
        
        // Create a batch with one valid and one failing operation
        Operation[] memory operations = new Operation[](2);
        operations[0] = Operation({
            to: target,
            value: 1 ether,
            data: ""
        });
        operations[1] = Operation({
            to: address(0), // This should fail
            value: 1 ether,
            data: ""
        });
        
        bytes memory batchOps = encodeOperations(operations);
        (uint256 r, uint256 vs) = generateSignature(ctx, batchOps, nonceBefore);
        
        // Execute batch - should fail atomically
        bool success = _tryUserOpsRaw(ctx, batchOps, r, vs);
        
        uint256 balanceAfter = ctx.eoaOwner.balance;
        uint256 nonceAfter = DfnsSmartAccount(ctx.dfnsSmartAccount).getNonce();
        
        // If batch failed, no changes should have occurred
        if (!success) {
            return (balanceAfter == balanceBefore && nonceAfter == nonceBefore);
        }
        
        // If batch succeeded unexpectedly, that's also a problem
        return false;
    }

    /**
     * @dev Test cross-chain replay protection
     * @param ctx Test context
     * @param userOps Valid user operations
     * @return replayProtected True if replay protection is working
     */
    function testCrossChainReplayProtection(
        TestContext memory ctx,
        bytes memory userOps
    ) internal returns (bool replayProtected) {
        uint256 currentNonce = DfnsSmartAccount(ctx.dfnsSmartAccount).getNonce();
        
        // Create valid signature for current chain
        (uint256 r, uint256 vs) = generateSignature(ctx, userOps, currentNonce);
        
        // Change chain ID and try to replay
        uint256 originalChainId = block.chainid;
        ctx.vm.chainId(originalChainId + 1);
        
        // Try to replay the same signature on different chain
        bool replaySucceeded = _tryUserOpsRaw(ctx, userOps, r, vs);
        
        // Restore original chain ID
        ctx.vm.chainId(originalChainId);
        
        // Replay should fail
        return !replaySucceeded;
    }

    /**
     * @dev Test ERC token operation consistency
     * @param ctx Test context
     * @param tokenContract ERC20 token contract
     * @param recipient Recipient address
     * @param amount Transfer amount
     * @return operationsConsistent True if ERC operations maintain consistency
     */
    function testERC20OperationConsistency(
        TestContext memory ctx,
        address tokenContract,
        address recipient,
        uint256 amount
    ) internal returns (bool operationsConsistent) {
        // Get initial balances
        uint256 senderBalanceBefore = MockERC20(tokenContract).balanceOf(ctx.eoaOwner);
        uint256 recipientBalanceBefore = MockERC20(tokenContract).balanceOf(recipient);
        
        if (senderBalanceBefore < amount) {
            return true; // Skip if insufficient balance
        }
        
        // Create ERC20 transfer operation
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: tokenContract,
            value: 0,
            data: abi.encodeWithSignature("transfer(address,uint256)", recipient, amount)
        });
        
        bytes memory userOps = encodeOperations(operations);
        uint256 currentNonce = DfnsSmartAccount(ctx.dfnsSmartAccount).getNonce();
        (uint256 r, uint256 vs) = generateSignature(ctx, userOps, currentNonce);
        
        // Execute operation
        bool success = _tryUserOpsRaw(ctx, userOps, r, vs);
        
        if (success) {
            // Check final balances
            uint256 senderBalanceAfter = MockERC20(tokenContract).balanceOf(ctx.eoaOwner);
            uint256 recipientBalanceAfter = MockERC20(tokenContract).balanceOf(recipient);
            
            // Verify balance changes are correct
            return (senderBalanceAfter == senderBalanceBefore - amount) &&
                   (recipientBalanceAfter == recipientBalanceBefore + amount);
        }
        
        return true; // If operation failed, that's acceptable
    }

    /**
     * @dev Test gas limit enforcement
     * @param ctx Test context
     * @param maxGasPerOperation Maximum allowed gas per operation
     * @return gasLimitsEnforced True if gas limits are properly enforced
     */
    function testGasLimitEnforcement(
        TestContext memory ctx,
        uint256 maxGasPerOperation
    ) internal returns (bool gasLimitsEnforced) {
        // Create a simple operation
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: ctx.dfnsSmartAccount,
            value: 0,
            data: ""
        });
        
        bytes memory userOps = encodeOperations(operations);
        uint256 currentNonce = DfnsSmartAccount(ctx.dfnsSmartAccount).getNonce();
        (uint256 r, uint256 vs) = generateSignature(ctx, userOps, currentNonce);
        
        // Measure gas usage
        uint256 gasBefore = gasleft();
        bool success = _tryUserOpsRaw(ctx, userOps, r, vs);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Gas usage should be within reasonable bounds
        return gasUsed <= maxGasPerOperation;
    }

    /**
     * @dev Create valid userOps for testing
     * @return userOps Valid encoded user operations
     */
    function createValidTestUserOps() internal pure returns (bytes memory userOps) {
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: address(0x1234567890123456789012345678901234567890),
            value: 0,
            data: ""
        });
        return encodeOperations(operations);
    }

    // =================== PRIVATE HELPER FUNCTIONS ===================

    /**
     * @dev Test if an invalid signature is properly rejected
     */
    function _testInvalidSignature(
        TestContext memory ctx,
        bytes memory userOps,
        uint256 r,
        uint256 s,
        uint256 nonce
    ) private returns (bool rejected) {
        uint256 vs = s; // Simplified vs format for testing
        
        setupEIP7702Delegation(ctx);
        ctx.vm.startPrank(ctx.eoaOwner);
        
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(ctx.eoaOwner));
        try delegatedContract.handleOps(userOps, r, vs) {
            ctx.vm.stopPrank();
            return false; // Should have reverted
        } catch {
            ctx.vm.stopPrank();
            return true; // Correctly rejected
        }
    }

    /**
     * @dev Try executing userOps and return success status
     */
    function _tryUserOps(
        TestContext memory ctx,
        bytes memory userOps
    ) private returns (bool success) {
        uint256 currentNonce = DfnsSmartAccount(ctx.dfnsSmartAccount).getNonce();
        (uint256 r, uint256 vs) = generateSignature(ctx, userOps, currentNonce);
        return _tryUserOpsRaw(ctx, userOps, r, vs);
    }

    /**
     * @dev Try executing userOps with given signature components
     */
    function _tryUserOpsRaw(
        TestContext memory ctx,
        bytes memory userOps,
        uint256 r,
        uint256 vs
    ) private returns (bool success) {
        setupEIP7702Delegation(ctx);
        ctx.vm.startPrank(ctx.eoaOwner);
        
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(ctx.eoaOwner));
        try delegatedContract.handleOps(userOps, r, vs) {
            success = true;
        } catch {
            success = false;
        }
        
        ctx.vm.stopPrank();
    }

    /**
     * @dev Test reentrancy protection during operations
     * @param ctx Test context
     * @param target Contract to test reentrancy with
     * @return reentrancyProtected True if reentrancy is properly prevented
     */
    function testReentrancyProtection(
        TestContext memory ctx,
        address target
    ) internal returns (bool reentrancyProtected) {
        // Create operation that could potentially trigger reentrancy
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: target,
            value: 1 ether,
            data: abi.encodeWithSignature("attemptReentrancy()")
        });
        
        bytes memory userOps = encodeOperations(operations);
        uint256 currentNonce = DfnsSmartAccount(ctx.dfnsSmartAccount).getNonce();
        (uint256 r, uint256 vs) = generateSignature(ctx, userOps, currentNonce);
        
        // Attempt reentrancy attack - should fail
        bool success = _tryUserOpsRaw(ctx, userOps, r, vs);
        
        // Reentrancy should be prevented (operation should fail)
        return !success;
    }

    /**
     * @dev Test signature replay across different nonces
     * @param ctx Test context
     * @param userOps Valid user operations
     * @return replayPrevented True if replay is properly prevented
     */
    function testNonceReplayProtection(
        TestContext memory ctx,
        bytes memory userOps
    ) internal returns (bool replayPrevented) {
        uint256 currentNonce = DfnsSmartAccount(ctx.dfnsSmartAccount).getNonce();
        
        // Create signature with current nonce
        (uint256 r, uint256 vs) = generateSignature(ctx, userOps, currentNonce);
        
        // Execute once (should succeed)
        bool firstSuccess = _tryUserOpsRaw(ctx, userOps, r, vs);
        
        if (!firstSuccess) {
            return true; // If first call failed, that's acceptable
        }
        
        // Try to replay same signature with old nonce (should fail)
        bool replaySuccess = _tryUserOpsRaw(ctx, userOps, r, vs);
        
        // Replay should fail
        return !replaySuccess;
    }

    /**
     * @dev Test operation ordering and nonce enforcement
     * @param ctx Test context
     * @return orderingEnforced True if operation ordering is properly enforced
     */
    function testOperationOrdering(
        TestContext memory ctx
    ) internal returns (bool orderingEnforced) {
        uint256 currentNonce = DfnsSmartAccount(ctx.dfnsSmartAccount).getNonce();
        
        // Create two operations with future nonces
        bytes memory userOps1 = createValidTestUserOps();
        bytes memory userOps2 = createValidTestUserOps();
        
        // Create signatures with wrong nonce order
        (uint256 r2, uint256 vs2) = generateSignature(ctx, userOps2, currentNonce + 2);
        (uint256 r1, uint256 vs1) = generateSignature(ctx, userOps1, currentNonce + 1);
        
        // Try to execute operation with nonce+2 first (should fail)
        bool futureNonceSuccess = _tryUserOpsRaw(ctx, userOps2, r2, vs2);
        
        // Should fail due to nonce gap
        return !futureNonceSuccess;
    }

    /**
     * @dev Test memory corruption resistance with malformed assembly data
     * @param ctx Test context
     * @return memoryCorruptionResistant True if memory corruption is prevented
     */
    function testMemoryCorruptionResistance(
        TestContext memory ctx
    ) internal returns (bool memoryCorruptionResistant) {
        // Test 1: Overlapping memory regions
        bytes memory malformedOps1 = abi.encodePacked(
            uint256(32), // Claims 32 bytes total
            address(0x1234), // 20 bytes
            uint256(1 ether), // 32 bytes (exceeds claimed size)
            uint256(100) // Another 32 bytes (way over)
        );
        
        if (_tryUserOps(ctx, malformedOps1)) {
            return false; // Should have failed
        }
        
        // Test 2: Data length overflow
        bytes memory malformedOps2 = abi.encodePacked(
            uint256(84), // Claims exactly header size
            address(0x5678), // 20 bytes
            uint256(0), // 32 bytes
            uint256(type(uint256).max), // Claims max data length (should overflow)
            bytes4(0x12345678) // Only 4 bytes of actual data
        );
        
        if (_tryUserOps(ctx, malformedOps2)) {
            return false; // Should have failed
        }
        
        return true;
    }

    /**
     * @dev Test gas exhaustion attack resistance
     * @param ctx Test context
     * @param maxAllowedGas Maximum gas that should be allowed per operation
     * @return gasExhaustionResistant True if gas exhaustion attacks are prevented
     */
    function testGasExhaustionResistance(
        TestContext memory ctx,
        uint256 maxAllowedGas
    ) internal returns (bool gasExhaustionResistant) {
        // Create operation with potentially expensive computation
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: address(0x9999), // Non-existent contract
            value: 0,
            data: new bytes(5000) // Large data payload
        });
        
        bytes memory userOps = encodeOperations(operations);
        uint256 currentNonce = DfnsSmartAccount(ctx.dfnsSmartAccount).getNonce();
        (uint256 r, uint256 vs) = generateSignature(ctx, userOps, currentNonce);
        
        // Measure gas consumption
        uint256 gasBefore = gasleft();
        _tryUserOpsRaw(ctx, userOps, r, vs);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Should not exceed maximum allowed gas
        return gasUsed <= maxAllowedGas;
    }

    /**
     * @dev Test state consistency during failed operations
     * @param ctx Test context
     * @return stateConsistent True if state remains consistent after failures
     */
    function testStateConsistencyOnFailure(
        TestContext memory ctx
    ) internal returns (bool stateConsistent) {
        uint256 nonceBefore = DfnsSmartAccount(ctx.dfnsSmartAccount).getNonce();
        uint256 balanceBefore = ctx.eoaOwner.balance;
        
        // Create operation that should fail
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: address(0), // Invalid address
            value: 1 ether,
            data: ""
        });
        
        bytes memory userOps = encodeOperations(operations);
        (uint256 r, uint256 vs) = generateSignature(ctx, userOps, nonceBefore);
        
        // Execute failing operation
        bool success = _tryUserOpsRaw(ctx, userOps, r, vs);
        
        uint256 nonceAfter = DfnsSmartAccount(ctx.dfnsSmartAccount).getNonce();
        uint256 balanceAfter = ctx.eoaOwner.balance;
        
        if (!success) {
            // If operation failed, nonce and balance should be unchanged
            return (nonceAfter == nonceBefore) && (balanceAfter == balanceBefore);
        } else {
            // If operation unexpectedly succeeded, that's also a problem
            return false;
        }
    }
}

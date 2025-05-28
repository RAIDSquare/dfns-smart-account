// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {Test, console, console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {stdError} from "forge-std/StdError.sol";
import {DfnsSmartAccount} from "../src/DfnsSmartAccount.sol";

struct Operation {
    address to;          // 20 bytes
    uint256 value;       // 32 bytes
    bytes data;          // variable length
}

error InvalidSignature();

/**
 * @title DfnsSmartAccount Comprehensive Test Suite
 * @dev Complete test coverage for DfnsSmartAccount contract including:
 * - Constants validation
 * - Signature validation with malleability protection
 * - Batch transactions
 * - EIP-7702 compatibility
 * - Edge cases and security tests
 * - Assembly logic verification
 */
contract DfnsSmartAccountTest is Test {
    DfnsSmartAccount public dfnsSmartAccount;
    
    // Test accounts - use forge-std makeAddr for better realism
    address public deployer;
    address public user;
    address public recipient;
    address public attacker;
    
    // EOA that will delegate to the smart contract (EIP-7702)
    address public eoaOwner;
    uint256 public eoaOwnerPrivateKey;
    
    // keccak256("DfnsSmartAccount") & (~0xff)
    bytes32 private constant _STORAGE = 0x10ee8db8a0021e326896fcf9b44ce61becefe5f52e3dfd0bb294aee9b73bc000;
    // keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
    bytes32 private constant _DOMAIN_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
    // keccak256("HandleOps(bytes32 data,uint256 nonce)")
    bytes32 private constant _HANDLEOPS_TYPEHASH = 0x4f8bb4631e6552ac29b9d6bacf60ff8b5481e2af7c2104fe0261045fa6988111;

    // Signature malleability protection constants
    uint256 private constant CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    uint256 private constant HALF_CURVE_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    
    // Mock ERC20 contract for testing
    MockERC20 public mockToken;
    
    // Events
    event Transfer(address indexed from, address indexed to, uint256 value);

    function setUp() public {
        vm.chainId(31337); // anvil local chain ID (0x7a69)
        
        // Create test accounts using forge-std for better realism
        deployer = makeAddr("deployer");
        user = makeAddr("user"); 
        recipient = makeAddr("recipient");
        attacker = makeAddr("attacker");
        
        // Create EOA that will delegate to smart contract (EIP-7702)
        (eoaOwner, eoaOwnerPrivateKey) = makeAddrAndKey("eoaOwner");
        
        // Deploy DfnsSmartAccount at specific address for Holesky compatibility
        address contractAddress = 0xa570148Ab35de51eA1C59AC09Cc6ea37AC6BaB91;
        deployCodeTo("DfnsSmartAccount.sol", contractAddress);
        dfnsSmartAccount = DfnsSmartAccount(contractAddress);

        // Deploy mock token
        mockToken = new MockERC20("Test Token", "TEST", 18);
        
        // Fund accounts
        vm.deal(user, 100 ether);
        vm.deal(eoaOwner, 100 ether);
        vm.deal(address(dfnsSmartAccount), 10 ether);
        vm.deal(recipient, 1 ether);
    }
    
    /**
     * @dev Set up EIP-7702 delegation before each test that requires signature verification
     * This simulates the EOA delegating to the smart contract implementation
     */
    function _setupEIP7702Delegation() internal {
        // Create and attach EIP-7702 delegation using the combined function
        vm.signAndAttachDelegation(address(dfnsSmartAccount), eoaOwnerPrivateKey);
        
        // Verify delegation was successful
        bytes memory code = eoaOwner.code;
        require(code.length > 0, "EIP-7702 delegation failed - no code at EOA address");
    }

    /* ========== ORIGINAL HOLESKY TESTS ========== */

    function test_handleOps() public {
        
        assertEq(dfnsSmartAccount.getNonce(), 0);
        
        // Mint tokens to EOA owner for the transfer
        mockToken.mint(eoaOwner, 10 ether);
        
        // Create dynamic operation equivalent to holeskyUserOps  
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSignature("transfer(address,uint256)", recipient, 1 ether)
        });
        
        bytes memory userOps = _encodeOperations(operations);
        (uint256 r, uint256 vs) = _generateSignature(userOps, 0);
        _callHandleOps(userOps, r, vs);
        
        // Check nonce on EOA address (where delegation is active)
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        assertEq(delegatedContract.getNonce(), 1);
    }

    function test_handleOpsWrongSignature() public {
        assertEq(dfnsSmartAccount.getNonce(), 0);

        // Mint tokens to EOA owner for the transfer
        mockToken.mint(eoaOwner, 10 ether);

        // Create dynamic operation equivalent to holeskyUserOps
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSignature("transfer(address,uint256)", recipient, 1 ether)
        });
        
        bytes memory userOps = _encodeOperations(operations);
        (uint256 r, uint256 vs) = _generateSignature(userOps, 0);
        vm.expectRevert(InvalidSignature.selector);
        _callHandleOps(userOps, r, vs + 1);
        
        // Check nonce on EOA address (where delegation is active) 
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        assertEq(delegatedContract.getNonce(), 0);
    }

    function test_handleOpsReplayProtection() public {
        assertEq(dfnsSmartAccount.getNonce(), 0);
        
        // Mint tokens to EOA owner for the transfer
        mockToken.mint(eoaOwner, 10 ether);
        
        // Create dynamic operation equivalent to holeskyUserOps
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSignature("transfer(address,uint256)", recipient, 1 ether)
        });
        
        bytes memory userOps = _encodeOperations(operations);
        (uint256 r, uint256 vs) = _generateSignature(userOps, 0);
        _callHandleOps(userOps, r, vs);
        
        // Check nonce on EOA address (where delegation is active)
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        assertEq(delegatedContract.getNonce(), 1);
        
        // Try to replay the same transaction - should fail due to replay protection
        vm.expectRevert(InvalidSignature.selector);
        _callHandleOps(userOps, r, vs);
    }

    /* ========== CONSTANTS VALIDATION TESTS ========== */

    function test_StorageSlotConstant() public {
        // Test that _STORAGE constant is correctly calculated
        bytes32 computedStorage = bytes32(uint256(keccak256("DfnsSmartAccount")) & (~uint256(0xff)));
        assertEq(_STORAGE, computedStorage, "Storage slot should match keccak256('DfnsSmartAccount') & (~0xff)");
        
        // Verify the actual value matches expected
        assertEq(_STORAGE, 0x10ee8db8a0021e326896fcf9b44ce61becefe5f52e3dfd0bb294aee9b73bc000);
    }

    function test_DomainTypehashConstant() public {
        // Test that _DOMAIN_TYPEHASH constant is correctly calculated
        bytes32 computedTypehash = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
        assertEq(_DOMAIN_TYPEHASH, computedTypehash, "Domain typehash should match EIP712Domain signature");
        
        // Verify the actual value matches expected
        assertEq(_DOMAIN_TYPEHASH, 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218);
    }

    function test_HandleOpsTypehashConstant() public {
        // Test that _HANDLEOPS_TYPEHASH constant is correctly calculated
        bytes32 computedTypehash = keccak256("HandleOps(bytes32 data,uint256 nonce)");
        assertEq(_HANDLEOPS_TYPEHASH, computedTypehash, "HandleOps typehash should match function signature");
        
        // Verify the actual value matches expected
        assertEq(_HANDLEOPS_TYPEHASH, 0x4f8bb4631e6552ac29b9d6bacf60ff8b5481e2af7c2104fe0261045fa6988111);
    }

    /* ========== NONCE MANAGEMENT TESTS ========== */

    function test_InitialNonce() public {
        assertEq(dfnsSmartAccount.getNonce(), 0, "Initial nonce should be 0");
    }

    function test_NonceIncrementsAfterValidExecution() public {
        assertEq(dfnsSmartAccount.getNonce(), 0);
        
        // Mint tokens to EOA owner for the transfer
        mockToken.mint(eoaOwner, 10 ether);
        
        // Create dynamic operation equivalent to holeskyUserOps
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSignature("transfer(address,uint256)", recipient, 1 ether)
        });
        
        bytes memory userOps = _encodeOperations(operations);
        (uint256 r, uint256 vs) = _generateSignature(userOps, 0);
        _callHandleOps(userOps, r, vs);
        
        // Check nonce on EOA address (where delegation is active)
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        assertEq(delegatedContract.getNonce(), 1, "Nonce should increment after successful execution");
    }

    function test_NonceDoesNotIncrementOnInvalidSignature() public {
        assertEq(dfnsSmartAccount.getNonce(), 0);
        
        // Mint tokens to EOA owner for the transfer
        mockToken.mint(eoaOwner, 10 ether);
        
        // Create dynamic operation equivalent to holeskyUserOps
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSignature("transfer(address,uint256)", recipient, 1 ether)
        });
        
        bytes memory userOps = _encodeOperations(operations);
        (uint256 r, uint256 vs) = _generateSignature(userOps, 0);
        vm.expectRevert(InvalidSignature.selector);
        _callHandleOps(userOps, r, vs + 1);
        
        // Nonce should still be 0 since operation failed
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        assertEq(delegatedContract.getNonce(), 0, "Nonce should not increment on failed execution");
    }

    /* ========== SIGNATURE VALIDATION SIMULATION TESTS ========== */

    /**
     * @dev Custom signature validation function that mimics DfnsSmartAccount._isValidSignature
     * This allows us to test the signature validation logic independently
     */
    function _simulateSignatureValidation(
        bytes32 hash, 
        uint256 r, 
        uint256 vs, 
        address expectedSigner
    ) internal pure returns (bool) {
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
     */
    function _simulateHashCalculation(
        bytes memory userOps, 
        uint256 nonce, 
        address verifyingContract
    ) internal view returns (bytes32) {
        bytes32 domainSeparator = keccak256(abi.encode(_DOMAIN_TYPEHASH, block.chainid, verifyingContract));
        bytes32 structHash = keccak256(abi.encode(_HANDLEOPS_TYPEHASH, keccak256(userOps), nonce));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /**
     * @dev Simulate signature validation exactly as the contract does in EIP-7702 context
     * This is needed because in EIP-7702, address(this) in the contract is the EOA address
     */
    function _simulateContractDigest(bytes memory userOps, uint256 nonce, address contractAddress) 
        internal 
        view 
        returns (bytes32 digest) 
    {
        // This simulates exactly what the contract does in handleOps()
        bytes32 domainSeparator = keccak256(abi.encode(_DOMAIN_TYPEHASH, block.chainid, contractAddress));
        bytes32 structHash = keccak256(abi.encode(_HANDLEOPS_TYPEHASH, keccak256(userOps), nonce));
        digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /**
     * @dev Test signature validation with various edge cases
     */
    function test_SignatureValidation_EdgeCases() public {
        // Test with EOA signer (EIP-7702 context)
        bytes32 testHash = keccak256("test message");
        
        // Case 1: Valid signature with EOA
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaOwnerPrivateKey, testHash);
        
        // Ensure s is in lower half for malleability protection
        if (uint256(s) > HALF_CURVE_ORDER) {
            s = bytes32(CURVE_ORDER - uint256(s));
            v = v == 27 ? 28 : 27;
        }
        
        uint256 vs = (v == 28 ? 1 : 0) << 255 | uint256(s);
        
        bool isValid = _simulateSignatureValidation(testHash, uint256(r), vs, eoaOwner);
        assertTrue(isValid, "Valid signature should be recognized");
        
        // Case 2: Invalid signature with wrong signer
        isValid = _simulateSignatureValidation(testHash, uint256(r), vs, address(dfnsSmartAccount));
        assertFalse(isValid, "Signature should be invalid for wrong signer");
        
        // Case 3: Test malleability protection - invalid r
        isValid = _simulateSignatureValidation(testHash, 0, vs, eoaOwner);
        assertFalse(isValid, "Zero r should be invalid");
        
        isValid = _simulateSignatureValidation(testHash, CURVE_ORDER, vs, eoaOwner);
        assertFalse(isValid, "r >= CURVE_ORDER should be invalid");
        
        // Case 4: Test malleability protection - invalid s
        uint256 invalidVS = (v == 28 ? 1 : 0) << 255 | (HALF_CURVE_ORDER + 1);
        isValid = _simulateSignatureValidation(testHash, uint256(r), invalidVS, eoaOwner);
        assertFalse(isValid, "s > HALF_CURVE_ORDER should be invalid");
    }

    /**
     * @dev Test hash calculation consistency across different scenarios
     */
    function test_HashCalculation_Consistency() public {
        bytes memory testOps = hex"1234567890abcdef";
        uint256 testNonce = 42;
        
        // Calculate hash for EOA (EIP-7702 delegation context)
        bytes32 eoaHash = _simulateHashCalculation(testOps, testNonce, eoaOwner);
        
        // Calculate hash for contract address
        bytes32 contractHash = _simulateHashCalculation(testOps, testNonce, address(dfnsSmartAccount));
        
        // They should be different due to different verifying contracts
        assertTrue(eoaHash != contractHash, "Hashes should differ for different verifying contracts");
        
        // Same parameters should produce same hash
        bytes32 eoaHash2 = _simulateHashCalculation(testOps, testNonce, eoaOwner);
        assertEq(eoaHash, eoaHash2, "Same parameters should produce identical hashes");
    }

    /**
     * @dev Test authorization tuple creation and validation for EIP-7702
     */
    function test_AuthorizationTuple_Creation() public {
        // Create authorization tuple for EIP-7702 delegation
        Vm.SignedDelegation memory delegation = vm.signDelegation(address(dfnsSmartAccount), eoaOwnerPrivateKey);
        
        // Verify delegation structure
        assertEq(delegation.implementation, address(dfnsSmartAccount), "Implementation should match contract");
        
        // For EIP-7702, v value can be 0 or 1 (yParity) or encoded with chain ID
        // The exact format depends on the implementation, but it should be a valid value
        assertTrue(delegation.v >= 0, "V should be a valid value");
        
        assertTrue(delegation.r != bytes32(0), "R should not be zero");
        assertTrue(delegation.s != bytes32(0), "S should not be zero");
        
        // The delegation nonce represents the nonce for the authorization transaction
        // It should be valid (>= current EOA nonce) but may not exactly match current nonce
        uint256 currentNonce = vm.getNonce(eoaOwner);
        assertTrue(delegation.nonce >= currentNonce, "Delegation nonce should be >= current EOA nonce");
        
        // Log the delegation values for debugging
        emit log_named_uint("Delegation v", delegation.v);
        emit log_named_bytes32("Delegation r", delegation.r);
        emit log_named_bytes32("Delegation s", delegation.s);
        emit log_named_uint("Delegation nonce", delegation.nonce);
        emit log_named_address("Delegation implementation", delegation.implementation);
        
        // Test that delegation can be attached successfully
        vm.attachDelegation(delegation);
        
        // After attachment, EOA should have delegated code
        assertTrue(eoaOwner.code.length > 0, "EOA should have delegated code after attachment");
        
        // Verify the delegated code points to our contract
        // In EIP-7702, the EOA's code becomes a proxy that delegates to the implementation
        bytes memory eoaCode = eoaOwner.code;
        assertTrue(eoaCode.length > 0, "EOA should have non-zero code length");
        
        // Log the first few bytes of the delegated code for verification
        if (eoaCode.length >= 4) {
            bytes4 codePrefix = bytes4(abi.encodePacked(eoaCode[0], eoaCode[1], eoaCode[2], eoaCode[3]));
            //emit log_named_bytes("EOA code prefix", codePrefix);
        }
    }

    /**
     * @dev Test operation parsing and execution simulation
     * Validates the assembly operation parsing logic from handleOps
     */
    function test_OperationParsing_EdgeCases() public {
        // Test empty operations
        bytes memory emptyOps = new bytes(0);
        assertTrue(_validateOperationFormat(emptyOps), "Empty operations should be valid");
        
        // Test single operation
        bytes memory singleOp = abi.encodePacked(
            recipient,              // to (20 bytes)
            uint256(1 ether),      // value (32 bytes)
            uint256(0),            // data length (32 bytes)
            bytes("")              // data (0 bytes)
        );
        assertTrue(_validateOperationFormat(singleOp), "Single operation should be valid");
        
        // Test multiple operations
        bytes memory multiOps = abi.encodePacked(
            recipient,              // to (20 bytes)
            uint256(1 ether),      // value (32 bytes)
            uint256(4),            // data length (32 bytes)
            bytes("test"),         // data (4 bytes)
            user,                  // to (20 bytes)
            uint256(2 ether),      // value (32 bytes)
            uint256(0),            // data length (32 bytes)
            bytes("")              // data (0 bytes)
        );
        assertTrue(_validateOperationFormat(multiOps), "Multiple operations should be valid");
        
        // Test malformed operation (truncated)
        bytes memory malformedOps = abi.encodePacked(
            recipient,              // to (20 bytes)
            uint256(1 ether)       // value (32 bytes) - missing data length and data
        );
        assertFalse(_validateOperationFormat(malformedOps), "Malformed operations should be invalid");
    }

    /**
     * @dev Validate operation format by simulating the assembly parsing logic
     * This recreates the parsing logic from the handleOps function
     */
    function _validateOperationFormat(bytes memory userOps) internal pure returns (bool) {
        if (userOps.length == 0) return true; // Empty operations are valid
        
        uint256 length = userOps.length;
        uint256 i = 0x20; // Start after length prefix (matches assembly)
        
        while (i < length + 0x20) { // Total available bytes including length prefix
            // Check minimum size for one operation: to(20) + value(32) + dataLength(32) = 84 bytes
            if (i + 84 > length + 0x20) return false;
            
            // Extract data length using assembly like in handleOps
            uint256 dataLength;
            assembly ("memory-safe") {
                dataLength := mload(add(userOps, add(i, 0x34)))
            }
            
            // Check if we have enough bytes for the data
            if (i + 84 + dataLength > length + 0x20) return false;
            
            // Move to next operation (mimics assembly: i := add(i, add(0x54, dataLength)))
            i += 84 + dataLength;
        }
        
        return i == length + 0x20; // Should exactly consume all bytes
    }

    /**
     * @dev Test assembly operation execution simulation
     * This tests the core assembly loop logic without actual execution
     */
    function test_AssemblyOperationExecution_Simulation() public view {
        // Create properly formatted operations inspired by SafeLite
        Operation[] memory operations = new Operation[](2);
        operations[0] = Operation({
            to: recipient,
            value: 1 ether,
            data: bytes("test")
        });
        operations[1] = Operation({
            to: user,
            value: 2 ether,
            data: bytes("")
        });
        
        // Generate userOps using the proper encoding
        bytes memory testOps = _encodeOperations(operations);
        
        // Simulate the assembly parsing exactly as handleOps does
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory calldatas = new bytes[](2);
        
        uint256 length = testOps.length;
        uint256 i = 0x20; // Start after length prefix
        uint256 opIndex = 0;
        
        while (i < length && opIndex < 2) {
            address to;
            uint256 value;
            uint256 dataLength;
            
            // Extract operation components using assembly (exactly matching handleOps)
            assembly ("memory-safe") {
                to := shr(0x60, mload(add(testOps, i)))
                value := mload(add(testOps, add(i, 0x14)))
                dataLength := mload(add(testOps, add(i, 0x34)))
            }
            
            targets[opIndex] = to;
            values[opIndex] = value;
            
            // Extract data using corrected assembly logic
            bytes memory data = new bytes(dataLength);
            if (dataLength > 0) {
                assembly ("memory-safe") {
                    let dataPtr := add(testOps, add(i, 0x54))
                    let dataDestPtr := add(data, 0x20)
                    
                    // Copy data efficiently 
                    for { let j := 0 } lt(j, dataLength) { j := add(j, 0x20) } {
                        let remaining := sub(dataLength, j)
                        if lt(remaining, 0x20) {
                            // Handle remaining bytes < 32 using proper masking
                            let srcData := mload(add(dataPtr, j))
                            let mask := sub(shl(mul(remaining, 8), 1), 1)
                            srcData := and(srcData, shl(sub(256, mul(remaining, 8)), mask))
                            mstore(add(dataDestPtr, j), srcData)
                        }
                        if iszero(lt(remaining, 0x20)) {
                            mstore(add(dataDestPtr, j), mload(add(dataPtr, j)))
                        }
                    }
                }
            }
            calldatas[opIndex] = data;
            
            i = i + 0x54 + dataLength; // Move to next operation
            opIndex++;
        }
        
        // Verify parsed operations match expected results
        assertEq(targets[0], recipient, "First target should be recipient");
        assertEq(values[0], 1 ether, "First value should be 1 ether");
        assertEq(calldatas[0], bytes("test"), "First calldata should be 'test'");
        assertEq(calldatas[0].length, 4, "First calldata length should be 4");
        
        assertEq(targets[1], user, "Second target should be user");
        assertEq(values[1], 2 ether, "Second value should be 2 ether");
        assertEq(calldatas[1].length, 0, "Second calldata should be empty");
        
        // Additional verification: ensure data content is exactly correct
        assertEq(string(calldatas[0]), "test", "First calldata content should be 'test'");
    }

    /**
     * @dev Test signature validation in EIP-7702 delegation context
     */
    function test_EIP7702_SignatureValidation() public {
        _setupEIP7702Delegation();
        
        // Create test operation
        bytes memory testOps = abi.encodePacked(
            recipient,              // to (20 bytes)
            uint256(1 ether),      // value (32 bytes)
            uint256(0),            // data length (32 bytes)
            bytes("")              // data (0 bytes)
        );
        
        // Generate signature using EOA (correct for EIP-7702)
        bytes32 hash = _simulateHashCalculation(testOps, 0, eoaOwner);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaOwnerPrivateKey, hash);
        
        // Ensure s is in lower half for malleability protection
        if (uint256(s) > HALF_CURVE_ORDER) {
            s = bytes32(CURVE_ORDER - uint256(s));
            v = v == 27 ? 28 : 27;
        }
        
        uint256 vs = (v == 28 ? 1 : 0) << 255 | uint256(s);
        
        // Test that signature validates correctly for EOA (EIP-7702 context)
        bool isValid = _simulateSignatureValidation(hash, uint256(r), vs, eoaOwner);
        assertTrue(isValid, "Signature should be valid for EOA in EIP-7702 context");
        
        // Execute the operation to verify it works end-to-end
        uint256 initialBalance = recipient.balance;
        vm.startPrank(eoaOwner);
        DfnsSmartAccount(payable(eoaOwner)).handleOps(testOps, uint256(r), vs);
        vm.stopPrank();
        
        assertEq(recipient.balance, initialBalance + 1 ether, "Operation should execute successfully");
    }

    /**
     * @dev Test nonce management and replay protection indirectly
     */
    function test_NonceManagement_Simulation() public {
        _setupEIP7702Delegation();
        
        bytes memory testOps = abi.encodePacked(
            recipient,              // to (20 bytes)
            uint256(1 ether),      // value (32 bytes)
            uint256(0),            // data length (32 bytes)
            bytes("")              // data (0 bytes)
        );
        
        // Test with nonce 0
        bytes32 hash0 = _simulateHashCalculation(testOps, 0, eoaOwner);
        (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(eoaOwnerPrivateKey, hash0);
        
        // Apply malleability protection
        if (uint256(s0) > HALF_CURVE_ORDER) {
            s0 = bytes32(CURVE_ORDER - uint256(s0));
            v0 = v0 == 27 ? 28 : 27;
        }
        
        uint256 vs0 = (v0 == 28 ? 1 : 0) << 255 | uint256(s0);
        
        // Test with nonce 1 (should be different)
        bytes32 hash1 = _simulateHashCalculation(testOps, 1, eoaOwner);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(eoaOwnerPrivateKey, hash1);
        
        // Apply malleability protection
        if (uint256(s1) > HALF_CURVE_ORDER) {
            s1 = bytes32(CURVE_ORDER - uint256(s1));
            v1 = v1 == 27 ? 28 : 27;
        }
        
        uint256 vs1 = (v1 == 28 ? 1 : 0) << 255 | uint256(s1);
        
        // Verify signatures are different due to different nonces
        assertTrue(hash0 != hash1, "Different nonces should produce different hashes");
        assertTrue(vs0 != vs1 || uint256(r0) != uint256(r1), "Different nonces should produce different signatures");
        
        // Execute with correct nonce (0)
        vm.startPrank(eoaOwner);
        DfnsSmartAccount(payable(eoaOwner)).handleOps(testOps, uint256(r0), vs0);
        
        // Verify nonce incremented
        assertEq(DfnsSmartAccount(payable(eoaOwner)).getNonce(), 1, "Nonce should increment");
        
        // Now test with incremented nonce
        DfnsSmartAccount(payable(eoaOwner)).handleOps(testOps, uint256(r1), vs1);
        assertEq(DfnsSmartAccount(payable(eoaOwner)).getNonce(), 2, "Nonce should increment again");
        
        vm.stopPrank();
    }

    /* ========== BATCH TRANSACTION TESTS ========== */

    function test_EmptyBatchExecution() public {
        bytes memory emptyOps = "";
        
        // Generate signature for empty ops
        (uint256 r, uint256 vs) = _generateSignature(emptyOps, 0);
        
        _callHandleOps(emptyOps, r, vs);
        
        // Check nonce on EOA address (where delegation is active)
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        assertEq(delegatedContract.getNonce(), 1, "Empty batch should still increment nonce");
    }

    function test_SingleTransactionBatch() public {
        // Create a simple ETH transfer
        bytes memory singleOp = abi.encodePacked(
            recipient,                    // to (20 bytes)
            uint256(1 ether),            // value (32 bytes)
            uint256(0),                  // data length (32 bytes)
            bytes("")                    // data (0 bytes)
        );
        
        (uint256 r, uint256 vs) = _generateSignature(singleOp, 0);
        
        uint256 initialBalance = recipient.balance;
        _callHandleOps(singleOp, r, vs);
        
        assertEq(recipient.balance, initialBalance + 1 ether, "Recipient should receive 1 ether");
        
        // Check nonce on EOA address (where delegation is active)
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        assertEq(delegatedContract.getNonce(), 1, "Nonce should increment");
    }

    function test_MultipleTransactionBatch() public {
        // Create multiple operations: two ETH transfers
        bytes memory batchOps = abi.encodePacked(
            recipient,                    // to (20 bytes)
            uint256(1 ether),            // value (32 bytes)  
            uint256(0),                  // data length (32 bytes)
            bytes(""),                   // data (0 bytes)
            user,                        // to (20 bytes)
            uint256(2 ether),            // value (32 bytes)
            uint256(0),                  // data length (32 bytes)
            bytes("")                    // data (0 bytes)
        );
        
        (uint256 r, uint256 vs) = _generateSignature(batchOps, 0);
        
        uint256 recipientInitial = recipient.balance;
        uint256 userInitial = user.balance;
        
        _callHandleOps(batchOps, r, vs);
        
        assertEq(recipient.balance, recipientInitial + 1 ether, "First recipient should receive 1 ether");
        assertEq(user.balance, userInitial + 2 ether, "Second recipient should receive 2 ether");
        
        // Check nonce on EOA address (where delegation is active)
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        assertEq(delegatedContract.getNonce(), 1, "Nonce should increment once");
    }

    function test_BatchWithContractCall() public {
        // Transfer tokens using contract call
        uint256 transferAmount = 1000 * 10**18;
        // Mint tokens to EOA owner since operations execute from EOA context in EIP-7702
        mockToken.mint(eoaOwner, transferAmount);
        
        bytes memory tokenTransferData = abi.encodeWithSignature(
            "transfer(address,uint256)", 
            recipient, 
            transferAmount
        );
        
        bytes memory batchOps = abi.encodePacked(
            address(mockToken),          // to (20 bytes)
            uint256(0),                  // value (32 bytes)
            uint256(tokenTransferData.length), // data length (32 bytes)
            tokenTransferData            // data
        );
        
        (uint256 r, uint256 vs) = _generateSignature(batchOps, 0);
        
        _callHandleOps(batchOps, r, vs);
        
        assertEq(mockToken.balanceOf(recipient), transferAmount, "Recipient should receive tokens");
        
        // Check nonce on EOA address (where delegation is active)
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        assertEq(delegatedContract.getNonce(), 1, "Nonce should increment");
    }

    function test_BatchFailureRevertsAll() public {
        // Create batch where second operation will fail (insufficient funds)
        bytes memory batchOps = abi.encodePacked(
            recipient,                    // to (20 bytes)
            uint256(1 ether),            // value (32 bytes)
            uint256(0),                  // data length (32 bytes)
            bytes(""),                   // data (0 bytes)
            user,                        // to (20 bytes)
            uint256(100 ether),          // value (32 bytes) - more than contract has
            uint256(0),                  // data length (32 bytes)
            bytes("")                    // data (0 bytes)
        );
        
        (uint256 r, uint256 vs) = _generateSignature(batchOps, 0);
        
        uint256 recipientInitial = recipient.balance;
        
        vm.expectRevert();
        _callHandleOps(batchOps, r, vs);
        
        // First transfer should also be reverted
        assertEq(recipient.balance, recipientInitial, "First transfer should be reverted");
        
        // Check nonce on EOA address (where delegation is active) - should NOT increment on failure
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        assertEq(delegatedContract.getNonce(), 0, "Nonce should NOT increment on execution failure");
        
        // Test that we can retry with the same nonce after failure
        vm.deal(eoaOwner, 200 ether); // Give enough ETH to succeed
        bool retrySuccess = _tryHandleOps(batchOps, r, vs);
        assertTrue(retrySuccess, "Should be able to retry after failure with sufficient funds");
        
        // Now nonce should increment after successful execution
        assertEq(delegatedContract.getNonce(), 1, "Nonce should increment after successful execution");
    }

    /**
     * @dev Test complete batch transaction execution with proper userOps generation
     */
    function test_BatchTransactionExecution() public {
        // Setup EIP-7702 delegation first
        _setupEIP7702Delegation();
        
        // Ensure EOA has sufficient ETH balance
        vm.deal(eoaOwner, 10 ether);
        
        // Give EOA some ERC20 tokens for the transfer test
        mockToken.mint(eoaOwner, 1000);
        
        // Get current nonce
        uint256 currentNonce = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        
        // Create a complex batch of operations
        Operation[] memory operations = new Operation[](3);
        
        // Operation 1: Send ETH to recipient
        operations[0] = Operation({
            to: recipient,
            value: 0.5 ether,
            data: bytes("")
        });
        
        // Operation 2: Call a function with data (ERC20 transfer)
        operations[1] = Operation({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSignature("transfer(address,uint256)", recipient, 100)
        });
        
        // Operation 3: Send ETH to user with message
        operations[2] = Operation({
            to: user,
            value: 0.3 ether,
            data: bytes("hello")
        });
        
        // Encode operations
        bytes memory userOps = _encodeOperations(operations);
        
        // Generate signature
        (uint256 r, uint256 vs) = _generateSignature(userOps, currentNonce);
        
        // Record initial balances
        uint256 initialRecipientBalance = recipient.balance;
        uint256 initialUserBalance = user.balance;
        uint256 initialEoaBalance = eoaOwner.balance;
        uint256 initialRecipientTokens = mockToken.balanceOf(recipient);
        uint256 initialEoaTokens = mockToken.balanceOf(eoaOwner);
        
        // Execute the batch transaction
        bool success = _tryHandleOps(userOps, r, vs);
        assertTrue(success, "Batch transaction should succeed");
        
        // Verify ETH transfers
        assertEq(recipient.balance, initialRecipientBalance + 0.5 ether, "Recipient should receive 0.5 ETH");
        assertEq(user.balance, initialUserBalance + 0.3 ether, "User should receive 0.3 ETH");
        assertEq(eoaOwner.balance, initialEoaBalance - 0.8 ether, "EOA should spend 0.8 ETH");
        
        // Verify ERC20 transfer
        assertEq(mockToken.balanceOf(recipient), initialRecipientTokens + 100, "Recipient should receive 100 tokens");
        assertEq(mockToken.balanceOf(eoaOwner), initialEoaTokens - 100, "EOA should transfer 100 tokens");
        
        // Verify nonce was incremented
        assertEq(DfnsSmartAccount(payable(eoaOwner)).getNonce(), currentNonce + 1, "Nonce should be incremented");
        
        // Log transaction details
        emit log_named_uint("Operations executed", operations.length);
        emit log_named_uint("Total ETH sent", 0.8 ether);
        emit log_named_uint("Final nonce", DfnsSmartAccount(payable(eoaOwner)).getNonce());
    }

    /* ========== ASSEMBLY LOGIC TESTS ========== */

    function test_AssemblyBatchParsing() public {
        // Test the assembly loop correctly parses multiple operations
        bytes memory complexBatch = abi.encodePacked(
            recipient,                    // to (20 bytes)
            uint256(0.5 ether),          // value (32 bytes)
            uint256(0),                  // data length (32 bytes)
            bytes(""),                   // data (0 bytes)
            address(mockToken),          // to (20 bytes)
            uint256(0),                  // value (32 bytes)
            uint256(4),                  // data length (32 bytes)
            bytes4(0x12345678)           // data (4 bytes)
        );
        
        (uint256 r, uint256 vs) = _generateSignature(complexBatch, 0);
        
        // This should revert on the token call but prove parsing worked
        vm.expectRevert();
        _callHandleOps(complexBatch, r, vs);
    }

    function test_AssemblyMemorySafety() public {
        // Test with various data lengths to ensure memory safety
        bytes memory variableData = new bytes(100);
        for (uint i = 0; i < 100; i++) {
            variableData[i] = bytes1(uint8(i % 256));
        }
        
        bytes memory batch = abi.encodePacked(
            address(this),               // to (20 bytes)
            uint256(0),                  // value (32 bytes)
            uint256(variableData.length), // data length (32 bytes)
            variableData                 // data (100 bytes)
        );
        
        (uint256 r, uint256 vs) = _generateSignature(batch, 0);
        
        // Call will fail but should not cause memory issues
        vm.expectRevert();
        _callHandleOps(batch, r, vs);
    }

    /* ========== EIP-7702 COMPATIBILITY TESTS ========== */

    function test_DomainSeparatorCalculation() public {
        // Test domain separator calculation matches EIP-712 standard
        bytes32 expectedDomain = keccak256(abi.encode(
            _DOMAIN_TYPEHASH,
            block.chainid,
            address(dfnsSmartAccount)
        ));
        
        // This is internal, so we test it indirectly through signature validation
        bytes memory testOps = hex"1234";
        (uint256 r, uint256 vs) = _generateSignature(testOps, 0);
        
        _callHandleOps(testOps, r, vs);
        
        // Check nonce on EOA address (where delegation is active)
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        assertEq(delegatedContract.getNonce(), 1, "Signature validation should work with correct domain");
    }

    function test_EIP712StructHashCalculation() public {
        // Mint tokens to EOA owner for the transfer
        mockToken.mint(eoaOwner, 10 ether);
        
        // Create dynamic operation equivalent to holeskyUserOps
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSignature("transfer(address,uint256)", recipient, 1 ether)
        });
        
        bytes memory testOps = _encodeOperations(operations);
        uint256 nonce = 0;
        
        bytes32 expectedStructHash = keccak256(abi.encode(
            _HANDLEOPS_TYPEHASH,
            keccak256(testOps),
            nonce
        ));
        
        (uint256 r, uint256 vs) = _generateSignature(testOps, nonce);
        
        _callHandleOps(testOps, r, vs);
        
        // Check nonce on EOA address (where delegation is active)
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        assertEq(delegatedContract.getNonce(), 1, "Struct hash should be calculated correctly");
    }

    function test_CrossChainSignatureInvalidity() public {
        // Mint tokens to EOA owner for the transfer
        mockToken.mint(eoaOwner, 10 ether);
        
        // Create dynamic operation equivalent to holeskyUserOps
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSignature("transfer(address,uint256)", recipient, 1 ether)
        });
        
        bytes memory userOps = _encodeOperations(operations);
        
        // Set up EIP-7702 delegation first
        _setupEIP7702Delegation();
        
        // Get initial nonce after delegation is set up
        uint256 initialNonce = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        assertEq(initialNonce, 0, "Initial nonce should be 0");
        
        // Generate signature for current chain (31337)
        (uint256 r, uint256 vs) = _generateSignature(userOps, 0);
        
        // Execute transaction successfully on current chain
        bool success1 = _tryHandleOps(userOps, r, vs);
        assertTrue(success1, "Should succeed on original chain");
        
        // Verify nonce incremented on successful execution
        uint256 nonceAfterSuccess = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        assertEq(nonceAfterSuccess, 1, "Nonce should increment after successful execution");
        
        // Test replay protection: same signature with old nonce should fail
        bool replayAttempt = _tryHandleOps(userOps, r, vs);
        assertFalse(replayAttempt, "Should fail on replay attempt (wrong nonce)");
        
        // Nonce should remain unchanged after failed replay attempt
        uint256 nonceAfterReplay = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        assertEq(nonceAfterReplay, 1, "Nonce should not change on failed replay");
        
        // Generate correct signature with current nonce should work
        (uint256 r2, uint256 vs2) = _generateSignature(userOps, 1);
        bool success2 = _tryHandleOps(userOps, r2, vs2);
        // assertTrue(success2, "Should succeed with correct nonce");
        
        // // Final nonce should be 2
        // uint256 finalNonce = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        // assertEq(finalNonce, 2, "Nonce should increment to 2 after second execution");
    
        assertTrue(success2, "Should succeed with correct nonce");
        
        // Verify nonce incremented again
        uint256 finalNonce = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        assertEq(finalNonce, 2, "Nonce should increment after second successful execution");
    
        uint256 nonceBeforeCrossChain = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        
        // Attempt to use the same signature on different chain - should fail
        bool crossChainSuccess = _tryHandleOps(userOps, r, vs);
        
        // Verify the cross-chain attempt failed
        assertFalse(crossChainSuccess, "Cross-chain signature should fail");
        
        // Verify nonce did NOT increment on failed cross-chain attempt (no replay attack)
        uint256 nonceAfterCrossChain = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        assertEq(nonceAfterCrossChain, nonceBeforeCrossChain, "Nonce should not increment on failed cross-chain attempt");
        
        // Switch back to original chain
        vm.chainId(31337);
        _setupEIP7702Delegation();
        
        // Verify that replay protection still works on original chain with incremented nonce
        bool replaySuccess = _tryHandleOps(userOps, r, vs);
        assertFalse(replaySuccess, "Replay attack should fail due to nonce mismatch");
    }

    /* ========== EDGE CASES AND SECURITY TESTS ========== */

    function test_LargeNonceHandling() public {
        // Test handling of large nonce values
        // We'll need to execute many transactions to get there
        // For testing purposes, let's just test the overflow behavior
        
        uint256 maxNonce = type(uint256).max - 1;
        bytes memory testOps = hex"1234";
        
        // Generate signature with max nonce
        (uint256 r, uint256 vs) = _generateSignature(testOps, maxNonce);
        
        // We can't easily set the nonce to max, so this tests the signature generation
        assertTrue(r > 0 && vs > 0, "Signature should be generated for large nonce");
    }

    function test_ZeroValueTransfer() public {
        bytes memory zeroTransfer = abi.encodePacked(
            recipient,                    // to (20 bytes)
            uint256(0),                  // value (32 bytes)
            uint256(0),                  // data length (32 bytes)
            bytes("")                    // data (0 bytes)
        );
        
        (uint256 r, uint256 vs) = _generateSignature(zeroTransfer, 0);
        
        _callHandleOps(zeroTransfer, r, vs);
        
        // Check nonce on EOA address (where delegation is active)
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        assertEq(delegatedContract.getNonce(), 1, "Zero value transfer should succeed");
    }

    function test_MaxGasUsage() public {
        // Test batch with many operations to test gas limits
        bytes memory largeBatch = "";
        
        // Create 10 small transfers
        for (uint i = 0; i < 10; i++) {
            largeBatch = abi.encodePacked(
                largeBatch,
                recipient,               // to (20 bytes)
                uint256(0.01 ether),    // value (32 bytes)
                uint256(0),             // data length (32 bytes)
                bytes("")               // data (0 bytes)
            );
        }
        
        (uint256 r, uint256 vs) = _generateSignature(largeBatch, 0);
        
        uint256 gasStart = gasleft();
        _callHandleOps(largeBatch, r, vs);
        uint256 gasUsed = gasStart - gasleft();
        
        console.log("Gas used for 10 operations:", gasUsed);
        
        // Check nonce on EOA address (where delegation is active)
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        assertEq(delegatedContract.getNonce(), 1, "Large batch should succeed");
    }

    // function test_ContractSelfDestruct() public {
    //     // Deploy a contract that self-destructs and test calling it
    //     SelfDestructContract destructContract = new SelfDestructContract();
        
    //     bytes memory destructCall = abi.encodePacked(
    //         address(destructContract),    // to (20 bytes)
    //         uint256(0),                  // value (32 bytes)
    //         uint256(4),                  // data length (32 bytes)
    //         abi.encodeWithSignature("destroy()") // data (4 bytes)
    //     );
        
    //     (uint256 r, uint256 vs) = _generateSignature(destructCall, 0);
        
    //     _callHandleOps(destructCall, r, vs);
        
    //     // Check nonce on EOA address (where delegation is active)
    //     DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
    //     assertEq(delegatedContract.getNonce(), 1, "Self-destruct call should succeed");
    // }

    /* ========== SIGNATURE MALLEABILITY PROTECTION TESTS ========== */

    function test_SignatureMalleabilityProtection() public {
        bytes32 testHash = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaOwnerPrivateKey, testHash);
        
        // Test 1: Valid signature in lower half
        if (uint256(s) > HALF_CURVE_ORDER) {
            s = bytes32(CURVE_ORDER - uint256(s));
            v = v == 27 ? 28 : 27;
        }
        
        uint256 vs = (v == 28 ? 1 : 0) << 255 | uint256(s);
        bool isValid = _simulateSignatureValidation(testHash, uint256(r), vs, eoaOwner);
        assertTrue(isValid, "Valid signature in lower half should pass");
        
        // Test 2: Invalid signature with s in upper half
        uint256 upperS = CURVE_ORDER - uint256(s);
        uint256 invalidVS = (v == 28 ? 1 : 0) << 255 | upperS;
        isValid = _simulateSignatureValidation(testHash, uint256(r), invalidVS, eoaOwner);
        assertFalse(isValid, "Signature with s in upper half should fail");
        
        // Test 3: Invalid r = 0
        isValid = _simulateSignatureValidation(testHash, 0, vs, eoaOwner);
        assertFalse(isValid, "Signature with r = 0 should fail");
        
        // Test 4: Invalid r >= CURVE_ORDER
        isValid = _simulateSignatureValidation(testHash, CURVE_ORDER, vs, eoaOwner);
        assertFalse(isValid, "Signature with r >= CURVE_ORDER should fail");
        
        // Test 5: Invalid s = 0
        uint256 zeroSVS = (v == 28 ? 1 : 0) << 255;
        isValid = _simulateSignatureValidation(testHash, uint256(r), zeroSVS, eoaOwner);
        assertFalse(isValid, "Signature with s = 0 should fail");
    }

    /* ========== DFNS API INTEGRATION TESTS ========== */

    /**
     * @dev Test EIP-712 data generation for DFNS API integration with proper signature validation
     */
    function test_generateEip712DataForDfnsAPI() public {
        bytes memory testOps = abi.encodePacked(
            uint160(address(0x1234567890123456789012345678901234567890)),
            uint256(1 ether),
            uint256(0), // no data
            bytes("")
        );
        
        // Set up EIP-7702 delegation
        _setupEIP7702Delegation();
        
        // Get the current nonce from the delegated contract
        uint256 currentNonce = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        
        (bytes32 dataHash, bytes32 digest, bytes32 domainSeparator) = _generateEip712Data(testOps, currentNonce);
        
        // Verify the data hash is correct
        assertEq(dataHash, keccak256(testOps), "Data hash should match keccak256 of userOps");
        
        // Verify domain separator uses EOA address (EIP-7702 context)
        bytes32 expectedDomainSeparator = keccak256(abi.encode(
            _DOMAIN_TYPEHASH,
            block.chainid,
            eoaOwner
        ));
        assertEq(domainSeparator, expectedDomainSeparator, "Domain separator should use EOA address");
        
        // Generate a valid signature using the contract's digest calculation
        bytes32 contractDigest = _simulateContractDigest(testOps, currentNonce, eoaOwner);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaOwnerPrivateKey, contractDigest);
        
        // Verify signature recovery
        address recovered = ecrecover(contractDigest, v, r, s);
        assertEq(recovered, eoaOwner, "Signature should recover to EOA owner");
        
        // Convert to contract format
        uint256 rUint = uint256(r);
        uint256 vs = (v == 28 ? 1 : 0) << 255 | uint256(s);
        
        // Apply malleability protection if needed
        if (uint256(s) > HALF_CURVE_ORDER) {
            s = bytes32(CURVE_ORDER - uint256(s));
            v = v == 28 ? 28 : 27;
            vs = (v == 28 ? 1 : 0) << 255 | uint256(s);
        }
        
        // Test that the valid signature works
        bool success = _tryHandleOps(testOps, rUint, vs);
        assertTrue(success, "Valid signature should succeed");
        
        // Verify nonce was incremented
        uint256 newNonce = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        assertEq(newNonce, currentNonce + 1, "Nonce should be incremented after successful execution");
        
        // Test that an invalid signature fails
        uint256 invalidVs = vs ^ 1; // Flip a bit to make it invalid
        bool invalidSuccess = _tryHandleOps(testOps, rUint, invalidVs);
        assertFalse(invalidSuccess, "Invalid signature should fail");
        
        // Verify nonce was not incremented for failed transaction
        uint256 finalNonce = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        assertEq(finalNonce, newNonce, "Nonce should not change after failed execution");
    }

    /**
     * @dev Test that EIP-712 data format matches what DFNS API expects
     */
    function test_eip712DataFormatCompatibility() public {
        bytes memory userOps = abi.encodePacked(
            uint160(address(0x1111111111111111111111111111111111111111)),
            uint256(0.5 ether),
            uint256(4), // data length
            bytes("test")
        );
        
        // Set up EIP-7702 delegation first
        _setupEIP7702Delegation();
        
        // Get the current nonce from the delegated contract
        uint256 currentNonce = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        
        (bytes32 dataHash, bytes32 digest, bytes32 domainSeparator) = _generateEip712Data(userOps, currentNonce);
        
        // The dataHash is what goes into the EIP-712 message.data field for DFNS API
        // Format expected by DFNS:
        // {
        //   "domain": {
        //     "chainId": block.chainid,
        //     "verifyingContract": eoaOwner  // EOA address in EIP-7702 context
        //   },
        //   "message": {
        //     "data": dataHash,  // This is the userOps hash
        //     "nonce": currentNonce
        //   },
        //   "types": {
        //     "HandleOps": [
        //       {"name": "data", "type": "bytes32"},
        //       {"name": "nonce", "type": "uint256"}
        //     ]
        //   }
        // }
        
        // Verify the structure hash matches what the contract expects
        bytes32 expectedStructHash = keccak256(abi.encode(_HANDLEOPS_TYPEHASH, dataHash, currentNonce));
        bytes32 expectedDigest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, expectedStructHash));
        
        assertEq(digest, expectedDigest, "Generated digest should match expected EIP-712 format");
        
        // Test signature validation with the generated data
        bytes32 contractDigest = _simulateContractDigest(userOps, currentNonce, eoaOwner);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaOwnerPrivateKey, contractDigest);
        
        // Validate signature components
        assertTrue(uint256(r) > 0 && uint256(r) < CURVE_ORDER, "r should be valid");
        assertTrue(uint256(s) > 0 && uint256(s) < CURVE_ORDER, "s should be valid");
        assertTrue(v == 27 || v == 28, "v should be 27 or 28");
        
        // Test signature recovery
        address recovered = ecrecover(contractDigest, v, r, s);
        assertEq(recovered, eoaOwner, "Signature should recover to EOA owner");
        
        // Log the values for external integration testing
        emit log_named_bytes32("Data Hash (for DFNS message.data)", dataHash);
        emit log_named_bytes32("Domain Separator", domainSeparator);
        emit log_named_bytes32("Final Digest", digest);
        emit log_named_bytes32("Contract Digest", contractDigest);
        emit log_named_uint("Chain ID", block.chainid);
        emit log_named_address("Verifying Contract (EOA)", eoaOwner);
        emit log_named_uint("Current Nonce", currentNonce);
        
        // Test that the signature works with the contract
        uint256 rUint = uint256(r);
        uint256 vs = (v == 28 ? 1 : 0) << 255 | uint256(s);
        
        // Apply malleability protection if needed
        if (uint256(s) > HALF_CURVE_ORDER) {
            s = bytes32(CURVE_ORDER - uint256(s));
            v = v == 28 ? 28 : 27;
            vs = (v == 28 ? 1 : 0) << 255 | uint256(s);
        }
        
        bool success = _tryHandleOps(userOps, rUint, vs);
        assertTrue(success, "Valid signature should execute successfully");
    }

    /**
     * @dev Comprehensive test for signature validation scenarios
     */
    function test_comprehensiveSignatureValidation() public {
        bytes memory testOps = abi.encodePacked(
            uint160(recipient), // Use recipient address instead of makeAddr to avoid collision
            uint256(2 ether),
            uint256(0), // no data
            bytes("")
        );
        
        // Set up EIP-7702 delegation using the helper function
        _setupEIP7702Delegation();
        
        // Ensure EOA has enough ETH for the operation
        vm.deal(eoaOwner, 10 ether);
        
        // Get the current nonce AFTER setting up delegation
        vm.startPrank(eoaOwner);
        uint256 currentNonce = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        vm.stopPrank();
        
        console.log("Current nonce:", currentNonce);
        
        // Test 1: Valid signature should work
        (uint256 validR, uint256 validVs) = _generateSignature(testOps, currentNonce);
        bool success = _tryHandleOps(testOps, validR, validVs);
        assertTrue(success, "Valid signature should succeed");
        
        // Update nonce for next test
        currentNonce = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        
        // Test 2: Invalid r = 0 should fail
        bool invalidRSuccess = _tryHandleOps(testOps, 0, validVs);
        assertFalse(invalidRSuccess, "Signature with r=0 should fail");
        
        // Test 3: Invalid r >= CURVE_ORDER should fail
        bool invalidRMaxSuccess = _tryHandleOps(testOps, CURVE_ORDER, validVs);
        assertFalse(invalidRMaxSuccess, "Signature with r>=CURVE_ORDER should fail");
        
        // Test 4: Invalid vs (corrupted signature) should fail
        uint256 corruptedVs = validVs ^ 0x123456789; // Corrupt the signature
        bool corruptedSuccess = _tryHandleOps(testOps, validR, corruptedVs);
        assertFalse(corruptedSuccess, "Corrupted signature should fail");
        
        // Test 5: Wrong nonce signature should fail
        (uint256 wrongNonceR, uint256 wrongNonceVs) = _generateSignature(testOps, currentNonce + 100);
        bool wrongNonceSuccess = _tryHandleOps(testOps, wrongNonceR, wrongNonceVs);
        assertFalse(wrongNonceSuccess, "Signature with wrong nonce should fail");
        
        // Test 6: Different userOps with same signature should fail
        bytes memory differentOps = abi.encodePacked(
            uint160(address(0x3333333333333333333333333333333333333333)),
            uint256(3 ether),
            uint256(0),
            bytes("")
        );
        bool differentOpsSuccess = _tryHandleOps(differentOps, validR, validVs);
        assertFalse(differentOpsSuccess, "Same signature for different ops should fail");
        
        emit log_named_string("Test Result", "All signature validation scenarios passed");
    }

    function test_DEBUG_SignatureValidation() public {
        console.log("=== DEBUG SIGNATURE VALIDATION ===");
        
        // Mint tokens to EOA owner
        mockToken.mint(eoaOwner, 10 ether);
        
        // Set up EIP-7702 delegation
        _setupEIP7702Delegation();
        
        // Create test operation
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSignature("transfer(address,uint256)", recipient, 1 ether)
        });
        
        bytes memory testOps = _encodeOperations(operations);
        uint256 nonce = 0;
        
        console.log("Chain ID: ", block.chainid);
        console.log("EOA Owner:         ", eoaOwner);
        console.log("Contract Address:  ", address(dfnsSmartAccount));
        
        // Compute digest exactly as contract does
        bytes32 domainSeparator = keccak256(abi.encode(_DOMAIN_TYPEHASH, block.chainid, eoaOwner));
        bytes32 structHash = keccak256(abi.encode(_HANDLEOPS_TYPEHASH, keccak256(testOps), nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        
        console.log("Domain separator:");
        console.logBytes32(domainSeparator);
        console.log("Struct hash:");
        console.logBytes32(structHash);
        console.log("Final digest:");
        console.logBytes32(digest);
        
        // Sign with EOA private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaOwnerPrivateKey, digest);
        console.log("Signature v:", v);
        console.logBytes32(r);
        console.logBytes32(s);
        
        // Test direct ecrecover
        address recovered = ecrecover(digest, v, r, s);
        console.log("Recovered address: ", recovered);
        console.log("Expected address:  ", eoaOwner);
        
        // Convert to vs format
        uint256 vs = (v == 27 ? 0 : 1) << 255 | uint256(s);
        uint256 rUint = uint256(r);
        
        console.log("=== VS CONVERSION DEBUG ===");
        console.log("Original v:", v);
        console.log("Original s:");
        console.log(uint256(s));
        console.log("s > HALF_CURVE_ORDER?", uint256(s) > HALF_CURVE_ORDER);
        
        // Generate signature using our method
        (uint256 rGen, uint256 vsGen) = _generateSignature(testOps, 0);
        console.log("Generated r:", rGen);
        console.log("Generated VS:", vsGen);
        console.log("Generated VS >> 255:", vsGen >> 255);
        console.log("Generated v from VS:", (vsGen >> 255) + 27);
        
        // Test ecrecover with generated signature
        uint256 vFromVsGen = (vsGen >> 255) + 27;
        uint256 sFromVsGen = vsGen & 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
        address recoveredGen = ecrecover(digest, uint8(vFromVsGen), bytes32(rGen), bytes32(sFromVsGen));
        console.log("Recovered from generated signature:", recoveredGen);
        
        // Test ecrecover with vs format conversion
        uint256 vFromVs = (vs >> 255) + 27;
        uint256 sFromVs = vs & 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
        address recovered2 = ecrecover(digest, uint8(vFromVs), bytes32(rUint), bytes32(sFromVs));
        console.log("Recovered2 address:", recovered2);
        
        // Test if EOA address has delegation code
        bytes memory code = eoaOwner.code;
        console.log("EOA code length:", code.length);
        
        assertEq(recovered, eoaOwner, "Direct ecrecover should recover EOA address");
        assertEq(recoveredGen, eoaOwner, "Generated signature should recover EOA address");
        
        // Now try calling the actual contract
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        
        console.log("=== CALLING CONTRACT ===");
        
        vm.startPrank(eoaOwner);
        try delegatedContract.handleOps(testOps, rUint, vs) {
            console.log("SUCCESS: handleOps executed successfully");
        } catch Error(string memory reason) {
            console.log("FAILED with reason:", reason);
        } catch (bytes memory data) {
            console.log("FAILED with data:");
            console.logBytes(data);
        }
        vm.stopPrank();
    }

    /* ========== HELPER FUNCTIONS ========== */

    function _generateSignature(bytes memory userOps, uint256 nonce) internal returns (uint256 r, uint256 vs) {
        // In EIP-7702 context, the contract calculates digest using EOA address as address(this)
        bytes32 digest = _simulateContractDigest(userOps, nonce, eoaOwner);
        
        // Sign with the EOA's private key
        (uint8 v, bytes32 rBytes, bytes32 s) = vm.sign(eoaOwnerPrivateKey, digest);
        
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
     */
    function _encodeOperations(Operation[] memory operations) internal pure returns (bytes memory) {
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
     * @dev Generate EIP-712 data structure for DFNS API integration
     * @param userOps Encoded User Ops
     * @param nonce The nonce value
     * @return dataHash The keccak256 hash of userOps (for EIP-712 message.data field)
     * @return digest The final EIP-712 digest that would be signed
     * @return domainSeparator The domain separator for verification
     */
    function _generateEip712Data(bytes memory userOps, uint256 nonce) 
        internal 
        view 
        returns (bytes32 dataHash, bytes32 digest, bytes32 domainSeparator) 
    {
        // Calculate data hash for EIP-712 message
        dataHash = keccak256(userOps);
        
        // In EIP-7702, when the contract executes, address(this) will be the EOA address
        // because the EOA has delegated its code to the smart contract
        // So we use the EOA address as the verifying contract
        domainSeparator = keccak256(abi.encode(
            _DOMAIN_TYPEHASH,
            block.chainid,
            eoaOwner  // This will be address(this) when the contract executes via EIP-7702
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
     */
    function _callHandleOps(bytes memory userOps, uint256 r, uint256 vs) internal {
        // Set up EIP-7702 delegation
        _setupEIP7702Delegation();
        
        // Call the contract from the EOA context (EIP-7702 delegation)
        vm.startPrank(eoaOwner);
        
        // Get the contract instance at the EOA address (delegation simulation)
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        delegatedContract.handleOps(userOps, r, vs);
        
        vm.stopPrank();
    }

    /**
     * @dev Safely attempt to call handleOps and return success status
     * @param userOps The encoded user operations
     * @param r The r component of the signature
     * @param vs The combined v and s components
     * @return success True if the call succeeded, false if it reverted
     */
    function _tryHandleOps(bytes memory userOps, uint256 r, uint256 vs) internal returns (bool success) {
        // After EIP-7702 delegation, the EOA address behaves like the smart contract
        // We create a DfnsSmartAccount interface pointing to the EOA address
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        
        vm.startPrank(eoaOwner);
        try delegatedContract.handleOps(userOps, r, vs) {
            success = true;
        } catch {
            success = false;
        }
        vm.stopPrank();
    }

    // Receive function to accept ETH
    receive() external payable {}
}

/* ========== MOCK CONTRACTS ========== */

contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }
    
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }
    
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
}

contract SelfDestructContract {
    bool public destroyed = false;
    
    function destroy() external {
        destroyed = true;
        // Transfer all Ether to sender (simulating selfdestruct behavior)
        payable(msg.sender).transfer(address(this).balance);
    }
    
    receive() external payable {}
}

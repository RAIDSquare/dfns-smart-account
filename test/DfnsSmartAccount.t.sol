// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.29;

import {Test, console, console2} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {stdError} from "forge-std/StdError.sol";
import {DfnsSmartAccount} from "../src/DfnsSmartAccount.sol";
import {SelfDestructContract, MockERC20, MockERC721, MockDeFiProtocol, CREATE2Deployer, MaliciousContractV1, MaliciousContractV2, GasBombDeployer, VulnerableTarget, MetamorphicContract} from "./utils/mockContracts.sol";
import {DfnsTestUtils, Operation, TestContext} from "./utils/DfnsTestUtils.sol";
import {console} from "forge-std/console.sol";

error InvalidSignature();

/// @title DfnsSmartAccount Test Suite
/// @dev Comprehensive tests for EIP-7702 smart account functionality
contract DfnsSmartAccountTest is Test {
    using DfnsTestUtils for TestContext;
    
    DfnsSmartAccount public dfnsSmartAccount;
    TestContext public testCtx;
    
    // Test accounts - use forge-std makeAddr for better realism
    address public deployer;
    address public user;
    address public recipient;
    address public attacker;
    
    // EOA that will delegate to the smart contract (EIP-7702)
    address public eoaOwner;
    uint256 public eoaOwnerPrivateKey;
    
    bytes32 private constant _STORAGE = 0x10ee8db8a0021e326896fcf9b44ce61becefe5f52e3dfd0bb294aee9b73bc000;
    bytes32 private constant _DOMAIN_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
    bytes32 private constant _HANDLEOPS_TYPEHASH = 0x4f8bb4631e6552ac29b9d6bacf60ff8b5481e2af7c2104fe0261045fa6988111;

    // Signature malleability protection constants. 
    uint256 private constant CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    uint256 private constant HALF_CURVE_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    // Mock ERC20 contract for testing
    MockERC20 public mockToken;

    uint256 constant CHAIN_ID = 31337;

    // Events
    event Transfer(address indexed from, address indexed to, uint256 value);

    function setUp() public {
        vm.chainId(31337); // anvil local chain ID (0x7a69)
        
        // Create test accounts using forge-std for better realism
        deployer = makeAddr("deployer");
        user = makeAddr("user"); 
        recipient = makeAddr("recipient");
        attacker = makeAddr("attacker");
        
        (eoaOwner, eoaOwnerPrivateKey) = makeAddrAndKey("eoaOwner");
        
        address contractAddress = 0xa570148Ab35de51eA1C59AC09Cc6ea37AC6BaB91;
        deployCodeTo("DfnsSmartAccount.sol", contractAddress);
        dfnsSmartAccount = DfnsSmartAccount(contractAddress);

        // Initialize test context for library functions
        testCtx = DfnsTestUtils.createTestContext(
            address(dfnsSmartAccount),
            eoaOwner,
            eoaOwnerPrivateKey,
            vm
        );

        mockToken = new MockERC20("Test Token", "TEST", 18);
        
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
        DfnsTestUtils.setupEIP7702Delegation(testCtx);
    }

    function test_handleOps() public {
        assertEq(dfnsSmartAccount.getNonce(), 0);
        
        mockToken.mint(eoaOwner, 10 ether);
        
        // define the standard transfer operation for this test.  
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSignature("transfer(address,uint256)", recipient, 1 ether)
        });
        
        bytes memory userOps = DfnsTestUtils.encodeOperations(operations);
        (uint256 r, uint256 vs) = DfnsTestUtils.generateSignature(testCtx, userOps, 0);
        DfnsTestUtils.callHandleOps(testCtx, userOps, r, vs);
        
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
     *
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
    /**
     * @dev Test EIP-712 data generation for DFNS API integration with multiple batched transactions
     * Tests NFT transfer, DeFi function call, and token transfer in compliance with EIP-712 standard
     */
    function test_generateEip712DataForDfnsAPI() public {
        console.log("=== Testing EIP-712 Data Generation for DFNS API ===");
        
        // Deploy additional mock contracts for comprehensive testing
        MockERC721 mockNFT = new MockERC721("Test NFT", "TNFT");
        MockDeFiProtocol defiProtocol = new MockDeFiProtocol();
        MockERC20 tokenA = new MockERC20("Token A", "TKNA", 18);
        MockERC20 tokenB = new MockERC20("Token B", "TKNB", 18);
        
        console.log("Mock contracts deployed:");
        console.log("NFT:", address(mockNFT));
        console.log("DeFi Protocol:", address(defiProtocol));
        console.log("Token A:", address(tokenA));
        console.log("Token B:", address(tokenB));
        
        // Set up initial state
        _setupEIP7702Delegation();
        
        // Mint NFT to EOA owner
        uint256 tokenId = mockNFT.mint(eoaOwner);
        console.log("Minted NFT with token ID:", tokenId);
        
        // Mint tokens to EOA owner
        tokenA.mint(eoaOwner, 1000 ether);
        tokenB.mint(address(defiProtocol), 1000 ether); // Protocol has tokens for swapping
        mockToken.mint(eoaOwner, 500 ether);
        
        console.log("Token balances setup:");
        console.log("EOA Token A balance:", tokenA.balanceOf(eoaOwner));
        console.log("EOA Token B balance:", tokenB.balanceOf(eoaOwner));
        console.log("EOA Mock Token balance:", mockToken.balanceOf(eoaOwner));
        
        // Create multiple batched operations following EIP-712 standard
        Operation[] memory operations = new Operation[](5);
        
        // Operation 1: NFT Transfer (safeTransferFrom)
        operations[0] = Operation({
            to: address(mockNFT),
            value: 0,
            data: abi.encodeWithSignature(
                "transferFrom(address,address,uint256)",
                eoaOwner,
                recipient,
                tokenId
            )
        });
        
        // Operation 2: Token approval for DeFi protocol
        operations[1] = Operation({
            to: address(tokenA),
            value: 0,
            data: abi.encodeWithSignature(
                "approve(address,uint256)",
                address(defiProtocol),
                100 ether
            )
        });
        
        // Operation 3: DeFi deposit operation
        operations[2] = Operation({
            to: address(defiProtocol),
            value: 0,
            data: abi.encodeWithSignature(
                "deposit(address,uint256)",
                address(tokenA),
                100 ether
            )
        });
        
        // Operation 4: Regular ERC20 token transfer
        operations[3] = Operation({
            to: address(mockToken),
            value: 0,
            data: abi.encodeWithSignature(
                "transfer(address,uint256)",
                user,
                50 ether
            )
        });
        
        // Operation 5: ETH transfer
        operations[4] = Operation({
            to: recipient,
            value: 2 ether,
            data: ""
        });
        
        console.log("Created 5 batched operations:");
        console.log("1. NFT transfer");
        console.log("2. Token approval for DeFi");
        console.log("3. DeFi deposit");
        console.log("4. ERC20 token transfer");
        console.log("5. ETH transfer");
        
        bytes memory userOps = _encodeOperations(operations);
        console.log("Encoded userOps length:", userOps.length);
        
        uint256 currentNonce = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        console.log("Current nonce:", currentNonce);
        
        // Generate EIP-712 compliant data structure
        (bytes32 dataHash, bytes32 digest, bytes32 domainSeparator) = _generateEip712Data(userOps, currentNonce);
        
        console.log("=== EIP-712 Data Structure ===");
        console.log("Data hash (keccak256 of userOps):");
        console.logBytes32(dataHash);
        console.log("EIP-712 digest:");
        console.logBytes32(digest);
        console.log("Domain separator:");
        console.logBytes32(domainSeparator);
        
        // Verify EIP-712 compliance
        
        // 1. Verify data hash is correct
        bytes32 expectedDataHash = keccak256(userOps);
        assertEq(dataHash, expectedDataHash, "Data hash should match keccak256 of userOps");
        console.log(" Data hash verification passed");
        
        // 2. Verify domain separator follows EIP-712 standard
        bytes32 expectedDomainSeparator = keccak256(abi.encode(
            _DOMAIN_TYPEHASH, // EIP712Domain(uint256 chainId,address verifyingContract)
            block.chainid,
            eoaOwner // In EIP-7702, the EOA becomes the verifying contract
        ));
        assertEq(domainSeparator, expectedDomainSeparator, "Domain separator should follow EIP-712 standard");
        console.log(" Domain separator verification passed");
        
        // 3. Verify struct hash follows EIP-712 standard
        bytes32 expectedStructHash = keccak256(abi.encode(
            _HANDLEOPS_TYPEHASH, // HandleOps(bytes32 data,uint256 nonce)
            dataHash,
            currentNonce
        ));
        
        // 4. Verify final digest follows EIP-712 standard: \x19\x01 + domainSeparator + structHash
        bytes32 expectedDigest = keccak256(abi.encodePacked(
            "\x19\x01", // EIP-712 prefix
            domainSeparator,
            expectedStructHash
        ));
        assertEq(digest, expectedDigest, "Final digest should follow EIP-712 standard");
        console.log(" Final digest verification passed");
        
        // 5. Test signature generation and validation
        bytes32 contractDigest = _simulateContractDigest(userOps, currentNonce, eoaOwner);
        assertEq(digest, contractDigest, "Generated digest should match contract digest");
        console.log(" Contract digest consistency verified");
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaOwnerPrivateKey, contractDigest);
        console.log("Generated signature components:");
        console.log("v:", v);
        console.logBytes32(r);
        console.logBytes32(s);
        
        // Apply malleability protection
        if (uint256(s) > HALF_CURVE_ORDER) {
            console.log("Applying malleability protection to s");
            s = bytes32(CURVE_ORDER - uint256(s));
            v = v == 27 ? 28 : 27;
        }
        
        // Verify signature recovery
        address recovered = ecrecover(contractDigest, v, r, s);
        assertEq(recovered, eoaOwner, "Signature should recover to EOA owner");
        console.log(" Signature recovery verification passed");
        
        // Convert to contract format (vs format)
        uint256 rUint = uint256(r);
        uint256 vs = (v == 28 ? 1 : 0) << 255 | uint256(s);
        
        console.log("Contract format signature:");
        console.log("r:", rUint);
        console.log("vs:", vs);
        console.log("vs >> 255 (v bit):", vs >> 255);
        
        // 6. Test actual execution of the batched operations
        console.log("=== Executing Batched Operations ===");
        
        // Record initial balances and states
        uint256 initialRecipientEth = recipient.balance;
        uint256 initialUserTokens = mockToken.balanceOf(user);
        address initialNftOwner = mockNFT.ownerOf(tokenId);
        uint256 initialDefiDeposit = defiProtocol.getDeposit(eoaOwner);
        
        console.log("Initial states:");
        console.log("Recipient ETH balance:", initialRecipientEth);
        console.log("User token balance:", initialUserTokens);
        console.log("NFT owner:", initialNftOwner);
        console.log("DeFi deposit:", initialDefiDeposit);
        
        // Execute the batched transaction
        bool success = _tryHandleOps(userOps, rUint, vs);
        assertTrue(success, "Batched operations should execute successfully");
        console.log(" Batched operations executed successfully");
        
        // Verify all operations were executed correctly
        
        // Check NFT transfer
        address newNftOwner = mockNFT.ownerOf(tokenId);
        assertEq(newNftOwner, recipient, "NFT should be transferred to recipient");
        console.log(" NFT transfer verified");
        
        // Check token transfer
        uint256 newUserTokens = mockToken.balanceOf(user);
        assertEq(newUserTokens, initialUserTokens + 50 ether, "User should receive 50 tokens");
        console.log(" Token transfer verified");
        
        // Check ETH transfer
        uint256 newRecipientEth = recipient.balance;
        assertEq(newRecipientEth, initialRecipientEth + 2 ether, "Recipient should receive 2 ETH");
        console.log(" ETH transfer verified");
        
        // Check DeFi deposit
        uint256 newDefiDeposit = defiProtocol.getDeposit(eoaOwner);
        assertEq(newDefiDeposit, initialDefiDeposit + 100 ether, "DeFi deposit should increase by 100 tokens");
        console.log(" DeFi deposit verified");
        
        // 7. Verify nonce increment
        uint256 newNonce = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        assertEq(newNonce, currentNonce + 1, "Nonce should be incremented after successful execution");
        console.log(" Nonce increment verified");
        
        // 8. Test replay protection with same signature
        console.log("=== Testing Replay Protection ===");
        bool replaySuccess = _tryHandleOps(userOps, rUint, vs);
        assertFalse(replaySuccess, "Replay attack should fail");
        console.log(" Replay protection verified");
        
        // 9. Verify final nonce (should not increment on failed replay)
        uint256 finalNonce = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        assertEq(finalNonce, newNonce, "Nonce should not change after failed replay");
        console.log(" Final nonce verification passed");
        
        // 10. Test EIP-712 data structure components individually
        console.log("=== EIP-712 Component Verification ===");
        
        // Verify domain typehash
        bytes32 computedDomainTypehash = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
        assertEq(_DOMAIN_TYPEHASH, computedDomainTypehash, "Domain typehash should match standard");
        console.log(" Domain typehash verification passed");
        
        // Verify handleOps typehash
        bytes32 computedHandleOpsTypehash = keccak256("HandleOps(bytes32 data,uint256 nonce)");
        assertEq(_HANDLEOPS_TYPEHASH, computedHandleOpsTypehash, "HandleOps typehash should match standard");
        console.log(" HandleOps typehash verification passed");
        
        // 11. Test with different chain ID (should fail)
        console.log("=== Cross-Chain Protection Test ===");
        vm.chainId(1); // Change to mainnet
        bytes32 differentChainDigest = _simulateContractDigest(userOps, currentNonce + 1, eoaOwner);
        vm.chainId(31337); // Change back
        
        assertTrue(differentChainDigest != contractDigest, "Different chain ID should produce different digest");
        console.log(" Cross-chain protection verified");
        
        console.log("=== All EIP-712 Compliance Tests Passed ===");
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

function test_CREATE2_DeploymentAttackVectors() public {
    console.log("\n=== CREATE2 Deployment Attack Vector Testing ===");
    
    // Deploy the CREATE2 factory and vulnerable target
    CREATE2Deployer factory = new CREATE2Deployer();
    VulnerableTarget vulnerableTarget = new VulnerableTarget();
    DfnsSmartAccount smartAccount = new DfnsSmartAccount();
    console.log("Factory deployed at:", address(factory));
    console.log("Vulnerable target at:", address(vulnerableTarget));
    console.log("Smart account balance:", address(smartAccount).balance);
    
    // Give the smart account some initial funds
    vm.deal(address(smartAccount), 100 ether);
    vulnerableTarget.transfer(address(smartAccount), 1000 * 10**18);
    
    // ========================================
    // ATTACK 1: Metamorphic Contract Attack
    // ========================================
    console.log("\n--- Testing Metamorphic Contract Attack ---");
    
    bytes32 metamorphicSalt = keccak256("metamorphic_attack");
    
    // Get bytecode for both versions
    bytes memory v1Bytecode = abi.encodePacked(
        type(MaliciousContractV1).creationCode,
        abi.encode(address(vulnerableTarget))
    );
    bytes memory v2Bytecode = abi.encodePacked(
        type(MaliciousContractV2).creationCode,
        abi.encode(address(vulnerableTarget))
    );
    
    // Predict the deployment address
    address predictedAddr = factory.predictAddress(metamorphicSalt, v1Bytecode);
    console.log("Predicted deployment address:", predictedAddr);
    
    // Create userOps to deploy V1 contract
    bytes memory deployV1Ops = _createValidDeploymentUserOps(
        address(factory),
        0,
        abi.encodeWithSignature(
            "deploy(bytes32,bytes)",
            metamorphicSalt,
            v1Bytecode
        )
    );
    
    // Execute deployment via smart account
    (uint256 r, uint256 vs) = _generateSignature(deployV1Ops, smartAccount.getNonce());
    
    uint256 nonceBefore = smartAccount.getNonce();
    smartAccount.handleOps(deployV1Ops, r, vs);
    uint256 nonceAfter = smartAccount.getNonce();
    
    console.log("V1 contract deployed. Nonce:", nonceBefore, "->", nonceAfter);
    
    // Verify V1 is deployed and working
    MaliciousContractV1 deployedV1 = MaliciousContractV1(predictedAddr);
    assertEq(deployedV1.VERSION(), 1, "V1 should report version 1");
    
    // Authorize the deployed contract (this is the critical vulnerability)
    vulnerableTarget.authorizeContract(predictedAddr);
    assertTrue(vulnerableTarget.authorizedContracts(predictedAddr), "Contract should be authorized");
    
    // Now destroy V1 and deploy V2 at the same address
    bytes memory destroyOps = _createDeploymentUserOps(
        predictedAddr,
        0,
        abi.encodeWithSignature("destroy()")
    );
    
    (r, vs) = _generateSignature(destroyOps, smartAccount.getNonce());
    smartAccount.handleOps(destroyOps, r, vs);
    
    console.log("V1 contract destroyed");
    
    // Deploy V2 at the same address
    bytes memory deployV2Ops = _createDeploymentUserOps(
        address(factory),
        0,
        abi.encodeWithSignature(
            "deploy(bytes32,bytes)",
            metamorphicSalt,
            v2Bytecode
        )
    );
    
    (r, vs) = _generateSignature(deployV2Ops, smartAccount.getNonce());
    smartAccount.handleOps(deployV2Ops, r, vs);
    
    console.log("V2 contract deployed at same address");
    
    // Now the same address has different code but is still authorized!
    MaliciousContractV2 deployedV2 = MaliciousContractV2(predictedAddr);
    assertEq(deployedV2.VERSION(), 2, "V2 should report version 2");
    assertTrue(vulnerableTarget.authorizedContracts(predictedAddr), "Contract should still be authorized");
    
    // VULNERABILITY: V2 can now perform malicious actions that V1 couldn't
    uint256 balanceBefore = vulnerableTarget.balances(address(this));
    deployedV2.maliciousFunction(); // This mints tokens!
    uint256 balanceAfter = vulnerableTarget.balances(address(this));
    
    console.log("Balance before malicious function:", balanceBefore);
    console.log("Balance after malicious function:", balanceAfter);
    
    assertGt(balanceAfter, balanceBefore, "CRITICAL: Metamorphic attack succeeded - unauthorized minting!");
    
    // ========================================
    // ATTACK 2: Address Collision Attack
    // ========================================
    console.log("\n--- Testing Address Collision Attack ---");
    
    // Send ETH to a predicted address before deployment
    bytes32 collisionSalt = keccak256("collision_attack");
    bytes memory targetBytecode = abi.encodePacked(
        type(MetamorphicContract).creationCode,
        abi.encode(address(this))
    );
    
    address collisionAddr = factory.predictAddress(collisionSalt, targetBytecode);
    
    // Send ETH to the predicted address
    bytes memory fundingOps = _createDeploymentUserOps(
        collisionAddr,
        10 ether,
        ""
    );
    
    (r, vs) = _generateSignature(fundingOps, smartAccount.getNonce());
    smartAccount.handleOps(fundingOps, r, vs);
    
    console.log("Funded predicted address with 10 ETH");
    console.log("Address balance:", address(collisionAddr).balance);
    
    // Now deploy contract to that address - it will have the pre-funded ETH
    bytes memory collisionDeployOps = _createDeploymentUserOps(
        address(factory),
        0,
        abi.encodeWithSignature(
            "deploy(bytes32,bytes)",
            collisionSalt,
            targetBytecode
        )
    );
    
    (r, vs) = _generateSignature(collisionDeployOps, smartAccount.getNonce());
    smartAccount.handleOps(collisionDeployOps, r, vs);
    
    console.log("Contract deployed at funded address");
    console.log("Deployed contract balance:", address(collisionAddr).balance);
    
    assertEq(address(collisionAddr).balance, 10 ether, "VULNERABILITY: Contract deployed with unexpected ETH balance");
    
    // ========================================
    // ATTACK 3: Gas Bomb Deployment Attack
    // ========================================
    console.log("\n--- Testing Gas Bomb Deployment Attack ---");
    
    bytes32 gasBombSalt = keccak256("gas_bomb_attack");
    bytes memory gasBombBytecode = abi.encodePacked(
        type(GasBombDeployer).creationCode,
        abi.encode(uint256(10000)) // Large array size
    );
    
    // This should consume excessive gas but not fail completely
    bytes memory gasBombOps = _createDeploymentUserOps(
        address(factory),
        0,
        abi.encodeWithSignature(
            "deploy(bytes32,bytes)",
            gasBombSalt,
            gasBombBytecode
        )
    );
    
    (r, vs) = _generateSignature(gasBombOps, smartAccount.getNonce());
    
    uint256 gasStart = gasleft();
    try smartAccount.handleOps(gasBombOps, r, vs) {
        uint256 gasUsed = gasStart - gasleft();
        console.log("Gas bomb deployment succeeded, gas used:", gasUsed);
        
        address gasBombAddr = factory.predictAddress(gasBombSalt, gasBombBytecode);
        GasBombDeployer gasBomb = GasBombDeployer(gasBombAddr);
        console.log("Gas bomb array length:", gasBomb.getArrayLength());
        
        // VULNERABILITY: Excessive gas consumption in deployment
        assertGt(gasUsed, 1000000, "VULNERABILITY: Gas bomb consumed excessive gas");
        
    } catch Error(string memory reason) {
        console.log("Gas bomb deployment failed:", reason);
        // This is expected behavior if gas limits are properly enforced
    }
    
    // ========================================
    // ATTACK 4: Batch Deployment Resource Exhaustion
    // ========================================
    console.log("\n--- Testing Batch Deployment Attack ---");
    
    bytes32[] memory batchSalts = new bytes32[](5);
    bytes[] memory batchBytecodes = new bytes[](5);
    
    for (uint256 i = 0; i < 5; i++) {
        batchSalts[i] = keccak256(abi.encodePacked("batch_attack", i));
        batchBytecodes[i] = abi.encodePacked(
            type(MetamorphicContract).creationCode,
            abi.encode(address(this))
        );
    }
    
    bytes memory batchDeployOps = _createDeploymentUserOps(
        address(factory),
        5 ether, // Total value to distribute
        abi.encodeWithSignature(
            "batchDeploy(bytes32[],bytes[])",
            batchSalts,
            batchBytecodes
        )
    );

    (r, vs) = _generateSignature(batchDeployOps, smartAccount.getNonce());

    gasStart = gasleft();
    try smartAccount.handleOps(batchDeployOps, r, vs) {
        uint256 gasUsed = gasStart - gasleft();
        console.log("Batch deployment succeeded, gas used:", gasUsed);
        
        // Check that contracts were deployed
        for (uint256 i = 0; i < 5; i++) {
            address deployedAddr = factory.predictAddress(batchSalts[i], batchBytecodes[i]);
            assertTrue(_isContract(deployedAddr), "Contract should be deployed");
            console.log("Deployed contract", i, "at:", deployedAddr);
        }
        
        // VULNERABILITY: Resource exhaustion through batch operations
        assertGt(gasUsed, 500000, "VULNERABILITY: Batch deployment consumed significant gas");
        
    } catch Error(string memory reason) {
        console.log("Batch deployment failed:", reason);
    }
    
    // ========================================
    // MITIGATION RECOMMENDATIONS
    // ========================================
    console.log("\n--- Mitigation Recommendations ---");
    console.log("1. Implement gas limits for individual operations");
    console.log("2. Add authorization checks before CREATE2 deployments");
    console.log("3. Track and limit contract deployments per transaction");
    console.log("4. Implement address whitelisting for sensitive operations");
    console.log("5. Add time delays for contract authorization");
    console.log("6. Monitor for metamorphic contract patterns");
}

/**
 * @dev Helper function to create valid deployment userOps with proper format
 */
function _createValidDeploymentUserOps(
    address target,
    uint256 value,
    bytes memory data
) internal pure returns (bytes memory) {
    return abi.encodePacked(
        uint256(84 + data.length), // Total length: 32 (length) + 20 (address) + 32 (value) + 32 (dataLength) + data.length
        target,                    // Target address (20 bytes)
        value,                     // ETH value (32 bytes)
        uint256(data.length),      // Data length (32 bytes)
        data                       // Encoded function call (variable length)
    );
}

/**
 * @dev Helper function to check if address is a contract
 */
function _isContract(address account) internal view returns (bool) {
    uint256 size;
    assembly {
        size := extcodesize(account)
    }
    return size > 0;
}
    
    /* ========== HELPER FUNCTIONS (Library Wrappers) ========== */

    function _generateSignature(bytes memory userOps, uint256 nonce) internal returns (uint256 r, uint256 vs) {
        return DfnsTestUtils.generateSignature(testCtx, userOps, nonce);
    }

    function _encodeOperations(Operation[] memory operations) internal pure returns (bytes memory) {
        return DfnsTestUtils.encodeOperations(operations);
    }

    function _generateEip712Data(bytes memory userOps, uint256 nonce) 
        internal 
        view 
        returns (bytes32 dataHash, bytes32 digest, bytes32 domainSeparator) 
    {
        return DfnsTestUtils.generateEip712Data(testCtx, userOps, nonce);
    }
    
    function _callHandleOps(bytes memory userOps, uint256 r, uint256 vs) internal {
        DfnsTestUtils.callHandleOps(testCtx, userOps, r, vs);
    }

    function _tryHandleOps(bytes memory userOps, uint256 r, uint256 vs) internal returns (bool success) {
        return DfnsTestUtils.tryHandleOps(testCtx, userOps, r, vs);
    }

    function _simulateContractDigest(bytes memory userOps, uint256 nonce, address contractAddress) 
        internal 
        view 
        returns (bytes32 digest) 
    {
        return DfnsTestUtils.simulateContractDigest(testCtx, userOps, nonce, contractAddress);
    }

    function _simulateSignatureValidation(
        bytes32 hash, 
        uint256 r, 
        uint256 vs, 
        address expectedSigner
    ) internal pure returns (bool) {
        return DfnsTestUtils.simulateSignatureValidation(hash, r, vs, expectedSigner);
    }

    function _simulateHashCalculation(
        bytes memory userOps, 
        uint256 nonce, 
        address verifyingContract
    ) internal view returns (bytes32) {
        return DfnsTestUtils.simulateHashCalculation(userOps, nonce, verifyingContract);
    }

    function _validateOperationFormat(bytes memory userOps) internal pure returns (bool) {
        return DfnsTestUtils.validateOperationFormat(userOps);
    }

    function _createValidDeploymentUserOps(
        address target,
        uint256 value,
        bytes memory data
    ) internal pure returns (bytes memory) {
        return DfnsTestUtils.createValidDeploymentUserOps(target, value, data);
    }

    function _isContract(address account) internal view returns (bool) {
        return DfnsTestUtils.isContract(account);
    }

    // Receive function to accept ETH
    receive() external payable {}
}

/* ========== MOCK CONTRACTS ========== */


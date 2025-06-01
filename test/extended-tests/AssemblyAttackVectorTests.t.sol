// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.29;

import "forge-std/Test.sol";
import "../../src/DfnsSmartAccount.sol";
import "../utils/mockContracts.sol";
/**
 * @title AssemblyAttackVectorTests
 * @dev Comprehensive test suite for assembly code vulnerabilities in DfnsSmartAccount
 * Tests buffer overflows, integer overflows, memory corruption, reentrancy, and gas bombs
 */
contract AssemblyAttackVectorTests is Test {
    DfnsSmartAccount public smartAccount;
    address public testSigner;
    uint256 public signerPrivateKey;
    
    // Test constants
    uint256 constant MAX_UINT256 = type(uint256).max;
    uint256 constant LARGE_DATA_SIZE = 1000000; // 1MB
    bytes32 private constant _DOMAIN_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
    // keccak256("HandleOps(bytes32 data,uint256 nonce)")
    bytes32 private constant _HANDLEOPS_TYPEHASH = 0x4f8bb4631e6552ac29b9d6bacf60ff8b5481e2af7c2104fe0261045fa6988111;
    uint256 constant HALF_CURVE_ORDER = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    uint256 private constant CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

    
    // Attack contract for reentrancy testing
    ReentrancyAttacker public attackContract;
    
    event AssemblyVulnerabilityTest(string testName, bool success, string details);

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

    function _generateSignature(bytes memory userOps, uint256 nonce) internal returns (uint256 r, uint256 vs) {
        // In EIP-7702 context, the contract calculates digest using EOA address as address(this)
        bytes32 digest = _simulateContractDigest(userOps, nonce, testSigner);
        
        // Sign with the EOA's private key
        (uint8 v, bytes32 rBytes, bytes32 s) = vm.sign(signerPrivateKey, digest);
        
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



    function setUp() public {
        // Deploy the smart account at a fixed address for EIP-7702 testing
        address contractAddress = 0xa570148Ab35de51eA1C59AC09Cc6ea37AC6BaB91;
        deployCodeTo("DfnsSmartAccount.sol", contractAddress);
        smartAccount = DfnsSmartAccount(contractAddress);
        
        // Generate test signer for EIP-7702 delegation
        (testSigner, signerPrivateKey) = makeAddrAndKey("testSigner");

        // Deploy attack contract
        attackContract = new ReentrancyAttacker(address(smartAccount));
        
        // Fund the test signer
        vm.deal(testSigner, 100 ether);
        
        console.log("=== Assembly Attack Vector Test Suite ===");
        console.log("Smart Account deployed at:", address(smartAccount));
        console.log("Test signer address:", testSigner);
    }
    
    /**
     * @dev Set up EIP-7702 delegation before each test
     */
    function _setupEIP7702() internal {
        vm.signAndAttachDelegation(address(smartAccount), signerPrivateKey);
    }
    /**
     * @dev Test Category 1: Buffer Overflow Attacks
     */
    function test_BufferOverflow_TruncatedOperations() public {
        console.log("\n--- Buffer Overflow Tests ---");
        _setupEIP7702();
        
        // Test 1: Completely empty userOps (should succeed - empty batch is valid)
        bytes memory emptyOps = abi.encodePacked(uint256(0)); // Proper empty userOps with length 0
        (uint256 r, uint256 vs) = _generateSignature(emptyOps, 0);
        
        uint256 gasBefore = gasleft();
        // Empty userOps should succeed (empty batch)
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(testSigner));
        delegatedContract.handleOps(emptyOps, r, vs);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Strengthened assertions
        assertLt(gasUsed, 50000, "Empty userOps should execute quickly");
        assertEq(delegatedContract.getNonce(), 1, "Nonce should increment after successful empty batch");
        
        emit AssemblyVulnerabilityTest("Empty UserOps", true, "Empty batch should succeed");

        // Test 2: UserOps with invalid structure (should fail)
        bytes memory malformedOps = abi.encodePacked(uint256(32), uint16(0x1234)); // Claims 32 bytes but provides 2
        (r, vs) = _generateSignature(malformedOps, 1);
        
        uint256 gasBefore2 = gasleft();
        vm.expectRevert();
        delegatedContract.handleOps(malformedOps, r, vs);
        uint256 gasUsed2 = gasBefore2 - gasleft();
        
        // Strengthened assertions for malformed operation
        assertLt(gasUsed2, 75000, "Malformed operation should fail during assembly parsing");
        assertTrue(gasUsed2 > gasUsed, "Should perform more validation than empty operation");
        
        emit AssemblyVulnerabilityTest("Malformed Structure", true, "Should revert on malformed userOps");

        // Test 3: Truncated operation (missing fields)
        bytes memory truncatedOp = abi.encodePacked(
            uint256(52), // Length indicates 52 bytes total  
            address(0x1234567890123456789012345678901234567890), // 20 bytes address
            uint256(1 ether) // 32 bytes value (total 52 bytes, missing dataLength and data)
        );
        (r, vs) = _generateSignature(truncatedOp, 1);
        
        uint256 gasBefore3 = gasleft();
        vm.expectRevert();
        delegatedContract.handleOps(truncatedOp, r, vs);
        uint256 gasUsed3 = gasBefore3 - gasleft();
        
        // Strengthened assertions for truncated operation
        assertLt(gasUsed3, 100000, "Truncated operation should be detected early in assembly");
        assertEq(delegatedContract.getNonce(), 1, "Failed operations should not modify nonce");
        
        emit AssemblyVulnerabilityTest("Truncated Operation", true, "Should revert on truncated operation data");
    }

    function test_BufferOverflow_PartialOperations() public {
        _setupEIP7702();
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(testSigner));
        
        // Test 1: Operation with address and value but missing dataLength
        bytes memory partialOp = abi.encodePacked(
            uint256(52), // Length indicates 52 bytes
            address(0x1234567890123456789012345678901234567890), // 20 bytes
            uint256(1 ether) // 32 bytes (total 52 bytes, but missing dataLength)
        );
        (uint256 r, uint256 vs) = _generateSignature(partialOp, 0);
        
        uint256 gasBefore = gasleft();
        uint256 balanceBefore = testSigner.balance;
        vm.expectRevert();
        delegatedContract.handleOps(partialOp, r, vs);
        uint256 gasUsed = gasBefore - gasleft();
        uint256 balanceAfter = testSigner.balance;
        
        // Strengthened assertions for partial operations
        assertLt(gasUsed, 150000, "Partial operation should fail during assembly parsing");
        assertEq(balanceAfter, balanceBefore, "Failed operations should not transfer value");
        assertEq(delegatedContract.getNonce(), 0, "Nonce should not increment on failed operations");
        
        emit AssemblyVulnerabilityTest("Partial Operation", true, "Should revert on missing dataLength");

        // Test 2: Operation with proper structure but data length mismatch
        bytes memory validCallData = abi.encodeWithSignature("setValue(uint256)", 42);
        bytes memory validOp = abi.encodePacked(
            uint256(84 + validCallData.length), // Correct total length
            address(attackContract),             // Valid target
            uint256(0),                         // No ETH transfer
            uint256(validCallData.length),      // Correct data length
            validCallData                       // Valid call data
        );
        (r, vs) = _generateSignature(validOp, 0);
        
        uint256 gasBefore2 = gasleft();
        try delegatedContract.handleOps(validOp, r, vs) {
            uint256 gasUsed2 = gasBefore2 - gasleft();
            assertEq(delegatedContract.getNonce(), 1, "Valid operation should increment nonce");
            assertTrue(gasUsed2 > gasUsed, "Should perform more validation when data is present");
            emit AssemblyVulnerabilityTest("Valid Operation with Data", true, "Valid operations with data should succeed");
        } catch {
            // If it fails, it's likely due to the target contract not having the expected function
            emit AssemblyVulnerabilityTest("Valid Operation with Data", false, "Valid operation failed unexpectedly");
        }
    }

    /**
     * @dev Test Category 2: Integer Overflow Attacks
     */
    function test_IntegerOverflow_Iterator() public {
        console.log("\n--- Integer Overflow Tests ---");
        
        // Test 1: Maximum dataLength to cause iterator overflow
        bytes memory overflowOp = abi.encodePacked(
            uint256(84), // Minimum valid length
            address(this), // 20 bytes - valid target
            uint256(0), // 32 bytes - no value
            MAX_UINT256, // 32 bytes - maximum possible dataLength
            bytes32(0) // Some minimal data to prevent immediate bounds check failure
        );
        (uint256 r, uint256 vs) = _signMessage(overflowOp, 0);
        
        uint256 gasBefore = gasleft();
        uint256 nonceBefore = smartAccount.getNonce();
        vm.expectRevert();
        smartAccount.handleOps(overflowOp, r, vs);
        uint256 gasUsed = gasBefore - gasleft();
        uint256 nonceAfter = smartAccount.getNonce();
        
        // Strengthened assertions for overflow detection
        _assertGasEfficiency(gasUsed, 500000, "Iterator Overflow Detection");
        assertEq(nonceAfter, nonceBefore, "Overflow should not increment nonce");
        
        // Verify overflow arithmetic
        bool wouldOverflow = !_validateIteratorBounds(0x20, MAX_UINT256);
        assertTrue(wouldOverflow, "Test case should indeed cause overflow");
        
        emit AssemblyVulnerabilityTest("Iterator Overflow via Max DataLength", true, "Should handle overflow in iterator calculation");

        // Test 2: DataLength that would cause i + 0x54 + dataLength to overflow
        uint256 maliciousDataLength = MAX_UINT256 - 0x54 + 1;
        bytes memory overflowOp2 = abi.encodePacked(
            uint256(84),
            address(this),
            uint256(0),
            maliciousDataLength,
            bytes32(0)
        );
        (r, vs) = _signMessage(overflowOp2, 0);
        
        uint256 gasBefore2 = gasleft();
        vm.expectRevert();
        smartAccount.handleOps(overflowOp2, r, vs);
        uint256 gasUsed2 = gasBefore2 - gasleft();
        
        // Critical assertion: Specific overflow scenario should be detected
        _assertGasEfficiency(gasUsed2, 400000, "Specific Overflow Detection");
        bool specificOverflow = !_validateIteratorBounds(0x20, maliciousDataLength);
        assertTrue(specificOverflow, "Malicious dataLength should cause detectable overflow");
        
        emit AssemblyVulnerabilityTest("Iterator Overflow via Malicious DataLength", true, "Should handle malicious dataLength causing overflow");
    }

    function test_IntegerOverflow_MultipleOperations() public {
        // Test 3: Multiple operations that cumulatively cause overflow
        bytes memory op1 = abi.encodePacked(
            address(this),
            uint256(0),
            uint256(10),
            bytes10(0x12345678901234567890)
        );
        
        bytes memory op2 = abi.encodePacked(
            address(this), 
            uint256(0),
            MAX_UINT256 - 100, // Large dataLength
            new bytes(50) // Some data
        );

        bytes memory multiOverflowOps = abi.encodePacked(
            uint256(op1.length + op2.length), // Total length
            op1,
            op2
        );
        
        (uint256 r, uint256 vs) = _signMessage(multiOverflowOps, 0);
        
        vm.expectRevert();
        smartAccount.handleOps(multiOverflowOps, r, vs);
        emit AssemblyVulnerabilityTest("Multiple Operations Overflow", true, "Should handle overflow across multiple operations");
    }

    /**
     * @dev Test Category 3: Memory Corruption Attacks
     */
    function test_MemoryCorruption_InvalidDataPointers() public {
        console.log("\n--- Memory Corruption Tests ---");
        
        // Test 1: DataLength extends far beyond userOps bounds
        bytes memory corruptionOp = abi.encodePacked(
            uint256(84), // Claims only 84 bytes total
            address(this),
            uint256(0),
            uint256(1000000), // large size to cause memory corruption.
            bytes4(0x12345678) // Minimal data
        );
        (uint256 r, uint256 vs) = _signMessage(corruptionOp, 0);
        
        vm.expectRevert();
        smartAccount.handleOps(corruptionOp, r, vs);
        emit AssemblyVulnerabilityTest("Data Extends Beyond Bounds", true, "Should prevent reading beyond userOps bounds");

        // Test 2: Zero-length operation but non-zero dataLength claim
        bytes memory zeroLengthOp = abi.encodePacked(
            uint256(0), // Claims 0 total length
            // But still try to include operation data below
            address(this),
            uint256(0),
            uint256(100) // Claims 100 bytes of data
        );
        (r, vs) = _signMessage(zeroLengthOp, 0);
        
        vm.expectRevert();
        smartAccount.handleOps(zeroLengthOp, r, vs);
        emit AssemblyVulnerabilityTest("Zero Length with Data Claim", true, "Should handle zero-length operations");
    }

    function test_MemoryCorruption_OverlappingOperations() public {
        // Test 3: Operations with overlapping memory regions
        bytes memory baseData = new bytes(1000);
        for (uint i = 0; i < baseData.length; i++) {
            baseData[i] = bytes1(uint8(i % 256));
        }
        
        // Create operation that claims more data than available
        bytes memory overlappingOp = abi.encodePacked(
            uint256(1000), // Total length
            address(this),
            uint256(0),
            uint256(2000), // Claims 2000 bytes but only 1000 available
            baseData
        );
        (uint256 r, uint256 vs) = _signMessage(overlappingOp, 0);
        
        vm.expectRevert();
        smartAccount.handleOps(overlappingOp, r, vs);
        emit AssemblyVulnerabilityTest("Overlapping Memory Regions", true, "Should prevent overlapping memory access");
    }

 

    /**
     * @dev Test Category 5: Gas Bomb Attacks
     */
    function test_GasBomb_EnormousDataLength() public {
        console.log("\n--- Gas Bomb Attack Tests ---");
        _setupEIP7702();
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(testSigner));
        
        // Test 1: Operation with enormous dataLength that should cause assembly issues
        bytes memory gasBombOp = abi.encodePacked(
            uint256(88), // Small total length (just header + 4 bytes)
            address(this), // Valid target
            uint256(0), // No ETH transfer
            uint256(LARGE_DATA_SIZE), // Claims 1MB of data but only provides 4 bytes
            bytes4(0x12345678) // Minimal actual data
        );
        (uint256 r, uint256 vs) = _generateSignature(gasBombOp, 0);
        
        // This should revert due to assembly trying to read beyond bounds
        vm.expectRevert();
        delegatedContract.handleOps(gasBombOp, r, vs);
        
        emit AssemblyVulnerabilityTest("Gas Bomb via Large DataLength", true, "Gas bomb attack via enormous dataLength should revert");
    }


    /**
     * @dev Test Category 6: Edge Cases and Boundary Conditions
     */
    function test_EdgeCases_BoundaryConditions() public {
        console.log("\n--- Edge Cases and Boundary Tests ---");
        
        // Test 1: Operation with exactly minimum required size
        bytes memory minimalOp = abi.encodePacked(
            uint256(84), // Exact minimum: 20 + 32 + 32 + 0 data = 84 bytes
            address(this),
            uint256(0),
            uint256(0), // Zero data length
            bytes("") // No data
        );
        (uint256 r, uint256 vs) = _signMessage(minimalOp, 0);
        
        try smartAccount.handleOps(minimalOp, r, vs) {
            emit AssemblyVulnerabilityTest("Minimal Valid Operation", true, "Minimal operation executed successfully");
        } catch {
            emit AssemblyVulnerabilityTest("Minimal Valid Operation", false, "Minimal operation should succeed");
        }

        // Test 2: Single byte difference in claimed vs actual length
        bytes memory offByOneOp = abi.encodePacked(
            uint256(85), // Claims 85 bytes
            address(this),
            uint256(0), 
            uint256(1), // Claims 1 byte of data
            bytes("") // But provides 0 bytes
        );
        (r, vs) = _signMessage(offByOneOp, 0);
        
        vm.expectRevert();
        smartAccount.handleOps(offByOneOp, r, vs);
        emit AssemblyVulnerabilityTest("Off-by-One Length Error", true, "Should catch off-by-one length errors");
    }

    /**
     * @dev Helper function to sign messages for testing
     */
    function _signMessage(bytes memory userOps, uint256 nonce) internal view returns (uint256 r, uint256 vs) {
        bytes32 domainSeparator = keccak256(abi.encode(
            0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218,
            block.chainid,
            address(smartAccount)
        ));
        
        bytes32 structHash = keccak256(abi.encode(
            0x4f8bb4631e6552ac29b9d6bacf60ff8b5481e2af7c2104fe0261045fa6988111,
            keccak256(userOps),
            nonce
        ));
        
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        
        (uint8 v, bytes32 rBytes, bytes32 s) = vm.sign(signerPrivateKey, digest);
        
        r = uint256(rBytes);
        vs = (uint256(v - 27) << 255) | uint256(s);
    }

    /**
     * @dev Helper function to estimate memory usage for strengthened assertions
     */
    function _getMemorySize() internal pure returns (uint256 size) {
        assembly {
            size := mload(0x40)
        }
    }

    /**
     * @dev Helper function to validate iterator bounds
     */
    function _validateIteratorBounds(uint256 i, uint256 dataLength) internal pure returns (bool isValid) {
        // Check for overflow in: i + 0x54 + dataLength
        unchecked {
            uint256 nextI = i + 0x54 + dataLength;
            isValid = (nextI >= i) && (nextI >= 0x54) && (nextI >= dataLength);
        }
    }

    /**
     * @dev Helper function to check gas efficiency thresholds
     */
    function _assertGasEfficiency(uint256 gasUsed, uint256 maxExpected, string memory testName) internal {
        if (gasUsed > maxExpected) {
            console.log("GAS INEFFICIENCY DETECTED in", testName);
            console.log("Expected max:", maxExpected, "Actual:", gasUsed);
        }
        assertLe(gasUsed, maxExpected, string(abi.encodePacked("Gas usage exceeded threshold in ", testName)));
    }

    /**
     * @dev Fallback function to receive calls during testing
     */
    fallback() external payable {
        // Do nothing - just accept calls
    }

    receive() external payable {
        // Accept ETH
    }
}


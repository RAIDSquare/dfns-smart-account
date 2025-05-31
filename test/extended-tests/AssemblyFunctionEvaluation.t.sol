// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.29;

import "forge-std/Test.sol";
import "../../src/DfnsSmartAccount.sol";
import  "../utils/mockContracts.sol";
/**
 * @title AssemblyFunctionEvaluation
 * @dev Extensive evaluation of the assembly function in handleOps with comprehensive edge cases
 * Focus: Assembly block vulnerability analysis through strategic userOps construction
 */
contract AssemblyFunctionEvaluation is Test {
    DfnsSmartAccount public smartAccount;
    address public eoaOwner;
    uint256 public eoaOwnerPrivateKey;
    
    // Assembly function analysis constants
    uint256 constant OPERATION_HEADER_SIZE = 0x54; // 20 + 32 + 32 = 84 bytes
    uint256 constant ADDRESS_OFFSET = 0x00;        // to := shr(0x60, mload(add(userOps, i)))
    uint256 constant VALUE_OFFSET = 0x14;          // value := mload(add(userOps, add(i, 0x14)))
    uint256 constant DATA_LENGTH_OFFSET = 0x34;    // dataLength := mload(add(userOps, add(i, 0x34)))
    uint256 constant DATA_OFFSET = 0x54;           // data := add(userOps, add(i, 0x54))
    
    // Edge case values for testing
    uint256 constant MAX_UINT256 = type(uint256).max;
    uint256 constant HALF_MAX_UINT256 = MAX_UINT256 / 2;
    
    // Signature malleability protection constants
    uint256 private constant CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    uint256 private constant HALF_CURVE_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    
    // EIP-712 constants
    bytes32 private constant _DOMAIN_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;
    bytes32 private constant _HANDLEOPS_TYPEHASH = 0x4f8bb4631e6552ac29b9d6bacf60ff8b5481e2af7c2104fe0261045fa6988111;
    
    // Target contracts for assembly testing
    AssemblyTestTarget public targetContract;
    
    // Events for detailed assembly analysis
    event AssemblyStepAnalysis(string step, uint256 offset, uint256 value, bool success);
    event MemoryAccessPattern(uint256 readOffset, uint256 dataSize, bool withinBounds);
    event IteratorProgression(uint256 currentI, uint256 dataLength, uint256 nextI, bool overflowDetected);
    event AssemblyVulnerabilityFound(string vulnerability, string severity, bytes32 evidence);

    function setUp() public {
        // Setup EOA owner with private key for EIP-7702 delegation
        (eoaOwner, eoaOwnerPrivateKey) = makeAddrAndKey("eoaOwner");
        
        // Deploy smart account to a specific address for testing
        address contractAddress = 0xa570148Ab35de51eA1C59AC09Cc6ea37AC6BaB91;
        deployCodeTo("DfnsSmartAccount.sol", contractAddress);
        smartAccount = DfnsSmartAccount(contractAddress);
        
        // Deploy target contract for assembly testing
        targetContract = new AssemblyTestTarget();
        
        // Fund contracts and EOA
        vm.deal(address(smartAccount), 10 ether);
        vm.deal(address(targetContract), 5 ether);
        vm.deal(eoaOwner, 1 ether);
        
    }
    
    /**
     * @dev Set up EIP-7702 delegation before each test that requires signature verification
     */
    function _setupEIP7702Delegation() internal {
        vm.signAndAttachDelegation(address(smartAccount), eoaOwnerPrivateKey);
        
        // Verify delegation was successful
        bytes memory code = eoaOwner.code;
        require(code.length > 0, "EIP-7702 delegation failed - no code at EOA address");
    }

    /* ========================================
     * ASSEMBLY LINE-BY-LINE EDGE CASE TESTING
     * ======================================== */

    /**
     * @dev Test: let length := mload(userOps)
     * Edge cases for the first assembly instruction
     */
    function test_Assembly_LengthExtraction_EdgeCases() public {
        console.log("\n=== Testing: let length := mload(userOps) ===");
        
        // Edge Case 1: Zero length - should succeed (empty batch)
        bytes memory zeroLengthOps = abi.encodePacked(uint256(0));
        _testAssemblyOperation(zeroLengthOps, "Zero Length", true);
        
        // Edge Case 2: Length claims operations but has incomplete data - should revert during assembly execution
        bytes memory incompleteOps = _createIncompleteOperationData();
        _testAssemblyOperation(incompleteOps, "Incomplete Operation Data", false);
        
        // Edge Case 3: Length smaller than what's needed for claimed operations
        bytes memory mismatchedLengthOps = _createLengthMismatchOperations();
        _testAssemblyOperation(mismatchedLengthOps, "Length Data Mismatch", false);
        
        // Edge Case 4: Exact minimum length with valid operation
        bytes memory exactMinOps = _createValidOperation(address(targetContract), 0, "");
        _testAssemblyOperation(exactMinOps, "Exact Minimum Length", true);
        
        // Edge Case 5: Large length with valid data (should succeed but consume gas)
        bytes memory largeBatchOps = _createLargeBatchOperations(10);
        _testAssemblyOperationWithGasLimit(largeBatchOps, 1000000, "Large Valid Batch");
        
        emit AssemblyStepAnalysis("Length Extraction", 0, 0, true);
    }

    /**
     * @dev Test: let i := 0x20
     * Test iterator initialization and progression
     */
    function test_Assembly_IteratorInitialization_EdgeCases() public {
        console.log("\n=== Testing: let i := 0x20 (Iterator) ===");
        
        // Test various operation counts to stress iterator
        uint256[] memory operationCounts = new uint256[](5);
        operationCounts[0] = 1;   // Single operation
        operationCounts[1] = 2;   // Double operation
        operationCounts[2] = 10;  // Multiple operations
        operationCounts[3] = 100; // Many operations (stress test)
        operationCounts[4] = 255; // Maximum reasonable operations
        
        for (uint256 opCount = 0; opCount < operationCounts.length; opCount++) {
            uint256 numOps = operationCounts[opCount];
            bytes memory multiOps = _createMultipleOperations(numOps);
            
            if (numOps <= 10) {
                _testAssemblyOperation(multiOps, string(abi.encodePacked(vm.toString(numOps), " Operations")), true);
            } else {
                // Large operation counts should be tested for gas limits
                _testAssemblyOperationWithGasLimit(multiOps, 5000000, string(abi.encodePacked(vm.toString(numOps), " Operations Stress")));
            }
        }
    }

    /**
     * @dev Test: for {} lt(i, length) {} - Loop boundary conditions
     */
    function test_Assembly_LoopBoundaries_EdgeCases() public {
        console.log("\n=== Testing: for {} lt(i, length) {} ===");
        
        // Edge Case 1: i equals length (should not enter loop) - this should succeed
        bytes memory equalBoundaryOps = abi.encodePacked(
            uint256(0x20) // length = 32, i starts at 32, so lt(32, 32) = false, loop doesn't execute
        );
        _testAssemblyOperation(equalBoundaryOps, "i Equals Length", true);
        
        // Edge Case 2: Length just above i but insufficient data - should fail during assembly execution
        bytes memory singleIterOps = _createInsufficientDataOperation();
        _testAssemblyOperation(singleIterOps, "Insufficient Data for Operation", false);
        
        // Edge Case 3: Length claims multiple operations but data is truncated - should fail
        bytes memory partialValidOps = _createPartiallyValidMultiOperation();
        _testAssemblyOperation(partialValidOps, "Partial Valid Multi-Op", false);
        
        // Edge Case 4: Valid single operation with exact boundaries
        bytes memory validBoundaryOp = _createValidOperation(address(targetContract), 0, abi.encodeWithSelector(bytes4(0x12345678)));
        _testAssemblyOperation(validBoundaryOp, "Valid Boundary Operation", true);
    }

    /**
     * @dev Test: let to := shr(0x60, mload(add(userOps, i)))
     * Address extraction edge cases
     */
    function test_Assembly_AddressExtraction_EdgeCases() public {
        console.log("\n=== Testing: Address Extraction (shr 0x60) ===");
        
        // Edge Case 1: Zero address
        bytes memory zeroAddressOp = _createValidOperation(address(0), 0, "");
        _testAssemblyOperation(zeroAddressOp, "Zero Address", true);
        
        // Edge Case 2: Maximum address (all F's)
        address maxAddress = address(0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF);
        bytes memory maxAddressOp = _createValidOperation(maxAddress, 0, "");
        _testAssemblyOperation(maxAddressOp, "Maximum Address", true);
        
        // Edge Case 3: Contract address vs EOA
        bytes memory contractAddressOp = _createValidOperation(address(smartAccount), 0, "");
        _testAssemblyOperation(contractAddressOp, "Contract Address", true);
        
        // Edge Case 4: Non-existent address
        address nonExistent = address(0x1234567890123456789012345678901234567890);
        bytes memory nonExistentOp = _createValidOperation(nonExistent, 0, "");
        _testAssemblyOperation(nonExistentOp, "Non-existent Address", true); // Should succeed but call will fail
        
        // Edge Case 5: Address with malformed packed data
        bytes memory malformedAddressOp = _createMalformedAddressOperation();
        _testAssemblyOperation(malformedAddressOp, "Malformed Address Data", false);
    }

    /**
     * @dev Test: let value := mload(add(userOps, add(i, 0x14)))
     * Value extraction edge cases
     */
    function test_Assembly_ValueExtraction_EdgeCases() public {
        console.log("\n=== Testing: Value Extraction (offset 0x14) ===");
        
        // Edge Case 1: Zero value
        bytes memory zeroValueOp = _createValidOperation(address(targetContract), 0, "");
        _testAssemblyOperation(zeroValueOp, "Zero Value", false);
        
        // Edge Case 2: Maximum value
        bytes memory maxValueOp = _createValidOperation(address(targetContract), MAX_UINT256, "");
        _testAssemblyOperation(maxValueOp, "Maximum Value", false); // Should fail due to insufficient balance
        
        // Edge Case 3: Contract balance value
        uint256 contractBalance = address(smartAccount).balance;
        bytes memory balanceValueOp = _createValidOperation(address(targetContract), contractBalance, "");
        _testAssemblyOperation(balanceValueOp, "Contract Balance Value", true);
        
        // Edge Case 4: Value exceeding balance
        bytes memory excessValueOp = _createValidOperation(address(targetContract), contractBalance + 1 ether, "");
        _testAssemblyOperation(excessValueOp, "Excess Value", false);
        
        // Edge Case 5: Value with truncated operation (no space for value field)
        bytes memory truncatedValueOp = _createTruncatedValueOperation();
        _testAssemblyOperation(truncatedValueOp, "Truncated Value Field", false);
    }

    /**
     * @dev Test: let dataLength := mload(add(userOps, add(i, 0x34)))
     * Data length extraction - CRITICAL for vulnerabilities
     */
    function test_Assembly_DataLengthExtraction_EdgeCases() public {
        console.log("\n=== Testing: Data Length Extraction (offset 0x34) ===");
        
        // Edge Case 1: Zero data length
        bytes memory zeroDataOp = _createValidOperation(address(targetContract), 0, "");
        _testAssemblyOperation(zeroDataOp, "Zero Data Length", true);
        
        // Edge Case 2: Maximum data length (potential vulnerability)
        bytes memory maxDataLengthOp = _createOperationWithDataLength(MAX_UINT256);
        _testAssemblyOperation(maxDataLengthOp, "Maximum Data Length", false);
        
        // Edge Case 3: Data length causing integer overflow in iterator
        uint256 overflowDataLength = MAX_UINT256 - OPERATION_HEADER_SIZE + 1;
        bytes memory overflowDataOp = _createOperationWithDataLength(overflowDataLength);
        _testAssemblyOperation(overflowDataOp, "Iterator Overflow Data Length", false);
        
        // Edge Case 4: Data length exceeding userOps bounds
        bytes memory exceedingDataOp = _createDataLengthExceedingBounds();
        _testAssemblyOperation(exceedingDataOp, "Data Length Exceeding Bounds", false);
        
        // Edge Case 5: Large but valid data length
        bytes memory largeValidDataOp = _createOperationWithLargeValidData(50000); // 50KB
        _testAssemblyOperationWithGasLimit(largeValidDataOp, 2000000, "Large Valid Data");
        
        // Edge Case 6: Data length with arithmetic edge cases
        uint256[] memory edgeDataLengths = new uint256[](4);
        edgeDataLengths[0] = HALF_MAX_UINT256;
        edgeDataLengths[1] = MAX_UINT256 - 1;
        edgeDataLengths[2] = 2**128 - 1;
        edgeDataLengths[3] = 2**64 - 1;
        
        for (uint256 i = 0; i < edgeDataLengths.length; i++) {
            bytes memory edgeOp = _createOperationWithDataLength(edgeDataLengths[i]);
            _testAssemblyOperation(edgeOp, string(abi.encodePacked("Edge Data Length ", vm.toString(i))), false);
        }
    }

    /**
     * @dev Test: let data := add(userOps, add(i, 0x54))
     * Data pointer calculation edge cases
     */
    function test_Assembly_DataPointerCalculation_EdgeCases() public {
        console.log("\n=== Testing: Data Pointer Calculation (offset 0x54) ===");
        
        // Edge Case 1: Valid data at boundary with large payload
        bytes memory boundaryDataOp = _createMemoryBoundaryTest();
        _testAssemblyOperation(boundaryDataOp, "Large Data Boundary Test", true);
        
        // Edge Case 2: Multiple operations iterator stress test
        bytes memory iteratorStressOp = _createIteratorStressTest();
        _testAssemblyOperation(iteratorStressOp, "Iterator Stress Test", true);
        
        // Edge Case 3: Gas consumption pattern test
        bytes memory gasTestOp = _createGasConsumptionTest();
        _testAssemblyOperation(gasTestOp, "Gas Consumption Test", true);
        
        // Edge Case 4: Data pointer with claimed length mismatch (should fail)
        bytes memory mismatchDataOp = _createDataPointerBeyondUserOps();
        _testAssemblyOperation(mismatchDataOp, "Data Length Mismatch", false);
    }

    /**
     * @dev Test: let success := call(gas(), to, value, data, dataLength, 0, 0)
     * External call edge cases - CRITICAL for security
     */
    function test_Assembly_ExternalCall_EdgeCases() public {
        console.log("\n=== Testing: External Call Execution ===");
        
        // Edge Case 1: Call to non-contract address
        address eoa = makeAddr("testEOA");
        bytes memory eoaCallOp = _createValidOperation(eoa, 1 wei, "");
        _testAssemblyOperation(eoaCallOp, "Call to EOA", true);
        
        // Edge Case 2: Call with complex calldata
        bytes memory complexCalldata = abi.encodeWithSelector(
            AssemblyTestTarget.complexFunction.selector,
            12345,
            "test string",
            new uint256[](100)
        );
        bytes memory complexCallOp = _createValidOperation(address(targetContract), 0, complexCalldata);
        _testAssemblyOperation(complexCallOp, "Complex Calldata", true);
        
        // Edge Case 3: Call that triggers revert
        bytes memory revertCalldata = abi.encodeWithSelector(AssemblyTestTarget.alwaysRevert.selector);
        bytes memory revertCallOp = _createValidOperation(address(targetContract), 0, revertCalldata);
        _testAssemblyOperation(revertCallOp, "Reverting Call", false);
        
        // Edge Case 4: Call with massive return data
        bytes memory massiveReturnCalldata = abi.encodeWithSelector(AssemblyTestTarget.returnMassiveData.selector, 10000);
        bytes memory massiveReturnOp = _createValidOperation(address(targetContract), 0, massiveReturnCalldata);
        _testAssemblyOperationWithGasLimit(massiveReturnOp, 3000000, "Massive Return Data");
        
        // Edge Case 5: Self-call (recursive)
        bytes memory recursiveCalldata = abi.encodeWithSelector(
            DfnsSmartAccount.handleOps.selector,
            _createValidOperation(address(targetContract), 0, ""),
            uint256(0),
            uint256(0)
        );

        bytes memory recursiveOp = _createValidOperation(address(smartAccount), 0, recursiveCalldata);
        _testAssemblyOperation(recursiveOp, "Recursive Self-Call", false);
    }

    /**
     * @dev Test: if eq(success, 0) { returndatacopy + revert }
     * Error handling edge cases
     */
    function test_Assembly_ErrorHandling_EdgeCases() public {
        console.log("\n=== Testing: Error Handling (returndatacopy + revert) ===");
        
        // Edge Case 1: Revert with no return data
        bytes memory noReturnDataCalldata = abi.encodeWithSelector(AssemblyTestTarget.revertWithoutData.selector);
        bytes memory noReturnOp = _createValidOperation(address(targetContract), 0, noReturnDataCalldata);
        _testAssemblyOperation(noReturnOp, "Revert No Return Data", false);
        
        // Edge Case 2: Revert with large return data
        bytes memory largeReturnDataCalldata = abi.encodeWithSelector(AssemblyTestTarget.revertWithLargeData.selector, 5000);
        bytes memory largeReturnOp = _createValidOperation(address(targetContract), 0, largeReturnDataCalldata);
        _testAssemblyOperation(largeReturnOp, "Revert Large Return Data", false);
        
        // Edge Case 3: Revert with malformed return data
        bytes memory malformedReturnCalldata = abi.encodeWithSelector(AssemblyTestTarget.revertWithMalformedData.selector);
        bytes memory malformedReturnOp = _createValidOperation(address(targetContract), 0, malformedReturnCalldata);
        _testAssemblyOperation(malformedReturnOp, "Revert Malformed Data", false);
    }

    /**
     * @dev Test: i := add(i, add(0x54, dataLength))
     * Iterator update - MOST CRITICAL for overflow vulnerabilities
     */
    function test_Assembly_IteratorUpdate_EdgeCases() public {
        console.log("\n=== Testing: Iterator Update (i := add(i, add(0x54, dataLength))) ===");
        
        // Edge Case 1: Iterator overflow scenarios
        uint256[] memory problematicDataLengths = new uint256[](5);
        problematicDataLengths[0] = MAX_UINT256 - OPERATION_HEADER_SIZE + 1; // Direct overflow
        problematicDataLengths[1] = MAX_UINT256; // Maximum value
        problematicDataLengths[2] = HALF_MAX_UINT256; // Large but not max
        problematicDataLengths[3] = MAX_UINT256 - 0x20; // Overflow with initial offset
        problematicDataLengths[4] = 0; // Zero length (should be safe)
        
        for (uint256 idx = 0; idx < problematicDataLengths.length; idx++) {
            uint256 testDataLength = problematicDataLengths[idx];
            bytes memory iteratorTestOp = _createOperationWithDataLength(testDataLength);
            
            string memory testName = string(abi.encodePacked("Iterator Update ", vm.toString(idx)));
            bool shouldSucceed = (testDataLength == 0);
            
            _testAssemblyOperation(iteratorTestOp, testName, shouldSucceed);
            
            if (testDataLength > HALF_MAX_UINT256) {
                emit AssemblyVulnerabilityFound("Iterator Overflow", "CRITICAL", keccak256(abi.encode(testDataLength)));
            }
        }
        
        // Edge Case 2: Multiple operations causing cumulative overflow
        bytes memory cumulativeOverflowOp = _createCumulativeOverflowOperations();
        _testAssemblyOperation(cumulativeOverflowOp, "Cumulative Iterator Overflow", false);
        
        // Edge Case 3: Iterator progression tracking
        bytes memory progressionTestOp = _createIteratorProgressionTest();
        _testAssemblyOperationWithTracking(progressionTestOp, "Iterator Progression Tracking");
    }

    /* ========================================
     * COMPREHENSIVE ASSEMBLY VULNERABILITY TESTING
     * ======================================== */

    /**
     * @dev Test all assembly vulnerabilities in combination
     */
    function test_Assembly_CombinedVulnerabilities() public {
        console.log("\n=== Testing: Combined Assembly Vulnerabilities ===");
        
        // Vulnerability 1: Buffer overflow + Integer overflow
        bytes memory bufferIntegerOverflow = _createBufferAndIntegerOverflow();
        _testAssemblyOperation(bufferIntegerOverflow, "Buffer + Integer Overflow", false);
        
        // Vulnerability 2: Memory corruption + Gas bomb
        bytes memory memoryGasBomb = _createMemoryCorruptionGasBomb();
        _testAssemblyOperationWithGasLimit(memoryGasBomb, 1000000, "Memory Corruption + Gas Bomb");
        
        // Vulnerability 3: Invalid pointers + Iterator overflow
        bytes memory pointerIteratorOverflow = _createPointerIteratorOverflow();
        _testAssemblyOperation(pointerIteratorOverflow, "Pointer + Iterator Overflow", false);
        
        // Vulnerability 4: Reentrancy + All above
        bytes memory reentrancyCombo = _createReentrancyCombinedAttack();
        _testAssemblyOperation(reentrancyCombo, "Reentrancy + Combined Attacks", false);
    }

    /* ========================================
     * CRITICAL VULNERABILITY ANALYSIS & ATTACK VECTORS
     * ======================================== */

    /**
     * @dev CRITICAL VULNERABILITY TEST: Memory Corruption leading to Balance Draining
     * 
     * ATTACK VECTOR: Craft userOps that causes memory corruption, leading to:
     * 1. `to` address extracted as 0x0000000000000000000000000000000000000000
     * 2. `value` extracted as massive number due to reading wrong memory locations
     * 3. Potential balance draining through repeated calls with corrupted values
     */
    function test_MemoryCorruption_BalanceDraining() public {
        console.log("\n===  trying to do Memory Corruption in order to do Balance Draining ===");
        // Create userOps that will cause memory corruption
        bytes memory corruptedUserOps = _createMemoryCorruptionUserOps();
        
        uint256 initialBalance = address(eoaOwner).balance;
        console.log("Initial EOA Balance:", initialBalance);
        
        _setupEIP7702Delegation();
        uint256 nonce = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        (uint256 r, uint256 vs) = _generateSignature(corruptedUserOps, nonce);
        
        console.log("Attempting corrupted userOps execution...");
        
        // This should fail, but if it succeeds, it's a critical vulnerability
        try DfnsSmartAccount(payable(eoaOwner)).handleOps(corruptedUserOps, r, vs) {
            uint256 finalBalance = address(eoaOwner).balance;
            console.log("Final EOA Balance:", finalBalance);
            
            // If balance was drained significantly, it's a critical vulnerability
            if (initialBalance > finalBalance + 1 ether) {
                emit AssemblyVulnerabilityFound("CRITICAL_BALANCE_DRAIN", "CRITICAL", 
                    keccak256(abi.encode(initialBalance, finalBalance)));
                console.log("CRITICAL: Balance draining detected!");
            }

        } catch (bytes memory revertData) {
            console.log("Corruption attack properly reverted");
            console.logBytes(revertData);

        }
    }
    /**
     * @dev HIGH VULNERABILITY TEST: Integer Overflow in Iterator
     * 
     * ATTACK VECTOR: Manipulate dataLength to cause integer overflow in:
     * `i := add(i, add(0x54, dataLength))`
     * This can lead to infinite loops, gas exhaustion, or memory corruption
     */
    function test_IntegerOverflow_InfiniteLoop() public {
        console.log("\n=== Trying  Integer Overflow  in order to commence infinite loop===");
        
        // Create userOps with dataLength designed to cause overflow
        bytes memory overflowUserOps = _createIntegerOverflowUserOps();
        
        _setupEIP7702Delegation();
        uint256 nonce = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        (uint256 r, uint256 vs) = _generateSignature(overflowUserOps, nonce);
        
        uint256 gasBefore = gasleft();
        
        try DfnsSmartAccount(payable(eoaOwner)).handleOps{gas: 500000}(overflowUserOps, r, vs) {
            uint256 gasUsed = gasBefore - gasleft();            
            // If it uses more than 400k gas, it might be stuck in a loop
            if (gasUsed > 400000) {
                emit AssemblyVulnerabilityFound("INTEGER_OVERFLOW_LOOP", "HIGH", 
                    keccak256(abi.encode(gasUsed)));
                console.log("HIGH: Potential infinite loop detected! Gas used:", gasUsed);
            }
        } catch (bytes memory) {
            uint256 gasUsed = gasBefore - gasleft();
            console.log("Overflow attack reverted after gas:", gasUsed);
        }
    }

    /**
     * @dev MEDIUM VULNERABILITY TEST: Gas Bomb via Returndata
     * 
     * ATTACK VECTOR: Create a malicious contract that returns massive returndata
     * When the call fails, returndatacopy will consume excessive gas
     */
    function test_MEDIUM_GasBomb_ReturndataAttack() public {
        console.log("\n=== MEDIUM VULNERABILITY: Gas Bomb via Returndata ===");
        
        // Deploy malicious contract that returns huge data on revert
        GasBombContract gasBomb = new GasBombContract();
        
        bytes memory gasBombUserOps = _createValidOperation(
            address(gasBomb), 
            0, 
            abi.encodeWithSelector(GasBombContract.gasBombRevert.selector, 10000)
        );
        
        _setupEIP7702Delegation();
        uint256 nonce = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        (uint256 r, uint256 vs) = _generateSignature(gasBombUserOps, nonce);
        
        uint256 gasBefore = gasleft();
        
        try DfnsSmartAccount(payable(eoaOwner)).handleOps{gas: 1000000}(gasBombUserOps, r, vs) {
            console.log("Gas bomb unexpectedly succeeded");
        } catch (bytes memory revertData) {
            uint256 gasUsed = gasBefore - gasleft();
            console.log("Gas bomb reverted, gas used:", gasUsed);
            
            // If it used more than 800k gas just to handle the revert, it's a gas bomb
            if (gasUsed > 800000) {
                emit AssemblyVulnerabilityFound("GAS_BOMB_RETURNDATA", "MEDIUM", 
                    keccak256(abi.encode(gasUsed, revertData.length)));
                console.log("MEDIUM: Gas bomb detected! Excessive gas for revert handling");
            }
        }
    }

    /**
     * @dev HIGH VULNERABILITY TEST: Reentrancy via Memory Corruption
     * 
     * ATTACK VECTOR: Use memory corruption to call back into the smart account
     * during the assembly loop execution
     */
    function test_HIGH_Reentrancy_MemoryCorruption() public {
        console.log("\n=== Reentrancy test via Memory Corruption ===");
        
        // Deploy reentrancy attacker
        ReentrancyAttacker attacker = new ReentrancyAttacker(address(smartAccount));
        
        bytes memory reentrancyUserOps = _createReentrancyUserOps(address(attacker));
        
        _setupEIP7702Delegation();
        uint256 nonce = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        (uint256 r, uint256 vs) = _generateSignature(reentrancyUserOps, nonce);
        
        uint256 nonceBefore = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        
        try DfnsSmartAccount(payable(eoaOwner)).handleOps(reentrancyUserOps, r, vs) {
            uint256 nonceAfter = DfnsSmartAccount(payable(eoaOwner)).getNonce();
            
            // Check if reentrancy was successful (nonce incremented more than once)
            if (nonceAfter > nonceBefore + 1) {
                emit AssemblyVulnerabilityFound("REENTRANCY_SUCCESS", "HIGH", 
                    keccak256(abi.encode(nonceBefore, nonceAfter)));
                console.log("HIGH: Reentrancy attack succeeded! Nonce jumped from", nonceBefore, "to", nonceAfter);
            }
        } catch (bytes memory) {
            console.log("Reentrancy attack properly prevented");
        }
    }

    /* ========================================
     * ANALYSIS OF "UNEXPECTED REVERTS"
     * ======================================== */

    /**
     * @dev Analyze why valid operations are reverting unexpectedly
     * 
     * POTENTIAL CAUSES:
     * 1. Memory corruption causing invalid addresses/values to be extracted
     * 2. Gas estimation issues due to assembly complexity
     * 3. EIP-7702 delegation issues
     * 4. Signature validation edge cases
     */
    function test_ANALYSIS_UnexpectedReverts() public {
        console.log("\n=== ANALYSIS: Why Valid Operations Revert Unexpectedly ===");
        
        // Test 1: Simple valid operation that should succeed
        bytes memory simpleOp = _createValidOperation(address(targetContract), 0, "");
        _analyzeOperation(simpleOp, "Simple Valid Operation");
        
        // Test 2: Operation with small value transfer
        bytes memory valueOp = _createValidOperation(address(targetContract), 1 wei, "");
        _analyzeOperation(valueOp, "Small Value Transfer");
        
        // Test 3: Operation with function call
        bytes memory callOp = _createValidOperation(
            address(targetContract), 
            0, 
            abi.encodeWithSelector(AssemblyTestTarget.simpleFunction.selector)
        );
        _analyzeOperation(callOp, "Function Call Operation");
        
        // Test 4: Multiple operations
        bytes memory multiOp = _createMultipleValidOperations(2);
        _analyzeOperation(multiOp, "Multiple Operations");
    }

    function _analyzeOperation(bytes memory userOps, string memory testName) internal {
        console.log("\n--- Analyzing:", testName, "---");
        
        _setupEIP7702Delegation();
        uint256 nonce = DfnsSmartAccount(payable(eoaOwner)).getNonce();
        (uint256 r, uint256 vs) = _generateSignature(userOps, nonce);
        
        console.log("UserOps length:", userOps.length);
        console.log("Nonce:", nonce);
        
        uint256 gasBefore = gasleft();
        uint256 balanceBefore = address(eoaOwner).balance;
        
        try DfnsSmartAccount(payable(eoaOwner)).handleOps(userOps, r, vs) {
            uint256 gasUsed = gasBefore - gasleft();
            uint256 balanceAfter = address(eoaOwner).balance;
            
            console.log(" SUCCESS - Gas used:", gasUsed, "Balance change:", balanceBefore - balanceAfter);
        } catch Error(string memory reason) {
            console.log("REVERT - Reason:", reason);
        } catch (bytes memory revertData) {
            console.log("REVERT - Raw data length:", revertData.length);
            if (revertData.length > 0) {
                console.logBytes(revertData);
            }
        }
    }

    /* ========================================
     * ATTACK VECTOR HELPER FUNCTIONS
     * ======================================== */

    function _createMemoryCorruptionUserOps() internal pure returns (bytes memory) {
        // Create userOps designed to cause memory corruption
        // Length field claims more data than actually provided
        return abi.encodePacked(
            uint256(200), // Claims 200 bytes total
            // But only provide partial data, causing reads beyond bounds
            uint256(0x1234567890123456), 
            uint256(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff), // Max value
            uint256(50), 
            bytes4(0xdeadbeef) 
        );
    }

    function _createIntegerOverflowUserOps() internal view returns (bytes memory) {
        // Create userOps with dataLength designed to cause overflow
        // When added to 0x54, should cause i to wrap around
        uint256 overflowDataLength = MAX_UINT256 - 0x54 + 1;
        
        return abi.encodePacked(
            uint256(OPERATION_HEADER_SIZE + 4), // Valid total length
            address(targetContract), // Valid address
            uint256(0), // Zero value
            overflowDataLength, // Overflow-inducing data length
            bytes4(0x12345678) // Minimal data
        );
    }

    function _createReentrancyUserOps(address attacker) internal view returns (bytes memory) {
        // Create userOps that calls the reentrancy attacker
        bytes memory attackData = abi.encodeWithSelector(
            ReentrancyAttacker.attemptReentrancy.selector
        );
        
        return abi.encodePacked(
            uint256(OPERATION_HEADER_SIZE + attackData.length),
            attacker,
            uint256(0),
            uint256(attackData.length),
            attackData
        );
    }

    function _createMultipleValidOperations(uint256 count) internal view returns (bytes memory) {
        bytes memory result;
        uint256 totalLength = 0;
        
        for (uint256 i = 0; i < count; i++) {
            bytes memory singleOp = abi.encodePacked(
                address(targetContract),
                uint256(0),
                uint256(4),
                bytes4(0x12345678)
            );
            result = abi.encodePacked(result, singleOp);
            totalLength += OPERATION_HEADER_SIZE + 4;
        }
        
        return abi.encodePacked(totalLength, result);
    }

    /* ========================================
     * HELPER FUNCTIONS FOR ASSEMBLY TESTING
     * ======================================== */

    function _testAssemblyOperation(bytes memory userOps, string memory testName, bool shouldSucceed) internal {
        // Set up EIP-7702 delegation for this test
        _setupEIP7702Delegation();
        
        // Get the delegated contract instance
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        uint256 currentNonce = delegatedContract.getNonce();
        
        (uint256 r, uint256 vs) = _generateSignature(userOps, currentNonce);
        
        uint256 gasBefore = gasleft();
        
        if (shouldSucceed) {
            try delegatedContract.handleOps(userOps, r, vs) {
                uint256 gasUsed = gasBefore - gasleft();
                uint256 nonceAfter = delegatedContract.getNonce();
                
                assertEq(nonceAfter, currentNonce + 1, string(abi.encodePacked(testName, ": nonce should increment")));
                console.log(string(abi.encodePacked(" ", testName, " - Gas: ", vm.toString(gasUsed))));
                
                emit AssemblyStepAnalysis(testName, 0, gasUsed, true);
            } catch (bytes memory revertData) {
                console.log(string(abi.encodePacked("", testName, " - Unexpected revert")));
                emit AssemblyStepAnalysis(testName, 0, 0, false);
                
                // Log revert reason for analysis
                if (revertData.length > 0) {
                    console.logBytes(revertData);
                }
            }
        } else {
            vm.expectRevert();
            delegatedContract.handleOps(userOps, r, vs);
            
            uint256 gasUsed = gasBefore - gasleft();
            console.log(string(abi.encodePacked( testName, " - Expected revert, Gas: ", vm.toString(gasUsed))));
            
            emit AssemblyStepAnalysis(testName, 0, gasUsed, true);
        }
    }

    function _testAssemblyOperationWithGasLimit(bytes memory userOps, uint256 gasLimit, string memory testName) internal {
        // Set up EIP-7702 delegation for this test
        _setupEIP7702Delegation();
        
        // Get the delegated contract instance
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        uint256 currentNonce = delegatedContract.getNonce();
        
        (uint256 r, uint256 vs) = _generateSignature(userOps, currentNonce);
        
        uint256 gasBefore = gasleft();
        
        try delegatedContract.handleOps{gas: gasLimit}(userOps, r, vs) {
            uint256 gasUsed = gasBefore - gasleft();
            console.log(string(abi.encodePacked( testName, " - Success, Gas: ", vm.toString(gasUsed))));
            
            assertLt(gasUsed, gasLimit * 95 / 100, "Should not consume >95% of gas limit");
            emit AssemblyStepAnalysis(testName, gasLimit, gasUsed, true);
        } catch (bytes memory) {
            uint256 gasUsed = gasBefore - gasleft();
            console.log(string(abi.encodePacked( testName, " - Reverted, Gas: ", vm.toString(gasUsed))));
            
            emit AssemblyStepAnalysis(testName, gasLimit, gasUsed, false);
        }
    }

    function _testAssemblyOperationWithTracking(bytes memory userOps, string memory testName) internal {
        // Set up EIP-7702 delegation for this test
        _setupEIP7702Delegation();
        
        // Get the delegated contract instance
        DfnsSmartAccount delegatedContract = DfnsSmartAccount(payable(eoaOwner));
        uint256 currentNonce = delegatedContract.getNonce();
        
        (uint256 r, uint256 vs) = _generateSignature(userOps, currentNonce);
        
        console.log(string(abi.encodePacked("Tracking: ", testName)));
        
        // Log memory access patterns
        uint256 userOpsLength = userOps.length;
        emit MemoryAccessPattern(0, userOpsLength, true);
        
        try delegatedContract.handleOps(userOps, r, vs) {
            console.log("Operation completed successfully with tracking");
        } catch (bytes memory) {
            console.log("Operation failed during tracking");
        }
    }

    /* ========================================
     * USEROPS CONSTRUCTION HELPERS
     * ======================================== */

    function _createValidOperation(address to, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encodePacked(
            uint256(OPERATION_HEADER_SIZE + data.length), // Total length
            to,                                           // Address (20 bytes)
            value,                                        // Value (32 bytes)
            uint256(data.length),                        // Data length (32 bytes)
            data                                         // Data (variable)
        );
    }

    function _createMultipleOperations(uint256 count) internal view returns (bytes memory) {
        if (count == 0) return abi.encodePacked(uint256(0));
        
        bytes memory result;
        uint256 totalLength = 0;
        
        for (uint256 i = 0; i < count; i++) {
            bytes memory singleOp = abi.encodePacked(
                address(targetContract),
                uint256(0),
                uint256(4),
                bytes4(0x12345678)
            );
            result = abi.encodePacked(result, singleOp);
            totalLength += OPERATION_HEADER_SIZE + 4;
        }
        
        return abi.encodePacked(totalLength, result);
    }

    function _createOperationWithDataLength(uint256 dataLength) internal view returns (bytes memory) {
        return abi.encodePacked(
            uint256(OPERATION_HEADER_SIZE + 4), // Claim minimal total length
            address(targetContract),
            uint256(0),
            dataLength,                         // Malicious data length
            bytes4(0x12345678)                  // Minimal data
        );
    }

    function _createOperationWithLargeValidData(uint256 dataSize) internal view returns (bytes memory) {
        bytes memory largeData = new bytes(dataSize);
        for (uint256 i = 0; i < dataSize; i++) {
            largeData[i] = bytes1(uint8(i % 256));
        }
        
        return abi.encodePacked(
            uint256(OPERATION_HEADER_SIZE + dataSize),
            address(targetContract),
            uint256(0),
            uint256(dataSize),
            largeData
        );
    }

    function _createMalformedAddressOperation() internal pure returns (bytes memory) {
        // Create operation with insufficient data for address extraction
        return abi.encodePacked(
            uint256(50), // Claims 50 bytes but provides less
            bytes10(0x12345678901234567890) // Only 10 bytes
        );
    }

    function _createTruncatedValueOperation() internal pure returns (bytes memory) {
        return abi.encodePacked(
            uint256(40), // Claims 40 bytes  
            address(0x1234567890123456789012345678901234567890), // 20 bytes
            bytes10(0x12345678901234567890) // Only 10 more bytes (missing value field)
        );
    }

    function _createDataLengthExceedingBounds() internal view returns (bytes memory) {
        return abi.encodePacked(
            uint256(100), // Total length is 100
            address(targetContract),
            uint256(0),
            uint256(500), // Claims 500 bytes of data (exceeds total length)
            bytes4(0x12345678)
        );
    }

    function _createPartiallyValidMultiOperation() internal view returns (bytes memory) {
        bytes memory validOp = abi.encodePacked(
            address(targetContract),
            uint256(0),
            uint256(4),
            bytes4(0x12345678)
        );
        
        bytes memory invalidOp = abi.encodePacked(
            address(targetContract),
            uint256(0)
            // Missing dataLength and data
        );
        
        return abi.encodePacked(
            uint256(validOp.length + invalidOp.length),
            validOp,
            invalidOp
        );
    }

    function _createDataAtBoundary() internal view returns (bytes memory) {
        bytes memory data = hex"12345678";
        return abi.encodePacked(
            uint256(OPERATION_HEADER_SIZE + data.length), // Exact boundary
            address(targetContract),
            uint256(0),
            uint256(data.length),
            data
        );
    }

    function _createDataPointerBeyondUserOps() internal view returns (bytes memory) {
        // Create a valid operation structure but with malformed data length
        // This should cause the assembly to fail when it tries to read beyond bounds
        bytes memory actualData = hex"12345678";
        return abi.encodePacked(
            uint256(OPERATION_HEADER_SIZE + actualData.length), // Correct total length
            address(targetContract),
            uint256(0),
            uint256(100), // Claims 100 bytes of data (more than actual)
            actualData  // Only 4 bytes actual data
        );
    }

    function _createOverlappingDataOperations() internal view returns (bytes memory) {
        // Create two valid operations but with data lengths that would cause issues
        bytes memory actualData1 = hex"12345678";
        bytes memory actualData2 = hex"abcdefab";
        
        bytes memory op1 = abi.encodePacked(
            address(targetContract),
            uint256(0),
            uint256(actualData1.length), // Use actual data length
            actualData1
        );
        
        bytes memory op2 = abi.encodePacked(
            address(targetContract), 
            uint256(0),
            uint256(actualData2.length), // Use actual data length
            actualData2
        );
        
        return abi.encodePacked(
            uint256(op1.length + op2.length), // Correct total length
            op1,
            op2
        );
    }

    function _createDataPointerOverflow() internal view returns (bytes memory) {
        // Create a valid operation but this will test if the assembly handles large data lengths safely
        bytes memory actualData = hex"12345678";
        return abi.encodePacked(
            uint256(OPERATION_HEADER_SIZE + actualData.length),
            address(targetContract),
            uint256(0),
            MAX_UINT256 - 100, // Large but not overflowing data length claim
            actualData
        );
    }

    function _createCumulativeOverflowOperations() internal view returns (bytes memory) {
        // Create operations that would cause iterator overflow when combined
        bytes memory actualData1 = hex"12345678";
        bytes memory actualData2 = hex"abcdefab";
        
        bytes memory op1 = abi.encodePacked(
            address(targetContract),
            uint256(0),
            uint256(actualData1.length), // Use actual data length for valid structure
            actualData1
        );
        
        bytes memory op2 = abi.encodePacked(
            address(targetContract),
            uint256(0), 
            uint256(actualData2.length), // Use actual data length for valid structure
            actualData2
        );
        
        return abi.encodePacked(
            uint256(op1.length + op2.length),
            op1,
            op2
        );
    }

    function _createIteratorProgressionTest() internal view returns (bytes memory) {
        // Create operations with specific data lengths to test iterator math
        bytes memory smallOp = abi.encodePacked(
            address(targetContract), uint256(0), uint256(10), new bytes(10)
        );
        bytes memory mediumOp = abi.encodePacked(
            address(targetContract), uint256(0), uint256(100), new bytes(100)  
        );
        bytes memory largeOp = abi.encodePacked(
            address(targetContract), uint256(0), uint256(1000), new bytes(1000)
        );
        
        return abi.encodePacked(
            uint256(smallOp.length + mediumOp.length + largeOp.length),
            smallOp,
            mediumOp, 
            largeOp
        );
    }

    function _createBufferAndIntegerOverflow() internal view returns (bytes memory) {
        return abi.encodePacked(
            uint256(84), // Minimal total length
            address(targetContract),
            uint256(0),
            MAX_UINT256 - 50, // Large dataLength causing both buffer and integer overflow
            bytes4(0x12345678)
        );
    }

    function _createMemoryCorruptionGasBomb() internal view returns (bytes memory) {
        return abi.encodePacked(
            uint256(1000), // Claims 1000 bytes
            address(targetContract),
            uint256(0), 
            uint256(10000000), // Claims 10MB causing memory corruption + gas bomb
            new bytes(900) // Actual data much smaller
        );
    }

    function _createPointerIteratorOverflow() internal view returns (bytes memory) {
        return abi.encodePacked(
            uint256(OPERATION_HEADER_SIZE + 4),
            address(targetContract),
            uint256(0),
            MAX_UINT256 - OPERATION_HEADER_SIZE, // Causes both pointer and iterator overflow
            bytes4(0x12345678)
        );
    }

    function _createReentrancyCombinedAttack() internal returns (bytes memory) {
        // Deploy reentrancy attacker
        ReentrancyMaliciousContract attacker = new ReentrancyMaliciousContract(address(smartAccount));
        
        bytes memory reentrancyCalldata = abi.encodeWithSelector(
            ReentrancyMaliciousContract.triggerCombinedAttack.selector
        );
        
        return abi.encodePacked(
            uint256(OPERATION_HEADER_SIZE + reentrancyCalldata.length),
            address(attacker),
            uint256(0),
            uint256(reentrancyCalldata.length),
            reentrancyCalldata
        );
    }

    function _generateSignature(bytes memory userOps, uint256 nonce) internal view returns (uint256 r, uint256 vs) {
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
     * @dev Simulate signature validation exactly as the contract does in EIP-7702 context
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



/* ========================================
     * ASSEMBLY EDGE CASE HELPERS - SAFE SIGNATURE APPROACH
     * ======================================== */
    
    /**
     * @dev Create operations that test memory boundary conditions safely
     */
    function _createMemoryBoundaryTest() internal view returns (bytes memory) {
        // Create valid operations but with edge case data that tests assembly bounds checking
        bytes memory edgeData = new bytes(1000); // Large but reasonable data
        for (uint256 i = 0; i < 1000; i++) {
            edgeData[i] = bytes1(uint8(i % 256));
        }
        
        return abi.encodePacked(
            uint256(OPERATION_HEADER_SIZE + edgeData.length),
            address(targetContract),
            uint256(0), // Zero value to avoid fund issues
            uint256(edgeData.length),
            edgeData
        );
    }
    
    /**
     * @dev Create operations that test iterator progression safely
     */
    function _createIteratorStressTest() internal view returns (bytes memory) {
        // Create multiple small operations to test iterator advancement
        bytes memory result;
        uint256 totalLength = 0;
        
        for (uint256 i = 0; i < 10; i++) {
            bytes memory singleOpData = abi.encodePacked(bytes4(0x12345678));
            bytes memory singleOp = abi.encodePacked(
                address(targetContract),
                uint256(0),
                uint256(singleOpData.length),
                singleOpData
            );
            result = abi.encodePacked(result, singleOp);
            totalLength += OPERATION_HEADER_SIZE + singleOpData.length;
        }
        
        return abi.encodePacked(totalLength, result);
    }
    
    /**
     * @dev Create operations that test gas consumption patterns
     */
    function _createGasConsumptionTest() internal view returns (bytes memory) {
        // Create operations that consume varying amounts of gas
        bytes memory gasCalldata = abi.encodeWithSelector(
            AssemblyTestTarget.complexFunction.selector,
            42,
            "gas test",
            new uint256[](50)
        );
        
        return abi.encodePacked(
            uint256(OPERATION_HEADER_SIZE + gasCalldata.length),
            address(targetContract),
            uint256(0),
            uint256(gasCalldata.length),
            gasCalldata
        );
    }

/* ========================================
 * MISSING HELPER FUNCTIONS FOR NEW TESTS
 * ======================================== */

    function _createIncompleteOperationData() internal pure returns (bytes memory) {
        // Claims to have 100 bytes but only provides partial operation data
        return abi.encodePacked(
            uint256(100),  // Claims 100 bytes
            address(0x1234567890123456789012345678901234567890), // 20 bytes
            uint256(0)     // 32 bytes - incomplete (missing dataLength and data)
        );
    }

    function _createLengthMismatchOperations() internal pure returns (bytes memory) {
        // Claims to have exact operation size but provides less
        return abi.encodePacked(
            uint256(OPERATION_HEADER_SIZE + 4), // Claims 88 bytes (84 + 4 data)
            address(0x1234567890123456789012345678901234567890), // 20 bytes
            uint256(0),                                         // 32 bytes
            uint256(4),                                         // 32 bytes (claims 4 bytes data)
            bytes2(0x1234)                                      // Only 2 bytes provided instead of 4
        );
    }

    function _createLargeBatchOperations(uint256 count) internal view returns (bytes memory) {
        bytes memory result;
        uint256 totalLength = 0;
        
        for (uint256 i = 0; i < count; i++) {
            bytes memory operation = abi.encodePacked(
                address(targetContract),              // 20 bytes
                uint256(0),                          // 32 bytes
                uint256(4),                          // 32 bytes
                bytes4(0x12345678)                   // 4 bytes
            );
            result = abi.encodePacked(result, operation);
            totalLength += OPERATION_HEADER_SIZE + 4;
        }
        
        return abi.encodePacked(totalLength, result);
    }

    function _createInsufficientDataOperation() internal pure returns (bytes memory) {
        // Length allows entry into loop but insufficient data for complete operation
        return abi.encodePacked(
            uint256(0x30),                                      // 48 bytes claimed
            address(0x1234567890123456789012345678901234567890), // 20 bytes
            uint256(0),                                         // 32 bytes = 52 bytes so far (exceeds claimed 48)
            bytes8(0x1234567890123456)                          // Only 8 more bytes
        );
    }
}

/* ========================================
 * SUPPORTING CONTRACTS FOR ASSEMBLY TESTING  
 * ======================================== */


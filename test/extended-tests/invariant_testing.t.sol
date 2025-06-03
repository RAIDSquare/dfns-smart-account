// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.29;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
import "../../src/DfnsSmartAccount.sol";
import "../utils/mockContracts.sol";
import "../utils/DfnsTestUtils.sol";
/**
 * @title DfnsSmartAccountInvariantTest
 * @dev Comprehensive invariant testing using forge-std for DfnsSmartAccount
 * This test suite uses DfnsTestUtils library for actual validation logic instead of flag tracking
 */
contract DfnsSmartAccountInvariantTest is StdInvariant, Test {
    DfnsSmartAccount public smartAccount;
    MockTarget public mockTarget;
    MockERC20 public mockToken;
    MockERC721 public mockNFT;
    
    // Handler contract for stateful fuzzing
    InvariantTestHandler public handler;
    
    // Test context for library functions
    TestContext public testCtx;
    
    // Valid test private key and derived address
    uint256 private constant TEST_PRIVATE_KEY = 0x1234567890123456789012345678901234567890123456789012345678901234;
    address private testSigner;
    
    // Initial state tracking for invariants
    uint256 public initialNonce;
    uint256 public initialEthBalance;
    uint256 public initialTokenBalance;
    
    function setUp() public {
        // Deploy contracts
        smartAccount = new DfnsSmartAccount();
        mockTarget = new MockTarget();
        mockToken = new MockERC20("TestToken", "TEST", 18);
        mockNFT = new MockERC721("TestNFT", "TNFT");
        
        // Derive test signer address
        testSigner = vm.addr(TEST_PRIVATE_KEY);
        
        // Deploy handler for stateful fuzzing  
        handler = new InvariantTestHandler(smartAccount, mockTarget, mockToken, mockNFT, testSigner, TEST_PRIVATE_KEY);
        
        // Set up test context for library functions
        testCtx = TestContext({
            dfnsSmartAccount: address(smartAccount),
            eoaOwner: testSigner,
            eoaOwnerPrivateKey: TEST_PRIVATE_KEY,
            vm: vm
        });
        
        // Set up initial state
        initialNonce = smartAccount.getNonce();
        initialEthBalance = testSigner.balance;
        
        // Configure forge-std invariant testing to use handler
        targetContract(address(handler));
        
        // Fund contracts for testing
        vm.deal(address(smartAccount), 100 ether);
        vm.deal(address(handler), 100 ether);
        vm.deal(address(mockTarget), 10 ether);
        vm.deal(testSigner, 50 ether);
        
        // Update initial balance after funding
        initialEthBalance = testSigner.balance;
        
        // Mint tokens for testing
        mockToken.mint(address(smartAccount), 1000000 * 10**18);
        mockToken.mint(address(handler), 1000000 * 10**18);
        mockToken.mint(testSigner, 500000 * 10**18);
        
        initialTokenBalance = mockToken.balanceOf(testSigner);
        
        // Set up EIP-7702 delegation simulation
        DfnsTestUtils.setupEIP7702Delegation(testCtx);
    }
     /**
     * @dev Invariant 1: Nonce monotonicity and signature validation security
     * Ensures nonces always increase and malformed signatures are rejected
     */
    function invariant_NonceMonotonicityAndSignatureValidation() public view {
        // Validate nonce has not decreased from initial value
        assertTrue(
            DfnsTestUtils.validateNonceInvariant(testCtx, initialNonce),
            "Nonce invariant violated: nonce decreased or remained unchanged"
        );
    }

    /**
     * @dev Invariant 2: Signature malleability protection
     * Ensures that malleable signatures and invalid signature parameters are rejected
     */
    function invariant_SignatureMalleabilityProtection() public {
        // Test with valid userOps for signature validation
        bytes memory validUserOps = DfnsTestUtils.createValidTestUserOps();
        
        // This should not revert - all invalid signatures should be properly rejected
        assertTrue(
            DfnsTestUtils.testInvalidSignatureRejection(testCtx, validUserOps),
            "Signature malleability protection failed: invalid signatures were accepted"
        );
    }

    /**
     * @dev Invariant 3: Assembly parsing security and memory safety
     * Validates memory-safe assembly operations and proper userOps decoding
     */
    function invariant_AssemblyParsingSecurity() public {
        // Test assembly parsing with various edge cases
        assertTrue(
            DfnsTestUtils.testAssemblyParsingSecurity(testCtx),
            "Assembly parsing security violated: malformed userOps were processed"
        );
    }

    /**
     * @dev Invariant 4: Batch operation atomicity
     * Ensures that failed operations in a batch don't partially execute
     */
    function invariant_BatchAtomicity() public {
        // Test batch atomicity with mock target
        assertTrue(
            DfnsTestUtils.testBatchAtomicity(testCtx, address(mockTarget)),
            "Batch atomicity violated: partial execution occurred on batch failure"
        );
    }

    /**
     * @dev Invariant 5: Cross-chain replay protection  
     * Verifies that signatures are bound to the current chain ID
     */
    function invariant_CrossChainReplayProtection() public {
        // Test with valid userOps
        bytes memory validUserOps = DfnsTestUtils.createValidTestUserOps();
        
        assertTrue(
            DfnsTestUtils.testCrossChainReplayProtection(testCtx, validUserOps),
            "Cross-chain replay protection failed: signature replay succeeded on different chain"
        );
    }

    /**
     * @dev Invariant 6: ERC20 operation consistency
     * Validates that token operations maintain balance integrity
     */
    function invariant_ERC20OperationConsistency() public {
        // Only test if we have sufficient token balance
        uint256 testAmount = 1000 * 10**18;
        if (mockToken.balanceOf(testSigner) >= testAmount) {
            assertTrue(
                DfnsTestUtils.testERC20OperationConsistency(
                    testCtx,
                    address(mockToken),
                    address(mockTarget),
                    testAmount
                ),
                "ERC20 operation consistency violated: token balances don't match expected changes"
            );
        }
    }

    /**
     * @dev Invariant 7: Gas limit enforcement
     * Ensures that operations don't exceed reasonable gas limits
     */
    function invariant_GasLimitEnforcement() public {
        // Test gas limit enforcement with reasonable upper bound
        uint256 maxGasPerOperation = 500000; // 500K gas limit
        
        assertTrue(
            DfnsTestUtils.testGasLimitEnforcement(testCtx, maxGasPerOperation),
            "Gas limit enforcement failed: operation exceeded maximum allowed gas"
        );
    }
    
    /**
     * @dev Invariant 8: Reentrancy protection
     * Ensures that reentrancy attacks are properly prevented
     */
    function invariant_ReentrancyProtection() public {
        assertTrue(
            DfnsTestUtils.testReentrancyProtection(testCtx, address(mockTarget)),
            "Reentrancy protection failed: reentrancy attack succeeded"
        );
    }

    /**
     * @dev Invariant 9: Nonce replay protection
     * Ensures that signatures cannot be replayed with the same nonce
     */
    function invariant_NonceReplayProtection() public {
        bytes memory validUserOps = DfnsTestUtils.createValidTestUserOps();
        
        assertTrue(
            DfnsTestUtils.testNonceReplayProtection(testCtx, validUserOps),
            "Nonce replay protection failed: signature replay succeeded"
        );
    }

    /**
     * @dev Invariant 10: Operation ordering enforcement
     * Ensures that operations must be executed in correct nonce order
     */
    function invariant_OperationOrdering() public {
        assertTrue(
            DfnsTestUtils.testOperationOrdering(testCtx),
            "Operation ordering failed: out-of-order operations were accepted"
        );
    }

    /**
     * @dev Invariant 11: Memory corruption resistance
     * Ensures that malformed assembly data cannot corrupt memory
     */
    function invariant_MemoryCorruptionResistance() public {
        assertTrue(
            DfnsTestUtils.testMemoryCorruptionResistance(testCtx),
            "Memory corruption resistance failed: malformed data was processed"
        );
    }

    /**
     * @dev Invariant 12: Gas exhaustion attack resistance
     * Ensures that operations cannot consume excessive gas
     */
    function invariant_GasExhaustionResistance() public {
        uint256 maxGasPerOperation = 1000000; // 1M gas limit
        
        assertTrue(
            DfnsTestUtils.testGasExhaustionResistance(testCtx, maxGasPerOperation),
            "Gas exhaustion resistance failed: operation consumed excessive gas"
        );
    }

    /**
     * @dev Invariant 13: State consistency on failure
     * Ensures that state remains consistent even when operations fail
     */
    function invariant_StateConsistencyOnFailure() public {
        assertTrue(
            DfnsTestUtils.testStateConsistencyOnFailure(testCtx),
            "State consistency failed: state was modified during failed operation"
        );
    }
}

/**
 * @title InvariantTestHandler
 * @dev Handler contract for stateful invariant fuzzing of DfnsSmartAccount
 * This handler generates realistic operation sequences to stress test the invariants
 */
contract InvariantTestHandler is Test {
    DfnsSmartAccount public smartAccount;
    MockTarget public mockTarget;
    MockERC20 public mockToken;
    MockERC721 public mockNFT;
    
    // Test context for library functions
    TestContext public testCtx;
    
    // State tracking for meaningful operations
    uint256 public operationCount;
    uint256 public successfulOperations;
    uint256 public failedOperations;
    uint256 public maxGasUsedInOperation;
    
    // Valid test credentials
    address private testSigner;
    uint256 private testPrivateKey;
    
    constructor(
        DfnsSmartAccount _smartAccount,
        MockTarget _mockTarget,
        MockERC20 _mockToken,
        MockERC721 _mockNFT,
        address _testSigner,
        uint256 _testPrivateKey
    ) {
        smartAccount = _smartAccount;
        mockTarget = _mockTarget;
        mockToken = _mockToken;
        mockNFT = _mockNFT;
        testSigner = _testSigner;
        testPrivateKey = _testPrivateKey;
        
        // Set up test context for library functions
        testCtx = TestContext({
            dfnsSmartAccount: address(smartAccount),
            eoaOwner: testSigner,
            eoaOwnerPrivateKey: testPrivateKey,
            vm: vm
        });
        
        // Set up EIP-7702 delegation
        DfnsTestUtils.setupEIP7702Delegation(testCtx);
    }
     /**
     * @dev Handler function for testing realistic ETH transfer operations
     * Generates various ETH transfer scenarios to test the system
     */
    function testETHTransfer(
        address recipient,
        uint256 amount
    ) external {
        // Bound inputs to realistic ranges
        recipient = address(uint160(bound(uint160(recipient), 1, type(uint160).max)));
        amount = bound(amount, 0.001 ether, 5 ether);
        
        // Skip if insufficient balance
        if (testSigner.balance < amount) return;
        
        // Create ETH transfer operation
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: recipient,
            value: amount,
            data: ""
        });
        
        bytes memory userOps = DfnsTestUtils.encodeOperations(operations);
        uint256 currentNonce = smartAccount.getNonce();
        
        // Generate signature and execute
        (uint256 r, uint256 vs) = DfnsTestUtils.generateSignature(testCtx, userOps, currentNonce);
        
        uint256 gasBefore = gasleft();
        bool success = DfnsTestUtils.callHandleOps(testCtx, userOps, r, vs);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Track operation metrics
        operationCount++;
        if (success) {
            successfulOperations++;
        } else {
            failedOperations++;
        }
        
        if (gasUsed > maxGasUsedInOperation) {
            maxGasUsedInOperation = gasUsed;
        }
    }

    /**
     * @dev Handler function for testing ERC20 token operations
     * Generates various token transfer scenarios
     */
    function testERC20Operations(
        address recipient,
        uint256 amount,
        uint8 operationType
    ) external {
        // Bound inputs
        recipient = address(uint160(bound(uint160(recipient), 1, type(uint160).max)));
        amount = bound(amount, 1, 10000 * 10**18);
        operationType = uint8(bound(operationType, 0, 2)); // 0: transfer, 1: approve, 2: transferFrom
        
        bytes memory operationData;
        
        if (operationType == 0) {
            // Transfer operation
            operationData = abi.encodeWithSignature("transfer(address,uint256)", recipient, amount);
        } else if (operationType == 1) {
            // Approve operation
            operationData = abi.encodeWithSignature("approve(address,uint256)", recipient, amount);
        } else {
            // TransferFrom operation (requires prior approval)
            operationData = abi.encodeWithSignature("transferFrom(address,address,uint256)", testSigner, recipient, amount);
        }
        
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: address(mockToken),
            value: 0,
            data: operationData
        });
        
        bytes memory userOps = DfnsTestUtils.encodeOperations(operations);
        uint256 currentNonce = smartAccount.getNonce();
        
        (uint256 r, uint256 vs) = DfnsTestUtils.generateSignature(testCtx, userOps, currentNonce);
        
        uint256 gasBefore = gasleft();
        bool success = DfnsTestUtils.callHandleOps(testCtx, userOps, r, vs);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Track metrics
        operationCount++;
        if (success) {
            successfulOperations++;
        } else {
            failedOperations++;
        }
        
        if (gasUsed > maxGasUsedInOperation) {
            maxGasUsedInOperation = gasUsed;
        }
    }

    /**
     * @dev Handler function for testing batch operations
     * Creates multiple operations in a single batch to test atomicity
     */
    function testBatchOperations(
        uint8 batchSize,
        bool includeFailing,
        uint256 ethAmount
    ) external {
        // Bound inputs
        batchSize = uint8(bound(batchSize, 1, 5));
        ethAmount = bound(ethAmount, 0.01 ether, 1 ether);
        
        Operation[] memory operations = new Operation[](batchSize);
        
        for (uint8 i = 0; i < batchSize; i++) {
            if (i == batchSize - 1 && includeFailing) {
                // Last operation intentionally fails for atomicity testing
                operations[i] = Operation({
                    to: address(0), // Invalid address
                    value: ethAmount,
                    data: ""
                });
            } else {
                // Valid operations
                operations[i] = Operation({
                    to: address(mockTarget),
                    value: ethAmount / batchSize,
                    data: abi.encodeWithSignature("setValue(uint256)", i)
                });
            }
        }
        
        bytes memory userOps = DfnsTestUtils.encodeOperations(operations);
        uint256 currentNonce = smartAccount.getNonce();
        
        (uint256 r, uint256 vs) = DfnsTestUtils.generateSignature(testCtx, userOps, currentNonce);
        
        uint256 gasBefore = gasleft();
        bool success = DfnsTestUtils.callHandleOps(testCtx, userOps, r, vs);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Track metrics
        operationCount++;
        if (success) {
            successfulOperations++;
        } else {
            failedOperations++;
        }
        
        if (gasUsed > maxGasUsedInOperation) {
            maxGasUsedInOperation = gasUsed;
        }
    }

    /**
     * @dev Handler function for testing contract interactions
     * Tests various contract call scenarios
     */
    function testContractInteractions(
        uint256 functionSelector,
        uint256 dataSize,
        uint256 value
    ) external {
        // Bound inputs
        functionSelector = bound(functionSelector, 0, 5);
        dataSize = bound(dataSize, 0, 1000);
        value = bound(value, 0, 1 ether);
        
        bytes memory callData;
        address target = address(mockTarget);
        
        // Generate different types of contract calls
        if (functionSelector == 0) {
            callData = abi.encodeWithSignature("setValue(uint256)", block.timestamp);
        } else if (functionSelector == 1) {
            callData = abi.encodeWithSignature("getValue()");
        } else if (functionSelector == 2) {
            callData = abi.encodeWithSignature("processLargeData(bytes)", new bytes(dataSize));
        } else if (functionSelector == 3) {
            // NFT operations
            target = address(mockNFT);
            callData = abi.encodeWithSignature("mint(address)", testSigner);
        } else if (functionSelector == 4) {
            // Potential failing function
            callData = abi.encodeWithSignature("failingFunction()");
        } else {
            // Empty call
            callData = "";
        }
        
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: target,
            value: value,
            data: callData
        });
        
        bytes memory userOps = DfnsTestUtils.encodeOperations(operations);
        uint256 currentNonce = smartAccount.getNonce();
        
        (uint256 r, uint256 vs) = DfnsTestUtils.generateSignature(testCtx, userOps, currentNonce);
        
        uint256 gasBefore = gasleft();
        bool success = DfnsTestUtils.callHandleOps(testCtx, userOps, r, vs);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Track metrics
        operationCount++;
        if (success) {
            successfulOperations++;
        } else {
            failedOperations++;
        }
        
        if (gasUsed > maxGasUsedInOperation) {
            maxGasUsedInOperation = gasUsed;
        }
    }

    /**
     * @dev Handler function for testing edge case operations
     * Tests various edge cases and malformed operations
     */
function testEdgeCaseOperations(
    uint8 edgeCaseType,
    uint256 randomValue
) external {
    // Bound inputs
    edgeCaseType = uint8(bound(edgeCaseType, 0, 4));
    randomValue = bound(randomValue, 0, type(uint256).max);
    
    bytes memory userOps;
    bool shouldGenerateSignature = true;
    
    if (edgeCaseType == 0) {
        // Empty operations - don't try to sign
        userOps = "";
        shouldGenerateSignature = false;
    } else if (edgeCaseType == 1) {
        // Minimal valid operation
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: address(mockTarget),
            value: 0,
            data: ""
        });
        userOps = DfnsTestUtils.encodeOperations(operations);
    } else if (edgeCaseType == 2) {
        // Large data operation
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: address(mockTarget),
            value: 0,
            data: new bytes(bound(randomValue, 0, 1000))
        });
        userOps = DfnsTestUtils.encodeOperations(operations);
    } else if (edgeCaseType == 3) {
        // High value operation (will likely fail due to insufficient balance)
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: address(mockTarget),
            value: bound(randomValue, 1 ether, 10 ether),
            data: ""
        });
        userOps = DfnsTestUtils.encodeOperations(operations);
    } else {
        // Random valid operation
        Operation[] memory operations = new Operation[](1);
        operations[0] = Operation({
            to: address(mockTarget),
            value: randomValue % 1 ether,
            data: abi.encodeWithSignature("setValue(uint256)", randomValue)
        });
        userOps = DfnsTestUtils.encodeOperations(operations);
    }
    
    if (shouldGenerateSignature && DfnsTestUtils.validateOperationFormat(userOps)) {
        uint256 currentNonce = smartAccount.getNonce();
        (uint256 r, uint256 vs) = DfnsTestUtils.generateSignature(testCtx, userOps, currentNonce);
        
        uint256 gasBefore = gasleft();
        // Remove vm.expectRevert() and just call directly
        bool success = DfnsTestUtils.callHandleOps(testCtx, userOps, r, vs);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Track metrics
        operationCount++;
        if (success) {
            successfulOperations++;
        } else {
            failedOperations++;
        }
        
        if (gasUsed > maxGasUsedInOperation) {
            maxGasUsedInOperation = gasUsed;
        }
    }
}}


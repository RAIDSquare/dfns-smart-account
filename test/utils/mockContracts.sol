// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.29;

import {DfnsSmartAccount} from "../../src/DfnsSmartAccount.sol";
import {console} from "forge-std/console.sol";
// Mock contracts for testing
contract MockTarget {
    uint256 private value;
    bool private shouldFail;
    
    function setValue(uint256 _value) external {
        value = _value;
    }
    
    function getValue() external view returns (uint256) {
        return value;
    }
    
    function failingFunction() external pure {
        revert("Intentional failure");
    }
    
    function gasConsumingFunction() external pure {
        // Consume gas in a loop
        uint256 sum = 0;
        for (uint256 i = 0; i < 1000; i++) {
            sum += i;
        }
    }
    
    function processLargeData(bytes memory data) external pure returns (uint256) {
        return data.length;
    }
}

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

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Allowance exceeded");
        
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;
        
        emit Transfer(from, to, amount);
        return true;
    }
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool) {
        allowance[msg.sender][spender] += addedValue;
        emit Approval(msg.sender, spender, allowance[msg.sender][spender]);
        return true;
    }
}

contract MockERC721 {
    string public name;
    string public symbol;
    uint256 private _tokenIdCounter;
    
    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;
    mapping(uint256 => address) private _tokenApprovals;
    mapping(address => mapping(address => bool)) private _operatorApprovals;
    
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    
    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
    }
    
    function mint(address to) external returns (uint256) {
        uint256 tokenId = _tokenIdCounter;
        _tokenIdCounter++;
        
        _owners[tokenId] = to;
        _balances[to]++;
        
        emit Transfer(address(0), to, tokenId);
        return tokenId;
    }
    
    function ownerOf(uint256 tokenId) external view returns (address) {
        return _owners[tokenId];
    }
    
    function balanceOf(address owner) external view returns (uint256) {
        return _balances[owner];
    }
    
    function transferFrom(address from, address to, uint256 tokenId) external {
        require(_owners[tokenId] == from, "Not owner");
        require(msg.sender == from || msg.sender == _tokenApprovals[tokenId] || _operatorApprovals[from][msg.sender], "Not approved");
        
        _owners[tokenId] = to;
        _balances[from]--;
        _balances[to]++;
        delete _tokenApprovals[tokenId];
        
        emit Transfer(from, to, tokenId);
    }
    
    function approve(address to, uint256 tokenId) external {
        require(_owners[tokenId] == msg.sender, "Not owner");
        _tokenApprovals[tokenId] = to;
        emit Approval(msg.sender, to, tokenId);
    }
    
    function safeTransferFrom(address from, address to, uint256 tokenId) external {
        this.transferFrom(from, to, tokenId);
        // In a real ERC721, this would check if 'to' can receive NFTs
        // For testing purposes, we'll keep it simple
    }
    
    
}

contract MockDeFiProtocol {
    mapping(address => uint256) private deposits;
    mapping(address => uint256) private rewards;
    uint256 public totalLiquidity;
    
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event Swap(address indexed user, address tokenIn, address tokenOut, uint256 amountIn, uint256 amountOut);
    
    function deposit(address token, uint256 amount) external {
        MockERC20(token).transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
        totalLiquidity += amount;
        emit Deposit(msg.sender, amount);
    }
    
    function withdraw(address token, uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient deposit");
        deposits[msg.sender] -= amount;
        totalLiquidity -= amount;
        MockERC20(token).transfer(msg.sender, amount);
        emit Withdrawal(msg.sender, amount);
    }
    
    function swapTokens(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minAmountOut
    ) external returns (uint256 amountOut) {
        MockERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        
        // Simple 1:1 swap for testing (in reality would have complex pricing)
        amountOut = amountIn;
        require(amountOut >= minAmountOut, "Slippage too high");
        
        MockERC20(tokenOut).transfer(msg.sender, amountOut);
        emit Swap(msg.sender, tokenIn, tokenOut, amountIn, amountOut);
    }
    
    function getDeposit(address user) external view returns (uint256) {
        return deposits[user];
    }
    
    function addLiquidity(address tokenA, address tokenB, uint256 amountA, uint256 amountB) external returns (uint256 liquidity) {
        MockERC20(tokenA).transferFrom(msg.sender, address(this), amountA);
        MockERC20(tokenB).transferFrom(msg.sender, address(this), amountB);
        
        liquidity = (amountA + amountB) / 2; // Simplified calculation
        deposits[msg.sender] += liquidity;
        totalLiquidity += liquidity;
        
        return liquidity;
    }
    
    function claimRewards() external returns (uint256 reward) {
        reward = rewards[msg.sender];
        rewards[msg.sender] = 0;
        // In a real protocol, this would mint or transfer reward tokens
        return reward;
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

/**
 * @title ReentrancyMaliciousContract
 * @dev Contract designed to test reentrancy vulnerabilities in the assembly function
 */
contract ReentrancyMaliciousContract {
    // Expose a view function for test to check if reentrancy was attempted
    function reentrancyAttempted() external view returns (bool) {
        return reentrancySucceeded;
    }
    // Expose a function for reentrancy selector testing
    function triggerReentrancy() external {
        console.log("Reentrancy triggered");
    }
    DfnsSmartAccount public target;
    uint256 public attackCount = 0;
    bool public reentrancySucceeded = false;
    bool public bufferOverflowAttempted = false;
    bool public integerOverflowAttempted = false;
    
    constructor(address _target) {
        target = DfnsSmartAccount(_target);
    }
    
    function maliciousFunction() external {
        attackCount++;
        
        if (attackCount == 1) {
            // Attempt reentrancy attack
            bytes memory reentrancyOps = abi.encodePacked(
                uint256(84),
                address(this),
                uint256(0),
                uint256(0),
                bytes("")
            );
            
            try target.handleOps(reentrancyOps, 0, 0) {
                reentrancySucceeded = true;
            } catch {
                // Reentrancy blocked
            }
        }
    }
    
    function triggerBufferOverflow() external {
        bufferOverflowAttempted = true;
        // Attempt buffer overflow through malformed data
        bytes memory overflowOps = abi.encodePacked(
            uint256(100), // Claims 100 bytes
            address(this),
            uint256(0),
            uint256(1000000), // Claims 1MB of data
            bytes4(0x12345678) // Only 4 bytes actual data
        );
        
        try target.handleOps(overflowOps, 0, 0) {
            // Buffer overflow succeeded
        } catch {
            // Buffer overflow blocked
        }
    }
    
    function triggerIntegerOverflow() external {
        integerOverflowAttempted = true;
        // Attempt integer overflow in iterator calculation
        bytes memory overflowOps = abi.encodePacked(
            uint256(84),
            address(this),
            uint256(0),
            type(uint256).max, // Maximum uint256 to cause overflow
            bytes4(0x12345678)
        );
        
        try target.handleOps(overflowOps, 0, 0) {
            // Integer overflow succeeded
        } catch {
            // Integer overflow blocked
        }
    }
    
    function triggerCombinedAttack() public {
        attackCount++;
        if (attackCount < 3) {
            // Attempt reentrancy with malicious data
            bytes memory maliciousOps = abi.encodePacked(
                uint256(84),
                address(this),
                uint256(0),
                type(uint256).max, // Integer overflow attempt
                bytes4(0x12345678)
            );
            
            try target.handleOps(maliciousOps, 0, 0) {
                // Combined attack succeeded
            } catch {
                // Attack blocked
            }
        }
    }
    
    fallback() external payable {
        triggerCombinedAttack();
    }
    
    receive() external payable {
        this.maliciousFunction();
    }
}


/* ========================================
 * ATTACK CONTRACTS FOR ASSEMBLY TESTING
 * ======================================== */

contract AssemblyAttacker {
    DfnsSmartAccount public target;
    bool public lastComputationCompleted = false;
    uint256 public computationResult = 0;
    
    constructor(address _target) {
        target = DfnsSmartAccount(_target);
    }
    
    function complexComputation(uint256 iterations) external {
        lastComputationCompleted = false;
        uint256 result = 0;
        
        for (uint256 i = 0; i < iterations; i++) {
            result += i * i + uint256(keccak256(abi.encode(i, block.timestamp))) % 1000;
            if (i % 1000 == 0 && gasleft() < 10000) {
                break; // Prevent out of gas
            }
        }
        
        computationResult = result;
        lastComputationCompleted = true;
    }
    
    fallback() external payable {
        this.complexComputation(50000);
    }
    
    receive() external payable {
        this.complexComputation(10000);
    }
}


contract AssemblyTestTarget {
    uint256 public counter = 0;
    
    function simpleFunction() external {
        counter++;
    }
    
    function complexFunction(uint256 value, string memory text, uint256[] memory array) external returns (uint256) {
        counter += value;
        return array.length + bytes(text).length;
    }
    
    function alwaysRevert() external pure {
        revert("Always reverts");
    }
    
    function returnMassiveData(uint256 size) external pure returns (bytes memory) {
        return new bytes(size);
    }
    
    function revertWithoutData() external pure {
        revert();
    }
    
    function revertWithLargeData(uint256 size) external pure {
        bytes memory largeData = new bytes(size);
        revert(string(largeData));
    }
    
    function revertWithMalformedData() external pure {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0xabcdefabcdefabcdefabcdefabcdefab)
            revert(ptr, 16)
        }
    }
    
    fallback() external payable {
        counter++;
    }
    
    receive() external payable {
        counter++;
    }
}

/**
 * @title GasBombContract - Contract for testing excessive gas usage / exhaustion attacks
 */
contract GasBombContract {
    function gasBombRevert(uint256 dataSize) external pure {
        bytes memory hugeBombData = new bytes(dataSize);
        for (uint256 i = 0; i < dataSize && i < 1000; i++) {
            hugeBombData[i] = bytes1(uint8(i % 256));
        }
        revert(string(hugeBombData));
    }
    
    function gasBombReturn(uint256 dataSize) external pure returns (bytes memory) {
        bytes memory hugeBombData = new bytes(dataSize);
        for (uint256 i = 0; i < dataSize && i < 1000; i++) {
            hugeBombData[i] = bytes1(uint8(i % 256));
        }
        return hugeBombData;
    }
}

/**
 * @title ReentrancyAttacker - Contract for testing reentrancy attacks
 */
contract ReentrancyAttacker {
    DfnsSmartAccount public target;
    uint256 public callCount = 0;
    bool public reentrancyAttempted = false;
    
    constructor(address _target) {
        target = DfnsSmartAccount(_target);
    }
    
    function attemptReentrancy() external {
        callCount++;
        reentrancyAttempted = true;
        
        // Try to reenter the smart account
        if (callCount == 1) {
            // Create simple userOps for reentrancy
            bytes memory reentrantOps = abi.encodePacked(
                uint256(88), // Total length
                address(this), // Call back to this contract
                uint256(0), // No value
                uint256(4), // 4 bytes data
                bytes4(0xdeadbeef) // Simple data
            );
            
            try target.handleOps(reentrantOps, 0, 0) {
                // Reentrancy succeeded - this is bad!
                callCount += 100; // Mark successful reentrancy
            } catch {
                // Expected to fail
            }
        }
    }
    
    function getCallCount() external view returns (uint256) {
        return callCount;
    }
}

/**
 * @title CREATE2Deployer - Factory contract for deterministic deployments
 * @dev Allows deployment of contracts to deterministic addresses using CREATE2
 */
contract CREATE2Deployer {
    event ContractDeployed(address indexed contractAddress, bytes32 indexed salt, address indexed deployer);
    event DeploymentFailed(bytes32 indexed salt, address indexed deployer, string reason);
    
    mapping(address => bool) public deployedContracts;
    mapping(bytes32 => address) public saltToAddress;
    
    /**
     * @dev Deploy contract using CREATE2 opcode
     * @param salt The salt value for deterministic address generation
     * @param bytecode The contract bytecode to deploy
     * @return deployed The address of the deployed contract
     */
    function deploy(bytes32 salt, bytes memory bytecode) external payable returns (address deployed) {
        // Predict the address before deployment
        address predicted = predictAddress(salt, bytecode);
        
        // Check if contract already exists at this address
        require(!_isContract(predicted), "Contract already exists at address");
        
        assembly {
            deployed := create2(callvalue(), add(bytecode, 0x20), mload(bytecode), salt)
        }
        
        require(deployed != address(0), "CREATE2 deployment failed");
        require(deployed == predicted, "Deployed address mismatch");
        
        deployedContracts[deployed] = true;
        saltToAddress[salt] = deployed;
        
        emit ContractDeployed(deployed, salt, msg.sender);
    }
    
    /**
     * @dev Deploy contract with constructor parameters
     * @param salt The salt value for deterministic address generation
     * @param bytecode The contract bytecode without constructor parameters
     * @param constructorData The encoded constructor parameters
     * @return deployed The address of the deployed contract
     */
    function deployWithConstructor(
        bytes32 salt, 
        bytes memory bytecode, 
        bytes memory constructorData
    ) external payable returns (address deployed) {
        bytes memory deployBytecode = abi.encodePacked(bytecode, constructorData);
        return this.deploy{value: msg.value}(salt, deployBytecode);
    }
    
    /**
     * @dev Predict the deployment address for given salt and bytecode
     * @param salt The salt value
     * @param bytecode The contract bytecode
     * @return predicted The predicted deployment address
     */
    function predictAddress(bytes32 salt, bytes memory bytecode) public view returns (address predicted) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(bytecode)
            )
        );
        return address(uint160(uint256(hash)));
    }
    
    /**
     * @dev Batch deploy multiple contracts
     * @param salts Array of salt values
     * @param bytecodes Array of contract bytecodes
     * @return deployedAddresses Array of deployed contract addresses
     */
    function batchDeploy(
        bytes32[] memory salts, 
        bytes[] memory bytecodes
    ) external payable returns (address[] memory deployedAddresses) {
        require(salts.length == bytecodes.length, "Array length mismatch");
        
        deployedAddresses = new address[](salts.length);
        uint256 valuePerDeployment = msg.value / salts.length;
        
        for (uint256 i = 0; i < salts.length; i++) {
            try this.deploy{value: valuePerDeployment}(salts[i], bytecodes[i]) returns (address deployed) {
                deployedAddresses[i] = deployed;
            } catch Error(string memory reason) {
                emit DeploymentFailed(salts[i], msg.sender, reason);
                deployedAddresses[i] = address(0);
            }
        }
    }
    
    /**
     * @dev Deploy a metamorphic contract (for testing vulnerabilities)
     * @param salt The salt for deployment
     * @param initialBytecode The initial contract bytecode
     * @return deployed The deployed contract address
     */
    function deployMetamorphic(
        bytes32 salt, 
        bytes memory initialBytecode
    ) external payable returns (address deployed) {
        deployed = this.deploy{value: msg.value}(salt, initialBytecode);
        
        // The deployed contract can later self-destruct and be replaced
        return deployed;
    }
    
    /**
     * @dev Emergency function to destroy a deployed contract (if it supports it)
     * @param contractAddress The address of the contract to destroy
     */
    function emergencyDestroy(address contractAddress) external {
        require(deployedContracts[contractAddress], "Contract not deployed by this factory");
        
        // Call destroy function if the contract supports it
        (bool success,) = contractAddress.call(abi.encodeWithSignature("destroy()"));
        if (success) {
            deployedContracts[contractAddress] = false;
        }
    }
    
    function _isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}

/**
 * @title MetamorphicContract - Test contract for metamorphic deployment attacks
 */
contract MetamorphicContract {
    uint256 public version = 1;
    address public owner;
    bool public destroyed = false;
    
    constructor(address _owner) {
        owner = _owner;
    }
    
    function setVersion(uint256 _version) external {
        require(msg.sender == owner, "Only owner");
        version = _version;
    }
    
    function destroy() external {
        require(msg.sender == owner, "Only owner");
        destroyed = true;
        selfdestruct(payable(owner));
    }
    
    function maliciousFunction() external {
        // This function might not exist in the original contract
        // but could be added in a metamorphic replacement
        require(version >= 2, "Function not available in version 1");
    }
}

/**
 * @title VulnerableTarget - Contract with state that can be manipulated via CREATE2
 */
contract VulnerableTarget {
    mapping(address => uint256) public balances;
    mapping(address => bool) public authorizedContracts;
    uint256 public totalSupply;
    
    constructor() {
        totalSupply = 1000000 * 10**18;
        balances[msg.sender] = totalSupply;
    }
    
    function authorizeContract(address contractAddr) external {
        require(balances[msg.sender] > 0, "No balance");
        authorizedContracts[contractAddr] = true;
    }
    
    function mint(address to, uint256 amount) external {
        require(authorizedContracts[msg.sender], "Not authorized");
        balances[to] += amount;
        totalSupply += amount;
    }
    
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
}

/**
 * @title MaliciousContractV1 - First version of a contract for metamorphic testing
 */
contract MaliciousContractV1 {
    uint256 public constant VERSION = 1;
    address public target;
    
    constructor(address _target) {
        target = _target;
    }
    
    function legitimateFunction() external view returns (uint256) {
        return VERSION;
    }
    
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}

/**
 * @title MaliciousContractV2 - Second version with different behavior
 */
contract MaliciousContractV2 {
    uint256 public constant VERSION = 2;
    address public target;
    
    constructor(address _target) {
        target = _target;
    }
    
    function legitimateFunction() external view returns (uint256) {
        return VERSION;
    }
    
    function maliciousFunction() external {
        // This function didn't exist in V1 but can manipulate state
        VulnerableTarget(target).mint(msg.sender, 1000000 * 10**18);
    }
    
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}

/**
 * @title GasBombDeployer - Contract that consumes excessive gas during deployment
 */
contract GasBombDeployer {
    uint256[] public massiveArray;
    
    constructor(uint256 size) {
        // Consume gas during deployment
        for (uint256 i = 0; i < size && gasleft() > 10000; i++) {
            massiveArray.push(i);
        }
    }
    
    function getArrayLength() external view returns (uint256) {
        return massiveArray.length;
    }
}
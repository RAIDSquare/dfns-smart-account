# Dfns Smart Account

This smart contract is heavily inspired from the SafeLite example: https://github.com/5afe/safe-eip7702/blob/main/safe-eip7702-contracts/contracts/experimental/SafeLite.sol
It was stripped from all unnecessary logic to only keep the batch functionality.
It uses no dependency and relies on some assembly code to save gas usage.

The contract is intended to be used with EIP-7702 where EOA delegates to this contract implementation.

It is deployed on the following chains:

| Blockchain          | Contract Address                                                                                                                            |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Ethereum Mainnet    | [0xbd77a32e628e69d8b168d3813f019e51d787b569](https://etherscan.io/address/0xbd77a32e628e69d8b168d3813f019e51d787b569#code)                  |
| Ethereum Sepolia    | [0xbd77a32e628e69d8b168d3813f019e51d787b569](https://sepolia.etherscan.io/address/0xbd77a32e628e69d8b168d3813f019e51d787b569#code)          |
| Ethereum Holesky    | [0xbd77a32e628e69d8b168d3813f019e51d787b569](https://holesky.etherscan.io/address/0xbd77a32e628e69d8b168d3813f019e51d787b569#code)          |
| Base                | [0xbd77a32e628e69d8b168d3813f019e51d787b569](https://basescan.org/address/0xbd77a32e628e69d8b168d3813f019e51d787b569#code)                  |
| Base Sepolia        | [0xbd77a32e628e69d8b168d3813f019e51d787b569](https://sepolia.basescan.org/address/0xbd77a32e628e69d8b168d3813f019e51d787b569#code)          |
| Binance Smart Chain | [0xbd77a32e628e69d8b168d3813f019e51d787b569](https://bscscan.com/address/0xbd77a32e628e69d8b168d3813f019e51d787b569#code)                   |
| Binance Testnet     | [0xbd77a32e628e69d8b168d3813f019e51d787b569](https://testnet.bscscan.com/address/0xbd77a32e628e69d8b168d3813f019e51d787b569#code)           |
| Optimism            | [0xbd77a32e628e69d8b168d3813f019e51d787b569](https://optimistic.etherscan.io/address/0xbd77a32e628e69d8b168d3813f019e51d787b569#code)       |
| Optimism Sepolia    | [0xbd77a32e628e69d8b168d3813f019e51d787b569](https://sepolia-optimism.etherscan.io/address/0xbd77a32e628e69d8b168d3813f019e51d787b569#code) |


## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

-   **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
-   **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
-   **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
-   **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
forge build
```

### Test

```shell
# Run all tests
forge test

# Run unit tests
forge test --match-contract DfnsSmartAccountUnitTest

# Run integrated tests with Holesky fork
forge test --match-contract IntegratedTest --fork-url https://ethereum-holesky-rpc.publicnode.com

# Run fuzz tests
forge test --match-contract FuzzTestingDfnsSmartAccount

# Run tests with gas reports
forge test --gas-report
```

### Format

```shell
forge fmt
```

### Gas Snapshots

```shell
forge snapshot
```

## Deployment and Usage Guide

### Step 1: Deploy the Contract

Deploy the DfnsSmartAccount contract to your target network:

```shell
# Deploy to Holesky testnet
## 1. for test 
forge create src/DfnsSmartAccount.sol:DfnsSmartAccount \
    --rpc-url https://ethereum-holesky-rpc.publicnode.com \
    --private-key <your_private_key> \
    --verify \
    --etherscan-api-key <your_etherscan_api_key>

# Deploy to local Anvil
forge create src/DfnsSmartAccount.sol:DfnsSmartAccount \
    --rpc-url http://localhost:8545 \
    --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# Deploy using script (recommended)
forge script script/DeployDfnsSmartAccount.sol:DeployDfnsSmartAccount \
    --rpc-url <your_rpc_url> \
    --private-key <your_private_key> \
    --broadcast \
    --verify
```

**Example successful deployment output:**
```
Deployer: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
Deployed to: 0x5FbDB2315678afecb367f032d93F642f64180aa3
Transaction hash: 0x...
```

### Step 2: Set Up EIP-7702 Delegation (Using Forge)

Create an EIP-7702 delegation from your EOA to the deployed smart contract:

```shell
# Set environment variables
export SMART_ACCOUNT_ADDRESS=0x5FbDB2315678afecb367f032d93F642f64180aa3
export EOA_PRIVATE_KEY=0x59c6995e998f97436f5a7c3e6b3b3d2c8e6c3d6c8e6c3d6c8e6c3d6c8e6c3d6c
export RPC_URL=https://ethereum-holesky-rpc.publicnode.com

# Create delegation authorization tuple
cast call $SMART_ACCOUNT_ADDRESS "getNonce()" --rpc-url $RPC_URL

# Get EOA address from private key
cast wallet address $EOA_PRIVATE_KEY
# Output: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8

# Sign delegation (this creates the authorization tuple for EIP-7702)
# Note: This is done through transaction inclusion in EIP-7702
```

### Step 3: Build User Operations

#### Single Transaction Example

```shell
# Build a single ETH transfer operation
# Format: to(20 bytes) + value(32 bytes) + dataLength(32 bytes) + data(variable)

# Transfer 1 ETH to recipient
export RECIPIENT=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
export TRANSFER_AMOUNT=1000000000000000000  # 1 ETH in wei

# Create user operation (hex encoded)
# Recipient address (20 bytes): 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
# Value (32 bytes): 0x0de0b6b3a7640000 (1 ETH)
# Data length (32 bytes): 0x00000000000000000000000000000000000000000000000000000000000000000 (0 bytes)
# Data: (empty)

export SINGLE_USER_OPS="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC0000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000000000000"
```

#### Batch Transaction Example

```shell
# Build batch operations (ETH transfer + contract call)
export RECIPIENT_1=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
export RECIPIENT_2=0x90F79bf6EB2c4f870365E785982E1f101E93b906
export TOKEN_ADDRESS=0x... # Your ERC20 token address

# Operation 1: Send 0.5 ETH to recipient1
# Operation 2: Send 1 ETH to recipient2
export BATCH_USER_OPS="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC00000000000000000000000000000000000000000000000006f05b59d3b2000000000000000000000000000000000000000000000000000000000000000000000090F79bf6EB2c4f870365E785982E1f101E93b9060000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000000000000"
```

### Step 4: Generate EIP-712 Signature

```shell
# Generate EIP-712 signature for the user operations
# This requires creating the domain separator and struct hash

# Get contract nonce
export NONCE=$(cast call $SMART_ACCOUNT_ADDRESS "getNonce()" --rpc-url $RPC_URL)

# Create domain separator
# DOMAIN_TYPEHASH = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")
# For EIP-7702, verifyingContract is the EOA address (delegating address)
export EOA_ADDRESS=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
export CHAIN_ID=17000  # Holesky

# Create struct hash
# HANDLEOPS_TYPEHASH = keccak256("HandleOps(bytes32 data,uint256 nonce)")

# Sign the EIP-712 message
cast wallet sign --data "..." --private-key $EOA_PRIVATE_KEY
```

### Step 5: Execute handleOps

```shell
# Execute the user operations with signature
cast send $SMART_ACCOUNT_ADDRESS \
    "handleOps(bytes,uint256,uint256)" \
    $SINGLE_USER_OPS \
    $SIGNATURE_R \
    $SIGNATURE_VS \
    --rpc-url $RPC_URL \
    --private-key $EOA_PRIVATE_KEY \
    --gas-limit 500000

# Verify execution
cast call $SMART_ACCOUNT_ADDRESS "getNonce()" --rpc-url $RPC_URL
# Should return incremented nonce

# Check recipient balance
cast balance $RECIPIENT --rpc-url $RPC_URL
```

### Step 6: Complete Example Script

Create a complete example script:

```bash
#!/bin/bash
# complete_example.sh

# Deploy contract
echo "Deploying DfnsSmartAccount..."
DEPLOYMENT_OUTPUT=$(forge create src/DfnsSmartAccount.sol:DfnsSmartAccount \
    --rpc-url http://localhost:8545 \
    --private-key "<<your private key>>")

CONTRACT_ADDRESS=$(echo "$DEPLOYMENT_OUTPUT" | grep "Deployed to:" | cut -d' ' -f3)
echo "Contract deployed to: $CONTRACT_ADDRESS"

# Set up variables
EOA_PRIVATE_KEY=""
RECIPIENT=""

# Check initial balances
echo "Initial balances:"
echo "EOA: $(cast balance 0x70997970C51812dc3A010C7d01b50e0d17dc79C8)"
echo "Recipient: $(cast balance $RECIPIENT)"

# Create user operation (1 ETH transfer)
USER_OPS="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC0000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000000000000"

# Note: In a real implementation, you would:
# 1. Set up EIP-7702 delegation through transaction inclusion
# 2. Generate proper EIP-712 signature
# 3. Execute handleOps from the delegated EOA

echo "User operations created: $USER_OPS"
echo "Ready for EIP-7702 delegation and execution"
```

### Testing with Anvil

```shell
# Start Anvil with EIP-7702 support
anvil --hardfork prague

# Run the complete example
chmod +x complete_example.sh
./complete_example.sh
```

## Advanced Usage

### Custom Batch Operations

```shell
# Create complex batch with contract interactions
# Example: Approve + Transfer tokens in one batch

# Operation 1: Approve tokens
# target: token_address, value: 0, data: approve(spender, amount)
# Operation 2: Transfer tokens  
# target: token_address, value: 0, data: transfer(to, amount)

# Use cast to encode function calls
APPROVE_DATA=$(cast calldata "approve(address,uint256)" $SPENDER $AMOUNT)
TRANSFER_DATA=$(cast calldata "transfer(address,uint256)" $RECIPIENT $AMOUNT)

# Build batch operations
# [token_address][0][approve_data_length][approve_data][token_address][0][transfer_data_length][transfer_data]
```

### Gas Optimization

```shell
# Test gas usage for different batch sizes
forge test --match-test test_Performance_LargeBatch --gas-report

# Optimize user operations encoding
forge snapshot --match-contract DfnsSmartAccount
```

### Security Testing

```shell
# Run security-focused tests
forge test --match-test test_Security

# Test signature malleability
forge test --match-contract SignatureMalleabilityFixTest

# Fuzz testing
forge test --match-contract FuzzTestingDfnsSmartAccount
```

## Integration with Dfns API

After generating the transaction data using forge, use the Dfns API to broadcast:

```bash
# Use the transaction data from forge create output
curl -X POST "https://{{customerApiDomain}}/wallets/:walletId/transactions" \
  -H "Content-Type: application/json" \
  -d '{
    "kind": "Json",
    "transaction": {
      "data": "0x60a0604052348015600e575f5ffd5b506080516107065..."
    }
  }'
```

## Verification

```shell
# Verify on Holesky
forge verify-contract $CONTRACT_ADDRESS \
    ./src/DfnsSmartAccount.sol:DfnsSmartAccount \
    --verifier-url https://api-holesky.etherscan.io/api \
    --etherscan-api-key <etherscan-api-key> \
    --watch

# Verify on mainnet
forge verify-contract $CONTRACT_ADDRESS \
    ./src/DfnsSmartAccount.sol:DfnsSmartAccount \
    --etherscan-api-key <etherscan-api-key> \
    --watch
```

## Troubleshooting

### Common Issues

1. **Invalid Signature Error**
   - Ensure you're using the EOA address as verifying contract in EIP-712 domain
   - Verify the private key matches the delegating EOA
   - Check that EIP-7702 delegation is properly set up

2. **Gas Estimation Failures**
   - Increase gas limit for batch operations
   - Test with smaller batches first
   - Ensure sufficient ETH balance in smart account

3. **Nonce Mismatch**
   - Always fetch current nonce before signing
   - Account for pending transactions

### Help

```shell
forge --help
anvil --help
cast --help
```

## License

LGPL-3.0-only



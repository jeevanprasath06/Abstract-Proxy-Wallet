# proxyWallet

A high-security, gasless-enabled counterfactual smart wallet system built on Ethereum. The system consists of a proxy wallet implementation and a factory for deterministic deployments using CREATE2 and upgradeable beacons.

## Features

- **Counterfactual Deployment** — Deploy wallets deterministically using CREATE2 with owner address and salt
- **Upgradeable Architecture** — Uses OpenZeppelin's UpgradeableBeacon pattern for seamless upgrades
- **Gasless Meta-Transactions** — EIP-712 signed transactions with nonce and deadline replay protection
- **Batch Execution** — Atomic single and batch transaction execution
- **EIP-1271 Support** — Standard signature validation for smart contract wallets
- **ERC-1155 / ERC-721 Receipts** — Native token receipt handling
- **Reentrancy Protection** — Built-in non-reentrant modifiers
- **Ownership Management** — Transferable ownership with factory callbacks

## Architecture

```
proxyWalletFactory (Upgradeable)
    │
    ├── UpgradeableBeacon
    │       │
    │       └── proxyWallet (Implementation)
    │
    └── Registry Mappings
            ├── isProxyWallet[address]
            ├── getWallet[owner][salt]
            ├── walletSalt[wallet]
            ├── walletOwner[wallet]
            └── _userWallets[owner]
```

### Contracts

| Contract | Description |
|----------|-------------|
| `proxyWallet` | Core wallet implementation with execution, meta-transaction, and signature validation logic |
| `proxyWalletFactory` | Factory deploying BeaconProxy instances via CREATE2 |
| `IProxyWallet` | Interface defining wallet execution methods |
| `IProxyWalletFactory` | Interface defining factory deployment and lookup methods |

## Installation

```bash
forge install OpenZeppelin/openzeppelin-contracts-upgradeable
forge install OpenZeppelin/openzeppelin-contracts
```

## Usage

### Deploy Factory

```solidity
// Deploy implementation first
proxyWallet implementation = new proxyWallet();

// Deploy factory with implementation and owner
proxyWalletFactory factory = new proxyWalletFactory();
factory.initialize(address(implementation), ownerAddress);
```

### Create Wallet (Deterministic)

```solidity
address owner = 0x123...;
uint256 salt = 42;

// Predict address
address predicted = factory.getWalletAddress(owner, salt);

// Deploy
address wallet = factory.createWallet(owner, salt);
```

### Execute Transactions

```solidity
// Direct execution (owner only)
proxyWallet wallet = proxyWallet(walletAddress);
wallet.execute(target, value, data);

// Batch execution
wallet.executeBatch([
    Transaction({target: addr1, value: 0, data: data1}),
    Transaction({target: addr2, value: 1 ether, data: data2})
]);
```

### Meta-Transactions (Gasless)

```solidity
// Single meta-transaction
MetaTransaction metaTx = MetaTransaction({
    target: target,
    value: 0,
    data: calldata,
    nonce: 1,
    deadline: block.timestamp + 3600
});
bytes signature = owner.sign(eip712Digest);
wallet.executeMetaTransaction(metaTx, signature);

// Batch meta-transaction
BatchMetaTransaction batchMetaTx = BatchMetaTransaction({
    txs: [tx1, tx2],
    nonce: 2,
    deadline: block.timestamp + 3600
});
wallet.executeBatchMetaTransaction(batchMetaTx, signature);
```

### EIP-1271 Signature Validation

```solidity
bytes4 result = wallet.isValidSignature(hash, signature);
if (result == 0x1626ba7e) {
    // Valid signature
}
```

## Events

### proxyWallet
- `Initialized(address owner, address factory)`
- `OwnershipTransferred(address previousOwner, address newOwner)`
- `Executed(address target, uint256 value, bytes data)`
- `BatchExecuted(uint256 count)`
- `MetaTransactionExecuted(address relayer, bytes32 txHash, uint256 nonce)`
- `BatchMetaTransactionExecuted(address relayer, bytes32 txHash, uint256 nonce, uint256 count)`

### proxyWalletFactory
- `ProxyWalletCreated(address owner, address proxyWallet, uint256 salt)`
- `WalletOwnershipTransferred(address wallet, address oldOwner, address newOwner)`

## Testing

```bash
forge test
```

## Security

- All external calls protected by `nonReentrant` modifier
- Meta-transactions validate EIP-712 signature, nonce, and deadline
- Factory enforces CREATE2 collision prevention via registry
- Ownership transfers validated through factory callback
- Implementation follows OpenZeppelin upgradeable patterns

## License

MIT

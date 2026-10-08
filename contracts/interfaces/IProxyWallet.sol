// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

/**
 * @title IProxyWallet
 * @notice Interface defining the core structure and execution methods for proxy smart wallets.
 */
interface IProxyWallet {
    struct Transaction {
        address target;
        uint256 value;
        bytes data;
    }

    struct MetaTransaction {
        address target;
        uint256 value;
        bytes data;
        uint256 nonce;
        uint256 deadline;
    }

    struct BatchMetaTransaction {
        Transaction[] txs;
        uint256 nonce;
        uint256 deadline;
    }

    event Initialized(address indexed owner, address indexed factory);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Executed(address indexed target, uint256 value, bytes data);
    event BatchExecuted(uint256 count);
    event MetaTransactionExecuted(address indexed relayer, bytes32 indexed txHash, uint256 nonce);
    event BatchMetaTransactionExecuted(address indexed relayer, bytes32 indexed txHash, uint256 nonce, uint256 count);

    function initialize(address _owner, address _factory) external;
    function transferOwnership(address newOwner) external;
    function owner() external view returns (address);
    function factory() external view returns (address);
    function nonces(uint256 nonce) external view returns (bool);

    function execute(address target, uint256 value, bytes calldata data) external payable returns (bytes memory);
    function executeBatch(Transaction[] calldata txs) external payable returns (bytes[] memory);

    function executeMetaTransaction(MetaTransaction calldata metaTx, bytes calldata signature)
        external
        returns (bytes memory);

    function executeBatchMetaTransaction(BatchMetaTransaction calldata metaTx, bytes calldata signature)
        external
        returns (bytes[] memory);

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

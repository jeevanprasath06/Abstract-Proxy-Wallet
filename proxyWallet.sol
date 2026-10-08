// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IProxyWallet} from "./interfaces/IProxyWallet.sol";
import {IProxyWalletFactory} from "./interfaces/IProxyWalletFactory.sol";

/**
 * @title proxyWallet
 * @notice High-security, gasless-enabled counterfactual smart wallet contract.
 * Supports:
 * - Single & Atomic Batch Call Executions
 * - EIP-712 Gasless Meta-Transactions with nonces & deadline replay protection
 * - EIP-1271 Standard Signature Validation
 * - ERC-1155 / ERC-721 token receipts
 */
contract proxyWallet is Initializable, IProxyWallet, IERC1155Receiver, IERC721Receiver {
    using ECDSA for bytes32;

    // --- State Variables ---
    address public override owner;
    address public override factory;

    // Nonce registry to prevent meta-transaction replay attacks
    mapping(uint256 => bool) public override nonces;

    // Reentrancy guard state
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;

    uint256[50] private __gap;

    // --- EIP-712 Constants ---

    /**
     * @notice Computes the EIP-712 domain separator for this contract.
     * @dev Uses block.chainid and the contract address for replay protection across chains and instances.
     * @return The 32-byte domain separator hash.
     */
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("proxyWallet")),
                keccak256(bytes("1.0.0")),
                block.chainid,
                address(this)
            )
        );
    }
    bytes32 public constant TRANSACTION_TYPEHASH = keccak256("Transaction(address target,uint256 value,bytes data)");

    bytes32 public constant META_TRANSACTION_TYPEHASH =
        keccak256("MetaTransaction(address target,uint256 value,bytes data,uint256 nonce,uint256 deadline)");

    bytes32 public constant BATCH_META_TRANSACTION_TYPEHASH = keccak256(
        "BatchMetaTransaction(Transaction[] txs,uint256 nonce,uint256 deadline)Transaction(address target,uint256 value,bytes data)"
    );

    // EIP-1271 magic value (bytes4(keccak256("isValidSignature(bytes32,bytes)")))
    bytes4 internal constant EIP1271_MAGICVALUE = 0x1626ba7e;

    // --- Modifiers ---
    modifier onlyOwner() {
        require(msg.sender == owner, "proxyWallet: NOT_OWNER");
        _;
    }

    modifier onlyOwnerOrSelf() {
        require(msg.sender == owner || msg.sender == address(this), "proxyWallet: NOT_AUTHORIZED");
        _;
    }

    modifier nonReentrant() {
        require(_status != _ENTERED, "proxyWallet: REENTRANCY_GUARD");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }

/**
 * @notice Constructor for the proxyWallet implementation.
 * @dev Disables initializers to prevent the logic contract from being initialized directly.
 */
    constructor() {
        _status = _NOT_ENTERED;
        _disableInitializers();
    }

    /**
     * @notice Initializes a newly cloned Proxy Wallet instance.
     * @dev Sets the owner and factory address, and emits the Initialized event. Can only be called once.
     * @param _owner Wallet owner address.
     * @param _factory Proxy wallet factory address.
     */
    function initialize(address _owner, address _factory) external override initializer {
        require(_owner != address(0), "proxyWallet: INVALID_OWNER");
        require(_factory != address(0), "proxyWallet: INVALID_FACTORY");

        owner = _owner;
        factory = _factory;
        _status = _NOT_ENTERED;

        emit Initialized(_owner, _factory);
    }

    /**
     * @notice Transfers ownership of the proxy wallet to a new address.
     * @dev Reverts if the new owner is the zero address. Emits OwnershipTransferred.
     * @param newOwner Address of the new wallet owner.
     */
    function transferOwnership(address newOwner) external override onlyOwnerOrSelf {
        require(newOwner != address(0), "proxyWallet: INVALID_NEW_OWNER");
        address oldOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);

        if (factory != address(0) && factory.code.length > 0) {
            try IProxyWalletFactory(factory).onWalletOwnershipTransferred(oldOwner, newOwner) {} catch {}
        }
    }

    /**
     * @notice Executes a single transaction call from the wallet owner.
     * @dev Only callable by the owner. Reverts on call failure or reentrancy.
     * @param target Target smart contract address.
     * @param value Native token value to send.
     * @param data Calldata payload.
     * @return response The bytes returned from the executed call.
     */
    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        override
        onlyOwner
        nonReentrant
        returns (bytes memory response)
    {
        response = _call(target, value, data);
        emit Executed(target, value, data);
    }

    /**
     * @notice Executes a batch of transaction calls atomically from the wallet owner.
     * @dev Only callable by the owner. Reverts if any call fails. Reentrancy protected.
     * @param txs Array of Transaction structs.
     * @return responses An array of bytes returned from each executed call.
     */
    function executeBatch(Transaction[] calldata txs)
        external
        payable
        override
        onlyOwner
        nonReentrant
        returns (bytes[] memory responses)
    {
        require(txs.length > 0, "proxyWallet: EMPTY_BATCH");
        responses = new bytes[](txs.length);
        for (uint256 i = 0; i < txs.length; i++) {
            responses[i] = _call(txs[i].target, txs[i].value, txs[i].data);
        }
        emit BatchExecuted(txs.length);
    }

    /**
     * @notice Executes a single meta-transaction signed by owner and submitted by a relayer.
     * @dev Validates EIP-712 signature, nonce, and deadline. Reverts if expired, replayed, or invalid signature.
     * @param metaTx MetaTransaction struct.
     * @param signature EIP-712 signature from owner.
     * @return response The bytes returned from the executed call.
     */
    function executeMetaTransaction(MetaTransaction calldata metaTx, bytes calldata signature)
        external
        override
        nonReentrant
        returns (bytes memory response)
    {
        require(block.timestamp <= metaTx.deadline, "proxyWallet: EXPIRED_DEADLINE");
        require(!nonces[metaTx.nonce], "proxyWallet: NONCE_ALREADY_USED");

        bytes32 structHash = keccak256(
            abi.encode(
                META_TRANSACTION_TYPEHASH,
                metaTx.target,
                metaTx.value,
                keccak256(metaTx.data),
                metaTx.nonce,
                metaTx.deadline
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
        require(SignatureChecker.isValidSignatureNow(owner, digest, signature), "proxyWallet: INVALID_SIGNATURE");

        nonces[metaTx.nonce] = true;
        response = _call(metaTx.target, metaTx.value, metaTx.data);

        emit MetaTransactionExecuted(msg.sender, digest, metaTx.nonce);
    }

    /**
     * @notice Executes a batch of meta-transactions signed by owner and submitted by a relayer.
     * @dev Validates EIP-712 signature against the batch, nonce, and deadline. Reverts on any call failure.
     * @param metaTx BatchMetaTransaction struct.
     * @param signature EIP-712 signature from owner.
     * @return responses An array of bytes returned from each executed call.
     */
    function executeBatchMetaTransaction(BatchMetaTransaction calldata metaTx, bytes calldata signature)
        external
        override
        nonReentrant
        returns (bytes[] memory responses)
    {
        require(block.timestamp <= metaTx.deadline, "proxyWallet: EXPIRED_DEADLINE");
        require(!nonces[metaTx.nonce], "proxyWallet: NONCE_ALREADY_USED");
        require(metaTx.txs.length > 0, "proxyWallet: EMPTY_BATCH");

        bytes32[] memory txHashes = new bytes32[](metaTx.txs.length);
        for (uint256 i = 0; i < metaTx.txs.length; i++) {
            txHashes[i] = keccak256(
                abi.encode(
                    TRANSACTION_TYPEHASH, metaTx.txs[i].target, metaTx.txs[i].value, keccak256(metaTx.txs[i].data)
                )
            );
        }

        bytes32 structHash = keccak256(
            abi.encode(
                BATCH_META_TRANSACTION_TYPEHASH, keccak256(abi.encodePacked(txHashes)), metaTx.nonce, metaTx.deadline
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
        require(SignatureChecker.isValidSignatureNow(owner, digest, signature), "proxyWallet: INVALID_SIGNATURE");

        nonces[metaTx.nonce] = true;

        responses = new bytes[](metaTx.txs.length);
        for (uint256 i = 0; i < metaTx.txs.length; i++) {
            responses[i] = _call(metaTx.txs[i].target, metaTx.txs[i].value, metaTx.txs[i].data);
        }

        emit BatchMetaTransactionExecuted(msg.sender, digest, metaTx.nonce, metaTx.txs.length);
    }

    /**
     * @notice EIP-1271 interface for validating signatures on behalf of smart contracts.
     * @dev Verifies that the signature corresponds to the current wallet owner.
     * @param hash Data hash signed by user.
     * @param signature Signature payload.
     * @return The EIP-1271 magic value if the signature is valid, else 0x00000000.
     */
    function isValidSignature(bytes32 hash, bytes calldata signature) external view override returns (bytes4) {
        if (SignatureChecker.isValidSignatureNow(owner, hash, signature)) {
            return EIP1271_MAGICVALUE;
        }
        bytes32 ethSignedHash = hash.toEthSignedMessageHash();
        if (SignatureChecker.isValidSignatureNow(owner, ethSignedHash, signature)) {
            return EIP1271_MAGICVALUE;
        }
        return bytes4(0);
    }

    // --- Private Helper ---

    /**
     * @notice Internal helper to perform a raw call.
     * @dev Reverts with the returned error data if the call fails.
     * @param target Target smart contract address.
     * @param value Native token value to send.
     * @param data Calldata payload.
     * @return response The bytes returned from the executed call.
     */
    function _call(address target, uint256 value, bytes memory data) private returns (bytes memory response) {
        require(target != address(0), "proxyWallet: ZERO_TARGET_ADDRESS");
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            if (result.length > 0) {
                assembly {
                    let result_size := mload(result)
                    revert(add(32, result), result_size)
                }
            } else {
                revert("proxyWallet: CALL_FAILED");
            }
        }
        return result;
    }

    // --- Token Receiver Hooks ---

    /**
     * @notice Handles the receipt of a single ERC1155 token type.
     * @dev Always returns the expected magic value to accept the transfer.
     * @param operator The address which initiated the transfer (unused).
     * @param from The address which previously owned the token (unused).
     * @param id The ID of the token being transferred (unused).
     * @param value The amount of tokens being transferred (unused).
     * @param data Additional data with no specified format (unused).
     * @return The selector of this function `onERC1155Received`.
     */
    function onERC1155Received(address operator, address from, uint256 id, uint256 value, bytes calldata data)
        external
        pure
        override
        returns (bytes4)
    {
        return this.onERC1155Received.selector;
    }

    /**
     * @notice Handles the receipt of multiple ERC1155 token types.
     * @dev Always returns the expected magic value to accept the transfers.
     * @param operator The address which initiated the batch transfer (unused).
     * @param from The address which previously owned the token (unused).
     * @param ids An array containing ids of each token being transferred (unused).
     * @param values An array containing amounts of each token being transferred (unused).
     * @param data Additional data with no specified format (unused).
     * @return The selector of this function `onERC1155BatchReceived`.
     */
    function onERC1155BatchReceived(address operator, address from, uint256[] calldata ids, uint256[] calldata values, bytes calldata data)
        external
        pure
        override
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    /**
     * @notice Handles the receipt of an ERC721 token.
     * @dev Always returns the expected magic value to accept the transfer.
     * @param operator The address which called `safeTransferFrom` function (unused).
     * @param from The address which previously owned the token (unused).
     * @param tokenId The NFT identifier which is being transferred (unused).
     * @param data Additional data with no specified format (unused).
     * @return The selector of this function `onERC721Received`.
     */
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external pure override returns (bytes4) {
        return this.onERC721Received.selector;
    }

    /**
     * @notice Returns true if this contract implements the interface defined by `interfaceId`.
     * @dev Supports IERC1155Receiver, IERC721Receiver, and IERC165.
     * @param interfaceId The interface identifier.
     * @return True if the contract implements `interfaceId` and it is not 0xffffffff, false otherwise.
     */
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId || interfaceId == type(IERC721Receiver).interfaceId
            || interfaceId == type(IERC165).interfaceId || interfaceId == type(IERC1271).interfaceId;
    }

    /**
     * @notice Allows receiving ETH.
     * @dev Empty payable fallback function.
     */
    receive() external payable {}
}

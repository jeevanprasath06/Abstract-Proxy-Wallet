// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {BeaconProxy} from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {proxyWallet} from "./proxyWallet.sol";
import {IProxyWalletFactory} from "./interfaces/IProxyWalletFactory.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

/**
 * @title proxyWalletFactory
 * @notice Upgradeable Factory contract deploying UpgradeableBeacon proxies for user wallets.
 */
contract proxyWalletFactory is IProxyWalletFactory, Initializable, OwnableUpgradeable, UUPSUpgradeable {
    // Upgradeable beacon for proxy wallets
    address public beacon;

    // Registry tracking deployed proxy wallets
    mapping(address => bool) public override isProxyWallet;
    mapping(address => mapping(uint256 => address)) public override getWallet;

    // Reverse registry and deployment salt tracking (M-01)
    mapping(address => uint256) public override walletSalt;
    mapping(address => address) public override walletOwner;
    mapping(address => address[]) internal _userWallets;

    uint256[50] private __gap;

    /// @custom:oz-upgrades-unsafe-allow constructor
/**
 * @notice Constructor for the proxyWalletFactory.
 * @dev Disables initializers to prevent the implementation contract from being initialized.
 */
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes the factory with an implementation and an initial owner.
     * @dev Sets up the UpgradeableBeacon and transfers ownership.
     * @param _implementation The address of the initial wallet implementation.
     * @param initialOwner The address of the initial owner of this factory.
     */
    function initialize(address _implementation, address initialOwner) external initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();

        require(_implementation != address(0), "Invalid implementation");
        beacon = address(new UpgradeableBeacon(_implementation));
        
        address targetOwner = initialOwner != address(0) ? initialOwner : msg.sender;
        _transferOwnership(targetOwner);
    }

    /**
     * @notice Returns the current implementation address of the proxy wallets.
     * @dev Queries the UpgradeableBeacon for its current implementation.
     * @return The address of the current wallet implementation.
     */
    function implementation() external view override returns (address) {
        return UpgradeableBeacon(beacon).implementation();
    }

    /**
     * @notice Updates the wallet implementation used by all deployed proxy wallets.
     * @dev Only callable by the owner. Upgrades the beacon to point to the new implementation.
     * @param newImplementation The address of the new wallet implementation.
     */
    function updateWalletImplementation(address newImplementation) external onlyOwner {
        require(newImplementation != address(0), "Invalid implementation");
        UpgradeableBeacon(beacon).upgradeTo(newImplementation);
    }

    /**
     * @notice Computes a unique salt for deploying a proxy wallet.
     * @dev Uses keccak256 hash of the encoded owner address and provided salt.
     * @param owner The address of the wallet owner.
     * @param salt An arbitrary uint256 salt value.
     * @return The computed bytes32 salt hash.
     */
    function _getSalt(address owner, uint256 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(owner, salt));
    }

    /**
     * @notice Predicts or retrieves the address of a proxy wallet.
     * @dev If a wallet is already registered for owner at salt, returns that wallet address.
     * Otherwise, calculates the deterministic CREATE2 address bound to (owner, salt).
     * @param owner Wallet owner address.
     * @param salt Arbitrary salt parameter.
     * @return predicted The predicted or existing address of the proxy wallet.
     */
    function getWalletAddress(address owner, uint256 salt) public view override returns (address predicted) {
        address existing = getWallet[owner][salt];
        if (existing != address(0)) {
            return existing;
        }
        bytes32 saltHash = _getSalt(owner, salt);
        bytes memory bytecode = abi.encodePacked(
            type(BeaconProxy).creationCode,
            abi.encode(beacon, "")
        );
        predicted = Create2.computeAddress(saltHash, keccak256(bytecode), address(this));
    }

    /**
     * @notice Deploys a deterministic minimal proxy wallet for an owner.
     * @param owner Wallet owner address.
     * @param salt Arbitrary salt parameter.
     * @return wallet The address of the newly deployed proxy wallet.
     */
    function createWallet(address owner, uint256 salt) external override returns (address wallet) {
        require(owner != address(0), "proxyWalletFactory: ZERO_OWNER");
        require(getWallet[owner][salt] == address(0), "proxyWalletFactory: WALLET_ALREADY_EXISTS");

        bytes32 saltHash = _getSalt(owner, salt);
        bytes memory bytecode = abi.encodePacked(
            type(BeaconProxy).creationCode,
            abi.encode(beacon, "")
        );

        wallet = Create2.deploy(0, saltHash, bytecode);
        
        proxyWallet(payable(wallet)).initialize(owner, address(this));

        isProxyWallet[wallet] = true;
        getWallet[owner][salt] = wallet;
        walletSalt[wallet] = salt;
        walletOwner[wallet] = owner;
        _userWallets[owner].push(wallet);

        emit ProxyWalletCreated(owner, wallet, salt);
    }

    event WalletOwnershipTransferred(address indexed wallet, address indexed oldOwner, address indexed newOwner);

    /**
     * @notice Callback when a proxy wallet transfers ownership.
     * @dev Updates internal registries so newOwner is associated with the wallet and clears oldOwner.
     * @param oldOwner Previous owner of the wallet.
     * @param newOwner New owner of the wallet.
     */
    function onWalletOwnershipTransferred(address oldOwner, address newOwner) external override {
        require(isProxyWallet[msg.sender], "proxyWalletFactory: NOT_PROXY_WALLET");
        require(newOwner != address(0), "proxyWalletFactory: ZERO_OWNER");

        // Retain getWallet[creator][salt] permanently to preserve CREATE2 history and prevent redeployment collisions
        walletOwner[msg.sender] = newOwner;

        // Remove from old owner list
        address[] storage oldWallets = _userWallets[oldOwner];
        uint256 len = oldWallets.length;
        for (uint256 i = 0; i < len; i++) {
            if (oldWallets[i] == msg.sender) {
                oldWallets[i] = oldWallets[len - 1];
                oldWallets.pop();
                break;
            }
        }

        // Add to new owner list
        _userWallets[newOwner].push(msg.sender);

        emit WalletOwnershipTransferred(msg.sender, oldOwner, newOwner);
    }

    /**
     * @notice Returns all wallets currently owned by an address.
     * @param owner The wallet owner address to query.
     */
    function getWalletsByOwner(address owner) external view override returns (address[] memory) {
        return _userWallets[owner];
    }

    /**
     * @notice Authorizes an upgrade to a new factory implementation.
     * @dev Reverts if the caller is not the owner.
     * @param newImplementation Address of the new implementation contract.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}

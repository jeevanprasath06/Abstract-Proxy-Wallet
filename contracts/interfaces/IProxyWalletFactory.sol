// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

/**
 * @title IProxyWalletFactory
 * @notice Interface defining deployment and lookup routines for proxy wallet creation.
 */
interface IProxyWalletFactory {
    event ProxyWalletCreated(address indexed owner, address indexed proxyWallet, uint256 salt);

    function implementation() external view returns (address);
    function isProxyWallet(address proxyWallet) external view returns (bool);
    function getWallet(address owner, uint256 salt) external view returns (address);
    function getWalletAddress(address owner, uint256 salt) external view returns (address);
    function createWallet(address owner, uint256 salt) external returns (address wallet);
    function onWalletOwnershipTransferred(address oldOwner, address newOwner) external;
    function walletSalt(address proxyWallet) external view returns (uint256);
    function walletOwner(address proxyWallet) external view returns (address);
    function getWalletsByOwner(address owner) external view returns (address[] memory);
}

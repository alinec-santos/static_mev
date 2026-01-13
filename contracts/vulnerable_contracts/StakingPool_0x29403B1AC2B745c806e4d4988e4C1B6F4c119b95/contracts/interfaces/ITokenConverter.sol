// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IStakingPoolChild } from "./IStakingPoolChild.sol";

/// @title ITokenConverter is the interface for the token converter contract
/// It's used to convert token from one to another
interface ITokenConverter is IStakingPoolChild {
    /// @notice Emitted when token is converted
    /// @param fromToken The token address to convert from
    /// @param amountIn The amount of token to convert
    /// @param toToken The token address to convert to
    /// @param amountOut The amount of token converted
    event TokenConverted(address fromToken, uint256 amountIn, address toToken, uint256 amountOut);

    /// @notice Convert token from one to another
    /// @dev The _toToken should be transferred to the staking pool
    /// @param _amount The amount of token to convert
    /// @param _opt The optional data for converting
    function convertToken(uint256 _amount, bytes calldata _opt) external payable;
    function fromToken() external view returns (address);
    function toToken() external view returns (address);
}

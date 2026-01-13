// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IStakingPoolChild } from "./IStakingPoolChild.sol";

/// @title IStakingExecutor is the interface for staking executor contract.
/// It's used to stake asset token to staked token and withdraw staked token back to asset token.
/// The result of staking and withdrawing should be transferred to the owner of the staking executor.
interface IStakingExecutor is IStakingPoolChild {
    /// @notice Emitted when the asset token is staked to staked token
    /// @param assetAmount The amount of asset token staked
    /// @param stakedAmount The amount of staked token get by staking
    event Staked(uint256 assetAmount, uint256 stakedAmount);
    /// @notice Emitted when a withdraw request is submitted
    /// @param stakedAmount The amount of staked token to withdraw
    event WithdrawRequestSubmitted(uint256 stakedAmount);
    /// @notice Emitted when the withdrawn asset token is claimed
    event WithdrawRequestClaimed(uint256 assetAmount);

    /// @notice Stake asset token to staked token
    /// @param _amount The amount of asset token to stake
    /// @param _opt The optional data for staking
    function stake(uint256 _amount, bytes calldata _opt) external payable;
    /// @notice Withdraw staked token to asset token
    /// @param _amount The amount of staked token to withdraw
    /// @param _opt The optional data for withdrawing
    /// @dev The request NFT or other credentials may be stored here temporarily
    function requestWithdraw(uint256 _amount, bytes calldata _opt) external;
    /// @notice Claim The withdrawn asset token
    /// @param _opt The optional data for claiming
    /// @dev The claimed asset token should be transferred to the owner of the staking executor
    function claimWithdraw(bytes calldata _opt) external;
    /// @notice Withdraw unexpected token
    /// @param _token The token address to withdraw
    /// @param _amount The amount of token to withdraw
    /// @param _to The address to receive the withdrawn token
    function rescueWithdraw(address _token, uint256 _amount, address _to) external;

    /// @notice Check if the staking executor is claimable
    /// @param _opt The optional data for claiming
    function isClaimable(bytes calldata _opt) external view returns (bool);
    /// @notice Get staked token address
    /// @return The staked token address
    function stakedToken() external view returns (address);
    /// @notice Get asset token address
    /// @return The asset token address
    function assetToken() external view returns (address);
}

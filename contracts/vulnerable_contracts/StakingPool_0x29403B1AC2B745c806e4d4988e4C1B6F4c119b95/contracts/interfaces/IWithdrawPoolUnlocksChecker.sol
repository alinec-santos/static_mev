// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IWithdrawPoolUnlocksChecker is the interface for WithdrawPoolUnlocksChecker contract
interface IWithdrawPoolUnlocksChecker {
    /// @notice revert when the unlock amount is invalid
    /// @param _unlockLSDAmount The amount of LSD to unlock
    /// @param _maxUnlockLSDAmount The maximum amount of LSD allowed to be unlocked
    error InvalidUnlocks(uint256 _unlockLSDAmount, uint256 _maxUnlockLSDAmount);

    /// @notice Check if the unlock amount is valid
    function checkUnlocksLSDAmount(uint256 _unlockLSDAmount) external view;
}

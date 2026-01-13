// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IStakingPoolChild } from "./IStakingPoolChild.sol";

/// @title IRedemptionFulfiller is the interface for redemption fulfiller contract
/// It's used to fulfill redemption request from RedemptionAssetVault
interface IRedemptionFulfiller is IStakingPoolChild {
    /// @notice Emitted when a redemption request is fulfilled
    event RedemptionFulfilled(uint256 redemptionId, address[] tokens, uint256[] amounts);

    /// @notice Fulfill redemption request to RedemptionAssetVault
    /// @param _redemptionId The redemption request id
    /// @param _tokens The token addresses to fulfill
    /// @param _amount The amount of token to fulfill
    function fulfillRedemption(
        uint256 _redemptionId,
        address[] calldata _tokens,
        uint256[] calldata _amount
    ) external payable;

    /// @notice Withdraw unexpected token
    /// @param _token The token address to withdraw
    /// @param _amount The amount of token to withdraw
    /// @param _to The address to receive the withdrawn token
    function rescueWithdraw(address _token, uint256 _amount, address _to) external;
}

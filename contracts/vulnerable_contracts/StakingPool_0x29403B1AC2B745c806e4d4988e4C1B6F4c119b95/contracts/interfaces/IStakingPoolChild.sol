// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IStakingPoolChild is the interface for staking pool child contract
/// it's a abstract contract which is fully controlled by the staking pool
interface IStakingPoolChild {
    /// @notice Emitted when the staking pool is updated
    /// @param _stakingPool The new staking pool address
    event NewStakingPool(address _stakingPool);

    /// @notice Revert when the caller is not the staking pool
    error InvalidStakingPool(address _msgSender);

    /// @notice Get the staking pool address
    /// @return The staking pool address
    function stakingPool() external view returns (address);
}

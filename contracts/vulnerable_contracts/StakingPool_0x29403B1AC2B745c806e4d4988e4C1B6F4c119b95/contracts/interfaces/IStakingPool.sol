// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IStakingPool is the interface for StakingPool contract
/// This contract will hold most of asset token and staked token
interface IStakingPool {
    /// @notice emit when the operator is changed
    /// @param _operator The new operator address
    event NewOperator(address _operator);
    /// @notice emit when the next treasury is changed
    /// @param _nextTreasury The new next treasury address
    event NewNextTreasury(address _nextTreasury);
    /// @notice emit when the nav float rate is scheduled to change
    /// @param _newRate The new nav float rate
    /// @param _delay The delay time for the schedule operation
    event NewNavFloatRateScheduled(uint256 _newRate, uint256 _delay);
    /// @notice emit when the nav float rate is confirmed
    /// @param _newRate The new nav float rate
    event NewNavFloatRateConfirmed(uint256 _newRate);
    /// @notice emit when the scheduled operation to change nav float rate is cancelled
    /// @param _newRate The new nav float rate that has been cancelled
    event NewNavFloatRateCancelled(uint256 _newRate);
    /// @notice emit when the delay time is scheduled to change
    /// @param _newDelay The new delay time
    /// @param _delay The delay time for the schedule operation
    event NewDelayScheduled(uint256 _newDelay, uint256 _delay);
    /// @notice emit when the delay time is confirmed
    /// @param _newDelay The min delay time
    event NewDelayConfirmed(uint256 _newDelay);
    /// @notice emit when the scheduled operation to change delay time is cancelled
    /// @param _newDelay The new delay time that has been cancelled
    event NewDelayCancelled(uint256 _newDelay);
    /// @notice emit when the redemption fulfiller is scheduled to change
    /// @param _redemptionFulfiller The new redemption fulfiller address
    /// @param _delay The delay time for the schedule operation
    event NewRedemptionFulfillerScheduled(address _redemptionFulfiller, uint256 _delay);
    /// @notice emit when the redemption fulfiller is confirmed
    /// @param _redemptionFulfiller The new redemption fulfiller address
    event NewRedemptionFulfillerConfirmed(address _redemptionFulfiller);
    /// @notice emit when the scheduled operation to change redemption fulfiller is cancelled
    /// @param _redemptionFulfiller The new redemption fulfiller address
    event NewRedemptionFulfillerCancelled(address _redemptionFulfiller);
    /// @notice emit when the withdraw pool unlocks checker is scheduled to change
    /// @param _withdrawPoolUnlocksChecker The new withdraw pool unlocks checker address
    /// @param _delay The delay time for the schedule operation
    event NewWithdrawPoolUnlocksCheckerScheduled(address _withdrawPoolUnlocksChecker, uint256 _delay);
    /// @notice emit when the withdraw pool unlocks checker is confirmed
    /// @param _withdrawPoolUnlocksChecker The new withdraw pool unlocks checker address
    event NewWithdrawPoolUnlocksCheckerConfirmed(address _withdrawPoolUnlocksChecker);
    /// @notice emit when the scheduled operation to change withdraw pool unlocks checker is cancelled
    /// @param _withdrawPoolUnlocksChecker The new withdraw pool unlocks checker address
    event NewWithdrawPoolUnlocksCheckerCancelled(address _withdrawPoolUnlocksChecker);
    /// @notice emit when a executor is removed
    /// @param _executor The executor address
    event ExecutorRemoved(address _executor);
    /// @notice emit when a executor is scheduled to be added
    /// @param _executor The executor address
    /// @param _delay The delay time for the schedule operation
    event ExecutorAddedScheduled(address _executor, uint256 _delay);
    /// @notice emit when a executor is confirmed to be added
    /// @param _executor The executor address
    event ExecutorAddedConfirmed(address _executor);
    /// @notice emit when the scheduled operation to add executor is cancelled
    /// @param _executor The executor address
    event ExecutorAddedCancelled(address _executor);
    /// @notice emit when a token converter is scheduled to be added
    /// @param _converter The token converter address
    /// @param _delay The delay time for the schedule operation
    event TokenConverterAddedScheduled(address _converter, uint256 _delay);
    /// @notice emit when a token converter is confirmed to be added
    /// @param _converter The token converter address
    event TokenConverterAddedConfirmed(address _converter);
    /// @notice emit when the scheduled operation to add token converter is cancelled
    /// @param _converter The token converter address
    event TokenConverterAddedCancelled(address _converter);
    /// @notice emit when a token converter is removed
    /// @param _converter The token converter address
    event TokenConverterRemoved(address _converter);
    /// @notice emit when a air dropper is scheduled to be added
    /// @param _airDropper The air dropper address
    /// @param _delay The delay time for the schedule operation
    event AirDropperAddedScheduled(address _airDropper, uint256 _delay);
    /// @notice emit when a air dropper is confirmed to be added
    /// @param _airDropper The air dropper address
    event AirDropperAddedConfirmed(address _airDropper);
    /// @notice emit when the scheduled operation to add air dropper is cancelled
    /// @param _airDropper The air dropper address
    event AirDropperAddedCancelled(address _airDropper);
    /// @notice emit when a air dropper is removed
    /// @param _airDropper The air dropper address
    event AirDropperRemoved(address _airDropper);

    /// emit when a new token converter is added or removed
    /// @param _converter The token converter address
    /// @param _added True if the token converter is added, false if the token converter is removed
    event TokenConverterUpdated(address _converter, bool _added);

    /// @notice Revert when the child's staking pool is not this contract
    error InvalidChild(address _child, address _stakingPool);
    /// @notice Revert when the staking executor is not registered
    error InvalidStakingExecutor(address _executor);
    /// @notice Revert when the token converter is not registered
    error InvalidTokenConverter(address _converter);
    /// @notice Revert when the air dropper is not registered
    error InvalidAirDropper(address _airDropper);
    /// @notice Revert when the redemption fulfiller is not registered
    error InvalidRedemptionFulfiller(address _fulfiller);
    /// @notice Revert when the msg sender is not the operator
    error InvalidOperator(address _operator);
    /// @notice Revert when the msg sender is not the manager
    error InvalidManager(address _manager);
    /// @notice Revert when unlock amount is invalid
    error InvalidUnlockAmount(uint256 _lsdAmount, uint256 _assetAmount);
    /// @notice Revert when the claim airdrop failed
    error ClaimAirdropFailed(bytes ret);

    /// @notice Convert token from one to another
    /// @param _converter The token converter address
    /// @param _amount The amount of token to convert
    /// @param _opt The optional data for converting
    function convertToken(address _converter, uint256 _amount, bytes calldata _opt) external;
    /// @notice Withdraw asset token from deposit pool
    /// @param _amount The amount of asset token to withdraw
    function withdrawFromDepositPool(uint256 _amount) external;
    /// @notice Stake asset token to staked token
    /// @param _stakingExecutors The staking executor addresses
    /// @param _amounts The amount of asset token to stake
    /// @param _opts The optional data for staking
    function stake(address[] calldata _stakingExecutors, uint256[] calldata _amounts, bytes[] calldata _opts) external;
    /// @notice Withdraw asset token from deposit pool and stake to staked token
    /// @param _withdrawAmount The amount of asset token to withdraw from deposit pool
    /// @param _stakingExecutors The staking executor addresses
    /// @param _amounts The amount of asset token to stake
    /// @param _opts The optional data for staking
    function stakeFromDepositPool(
        uint256 _withdrawAmount,
        address[] calldata _stakingExecutors,
        uint256[] calldata _amounts,
        bytes[] calldata _opts
    ) external;
    /// @notice Request to withdraw staked token to asset token
    /// @param _stakingExecutors The staking executor addresses
    /// @param _amounts The amount of staked token to withdraw
    /// @param _opts The optional data for withdrawing
    function requestWithdraw(
        address[] calldata _stakingExecutors,
        uint256[] calldata _amounts,
        bytes[] calldata _opts
    ) external;
    /// @notice Claim the withdrawn asset token
    /// @param _stakingExecutors The staking executor addresses
    /// @param _opts The optional data for claiming
    function claimWithdraw(address[] calldata _stakingExecutors, bytes[] calldata _opts) external;
    /// @notice Claim the withdrawn asset token and transfer to withdraw pool to unlock
    /// @param _stakingExecutors The staking executor addresses
    /// @param _opts The optional data for claiming
    /// @param _lsdAmount The amount of LSD token to unlock
    /// @param _totalAmount The total amount of asset token to fulfill unlock
    function claimWithdrawToUnlock(
        address[] calldata _stakingExecutors,
        bytes[] calldata _opts,
        uint256 _lsdAmount,
        uint256 _totalAmount
    ) external payable;
    /// @notice Transfer asset token to add withdraw pool unlock
    /// @param _lsdAmount The amount of LSD token to unlock
    /// @param _amount The amount of asset token to fulfill unlock
    function addWithdrawPoolUnlocks(uint256 _lsdAmount, uint256 _amount) external payable;
    /// @notice Fulfill redemption request to RedemptionAssetVault
    /// @param _redemptionId The redemption request id
    /// @param _tokens The token addresses to fulfill
    /// @param _amount The amount of token to fulfill
    function fulfillRedemption(
        uint256 _redemptionId,
        address[] calldata _tokens,
        uint256[] calldata _amount
    ) external payable;
    /// @notice Claim airdrop on any contract
    /// @dev Should be called carefully, because this method would call any contract with the given call data
    /// @param _to The address to claim the airdrop
    /// @param _opt The call data for calling the contract on contract(_to) to claim airdrop
    function claimAirdrop(address _to, bytes calldata _opt) external payable;
    /// @notice Withdraw unexpected token or staked token to the next treasury
    /// The staked token will be used for further investment
    /// @param _token The token address to withdraw
    /// @param _amount The amount of token to withdraw
    function rescueWithdraw(address _token, uint256 _amount) external;

    /// @notice Check if a withdraw request on the staking executor is claimable
    /// @param _stakingExecutor The staking executor address
    /// @param _opt The bytes data for specified withdraw request
    /// @return True if the withdraw request is claimable, otherwise false
    function isClaimable(address _stakingExecutor, bytes calldata _opt) external view returns (bool);
    /// @notice Get the asset token address
    /// @return The asset token address
    function assetToken() external view returns (address);
    /// @notice Get the deposit pool address
    /// @return The deposit pool address
    function depositPool() external view returns (address);
    /// @notice Get the withdraw pool address
    /// @return The withdraw pool address
    function withdrawPool() external view returns (address);
}

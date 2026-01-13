// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IWithdrawPool {
    event SetUnstaker(address unstaker);
    event SetLzReceiveGasLimit(uint128 gasLimit);
    event Unlocked(uint256 unlockedLSDAmount, uint256 amount);
    event SmartSavingsOnGravityUpdated(address addr);

    event PoolUnlocksBridged(uint256 totalPoolUnlocks, uint256 fee, bytes32 guid);
    event Claimed(address to, uint256 underlyingTokenAmount, uint256 amountOfLSD, uint256 timestamp, bytes32 guid);

    error InvalidCaller();
    error WithdrawSentFailed();
    error InvalidLSD();
    error InvalidUnlockAmount();
    error InvalidBridgeMessage();
    error InvalidBridgeMessageFrom(address _address);
    error InvalidUnderlyingToken();
    error InvalidNav(uint256 _nav);
    error InvalidClaimAmount(uint256 _amount);
    error InvalidTimestamp(uint256 _tradingDays);
    error ClaimAmountTooSmall(uint256 _amount);
    error InsufficientFee(uint256 wanted, uint256 provided);
    error SendFailed(address to, uint256 amount);

    function setUnstaker(address _unstaker) external;
    function rescueWithdraw(address _token, address _to) external;
    function addPoolUnlocks(uint256 _unlockedLSDAmount, uint256 _amount) external payable;
    function totalPoolUnlocks() external returns (uint256);
    function unlockFee() external view returns (uint256);
}

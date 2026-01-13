// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IStakingPool } from "../interfaces/IStakingPool.sol";
import { IStakingExecutor } from "../interfaces/IStakingExecutor.sol";
import { ITokenConverter } from "../interfaces/ITokenConverter.sol";
import { IDepositPool } from "../depositPool/IDepositPool.sol";
import { IWithdrawPool } from "../interfaces/IWithdrawPool.sol";
import { IVaultNav } from "../vaultNav/IVaultNav.sol";
import { IRedemptionFulfiller } from "../interfaces/IRedemptionFulfiller.sol";
import { TimelockedOperations } from "../utils/TimelockedOperations.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { Ownable2Step, Ownable } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { RescueWithdraw } from "../utils/RescueWithdraw.sol";
import { EmptyChecker } from "../utils/EmptyChecker.sol";
import { IStakingPool } from "../interfaces/IStakingPool.sol";
import { IStakingPoolChild } from "../interfaces/IStakingPoolChild.sol";
import { IWithdrawPoolUnlocksChecker } from "../interfaces/IWithdrawPoolUnlocksChecker.sol";

/// @title StakingPool is the contract to manage asset token and staked tokens
contract StakingPool is Ownable2Step, Pausable, RescueWithdraw, IStakingPool {
    using TimelockedOperations for TimelockedOperations.AddressOperation;
    using TimelockedOperations for TimelockedOperations.Uint256Operation;
    using EnumerableSet for EnumerableSet.AddressSet;
    using SafeERC20 for IERC20;

    /// @notice deposit pool address, asset token are deposited here
    /// and will be withdrew to this contract to do batch stake
    address public immutable DEPOSIT_POOL;
    /// @notice withdraw pool address, to hold asset token for claim
    /// and this contract will do batch withdraw to fulfill unlock request
    address public immutable WITHDRAW_POOL;
    /// @notice the address to store the NAV of the vault
    address public immutable VAULT_NAV;
    /// @notice operator address, to call stake, withdraw, claim and fulfill redemption
    address public operator;
    /// @notice manager address, to call convert token
    address public manager;
    /// @notice the address to hold some staked tokens beside this contract
    /// such as pendle pt.
    address public nextTreasury;
    /// @notice the nav float rate to calculate the nav
    /// @dev nav in range [nav * (1 - navFloatRate / 10000), nav * (1 + navFloatRate / 10000)] is acceptable
    /// nav = assetTokenAmount / lsdTokenAmount
    uint256 public navFloatRate = 100;
    TimelockedOperations.Uint256Operation private _pendingNavFloatRate;
    /// @notice the delay time for the schedule operation
    uint256 public delay;
    TimelockedOperations.Uint256Operation private _pendingDelay;
    /// @notice the redemption fulfiller address to fulfill redemption request
    address public redemptionFulfiller;
    TimelockedOperations.AddressOperation private _pendingRedemptionFulfiller;
    /// @notice the hooker contract address to check the _lsdAmount argument of addWithdrawPoolUnlocks function
    address public withdrawPoolUnlocksChecker;
    TimelockedOperations.AddressOperation private _pendingWithdrawPoolUnlocksChecker;

    /// @notice staking executors set
    EnumerableSet.AddressSet private _innerStakingExecutors;
    TimelockedOperations.AddressOperation private _pendingStakingExecutor;
    /// @notice token converters set
    EnumerableSet.AddressSet private _innerTokenConverters;
    TimelockedOperations.AddressOperation private _pendingTokenConverter;
    /// @notice air droppers set
    EnumerableSet.AddressSet private _innerAirDroppers;
    TimelockedOperations.AddressOperation private _pendingAirDropper;

    modifier onlyOperator() {
        if (msg.sender != operator) {
            revert InvalidOperator(msg.sender);
        }
        _;
    }

    modifier onlyManager() {
        if (msg.sender != manager) {
            revert InvalidManager(msg.sender);
        }
        _;
    }

    modifier onlyValidStakingExecutor(address executor) {
        if (!_innerStakingExecutors.contains(executor)) {
            revert InvalidStakingExecutor(executor);
        }
        _;
    }

    modifier onlyValidStakingExecutors(address[] calldata executors) {
        for (uint256 i = 0; i < executors.length; i++) {
            if (!_innerStakingExecutors.contains(executors[i])) {
                revert InvalidStakingExecutor(executors[i]);
            }
        }
        _;
    }

    modifier onlyValidTokenConverter(address converter) {
        if (!_innerTokenConverters.contains(converter)) {
            revert InvalidTokenConverter(converter);
        }
        _;
    }

    modifier onlyValidAirDropper(address airDropper) {
        if (!_innerAirDroppers.contains(airDropper)) {
            revert InvalidAirDropper(airDropper);
        }
        _;
    }

    modifier onlyValidRedemptionFulfiller(address fulfiller) {
        if (fulfiller != redemptionFulfiller) {
            revert InvalidRedemptionFulfiller(fulfiller);
        }
        _;
    }

    modifier onlyValidChildToAdd(address child) {
        if (IStakingPoolChild(child).stakingPool() != address(this)) {
            revert InvalidChild(child, IStakingPoolChild(child).stakingPool());
        }
        _;
    }

    modifier onlyValidUnlockAmount(uint256 lsdAmount, uint256 assetAmount) {
        address lsd = IDepositPool(DEPOSIT_POOL).LSD();
        uint256 assetTokenDecimals = IDepositPool(DEPOSIT_POOL).ASSET_TOKEN_DECIMALS();
        uint256 assetAmountE18 = assetAmount * 10 ** (18 - assetTokenDecimals);
        uint256 averageNav = (assetAmountE18 * 10 ** 18) / lsdAmount;
        (uint256 currentNav, ) = IVaultNav(VAULT_NAV).getNavByTimestamp(lsd, uint48(block.timestamp));
        // The unlock amount is the accumulated amount of withdraw requests submitted within a period.
        // And the averageNav of the period should be close to the currentNav.
        // So we can get a limit to ensure the unlock amount is valid.
        // currentNav * (1 - navFloatRate / 10000) <= averageNav <= currentNav * (1 + navFloatRate / 10000)
        if (
            averageNav < (currentNav * (10000 - navFloatRate)) / 10000 ||
            averageNav > (currentNav * (10000 + navFloatRate)) / 10000
        ) {
            revert InvalidUnlockAmount(lsdAmount, assetAmount);
        }
        if (withdrawPoolUnlocksChecker != address(0)) {
            IWithdrawPoolUnlocksChecker(withdrawPoolUnlocksChecker).checkUnlocksLSDAmount(lsdAmount);
        }
        _;
    }

    constructor(
        address _owner, // solhint-disable-line no-unused-vars
        address _nextTreasury,
        address _depositPool,
        address _withdrawPool,
        address _vaultNav,
        address _operator,
        address _manager
    ) Ownable(_owner) {
        EmptyChecker.checkEmptyAddress(_nextTreasury);
        EmptyChecker.checkEmptyAddress(_depositPool);
        EmptyChecker.checkEmptyAddress(_withdrawPool);
        EmptyChecker.checkEmptyAddress(_vaultNav);
        EmptyChecker.checkEmptyAddress(_operator);
        EmptyChecker.checkEmptyAddress(_manager);
        nextTreasury = _nextTreasury;
        DEPOSIT_POOL = _depositPool;
        WITHDRAW_POOL = _withdrawPool;
        VAULT_NAV = _vaultNav;
        operator = _operator;
        manager = _manager;
    }

    receive() external payable {}

    /// @notice Pause the contract.
    /// @dev Emit a `Paused` event.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Pause the contract.
    /// @dev Emit a `Unpaused` event.
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice Update the operator address.
    /// @param _operator The new operator address.
    function updateOperator(address _operator) external onlyOwner {
        EmptyChecker.checkEmptyAddress(_operator);
        operator = _operator;
        emit NewOperator(_operator);
    }

    /// @notice Update the next treasury address.
    /// @param _nextTreasury The new next treasury address.
    function updateNextTreasury(address _nextTreasury) external onlyOwner {
        EmptyChecker.checkEmptyAddress(_nextTreasury);
        nextTreasury = _nextTreasury;
        emit NewNextTreasury(_nextTreasury);
    }

    function updateNavFloatRate(uint256 _newNavFloatRate) external onlyOwner {
        _pendingNavFloatRate.scheduleOperation(_newNavFloatRate, delay);
        emit NewNavFloatRateScheduled(_newNavFloatRate, delay);
    }

    function confirmNavFloatRate(uint256 _newNavFloatRate) external onlyOwner {
        _pendingNavFloatRate.executeOperation(_newNavFloatRate);
        navFloatRate = _newNavFloatRate;
        emit NewNavFloatRateConfirmed(_newNavFloatRate);
    }

    function cancelNavFloatRate() external onlyOwner {
        uint256 toCancel = pendingNavFloatRate();
        _pendingNavFloatRate.cancelOperation();
        emit NewNavFloatRateCancelled(toCancel);
    }

    /// @notice Update the delay time.
    /// @param _newDelay The new min delay time.
    function updateDelay(uint256 _newDelay) external onlyOwner {
        _pendingDelay.scheduleOperation(_newDelay, delay);
        emit NewDelayScheduled(_newDelay, delay);
    }

    /// @notice Confirm the scheduled operation to change delay time.
    /// @param _newDelay The new min delay time.
    function confirmDelay(uint256 _newDelay) external onlyOwner {
        _pendingDelay.executeOperation(_newDelay);
        delay = _newDelay;
        emit NewDelayConfirmed(_newDelay);
    }

    /// @notice Cancel the scheduled operation to change delay time.
    function cancelDelay() external onlyOwner {
        uint256 toCancel = pendingDelay();
        _pendingDelay.cancelOperation();
        emit NewDelayCancelled(toCancel);
    }

    /// @notice Update the redemption fulfiller address.
    /// @param _newRedemptionFulfiller The new redemption fulfiller address.
    function updateRedemptionFulfiller(
        address _newRedemptionFulfiller
    ) external onlyOwner onlyValidChildToAdd(_newRedemptionFulfiller) {
        EmptyChecker.checkEmptyAddress(_newRedemptionFulfiller);
        _pendingRedemptionFulfiller.scheduleOperation(_newRedemptionFulfiller, delay);
        emit NewRedemptionFulfillerScheduled(_newRedemptionFulfiller, delay);
    }

    /// @notice Confirm the scheduled operation to change redemption fulfiller.
    /// @param _newRedemptionFulfiller The new redemption fulfiller address.
    function confirmRedemptionFulfiller(address _newRedemptionFulfiller) external onlyOwner {
        _pendingRedemptionFulfiller.executeOperation(_newRedemptionFulfiller);
        redemptionFulfiller = _newRedemptionFulfiller;
        emit NewRedemptionFulfillerConfirmed(_newRedemptionFulfiller);
    }

    /// @notice Cancel the scheduled operation to change redemption fulfiller.
    function cancelRedemptionFulfiller() external onlyOwner {
        address toCancelAddr = pendingRedemptionFulfiller();
        _pendingRedemptionFulfiller.cancelOperation();
        emit NewRedemptionFulfillerCancelled(toCancelAddr);
    }

    /// @notice Update the withdraw pool unlocks checker address.
    /// @param _newWithdrawPoolUnlocksChecker The new withdraw pool unlocks checker address.
    function updateWithdrawPoolUnlocksChecker(address _newWithdrawPoolUnlocksChecker) external onlyOwner {
        _pendingWithdrawPoolUnlocksChecker.scheduleOperation(_newWithdrawPoolUnlocksChecker, delay);
        emit NewWithdrawPoolUnlocksCheckerScheduled(_newWithdrawPoolUnlocksChecker, delay);
    }

    /// @notice Confirm the scheduled operation to change withdraw pool unlocks checker.
    /// @param _newWithdrawPoolUnlocksChecker The new withdraw pool unlocks checker address.
    function confirmWithdrawPoolUnlocksChecker(address _newWithdrawPoolUnlocksChecker) external onlyOwner {
        _pendingWithdrawPoolUnlocksChecker.executeOperation(_newWithdrawPoolUnlocksChecker);
        withdrawPoolUnlocksChecker = _newWithdrawPoolUnlocksChecker;
        emit NewWithdrawPoolUnlocksCheckerConfirmed(_newWithdrawPoolUnlocksChecker);
    }

    /// @notice Cancel the scheduled operation to change withdraw pool unlocks checker.
    function cancelWithdrawPoolUnlocksChecker() external onlyOwner {
        address toCancelAddr = pendingWithdrawPoolUnlocksChecker();
        _pendingWithdrawPoolUnlocksChecker.cancelOperation();
        emit NewWithdrawPoolUnlocksCheckerCancelled(toCancelAddr);
    }

    /// @notice Remove staking executor address.
    /// @param _executor The staking executor address.
    function removeStakingExecutor(address _executor) external onlyOwner {
        _innerStakingExecutors.remove(_executor);
        emit ExecutorRemoved(_executor);
    }

    /// @notice Add staking executor address.
    /// @param _executor The staking executor address.
    function addStakingExecutor(address _executor) external onlyOwner onlyValidChildToAdd(_executor) {
        EmptyChecker.checkEmptyAddress(_executor);
        _pendingStakingExecutor.scheduleOperation(_executor, delay);
        emit ExecutorAddedScheduled(_executor, delay);
    }

    /// @notice Confirm the scheduled operation to add staking executor.
    /// @param _executor The staking executor address.
    function confirmAddStakingExecutor(address _executor) external onlyOwner {
        _pendingStakingExecutor.executeOperation(_executor);
        _innerStakingExecutors.add(_executor);
        emit ExecutorAddedConfirmed(_executor);
    }

    /// @notice Cancel the scheduled operation to add staking executor.
    function cancelAddStakingExecutor() external onlyOwner {
        address toCancelAddr = pendingStakingExecutor();
        _pendingStakingExecutor.cancelOperation();
        emit ExecutorAddedCancelled(toCancelAddr);
    }

    /// @notice Remove token converter address.
    /// @param _converter The token converter address.
    function removeTokenConverter(address _converter) external onlyOwner {
        _innerTokenConverters.remove(_converter);
        emit TokenConverterRemoved(_converter);
    }

    /// @notice Add token converter address.
    /// @param _converter The token converter address.
    function addTokenConverter(address _converter) external onlyOwner onlyValidChildToAdd(_converter) {
        EmptyChecker.checkEmptyAddress(_converter);
        _pendingTokenConverter.scheduleOperation(_converter, delay);
        emit TokenConverterAddedScheduled(_converter, delay);
    }

    /// @notice Confirm the scheduled operation to add token converter.
    /// @param _converter The token converter address.
    function confirmAddTokenConverter(address _converter) external onlyOwner {
        _pendingTokenConverter.executeOperation(_converter);
        _innerTokenConverters.add(_converter);
        emit TokenConverterAddedConfirmed(_converter);
    }

    /// @notice Cancel the scheduled operation to add token converter.
    function cancelAddTokenConverter() external onlyOwner {
        address toCancelAddr = pendingTokenConverter();
        _pendingTokenConverter.cancelOperation();
        emit TokenConverterAddedCancelled(toCancelAddr);
    }

    /// @notice Remove air dropper address.
    /// @param _airDropper The air dropper address.
    function removeAirDropper(address _airDropper) external onlyOwner {
        _innerAirDroppers.remove(_airDropper);
        emit AirDropperRemoved(_airDropper);
    }

    /// @notice Add air dropper address.
    /// @param _airDropper The air dropper address.
    function addAirDropper(address _airDropper) external onlyOwner {
        EmptyChecker.checkEmptyAddress(_airDropper);
        _pendingAirDropper.scheduleOperation(_airDropper, delay);
        emit AirDropperAddedScheduled(_airDropper, delay);
    }

    /// @notice Confirm the scheduled operation to add air dropper.
    /// @param _airDropper The air dropper address.
    function confirmAddAirDropper(address _airDropper) external onlyOwner {
        _pendingAirDropper.executeOperation(_airDropper);
        _innerAirDroppers.add(_airDropper);
        emit AirDropperAddedConfirmed(_airDropper);
    }

    /// @notice Cancel the scheduled operation to add air dropper.
    function cancelAddAirDropper() external onlyOwner {
        address toCancelAddr = pendingAirDropper();
        _pendingAirDropper.cancelOperation();
        emit AirDropperAddedCancelled(toCancelAddr);
    }

    /// @notice Claim airdrop on any contract
    /// @dev Should be called carefully, because this method would call any contract with the given call data
    /// @param _to The address to claim the airdrop
    /// @param _opt The call data for calling the contract on contract(_to) to claim airdrop
    function claimAirdrop(
        address _to,
        bytes calldata _opt
    ) external payable override onlyOwner onlyValidAirDropper(_to) {
        (bool success, bytes memory ret) = _to.call{ value: msg.value }(_opt);
        if (!success) {
            revert ClaimAirdropFailed(ret);
        }
    }

    /// @notice Withdraw asset token from deposit pool and stake to staking executor
    /// @param _withdrawAmount The amount of asset token to withdraw
    /// @param _stakingExecutors The staking executor addresses
    /// @param _amounts The amount of asset token to stake
    /// @param _opts The optional data for staking
    function stakeFromDepositPool(
        uint256 _withdrawAmount,
        address[] calldata _stakingExecutors,
        uint256[] calldata _amounts,
        bytes[] calldata _opts
    ) external override onlyOperator onlyValidStakingExecutors(_stakingExecutors) {
        withdrawFromDepositPool(_withdrawAmount);
        stake(_stakingExecutors, _amounts, _opts);
    }

    /// @notice Request to withdraw staked token to asset token
    /// @param _stakingExecutors The staking executor addresses
    /// @param _amounts The amount of staked token to withdraw
    /// @param _opts The optional data for withdrawing
    function requestWithdraw(
        address[] calldata _stakingExecutors,
        uint256[] calldata _amounts,
        bytes[] calldata _opts
    ) external override onlyOperator onlyValidStakingExecutors(_stakingExecutors) {
        for (uint256 i = 0; i < _stakingExecutors.length; i++) {
            IERC20(IStakingExecutor(_stakingExecutors[i]).stakedToken()).forceApprove(
                _stakingExecutors[i],
                _amounts[i]
            );
            IStakingExecutor(_stakingExecutors[i]).requestWithdraw(_amounts[i], _opts[i]);
        }
    }

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
    ) external payable override onlyOperator onlyValidStakingExecutors(_stakingExecutors) {
        claimWithdraw(_stakingExecutors, _opts);
        addWithdrawPoolUnlocks(_lsdAmount, _totalAmount);
    }

    /// @notice Fulfill redemption request by redemption fulfiller
    /// @param _redemptionId The redemption request id
    /// @param _tokens The token addresses to fulfill
    /// @param _amount The amount of token to fulfill
    function fulfillRedemption(
        uint256 _redemptionId,
        address[] calldata _tokens,
        uint256[] calldata _amount
    ) external payable override onlyOperator {
        uint256 sendValue = 0;
        for (uint256 i = 0; i < _tokens.length; i++) {
            if (_tokens[i] == address(0)) {
                sendValue += _amount[i];
            } else {
                IERC20(_tokens[i]).forceApprove(redemptionFulfiller, _amount[i]);
            }
        }
        IRedemptionFulfiller(redemptionFulfiller).fulfillRedemption{ value: sendValue }(
            _redemptionId,
            _tokens,
            _amount
        );
    }

    /// @notice Convert token from one to another
    /// @param _converter The token converter address
    /// @param _amount The amount of token to convert
    /// @param _opt The optional data for converting
    function convertToken(
        address _converter,
        uint256 _amount,
        bytes calldata _opt
    ) external override onlyManager onlyValidTokenConverter(_converter) {
        address _fromToken = ITokenConverter(_converter).fromToken();
        if (_fromToken == address(0)) {
            // If fromToken is native token, transfer by calling with value
            ITokenConverter(_converter).convertToken{ value: _amount }(_amount, _opt);
        } else {
            // If fromToken is erc20 token, transfer by erc20 approve and transferFrom
            IERC20(_fromToken).forceApprove(_converter, _amount);
            ITokenConverter(_converter).convertToken(_amount, _opt);
        }
    }

    /// @notice Withdraw unexpected token or staked token for further investment
    /// @dev These tokens should be only sent to next treasury address
    /// @param token The token address to withdraw
    /// @param amount The amount of token to withdraw
    function rescueWithdraw(address token, uint256 amount) external onlyOwner {
        _sendToken(token, nextTreasury, amount);
    }

    /// @notice Check if the staking executor is claimable
    /// @param _stakingExecutor The staking executor address
    /// @param _opt The optional data for check claimable
    function isClaimable(address _stakingExecutor, bytes calldata _opt) external view returns (bool) {
        return IStakingExecutor(_stakingExecutor).isClaimable(_opt);
    }

    /// @notice Get the deposit pool address
    /// @return The deposit pool address
    function depositPool() external view override returns (address) {
        return DEPOSIT_POOL;
    }

    /// @notice Get the withdraw pool address
    /// @return The withdraw pool address
    function withdrawPool() external view override returns (address) {
        return WITHDRAW_POOL;
    }

    /// @notice Claim the withdrawn asset token
    /// @param _stakingExecutors The staking executor addresses
    /// @param _opts The optional data for claiming
    function claimWithdraw(
        address[] calldata _stakingExecutors,
        bytes[] calldata _opts
    ) public override onlyOperator onlyValidStakingExecutors(_stakingExecutors) {
        for (uint256 i = 0; i < _stakingExecutors.length; i++) {
            IStakingExecutor(_stakingExecutors[i]).claimWithdraw(_opts[i]);
        }
    }

    /// @notice Add unlock to withdraw pool
    /// @param _lsdAmount The amount of LSD token to unlock
    /// @param _amount The amount of asset token to unlock
    function addWithdrawPoolUnlocks(
        uint256 _lsdAmount,
        uint256 _amount
    ) public payable onlyOperator onlyValidUnlockAmount(_lsdAmount, _amount) {
        // unlock fee in native token
        uint256 valueToSend = IWithdrawPool(WITHDRAW_POOL).unlockFee();
        address token = assetToken();
        if (token == address(0)) {
            // If asset token is native token, unlock fee and asset token amount should be sent together
            valueToSend += _amount;
        } else {
            // If asset token is erc20 token, should approve withdraw pool to transfer asset token
            IERC20(token).forceApprove(WITHDRAW_POOL, _amount);
        }
        IWithdrawPool(WITHDRAW_POOL).addPoolUnlocks{ value: valueToSend }(_lsdAmount, _amount);
    }

    /// @notice Withdraw asset token from deposit pool
    /// @param _withdrawAmount The amount of asset token to withdraw
    function withdrawFromDepositPool(uint256 _withdrawAmount) public onlyOperator {
        IDepositPool(DEPOSIT_POOL).withdraw(_withdrawAmount);
    }

    /// @notice Stake asset token to staked token
    /// @param _stakingExecutors The staking executor addresses
    /// @param _amounts The amount of asset token to stake
    /// @param _opts The optional data for staking
    function stake(
        address[] calldata _stakingExecutors,
        uint256[] calldata _amounts,
        bytes[] calldata _opts
    ) public override onlyOperator onlyValidStakingExecutors(_stakingExecutors) {
        for (uint256 i = 0; i < _stakingExecutors.length; i++) {
            if (assetToken() == address(0)) {
                // If asset token is native token, transfer by calling with value
                IStakingExecutor(_stakingExecutors[i]).stake{ value: _amounts[i] }(_amounts[i], _opts[i]);
            } else {
                // If asset token is erc20 token, transfer by erc20 approve and transferFrom
                IERC20(assetToken()).forceApprove(_stakingExecutors[i], _amounts[i]);
                IStakingExecutor(_stakingExecutors[i]).stake(_amounts[i], _opts[i]);
            }
        }
    }

    /// @notice Get staked token address
    /// @return The staked token address
    function assetToken() public view override returns (address) {
        return IDepositPool(DEPOSIT_POOL).ASSET_TOKEN();
    }

    /// @notice Get staking executors
    /// @return The staking executor addresses
    function stakingExecutors() public view returns (address[] memory) {
        return _innerStakingExecutors.values();
    }

    /// @notice Get token converters
    /// @return The token converter addresses
    function tokenConverters() public view returns (address[] memory) {
        return _innerTokenConverters.values();
    }

    /// @notice Get air droppers
    /// @return The air dropper addresses
    function airDroppers() public view returns (address[] memory) {
        return _innerAirDroppers.values();
    }

    /// @notice Get the pending nav float rate
    /// @return The pending nav float rate
    function pendingNavFloatRate() public view returns (uint256) {
        return _pendingNavFloatRate.pendingValue();
    }

    /// @notice Get the pending delay time
    /// @return The pending delay time
    function pendingDelay() public view returns (uint256) {
        return _pendingDelay.pendingValue();
    }

    /// @notice Get the pending redemption fulfiller
    /// @return The pending redemption fulfiller
    function pendingRedemptionFulfiller() public view returns (address) {
        return _pendingRedemptionFulfiller.pendingValue();
    }

    /// @notice Get the pending withdraw pool unlocks checker
    /// @return The pending withdraw pool unlocks checker
    function pendingWithdrawPoolUnlocksChecker() public view returns (address) {
        return _pendingWithdrawPoolUnlocksChecker.pendingValue();
    }

    /// @notice Get the pending staking executor
    /// @return The pending staking executor
    function pendingStakingExecutor() public view returns (address) {
        return _pendingStakingExecutor.pendingValue();
    }

    /// @notice Get the pending token converter
    /// @return The pending token converter
    function pendingTokenConverter() public view returns (address) {
        return _pendingTokenConverter.pendingValue();
    }

    /// @notice Get the pending air dropper address
    /// @return The pending air dropper address
    function pendingAirDropper() public view returns (address) {
        return _pendingAirDropper.pendingValue();
    }
}

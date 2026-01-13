// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IDepositPool {
    /// @notice ERC-2612 permit. Always use this contract as spender and use
    /// msg.sender as owner
    struct PermitInput {
        uint256 value;
        uint256 deadline;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    event Deposited(
        address indexed from,
        address indexed to,
        address token,
        uint256 amount,
        address lsd,
        uint256 lsdAmount,
        uint256 timestamp,
        bytes32 guid,
        uint256 fee
    );

    event Withdrawn(address indexed _to, address _token, uint256 _amount, address _lsd);

    event NewWithdrawer(address withdrawer);
    event NewDepositCap(uint256 cap);
    event NewTreasury(address treasury);
    event NewLzReceiveGasLimit(uint128 gasLimit);
    event SmartSavingsOnGravityUpdated(address addr);
    event TotalLsdMintedInitialized(uint256 amount);

    error InvalidLSD();
    error InvalidVaultToken();
    error InvalidDepositAmount();
    error AmountExceedsDepositCap();
    error InvalidDepositCap(uint256 _cap);
    error SendFailed(address to, uint256 amount);
    error InvalidWithdrawer(address withdrawer);
    error InvalidWithdrawalAmount(uint256 amount);
    error InvalidAddress(address addr);
    error DepositAmountTooSmall(uint256 amount);
    error InsufficientFee(uint256 wanted, uint256 provided);
    error NotImplemented(bytes4 selector);
    error InvalidInitialLsdMinted(uint256 amount);

    function deposit(address _to, uint256 _amount, bool mintOnGravity) external payable;
    function depositWithPermit(
        address _to,
        uint256 _amount,
        bool mintOnGravity,
        PermitInput calldata _permit
    ) external payable;

    function setDepositCap(uint256 _amount) external;

    function setWithdrawer(address _withdrawer) external;

    function setTreasury(address _treasury) external;

    function withdraw(uint256 _amount) external;

    function remainingDepositCap() external view returns (uint256);
    function depositFee(address _to) external view returns (uint256);

    function LSD() external view returns (address); // solhint-disable-line style-guide-casing
    function ASSET_TOKEN() external view returns (address); // solhint-disable-line style-guide-casing
    function ASSET_TOKEN_DECIMALS() external view returns (uint256); // solhint-disable-line style-guide-casing
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IVaultNav {
    event NavUpdated(address indexed lsd, uint256 nav, uint256 timestamp);
    event SetNavUpdater(address indexed lsd, address updater);

    error NavNotFound(uint48 _timestamp);
    error InvalidNavUpdater(address updater);
    error NavInvalidValue(uint256 nav);
    error TimestampTooLarge();
    error InvalidUpdatePeriod();
    error NavUpdateInvalidTimestamp();

    function appendNav(address lsd, uint256 nav, uint48 timestamp) external;
    function setNavUpdater(address lsd, address updater) external;
    function getNavByTimestamp(
        address vaultType,
        uint48 timestamp
    ) external view returns (uint256 nav, uint48 updateTime);

    function lsdToTokenE18AtTime(address _lsd, uint256 _amount, uint48 _timestamp) external view returns (uint256);
    function tokenE18ToLsdAtTime(
        address _lsd,
        uint256 _tokenAmountE18,
        uint48 _timestamp
    ) external view returns (uint256);
}

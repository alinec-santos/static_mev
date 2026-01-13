// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library EmptyChecker {
    error EmptyAddress(address arg);

    function checkEmptyAddress(address _address) internal pure {
        if (_address == address(0)) {
            revert EmptyAddress(_address);
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

abstract contract RescueWithdraw {
    using SafeERC20 for IERC20;

    error SendNativeFailed(address _to, uint256 _value);

    /// @notice withdraw unexpected erc20 or native token
    /// @param _token The token address to withdraw
    /// @param _amount The amount of token to withdraw
    /// @param _to The address to receive the withdrawn token
    function _rescueWithdraw(address _token, uint256 _amount, address _to) internal {
        _sendToken(_token, _to, _amount);
    }

    /// @notice withdraw unexpected erc721 token
    /// @param _token The token address to withdraw
    /// @param _tokenId The tokenId of token to withdraw
    /// @param _to The address to receive the withdrawn token
    function _rescueWithdrawERC721(address _token, uint256 _tokenId, address _to) internal {
        IERC721(_token).safeTransferFrom(address(this), _to, _tokenId);
    }

    /// @notice send erc20 or native token
    /// @param _token The token address to send
    /// @param _to The address to receive the token
    /// @param _amount The amount of token to send
    function _sendToken(address _token, address _to, uint256 _amount) internal {
        if (_token != address(0)) {
            IERC20(_token).safeTransfer(_to, _amount);
        } else {
            (bool sent, ) = _to.call{ value: _amount }("");
            if (!sent) {
                revert SendNativeFailed(_to, _amount);
            }
        }
    }
}

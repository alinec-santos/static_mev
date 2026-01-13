// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library TimelockedOperations {
    struct Operation {
        uint256 timestamp; // Time when the operation can be executed
        bool executed;
    }

    struct AddressOperation {
        address _pendingValue;
        Operation _operation;
    }

    struct Uint256Operation {
        uint256 _pendingValue;
        Operation _operation;
    }

    error OperationNotReady(uint256 currentTime, uint256 readyTime);
    error NoOperationToExecute();
    error OperationAlreadyExecuted();
    error AddressOperationInvalid(address expected, address received);
    error Uint256OperationInvalid(uint256 expected, uint256 received);

    modifier onlyExecutableOperation(Operation storage operation) {
        if (operation.timestamp == 0) {
            revert NoOperationToExecute();
        }
        // verify operation delay is fulfilled
        if (operation.timestamp > block.timestamp) {
            revert OperationNotReady(block.timestamp, operation.timestamp);
        }
        // verify operation is not executed
        if (operation.executed) {
            revert OperationAlreadyExecuted();
        }
        _;
    }

    modifier onlyValidAddressOperationValue(AddressOperation storage operation, address value) {
        if (operation._pendingValue != value) {
            revert AddressOperationInvalid(operation._pendingValue, value);
        }
        _;
    }

    modifier onlyValidUint256OperationValue(Uint256Operation storage operation, uint256 value) {
        if (operation._pendingValue != value) {
            revert Uint256OperationInvalid(operation._pendingValue, value);
        }
        _;
    }

    // internal functions for base operation scheduling
    function scheduleOperation(Operation storage _operation, uint256 _delay) internal {
        _operation.timestamp = block.timestamp + _delay;
        _operation.executed = false;
    }

    function cancelOperation(Operation storage _operation) internal {
        if (_operation.executed) {
            revert OperationAlreadyExecuted();
        }
        _operation.timestamp = 0;
    }

    function executeOperation(Operation storage _operation) internal onlyExecutableOperation(_operation) {
        _operation.executed = true;
    }

    // internal functions for address operation scheduling
    function scheduleOperation(AddressOperation storage _operation, address _value, uint256 _delay) internal {
        _operation._pendingValue = _value;
        scheduleOperation(_operation._operation, _delay);
    }

    function cancelOperation(AddressOperation storage _operation) internal {
        cancelOperation(_operation._operation);
    }

    function executeOperation(
        AddressOperation storage _operation,
        address _value // solhint-disable-line no-unused-vars
    ) internal onlyValidAddressOperationValue(_operation, _value) {
        executeOperation(_operation._operation);
    }

    // internal functions for uint256 operation scheduling
    function scheduleOperation(Uint256Operation storage _operation, uint256 _value, uint256 _delay) internal {
        _operation._pendingValue = _value;
        scheduleOperation(_operation._operation, _delay);
    }

    function cancelOperation(Uint256Operation storage _operation) internal {
        cancelOperation(_operation._operation);
    }

    function executeOperation(
        Uint256Operation storage _operation,
        uint256 _value // solhint-disable-line no-unused-vars
    ) internal onlyValidUint256OperationValue(_operation, _value) {
        executeOperation(_operation._operation);
    }

    // internal view functions for address operation
    function pendingValue(AddressOperation storage _operation) internal view returns (address) {
        return _operation._pendingValue;
    }

    function pendingValue(Uint256Operation storage _operation) internal view returns (uint256) {
        return _operation._pendingValue;
    }
}

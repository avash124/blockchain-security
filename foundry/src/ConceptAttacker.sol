// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

interface IFlashLoanReceiver {
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32);
}

contract ConceptAttacker {
    address public owner;
    address public target;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _target) {
        owner = msg.sender;
        target = _target;
    }

    function attack() external onlyOwner {
        _setup();
        _executePayload();
        _collectProfit();
    }

    function _setup() internal virtual {
    }

    function _executePayload() internal virtual {
        revert("ConceptAttacker: payload not implemented");
    }

    function _collectProfit() internal virtual {
    }

    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32) {
        _executePayload();
        IERC20(token).approve(msg.sender, amount + fee);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    receive() external payable {}
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/ConceptAttacker.sol";

contract ReplayTest is Test {
    ConceptAttacker attacker;

    uint256 constant FORK_BLOCK = 16_817_995;
    address constant TARGET = address(0);

    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"), FORK_BLOCK);
        attacker = new ConceptAttacker(TARGET);
    }

    function test_replay_attack() public {
        uint256 preBalance = address(attacker).balance;

        vm.prank(address(this));
        attacker.attack();

        uint256 postBalance = address(attacker).balance;
        assertGt(postBalance, preBalance, "attacker should have profited");
    }

    function test_no_attack_without_owner() public {
        vm.prank(address(0xdead));
        vm.expectRevert("not owner");
        attacker.attack();
    }
}

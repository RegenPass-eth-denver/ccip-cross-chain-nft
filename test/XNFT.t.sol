// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {CCIPLocalSimulatorFork, Register} from "@chainlink/local/src/ccip/CCIPLocalSimulatorFork.sol";

import {CrossChainPOAP} from "../src/XNFT.sol";
import {EncodeExtraArgs} from "./utils/EncodeExtraArgs.sol";

contract CrossChainPOAPTest is Test {
    CCIPLocalSimulatorFork public ccipLocalSimulatorFork;
    uint256 ethSepoliaFork;
    uint256 arbSepoliaFork;
    uint256 baseSepoliaFork;
    Register.NetworkDetails ethSepoliaNetworkDetails;
    Register.NetworkDetails arbSepoliaNetworkDetails;
    Register.NetworkDetails baseSepoliaNetworkDetails;

    address alice;
    address bob;

    CrossChainPOAP public ethSepoliaPOAP;
    CrossChainPOAP public arbSepoliaPOAP;
    CrossChainPOAP public baseSepoliaPOAP;

    EncodeExtraArgs public encodeExtraArgs;

    function setUp() public {
        alice = makeAddr("alice");
        bob = makeAddr("bob");

        string memory ETHEREUM_SEPOLIA_RPC_URL = vm.envString("ETHEREUM_SEPOLIA_RPC_URL");
        string memory ARBITRUM_SEPOLIA_RPC_URL = vm.envString("ARBITRUM_SEPOLIA_RPC_URL");
        string memory BASE_SEPOLIA_RPC_URL = vm.envString("BASE_SEPOLIA_RPC_URL");

        ethSepoliaFork = vm.createSelectFork(ETHEREUM_SEPOLIA_RPC_URL);
        arbSepoliaFork = vm.createFork(ARBITRUM_SEPOLIA_RPC_URL);
        baseSepoliaFork = vm.createFork(BASE_SEPOLIA_RPC_URL);

        ccipLocalSimulatorFork = new CCIPLocalSimulatorFork();
        vm.makePersistent(address(ccipLocalSimulatorFork));

        // Deploy CrossChainPOAP on Ethereum Sepolia
        vm.selectFork(ethSepoliaFork);
        ethSepoliaNetworkDetails = ccipLocalSimulatorFork.getNetworkDetails(block.chainid);
        ethSepoliaPOAP = new CrossChainPOAP(
            ethSepoliaNetworkDetails.routerAddress,
            ethSepoliaNetworkDetails.linkAddress,
            ethSepoliaNetworkDetails.chainSelector
        );

        // Deploy CrossChainPOAP on Arbitrum Sepolia
        vm.selectFork(arbSepoliaFork);
        arbSepoliaNetworkDetails = ccipLocalSimulatorFork.getNetworkDetails(block.chainid);
        arbSepoliaPOAP = new CrossChainPOAP(
            arbSepoliaNetworkDetails.routerAddress,
            arbSepoliaNetworkDetails.linkAddress,
            arbSepoliaNetworkDetails.chainSelector
        );

        // Deploy CrossChainPOAP on Base Sepolia
        vm.selectFork(baseSepoliaFork);
        baseSepoliaNetworkDetails = ccipLocalSimulatorFork.getNetworkDetails(block.chainid);
        baseSepoliaPOAP = new CrossChainPOAP(
            baseSepoliaNetworkDetails.routerAddress,
            baseSepoliaNetworkDetails.linkAddress,
            baseSepoliaNetworkDetails.chainSelector
        );
    }

    function testShouldCrossChainMintPOAPFromArbitrumToEthereum() public {
        // Step 1) On Ethereum Sepolia, enable the Arbitrum chain for cross-chain minting.
        vm.selectFork(ethSepoliaFork);
        encodeExtraArgs = new EncodeExtraArgs();
        uint256 gasLimit = 200_000;
        bytes memory extraArgs = encodeExtraArgs.encode(gasLimit);
        ethSepoliaPOAP.enableChain(arbSepoliaNetworkDetails.chainSelector, address(arbSepoliaPOAP), extraArgs);

        // Step 2) On Arbitrum Sepolia, enable the Ethereum chain for cross-chain minting.
        vm.selectFork(arbSepoliaFork);
        arbSepoliaPOAP.enableChain(ethSepoliaNetworkDetails.chainSelector, address(ethSepoliaPOAP), extraArgs);

        // Step 3) Fund the Arbitrum POAP contract with LINK (3 LINK).
        ccipLocalSimulatorFork.requestLinkFromFaucet(address(arbSepoliaPOAP), 3 ether);

        // Step 4) On Arbitrum, have Alice initiate a cross-chain mint for Bob.
        vm.startPrank(alice);
        string memory testTokenURI = "ipfs://testPOAP";
        bytes32 messageId = arbSepoliaPOAP.crossChainMint(
            bob,
            testTokenURI,
            ethSepoliaNetworkDetails.chainSelector,
            CrossChainPOAP.PayFeesIn.LINK
        );
        vm.stopPrank();

        // Step 5) Simulate CCIP message delivery to Ethereum Sepolia.
        ccipLocalSimulatorFork.switchChainAndRouteMessage(ethSepoliaFork);

        // Step 6) Verify that on Ethereum Sepolia, Bob received the newly minted POAP.
        assertEq(ethSepoliaPOAP.balanceOf(bob), 1);
        uint256 tokenId = 0; // First minted token on Ethereum.
        assertEq(ethSepoliaPOAP.ownerOf(tokenId), bob);
        assertEq(ethSepoliaPOAP.tokenURI(tokenId), testTokenURI);
    }

    function testShouldCrossChainMintPOAPFromArbitrumToBase() public {
        // Step 1) On Base Sepolia, enable the Arbitrum chain for cross-chain minting.
        vm.selectFork(baseSepoliaFork);
        encodeExtraArgs = new EncodeExtraArgs();
        uint256 gasLimit = 200_000;
        bytes memory extraArgs = encodeExtraArgs.encode(gasLimit);
        baseSepoliaPOAP.enableChain(arbSepoliaNetworkDetails.chainSelector, address(arbSepoliaPOAP), extraArgs);

        // Step 2) On Arbitrum Sepolia, enable the Base chain for cross-chain minting.
        vm.selectFork(arbSepoliaFork);
        arbSepoliaPOAP.enableChain(baseSepoliaNetworkDetails.chainSelector, address(baseSepoliaPOAP), extraArgs);

        // Step 3) Fund the Arbitrum POAP contract with LINK (3 LINK).
        ccipLocalSimulatorFork.requestLinkFromFaucet(address(arbSepoliaPOAP), 3 ether);

        // Step 4) On Arbitrum, have Alice initiate a cross-chain mint for Bob targeting Base Sepolia.
        vm.startPrank(alice);
        string memory testTokenURI = "ipfs://testPOAPBase";
        bytes32 messageId = arbSepoliaPOAP.crossChainMint(
            bob,
            testTokenURI,
            baseSepoliaNetworkDetails.chainSelector,
            CrossChainPOAP.PayFeesIn.LINK
        );
        vm.stopPrank();

        // Step 5) Simulate CCIP message delivery to Base Sepolia.
        ccipLocalSimulatorFork.switchChainAndRouteMessage(baseSepoliaFork);

        // Step 6) Verify that on Base Sepolia, Bob received the newly minted POAP.
        assertEq(baseSepoliaPOAP.balanceOf(bob), 1);
        uint256 tokenId = 0; // First minted token on Base Sepolia.
        assertEq(baseSepoliaPOAP.ownerOf(tokenId), bob);
        assertEq(baseSepoliaPOAP.tokenURI(tokenId), testTokenURI);
    }
}

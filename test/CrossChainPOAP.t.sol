// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {CCIPLocalSimulatorFork, Register} from "@chainlink/local/src/ccip/CCIPLocalSimulatorFork.sol";

import {CrossChainPOAP} from "../src/CrossChainPOAP.sol";
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

    // Instances on each chain
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

        // Deploy POAP contracts on all three chains.
        // In the new flow, the contract deployed on Base Sepolia is the source for cross-chain calls.
        
        // Deploy on Ethereum Sepolia (destination)
        vm.selectFork(ethSepoliaFork);
        ethSepoliaNetworkDetails = ccipLocalSimulatorFork.getNetworkDetails(block.chainid);
        console.log("ethSepoliaNetworkDetails.routerAddress: %s", ethSepoliaNetworkDetails.routerAddress);
        console.log("ethSepoliaNetworkDetails.linkAddress: %s", ethSepoliaNetworkDetails.linkAddress);
        console.log("ethSepoliaNetworkDetails.chainSelector: %s", ethSepoliaNetworkDetails.chainSelector);
        ethSepoliaPOAP = new CrossChainPOAP(
            ethSepoliaNetworkDetails.routerAddress,
            ethSepoliaNetworkDetails.linkAddress,
            ethSepoliaNetworkDetails.chainSelector
        );

        // Deploy on Arbitrum Sepolia (destination)
        vm.selectFork(arbSepoliaFork);
        arbSepoliaNetworkDetails = ccipLocalSimulatorFork.getNetworkDetails(block.chainid);
        console.log("arbSepoliaNetworkDetails.routerAddress: %s", arbSepoliaNetworkDetails.routerAddress);
        console.log("arbSepoliaNetworkDetails.linkAddress: %s", arbSepoliaNetworkDetails.linkAddress);
        console.log("arbSepoliaNetworkDetails.chainSelector: %s", arbSepoliaNetworkDetails.chainSelector);
        arbSepoliaPOAP = new CrossChainPOAP(
            arbSepoliaNetworkDetails.routerAddress,
            arbSepoliaNetworkDetails.linkAddress,
            arbSepoliaNetworkDetails.chainSelector
        );

        // Deploy on Base Sepolia (source)
        vm.selectFork(baseSepoliaFork);
        baseSepoliaNetworkDetails = ccipLocalSimulatorFork.getNetworkDetails(block.chainid);
        console.log("baseSepoliaNetworkDetails.routerAddress: %s", baseSepoliaNetworkDetails.routerAddress);
        console.log("baseSepoliaNetworkDetails.linkAddress: %s", baseSepoliaNetworkDetails.linkAddress);
        console.log("baseSepoliaNetworkDetails.chainSelector: %s", baseSepoliaNetworkDetails.chainSelector);
        baseSepoliaPOAP = new CrossChainPOAP(
            baseSepoliaNetworkDetails.routerAddress,
            baseSepoliaNetworkDetails.linkAddress,
            baseSepoliaNetworkDetails.chainSelector
        );
    }

    /// @notice Direct mint on Base Sepolia (source chain)
    function testDirectMintOnBase() public {
        vm.selectFork(baseSepoliaFork);
        vm.startPrank(alice);
        string memory directTokenURI = "ipfs://directMintPOAPBase";
        baseSepoliaPOAP.mint(directTokenURI);
        uint256 tokenId = 0; // First minted token.
        assertEq(baseSepoliaPOAP.balanceOf(alice), 1);
        assertEq(baseSepoliaPOAP.ownerOf(tokenId), alice);
        assertEq(baseSepoliaPOAP.tokenURI(tokenId), directTokenURI);
        vm.stopPrank();
    }

    /// @notice Cross-chain mint from Base Sepolia to Arbitrum Sepolia.
    function testCrossChainMintFromBaseToArbitrum() public {
        // Step 1) On Base Sepolia, enable Arbitrum for cross-chain minting.
        vm.selectFork(baseSepoliaFork);
        encodeExtraArgs = new EncodeExtraArgs();
        uint256 gasLimit = 200_000;
        bytes memory extraArgs = encodeExtraArgs.encode(gasLimit);
        baseSepoliaPOAP.enableChain(arbSepoliaNetworkDetails.chainSelector, address(arbSepoliaPOAP), extraArgs);

        // Step 2) On Arbitrum, enable Base for cross-chain minting.
        vm.selectFork(arbSepoliaFork);
        arbSepoliaPOAP.enableChain(baseSepoliaNetworkDetails.chainSelector, address(baseSepoliaPOAP), extraArgs);

        // Step 3) Fund the Base contract with LINK (using 3 LINK here).
        ccipLocalSimulatorFork.requestLinkFromFaucet(address(baseSepoliaPOAP), 3 ether);

        // Step 4) On Base, have Alice initiate a cross-chain mint for Bob targeting Arbitrum.
        vm.selectFork(baseSepoliaFork);
        vm.startPrank(alice);
        string memory testTokenURI = "ipfs://testPOAPArb";
        baseSepoliaPOAP.crossChainMint(
            bob,
            testTokenURI,
            arbSepoliaNetworkDetails.chainSelector,
            CrossChainPOAP.PayFeesIn.LINK
        );
        vm.stopPrank();

        // Step 5) Simulate CCIP message delivery to Arbitrum.
        ccipLocalSimulatorFork.switchChainAndRouteMessage(arbSepoliaFork);

        // Step 6) Verify that on Arbitrum, Bob received the newly minted POAP.
        assertEq(arbSepoliaPOAP.balanceOf(bob), 1);
        uint256 tokenId = 0; // First minted token on Arbitrum.
        assertEq(arbSepoliaPOAP.ownerOf(tokenId), bob);
        assertEq(arbSepoliaPOAP.tokenURI(tokenId), testTokenURI);
    }

    /// @notice Cross-chain mint from Base Sepolia to Ethereum Sepolia.
    function testCrossChainMintFromBaseToEthereum() public {
        // Step 1) On Base Sepolia, enable Ethereum for cross-chain minting.
        vm.selectFork(baseSepoliaFork);
        encodeExtraArgs = new EncodeExtraArgs();
        uint256 gasLimit = 200_000;
        bytes memory extraArgs = encodeExtraArgs.encode(gasLimit);
        // console.log("extraArgs: %s", extraArgs);
        baseSepoliaPOAP.enableChain(ethSepoliaNetworkDetails.chainSelector, address(ethSepoliaPOAP), extraArgs);

        // Step 2) On Ethereum, enable Base for cross-chain minting.
        vm.selectFork(ethSepoliaFork);
        ethSepoliaPOAP.enableChain(baseSepoliaNetworkDetails.chainSelector, address(baseSepoliaPOAP), extraArgs);

        // Step 3) Fund the Base contract with LINK.
        ccipLocalSimulatorFork.requestLinkFromFaucet(address(baseSepoliaPOAP), 3 ether);

        // Step 4) On Base, have Alice initiate a cross-chain mint for Bob targeting Ethereum.
        vm.selectFork(baseSepoliaFork);
        vm.startPrank(alice);
        string memory testTokenURI = "ipfs://testPOAPEth";
        baseSepoliaPOAP.crossChainMint(
            bob,
            testTokenURI,
            ethSepoliaNetworkDetails.chainSelector,
            CrossChainPOAP.PayFeesIn.LINK
        );
        vm.stopPrank();

        // Step 5) Simulate CCIP message delivery to Ethereum.
        ccipLocalSimulatorFork.switchChainAndRouteMessage(ethSepoliaFork);

        // Step 6) Verify that on Ethereum, Bob received the newly minted POAP.
        assertEq(ethSepoliaPOAP.balanceOf(bob), 1);
        uint256 tokenId = 0; // First minted token on Ethereum.
        assertEq(ethSepoliaPOAP.ownerOf(tokenId), bob);
        assertEq(ethSepoliaPOAP.tokenURI(tokenId), testTokenURI);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {VRFConsumerBaseV2Plus} from "@chainlink/contracts@1.1.1/src/v0.8/vrf/dev/VRFConsumerBaseV2Plus.sol";
import {VRFV2PlusClient} from "@chainlink/contracts@1.1.1/src/v0.8/vrf/dev/libraries/VRFV2PlusClient.sol";

// Minimal interface for the VRF Coordinator.
interface IVRFCoordinatorV2Plus {
    function requestRandomWords(VRFV2PlusClient.RandomWordsRequest calldata request) external returns (uint256);
}

contract RandomNumberGenerator is VRFConsumerBaseV2Plus {
    // Hardcoded Base Sepolia testnet settings
    IVRFCoordinatorV2Plus public coordinator = IVRFCoordinatorV2Plus(0x5C210eF41CD1a72de73bF76eC39637bB0d3d7BEE);
    uint256 public subscriptionId = 98979509481261273982979648191580057436713607096695928603340622617130529082903;
    bytes32 public keyHash = 0x9e1344a1247c8a1785d0a4681a27152bffdb43666ae5bf7d14d24a5efd44bf71;
    uint32 public callbackGasLimit = 2500000; // Maximum Gas Limit
    uint16 public requestConfirmations = 0;    // Minimum Confirmations
    uint32 public numWords = 1;                // Request one random value

    // This will hold the random number between 1 and 3.
    uint256 public randomResult;

    event RandomNumberGenerated(uint256 requestId, uint256 randomResult);

    constructor() VRFConsumerBaseV2Plus(0x5C210eF41CD1a72de73bF76eC39637bB0d3d7BEE) {}

    /// @notice Initiates a VRF request.
    function requestRandomNumber() external returns (uint256 requestId) {
        VRFV2PlusClient.RandomWordsRequest memory req = VRFV2PlusClient.RandomWordsRequest({
            keyHash: keyHash,
            subId: subscriptionId,
            requestConfirmations: requestConfirmations,
            callbackGasLimit: callbackGasLimit,
            numWords: numWords,
            extraArgs: VRFV2PlusClient._argsToBytes(
                VRFV2PlusClient.ExtraArgsV1({ nativePayment: false })
            )
        });
        requestId = coordinator.requestRandomWords(req);
    }

    /// @notice Callback used by the VRF Coordinator.
    function fulfillRandomWords(uint256 requestId, uint256[] calldata randomWords) internal override {
        // Transform the first random word into a number between 1 and 3.
        randomResult = (randomWords[0] % 3) + 1;
        emit RandomNumberGenerated(requestId, randomResult);
    }
}

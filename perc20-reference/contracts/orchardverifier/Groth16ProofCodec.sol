// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Groth16ProofCodec
/// @notice ABI encoding for snarkjs Groth16 proof components (pA, pB, pC).
///         The wire format used by `IEndpointCore.BundleAction.proof` is
///         `abi.encode(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)`.
library Groth16ProofCodec {
    function encode(
        uint256[2] memory pA,
        uint256[2][2] memory pB,
        uint256[2] memory pC
    ) internal pure returns (bytes memory) {
        return abi.encode(pA, pB, pC);
    }

    function decode(bytes memory proof)
        internal
        pure
        returns (uint256[2] memory pA, uint256[2][2] memory pB, uint256[2] memory pC)
    {
        return abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));
    }
}

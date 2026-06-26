// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IActionGroth16Verifier} from "../interfaces/IActionGroth16Verifier.sol";
import {ActionPubHash} from "../crypto/hash/ActionPubHash.sol";
import {Groth16ProofCodec} from "./Groth16ProofCodec.sol";
import {Groth16PairingVerifier} from "./Groth16PairingVerifier.sol";

/// @title ActionGroth16Verifier
/// @notice Hand-written wrapper implementing `IActionGroth16Verifier`. Decodes the
///         action proof, recomputes `pub_hash` from the 8 public fields, then delegates
///         to the snarkjs-generated `Groth16PairingVerifier` (VK embedded in bytecode).
contract ActionGroth16Verifier is IActionGroth16Verifier {
    Groth16PairingVerifier public immutable pairingVerifier;

    constructor() {
        pairingVerifier = new Groth16PairingVerifier();
    }

    /// @inheritdoc IActionGroth16Verifier
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256 pubHash
    ) external view returns (bool) {
        uint256[1] memory pub = [pubHash];
        return pairingVerifier.verifyProof(pA, pB, pC, pub);
    }

    /// @inheritdoc IActionGroth16Verifier
    function verifyAction(bytes calldata proof, uint256[8] calldata pubFields)
        external
        view
        returns (bool)
    {
        (uint256[2] memory pA, uint256[2][2] memory pB, uint256[2] memory pC) =
            Groth16ProofCodec.decode(proof);
        uint256 expected = ActionPubHash.hash(
            pubFields[0],
            pubFields[1],
            pubFields[2],
            pubFields[3],
            pubFields[4],
            pubFields[5],
            pubFields[6],
            pubFields[7]
        );
        uint256[1] memory pub = [expected];
        return pairingVerifier.verifyProof(pA, pB, pC, pub);
    }
}

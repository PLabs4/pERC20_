// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IActionGroth16Verifier
/// @notice Verifies a single-action Groth16 proof with one public signal (`pub_hash`).
///         The 8 calldata public fields are hashed on-chain via `ActionPubHash` to
///         the SNARK's single public input, binding pubFields to the SNARK proof.
interface IActionGroth16Verifier {
    /// @param pA G1 point (snarkjs export, Y negated in calldata).
    /// @param pB G2 point.
    /// @param pC G1 point.
    /// @param pubHash Public input bound in the SNARK (`pub_hash`).
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256 pubHash
    ) external view returns (bool);

    /// @param proof `abi.encode(pA, pB, pC)` (see `Groth16ProofCodec`).
    /// @param pubFields `[anchor, cv_x, cv_y, nf, rk_x, rk_y, cmx, rt_frozen]`.
    function verifyAction(bytes calldata proof, uint256[8] calldata pubFields)
        external
        view
        returns (bool);
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BabyJubJub} from "../curve/BabyJubJub.sol";

/// @title SpendAuthSignature
/// @notice Verifies the per-action Baby JubJub Schnorr spend-authorisation signature.
///
/// Each action that spends a note must carry a SpendAuthSig
/// under the randomised spend-auth key `rk = [rsk] · G_SPEND_AUTH` where
///   rsk = ask + alpha  (BN254 Fr arithmetic, matching the action witness).
///
/// The sighash covers all fields that are NOT protected by the Groth16 proof:
///   epk, enc_ciphertext (via keccak256), out_ciphertext (via keccak256).
/// Fields already constrained by the proof (anchor, nf, cmx, cv_net, rk)
/// are included for nf/cmx only as replay-protection anchors.
///
/// Schnorr equation:  s · G_SPEND_AUTH == R + e · rk
/// Challenge:         e = keccak256(R || rk || sighash) mod ℓ
///
/// SIGHASH:
///   keccak256(
///     "SpendAuth.action.v2"
///     ‖ chainId (uint256)
///     ‖ contractAddr (address → 20 bytes in abi.encodePacked)
///     ‖ nfOld (bytes32)
///     ‖ cmx   (bytes32)
///     ‖ epk   (bytes32)
///     ‖ keccak256(encCiphertext)  (bytes32)
///     ‖ keccak256(outCiphertext)  (bytes32)
///     ‖ executor (address → 20 bytes)
///   )
///
/// `executor` (v2) mirrors the binding-signature binding: when non-zero, every
/// action in the bundle is authorised only for submission by that address, so a
/// single swap leg cannot be replayed/extracted on its own.
library SpendAuthSignature {
    uint256 internal constant SUBGROUP_ORDER = BabyJubJub.SUBGROUP_ORDER;

    // ── SIGHASH ───────────────────────────────────────────────────────────────

    /// @notice Build the domain-separated spend-auth sighash for one action.
    function buildSighash(
        uint256 chainId,
        address contractAddr,
        bytes32 nfOld,
        bytes32 cmx,
        bytes32 epk,
        bytes memory encCiphertext,
        bytes memory outCiphertext,
        address executor
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            "SpendAuth.action.v2",
            chainId,
            contractAddr,
            nfOld,
            cmx,
            epk,
            keccak256(encCiphertext),
            keccak256(outCiphertext),
            executor
        ));
    }

    // ── Schnorr Verification ──────────────────────────────────────────────────

    /// @notice Verify a SpendAuthSig for a single action.
    ///
    /// @param rkX      rk.x from pubFields[4] — already verified by Groth16 + pub_hash.
    /// @param rkY      rk.y from pubFields[5] — already verified by Groth16 + pub_hash.
    /// @param sighash  Output of buildSighash().
    /// @param sigRx    Signature R.x
    /// @param sigRy    Signature R.y
    /// @param sigS     Signature scalar s
    function verify(
        uint256 rkX,
        uint256 rkY,
        bytes32 sighash,
        uint256 sigRx,
        uint256 sigRy,
        uint256 sigS
    ) internal view returns (bool) {
        // R is attacker-supplied and not constrained by the Groth16 proof: reject any
        // off-curve / non-canonical point before doing the Schnorr arithmetic.
        if (!BabyJubJub.isOnCurve(sigRx, sigRy)) return false;
        // Audit L-02: reject non-canonical s (s and s+ℓ would otherwise both verify).
        if (sigS >= SUBGROUP_ORDER) return false;
        // Audit L-01: defense-in-depth on-curve check on the proof-attested rk, so on-chain
        // soundness for this point does not rely solely on circuit soundness.
        if (!BabyJubJub.isOnCurve(rkX, rkY)) return false;

        // e = keccak256(R || rk || sighash) mod ℓ
        uint256 e = uint256(keccak256(abi.encodePacked(
            bytes32(sigRx), bytes32(sigRy),
            bytes32(rkX),   bytes32(rkY),
            sighash
        ))) % SUBGROUP_ORDER;

        // LHS = s · G_SPEND_AUTH
        (uint256 lhsX, uint256 lhsY) = BabyJubJub.scalarMul(
            BabyJubJub.G_SPEND_AUTH_X, BabyJubJub.G_SPEND_AUTH_Y, sigS
        );

        // RHS = R + e · rk
        (uint256 erkX, uint256 erkY) = BabyJubJub.scalarMul(rkX, rkY, e);
        (uint256 rhsX, uint256 rhsY) = BabyJubJub.pointAdd(sigRx, sigRy, erkX, erkY);

        return lhsX == rhsX && lhsY == rhsY;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BabyJubJub} from "../curve/BabyJubJub.sol";

/// @title BindingSignature
/// @notice Verifies the Baby Jubjub Schnorr binding signature for a privacy pool bundle.
///
/// The binding signature proves that the signer knows
///   bsk = Σ rcv_i  (accumulated across all actions)
/// such that
///   bvk = Σ cv_net_i − ValueCommit(valueBalance, 0)
///       = bsk * G_RANDOM
///
/// Schnorr verification:
///   s * G_RANDOM == R + hash(R || bvk || sighash) * bvk
///
/// valueBalance sign-bit encoding (sign bit in bit 255; magnitude in the low 255 bits):
///   bit 255 = 0, low 255 bits = v  → unshield/burn +v  (BJJ scalar = v mod ℓ)
///   bit 255 = 1, low 255 bits = v  → shield/mint   −v  (BJJ scalar = ℓ − (v mod ℓ))
///   all zeros                      → transfer (balanced)
///
/// NOTE: pERC20 amounts use the full low 255 bits (not just 64), since token amounts
/// (e.g. 18-decimals) routinely exceed 2^64. `PERC20._requireAmountMatchesVb` checks
/// `valueBalance & ((1<<255)-1) == amount`.
///
/// The raw `valueBalance` bytes are included verbatim in the SIGHASH, so the
/// prover and contract always hash the same readable integer representation.
/// The sign-bit decode only affects the scalar used in bvk computation.
///
/// SIGHASH binds the signature to the specific bundle:
///   keccak256("PrivacyPool.bundle.v2" || chainId || contractAddr
///             || nf[0] || nf[1] || ... || cmx[0] || cmx[1] || ...
///             || valueBalance || recipientMeta || executor)
///
/// `executor` (v2): when non-zero, the bundle MUST be submitted by exactly that
/// address (enforced at the asset layer, e.g. PERC20.transfer). Binding it into the
/// SIGHASH lets an atomic-swap coordinator be the only valid submitter of a leg,
/// preventing single-leg replay/front-running. `address(0)` = permissionless submit
/// (mint/burn and ordinary transfers).
///
/// Security:
///   1. NUMS generators: log_{G_RANDOM}(G_VALUE) unknown (Poseidon hash-to-curve).
///   2. ZK property: rcv is private input, not leaked by the Groth16 proof.
///   3. Domain-separated SIGHASH: binds to all nullifiers + commitments, preventing
///      cross-bundle splicing or proof reuse in a different context.
library BindingSignature {
    uint256 internal constant Fr = BabyJubJub.Fr;

    // ── SIGHASH ───────────────────────────────────────────────────────────────

    /// @notice Build the domain-separated sighash covering the entire bundle.
    ///
    /// Matches §4.10 "SIGHASH Transaction Hashing" — binds the binding signature
    /// to all nullifiers (spend inputs) and all new commitments (outputs), plus
    /// the net value balance and recipient metadata.
    ///
    /// @param chainId        EVM chain ID (anti-cross-chain-replay).
    /// @param contractAddr   This contract's address (anti-cross-contract-replay).
    /// @param nullifiers     All nf_old values in the bundle (including dummy-input nullifiers for mint).
    /// @param commitments    All cmx values in the bundle (output actions only; bytes32(0) for spend-only).
    /// @param valueBalance   Net value change (sign-bit encoding: bit255=1 → shield −v,
    ///                       bit255=0 non-zero → unshield +v, 0 → transfer).
    /// @param recipientMeta  Recipient binding for unshield (e.g. bytes32(uint256(uint160(recipient))));
    ///                       bytes32(0) for transfer/mint/burn.
    /// @param executor       Required submitter for this bundle, or address(0) for permissionless.
    function buildSighash(
        uint256 chainId,
        address contractAddr,
        bytes32[] memory nullifiers,
        bytes32[] memory commitments,
        uint256 valueBalance,
        bytes32 recipientMeta,
        address executor
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            "PrivacyPool.bundle.v2",
            chainId,
            contractAddr,
            nullifiers,
            commitments,
            valueBalance,
            recipientMeta,
            executor
        ));
    }

    // ── Schnorr Verification ──────────────────────────────────────────────────

    /// @notice Verify the binding signature for a multi-action bundle.
    ///
    /// @param cvNetXs       cv_net x-coordinates for all actions (from pubFields[1]).
    /// @param cvNetYs       cv_net y-coordinates for all actions (from pubFields[2]).
    /// @param valueBalance  Net value balance (sign-bit encoding: bit255=0 → +v unshield,
    ///                      bit255=1 → −v shield, 0 → transfer). Low 255 bits = magnitude.
    /// @param sighash       Output of buildSighash().
    /// @param sigRx         Binding signature R.x
    /// @param sigRy         Binding signature R.y
    /// @param sigS          Binding signature scalar s
    function verify(
        uint256[] memory cvNetXs,
        uint256[] memory cvNetYs,
        uint256 valueBalance,
        bytes32 sighash,
        uint256 sigRx,
        uint256 sigRy,
        uint256 sigS
    ) internal view returns (bool) {
        require(cvNetXs.length == cvNetYs.length, "BindingSig: cv arrays mismatch");
        require(cvNetXs.length > 0, "BindingSig: empty bundle");

        // R is attacker-supplied and not constrained by the Groth16 proof: reject any
        // off-curve / non-canonical point before doing the Schnorr arithmetic.
        if (!BabyJubJub.isOnCurve(sigRx, sigRy)) return false;
        // Audit L-02: reject non-canonical s (s and s+ℓ would otherwise both verify).
        if (sigS >= BabyJubJub.SUBGROUP_ORDER) return false;

        // 1. bvk = Σ cv_net_i − vbScalar * G_VALUE
        //
        // Decode sign-bit encoding → BJJ scalar:
        //   bit255=0 (unshield/transfer): scalar = low-255-bit magnitude (mod ℓ)
        //   bit255=1 (shield):            scalar = ℓ − amount  (additive inverse mod ℓ)
        uint256 vbScalar;
        {
            bool negative = (valueBalance >> 255) == 1;
            uint256 absAmount = valueBalance & ((1 << 255) - 1); // clear sign bit
            if (negative && absAmount != 0) {
                uint256 absModL = absAmount % BabyJubJub.SUBGROUP_ORDER;
                vbScalar = absModL == 0 ? 0 : BabyJubJub.SUBGROUP_ORDER - absModL;
            } else {
                vbScalar = absAmount;
            }
        }

        // Audit L-01: on-curve check each proof-attested cv_net before EC arithmetic, so on-chain
        // soundness does not rely solely on circuit soundness for these points.
        if (!BabyJubJub.isOnCurve(cvNetXs[0], cvNetYs[0])) return false;
        (uint256 sumX, uint256 sumY) = (cvNetXs[0], cvNetYs[0]);
        for (uint256 i = 1; i < cvNetXs.length; i++) {
            if (!BabyJubJub.isOnCurve(cvNetXs[i], cvNetYs[i])) return false;
            (sumX, sumY) = BabyJubJub.pointAdd(sumX, sumY, cvNetXs[i], cvNetYs[i]);
        }
        (uint256 vbX, uint256 vbY) = BabyJubJub.scalarMul(
            BabyJubJub.G_VALUE_X, BabyJubJub.G_VALUE_Y,
            vbScalar
        );
        (uint256 negVbX, uint256 negVbY) = BabyJubJub.pointNeg(vbX, vbY);
        (uint256 bvkX, uint256 bvkY) = BabyJubJub.pointAdd(sumX, sumY, negVbX, negVbY);

        // 2. e = keccak256(R || bvk || sighash) mod ℓ (EIP-2494 prime subgroup order)
        uint256 e = uint256(keccak256(abi.encodePacked(
            bytes32(sigRx), bytes32(sigRy),
            bytes32(bvkX),  bytes32(bvkY),
            sighash
        ))) % BabyJubJub.SUBGROUP_ORDER;

        // 3. LHS = s * G_RANDOM
        (uint256 lhsX, uint256 lhsY) = BabyJubJub.scalarMul(
            BabyJubJub.G_RANDOM_X, BabyJubJub.G_RANDOM_Y, sigS
        );

        // 4. RHS = R + e * bvk
        (uint256 ebvkX, uint256 ebvkY) = BabyJubJub.scalarMul(bvkX, bvkY, e);
        (uint256 rhsX, uint256 rhsY) = BabyJubJub.pointAdd(sigRx, sigRy, ebvkX, ebvkY);

        return lhsX == rhsX && lhsY == rhsY;
    }
}

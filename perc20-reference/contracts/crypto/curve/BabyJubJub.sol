// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BabyJubJub
/// @notice Baby Jubjub elliptic curve arithmetic over BN254 scalar field Fr.
///
/// Curve: ax² + y² = 1 + dx²y²  (twisted Edwards form)
///   a = 168700
///   d = 168696
/// Coordinates live in F_r where r is the BN254 scalar field prime below.
/// Scalar multiplication uses exponents reduced mod ℓ, the prime subgroup order
/// from EIP-2494 (curve order n = 8·ℓ); ℓ ≠ r.
///
/// Gas optimisation — projective coordinates
/// -----------------------------------------
/// The original affine implementation called _modInv (MODEXP precompile, ~4 048 gas)
/// twice per pointAdd and therefore 762 times per scalarMul, costing ~3.08 M gas.
///
/// This version keeps all arithmetic in homogeneous projective coordinates (X:Y:Z)
/// using the EFD formulas:
///   dbl-2008-bbjlp  — 4S + 3M ≈ 7 mulmod  (no MODEXP)
///   add-2008-bbjlp  — 1S + 10M ≈ 11 mulmod (no MODEXP)
///
/// Only one MODEXP is needed per scalarMul at the very end to convert (X:Y:Z) → (x,y).
/// A standalone pointAdd(affine, affine) costs one MODEXP (down from two).
///
/// Result: ~98 × gas reduction for scalarMul  (3.08 M → ~31 K gas).
///
/// Reference: EIP-2494, iden3/baby-jubjub,
///            https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html
library BabyJubJub {
    // ── Field modulus (BN254 Fr) ──────────────────────────────────────────────
    uint256 internal constant Fr =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Prime-order subgroup size ℓ with n = 8·ℓ (EIP-2494 § Order).
    uint256 internal constant SUBGROUP_ORDER =
        2736030358979909402780800718157159386076813972158567259200215660948447373041;

    // ── Curve parameters ──────────────────────────────────────────────────────
    uint256 internal constant A = 168700;
    uint256 internal constant D = 168696;

    // ── NUMS generators (big-endian, Solidity uint256) ────────────────────────
    // Audit I-02: all three generators were verified off-chain to be on-curve, in the
    // prime-order subgroup ([ℓ]G = O), and != identity. `test/Generators.t.sol` asserts
    // on-curve on-chain; prime-order is recorded here (scalarMul reduces mod ℓ, so it cannot
    // re-test subgroup membership in-contract).
    uint256 internal constant G_VALUE_X =
        0x17fd59f6a76603fa600c9b7a5ef1b693b699e1a3b99dd8388c6090614cbfbd81;
    uint256 internal constant G_VALUE_Y =
        0x2e4f05547eb757a53ca2144eb3d906765944cc5d2aa42af14db8eeb7b383d396;

    uint256 internal constant G_RANDOM_X =
        0x27ce0892199f95ef98264f2b1c462f1f0c78c4a8889b2227cdff59b9cbc20318;
    uint256 internal constant G_RANDOM_Y =
        0x0b5cdda12f9788cd04b1eb41e026fb608d394b219b5c659313ea5a70f1262f81;

    uint256 internal constant G_SPEND_AUTH_X =
        0x1500e9f13e31bb51f59740ae2c7a904eca7ab98c964d4eabdf41f8384d3d45fe;
    uint256 internal constant G_SPEND_AUTH_Y =
        0x0a15846c8fab9380e66c443f85c8ac73656217d6e8008968a5d63b282d7ab167;

    // ── Identity point (affine) ───────────────────────────────────────────────
    uint256 internal constant IDENTITY_X = 0;
    uint256 internal constant IDENTITY_Y = 1;

    // ── Point addition (public API, affine in / affine out) ───────────────────

    /// @notice Twisted Edwards point addition in affine coordinates.
    ///         Internally uses projective arithmetic to avoid a second MODEXP.
    function pointAdd(
        uint256 x1, uint256 y1,
        uint256 x2, uint256 y2
    ) internal view returns (uint256 x3, uint256 y3) {
        // Affine → projective: (x,y) = (x:y:1), no field ops needed.
        (uint256 X3, uint256 Y3, uint256 Z3) = _pointAddProj(x1, y1, 1, x2, y2, 1);
        (x3, y3) = _projToAffine(X3, Y3, Z3);
    }

    /// @notice Negate a point: -(x, y) = (-x, y). Audit I-04: return canonical x = 0 (not Fr)
    ///         when x = 0, so negating the identity / any x = 0 point stays in canonical range.
    function pointNeg(uint256 x, uint256 y) internal pure returns (uint256, uint256) {
        return (x == 0 ? 0 : Fr - x, y);
    }

    /// @notice Check that (x, y) is a canonical affine point on the twisted Edwards curve
    ///         `a·x² + y² == 1 + d·x²·y²`. Rejects non-reduced coordinates (≥ Fr).
    /// @dev    Used to validate attacker-supplied signature points (e.g. Schnorr `R`),
    ///         which are otherwise unconstrained by the Groth16 proof.
    function isOnCurve(uint256 x, uint256 y) internal pure returns (bool) {
        if (x >= Fr || y >= Fr) return false;
        uint256 xx = mulmod(x, x, Fr);
        uint256 yy = mulmod(y, y, Fr);
        uint256 lhs = addmod(mulmod(A, xx, Fr), yy, Fr);
        uint256 rhs = addmod(1, mulmod(mulmod(D, xx, Fr), yy, Fr), Fr);
        return lhs == rhs;
    }

    // ── Scalar multiplication ─────────────────────────────────────────────────

    /// @notice Scalar multiplication: returns scalar * (baseX, baseY).
    /// @dev MSB-first double-and-add entirely in projective coordinates.
    ///      One MODEXP at the end for the final affine conversion.
    function scalarMul(
        uint256 baseX, uint256 baseY,
        uint256 scalar
    ) internal view returns (uint256 rx, uint256 ry) {
        scalar = scalar % SUBGROUP_ORDER;

        // Projective identity: (0 : 1 : 1)
        uint256 rX = 0;
        uint256 rY = 1;
        uint256 rZ = 1;

        for (uint256 i = 0; i < 254; i++) {
            (rX, rY, rZ) = _pointDoubleProj(rX, rY, rZ);
            if ((scalar >> (253 - i)) & 1 == 1) {
                // baseX/baseY are affine (Z=1); pass Z=1 explicitly.
                (rX, rY, rZ) = _pointAddProj(rX, rY, rZ, baseX, baseY, 1);
            }
        }

        (rx, ry) = _projToAffine(rX, rY, rZ);
    }

    // ── Projective coordinate internals ───────────────────────────────────────

    /// @dev Homogeneous projective point doubling.
    ///      Formula: EFD twisted-projective dbl-2008-bbjlp
    ///      (a=168700, general twisted Edwards)
    ///      Cost: 4S + 3M  (7 mulmod, 0 MODEXP)
    ///
    ///      B  = (X1+Y1)²
    ///      C  = X1²
    ///      Dv = Y1²
    ///      E  = a·C
    ///      F  = E+Dv
    ///      H  = Z1²
    ///      J  = F−2H
    ///      X3 = (B−C−Dv)·J
    ///      Y3 = F·(E−Dv)
    ///      Z3 = F·J
    function _pointDoubleProj(
        uint256 X1, uint256 Y1, uint256 Z1
    ) private pure returns (uint256 X3, uint256 Y3, uint256 Z3) {
        uint256 p  = Fr;
        uint256 av = A; // 168700

        uint256 B  = mulmod(addmod(X1, Y1, p), addmod(X1, Y1, p), p);
        uint256 C  = mulmod(X1, X1, p);
        uint256 Dv = mulmod(Y1, Y1, p);
        uint256 E  = mulmod(av, C, p);
        uint256 F  = addmod(E, Dv, p);
        uint256 H  = mulmod(Z1, Z1, p);
        // J = F − 2H  mod p
        uint256 J  = addmod(F, p - addmod(H, H, p), p);

        // X3 = (B−C−Dv) · J   (B−C−Dv = 2·X1·Y1)
        X3 = mulmod(addmod(B, p - addmod(C, Dv, p), p), J, p);
        // Y3 = F · (E−Dv)
        Y3 = mulmod(F, addmod(E, p - Dv, p), p);
        // Z3 = F · J
        Z3 = mulmod(F, J, p);
    }

    /// @dev Homogeneous projective point addition (unified — handles identity,
    ///      doubling, and distinct-point cases correctly on the Baby JubJub curve).
    ///      Formula: EFD twisted-projective add-2008-bbjlp
    ///      (a=168700, d=168696)
    ///      Cost: 1S + 10M  (11 mulmod, 0 MODEXP)
    ///
    ///      Av  = Z1·Z2
    ///      Bv  = Av²
    ///      Cv  = X1·X2
    ///      Dv  = Y1·Y2
    ///      Ev  = d·Cv·Dv
    ///      Fv  = Bv−Ev
    ///      Gv  = Bv+Ev
    ///      X3  = Av·Fv·((X1+Y1)·(X2+Y2)−Cv−Dv)
    ///      Y3  = Av·Gv·(Dv−a·Cv)
    ///      Z3  = Fv·Gv
    ///
    ///      When adding an affine point (Z2=1) the caller passes Z2=1 directly;
    ///      the formula degenerates correctly without a specialised path.
    function _pointAddProj(
        uint256 X1, uint256 Y1, uint256 Z1,
        uint256 X2, uint256 Y2, uint256 Z2
    ) private pure returns (uint256 X3, uint256 Y3, uint256 Z3) {
        uint256 p  = Fr;
        uint256 av = A; // 168700
        uint256 dv = D; // 168696

        uint256 Av = mulmod(Z1, Z2, p);
        uint256 Bv = mulmod(Av, Av, p);
        uint256 Cv = mulmod(X1, X2, p);
        uint256 Dv = mulmod(Y1, Y2, p);
        uint256 Ev = mulmod(mulmod(dv, Cv, p), Dv, p);
        uint256 Fv = addmod(Bv, p - Ev, p);
        uint256 Gv = addmod(Bv, Ev, p);

        // (X1+Y1)·(X2+Y2) − Cv − Dv
        uint256 cross = addmod(
            mulmod(addmod(X1, Y1, p), addmod(X2, Y2, p), p),
            p - addmod(Cv, Dv, p),
            p
        );

        X3 = mulmod(mulmod(Av, Fv, p), cross, p);
        // Dv − a·Cv
        uint256 DaC = addmod(Dv, p - mulmod(av, Cv, p), p);
        Y3 = mulmod(mulmod(Av, Gv, p), DaC, p);
        Z3 = mulmod(Fv, Gv, p);
    }

    /// @dev Convert projective (X:Y:Z) to affine (X·Z⁻¹, Y·Z⁻¹).
    ///      Costs exactly one MODEXP (field inversion).
    function _projToAffine(
        uint256 X, uint256 Y, uint256 Z
    ) private view returns (uint256 x, uint256 y) {
        uint256 zInv = _modInv(Z, Fr);
        x = mulmod(X, zInv, Fr);
        y = mulmod(Y, zInv, Fr);
    }

    // ── Modular inverse via Fermat's little theorem ───────────────────────────
    function _modInv(uint256 a, uint256 p) private view returns (uint256 result) {
        bytes memory input = abi.encode(
            uint256(32), // base length
            uint256(32), // exp length
            uint256(32), // mod length
            a,
            p - 2,
            p
        );
        bool ok;
        assembly {
            ok := staticcall(gas(), 5, add(input, 32), mload(input), add(input, 32), 32)
            result := mload(add(input, 32))
        }
        require(ok, "BabyJubJub: modexp failed");
    }
}

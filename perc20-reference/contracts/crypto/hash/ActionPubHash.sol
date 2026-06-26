// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PoseidonT3} from "./PoseidonT3.sol";

/// @title ActionPubHash
/// @notice On-chain recomputation of Groth16 public input `pub_hash` for the pERC20
///         action circuit (single-action witness).
///
/// @dev MUST match `PubHashAction()` in `circuits/poseidon_bn254.circom`
///      (ConstantLength<9> sponge, rate=2). The 9 absorbed inputs are:
///         (DOMAIN_ACTION_V1, anchor, cv_x, cv_y, nf, rk_x, rk_y, cmx, rt_frozen)
library ActionPubHash {
    uint256 internal constant FIELD_MODULUS =
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    /// @dev DOMAIN_ACTION_V1 in `circuits/constants.circom` (decimal).
    uint256 internal constant DOMAIN_ACTION_V1 =
        1629194783969501186922682804819505;

    /// @dev Poseidon ConstantLength<9> capacity: 9 << 64.
    uint256 internal constant CAP9 =
        82902010526333902703151216816934996401094022412701412326608725394220259295872;

    /// @notice `pub_hash = sponge(DOMAIN, anchor, cv_x, cv_y, nf, rk_x, rk_y, cmx, rt_frozen)`.
    function hash(
        uint256 anchor,
        uint256 cvNetX,
        uint256 cvNetY,
        uint256 nfOld,
        uint256 rkX,
        uint256 rkY,
        uint256 cmx,
        uint256 rtFrozen
    ) internal pure returns (uint256) {
        uint256 s0;
        uint256 s1;
        uint256 s2;
        (s0, s1, s2) = _absorbPair(0, 0, CAP9, DOMAIN_ACTION_V1, anchor);
        (s0, s1, s2) = _absorbPair(s0, s1, s2, cvNetX, cvNetY);
        (s0, s1, s2) = _absorbPair(s0, s1, s2, nfOld, rkX);
        (s0, s1, s2) = _absorbPair(s0, s1, s2, rkY, cmx);
        (s0, s1, s2) = _absorbPair(s0, s1, s2, rtFrozen, 0);
        return s0;
    }

    function _absorbPair(uint256 s0, uint256 s1, uint256 s2, uint256 a, uint256 b)
        private
        pure
        returns (uint256, uint256, uint256)
    {
        s0 = addmod(s0, a, FIELD_MODULUS);
        s1 = addmod(s1, b, FIELD_MODULUS);
        return PoseidonT3.permute(s0, s1, s2);
    }
}

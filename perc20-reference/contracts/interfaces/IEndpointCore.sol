// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IEndpointCore
/// @notice Implementation layer: note state machine + ZK verification (Relayer / SDK).
///
/// @dev Public-fields layout (`pubFields[8]`):
///        [0] anchor       — Merkle root used in the proof
///        [1] cv_net_x     — net value commitment X
///        [2] cv_net_y     — net value commitment Y
///        [3] nf_old       — nullifier (`0` for output-only mint actions)
///        [4] rk_x         — randomised authorisation key X
///        [5] rk_y         — randomised authorisation key Y
///        [6] cmx          — new note commitment (non-zero for all operations)
///        [7] rt_frozen    — compliance frozen SMT root (must equal `IPERC20.cmxFrozenRoot()`)
interface IEndpointCore {
    struct BundleAction {
        bytes32 cmx;
        bytes encCiphertext;        // 580 bytes
        bytes outCiphertext;        // 80 bytes
        bytes32 epk;
        bytes32 nfOld;              // nullifier of the consumed (or dummy) input note
        bytes32 anchor;             // historical root used by the consumed (or dummy) input
        /// @dev Groth16 proof: `abi.encode(pA, pB, pC)` (see `Groth16ProofCodec`).
        bytes proof;
        uint256[8] pubFields;       // [7] = rt_frozen
        uint256[3] spendAuthSig;
    }

    /// @notice Latest commitment-tree root on chain.
    /// @dev Anyone can rebuild the note tree locally from `NoteAdded` / `NoteConfirmed`
    ///      events and compare the derived root against this value for consistency checks.
    function cmxRoot() external view returns (bytes32);

    /// @notice Whether `root` was ever emitted by this contract's commitment tree.
    /// @dev Wallets SHOULD call this before submitting a transaction to validate the
    ///      proof anchor, removing reliance on an indexer as the sole source of truth.
    function isValidAnchor(bytes32 root) external view returns (bool);

    /// @notice New output note (from mint / transfer / burn).
    /// @dev `outCiphertext` (80 bytes) + `cvNetX` are emitted alongside `encCiphertext`
    ///      so that wallets holding the *outgoing-viewing-key* (OVK) can scan their
    ///      sent notes directly from logs, without parsing mint/burn/transfer calldata.
    ///
    ///      Audit I-01 — TRUST BOUNDARY: the ZK proof does NOT prove that `encCiphertext`
    ///      correctly encrypts the note committed by `cmx` (the spend-auth signature only
    ///      binds the ciphertext against in-flight tampering). A "received note" therefore
    ///      means "successfully trial-decrypted", NEVER merely "a NoteAdded event exists":
    ///      a malicious SENDER can emit an undecryptable note, which the recipient simply
    ///      cannot spend (non-receipt, equivalent to not paying — not theft/counterfeit).
    event NoteAdded(
        bytes32 indexed cmx,
        bytes encCiphertext,
        bytes outCiphertext,
        bytes32 epk,
        bytes32 nfOld,
        bytes32 cvNetX
    );
    event NoteConfirmed(bytes32 indexed cmx, bytes32 newRoot, uint256 position);
    event BundleExecuted(uint256 valueBalance, uint256 amount, bytes32 recipientMeta);
}

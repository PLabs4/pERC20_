// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IncrementalMerkleTree} from "../crypto/merkle/IncrementalMerkleTree.sol";
import {IEndpointCore} from "../interfaces/IEndpointCore.sol";
import {BabyJubJub} from "../crypto/curve/BabyJubJub.sol";
import {BindingSignature} from "../crypto/signature/BindingSignature.sol";
import {SpendAuthSignature} from "../crypto/signature/SpendAuthSignature.sol";
import {IActionGroth16Verifier} from "../interfaces/IActionGroth16Verifier.sol";

/// @title OrchardVerifier — Orchard note state machine (pERC20 core)
///
/// @notice Validates Groth16 ZK proofs, maintains the note Merkle tree and nullifier set,
///   and verifies binding / spend-auth signatures. Asset-specific supply accounting
///   lives in PERC20 (IPERC20).
///
///   Each pool instance owns:
///     - its own Merkle commitment tree + historical roots,
///     - its own nullifier-spent set,
///     - its own `groth16Verifier` reference (snarkjs-generated VK is embedded inside),
///     - its own `cmxFrozenRoot` (per-asset compliance blacklist root).
///
///   Compliance officer = `admin`. On `PERC20`, the admin updates the root via
///   `IPERC20.setFrozenRoot` after rebuilding the off-chain blacklist SMT; every
///   action's `pubFields[7]` MUST equal `IPERC20.cmxFrozenRoot()`, otherwise
///   verification reverts with `BadFrozenRoot`.
contract OrchardVerifier is IEndpointCore {
    using IncrementalMerkleTree for IncrementalMerkleTree.State;

    /// @notice Per-asset admin (= issuer at construction). Holds `setGroth16Verifier`
    ///         and admin-transfer authority. Compliance root updates go through
    ///         `IPERC20.setFrozenRoot` on `PERC20`.
    address public admin;

    /// @notice Groth16 action verifier (`ActionGroth16Verifier` or test mock).
    IActionGroth16Verifier public groth16Verifier;

    /// @notice Compliance frozen SMT root (must match `pubFields[7]` in each action).
    uint256 private _frozenRoot;

    /// @notice Per-bundle action cap. Set in `_initOrchardVerifier` (NOT an inline initializer,
    ///         which would not run for EIP-1167 clones).
    uint256 public maxActions;

    /// @notice Address allowed to call `acceptAdmin` to complete a two-step transfer.
    address public pendingAdmin;

    /// @notice BN254 scalar field modulus. Every `pubFields` entry MUST be a canonical
    ///         field element (`< FIELD_MODULUS`); see `_verifyAction`.
    uint256 internal constant FIELD_MODULUS = BabyJubJub.Fr;

    /// @notice Prime-order subgroup size ℓ. Public `amount` values MUST be `< SUBGROUP_ORDER`
    ///         so that the binding scalar (`amount mod ℓ`) equals the declared amount.
    uint256 internal constant SUBGROUP_ORDER = BabyJubJub.SUBGROUP_ORDER;

    IncrementalMerkleTree.State private _tree;

    /// @notice Recent Merkle roots kept in a fixed-size ring buffer for O(1) updates.
    ///         Anchor validity itself is checked via the permanent `_allRootsEver` set,
    ///         so this window only powers the `historicalRoot*` view helpers.
    uint256 public constant HISTORICAL_ROOT_WINDOW = 100;
    bytes32[HISTORICAL_ROOT_WINDOW] private _historicalRing;
    uint256 private _rootsPushed;
    mapping(bytes32 => bool) private _allRootsEver;

    mapping(bytes32 => bool) private _isSpent;

    /// @notice Tracks every commitment ever inserted, to reject duplicate `cmx` leaves.
    mapping(bytes32 => bool) public cmxExists;

    // ── Audit L-04 (frozen-root grace) ────────────────────────────────────────
    // Declared at the END of storage to keep the prior slot layout stable.
    /// @notice Immediately-previous frozen root and the timestamp it was replaced. When
    ///         `frozenRootGracePeriod > 0`, an action proven against `_prevFrozenRoot` is still
    ///         accepted until `_frozenRootUpdatedAt + frozenRootGracePeriod`, so a `setFrozenRoot`
    ///         does not instantly invalidate in-flight proofs (liveness).
    uint256 private _prevFrozenRoot;
    uint256 private _frozenRootUpdatedAt;
    /// @notice Grace window (seconds) for accepting `_prevFrozenRoot`. Default 0 = strict (no
    ///         grace); the admin opts in via `setFrozenRootGracePeriod` (trades immediate
    ///         compliance enforcement for relayer liveness).
    uint256 public frozenRootGracePeriod;

    /// @notice One-time-initialization guard. Set by the constructor (standalone deploy) or by
    ///         the first `initialize(...)` (EIP-1167 clone deploy). Declared LAST so adding it
    ///         does not shift any prior storage slot (cf. `_allRootsEver` at slot 140, which the
    ///         e2e anchor-injection depends on).
    bool private _initialized;

    error NotAdmin();
    error BadEncLen();
    error NullifierSpent();
    error BadAnchor();
    error InvalidProof();
    error VerifierNotSet();
    error BadBindingSig();
    error BadSpendAuthSig();
    error BadFrozenRoot();
    error PubFieldOutOfRange();
    error DuplicateCommitment();
    error ZeroCommitment();
    error ZeroNullifier();
    error ZeroAddress();
    error NotPendingAdmin();
    error AlreadyInitialized();

    /// @notice Emitted when the Groth16 verifier reference is rotated.
    event Groth16VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    /// @notice Emitted when a two-step admin transfer is initiated.
    event AdminTransferStarted(address indexed currentAdmin, address indexed pendingAdmin);
    /// @notice Emitted when a pending admin accepts ownership.
    event AdminUpdated(address indexed oldAdmin, address indexed newAdmin);
    /// @notice Emitted when the per-bundle action cap changes.
    event MaxActionsUpdated(uint256 oldLimit, uint256 newLimit);
    /// @notice Emitted when the frozen-root grace window changes (audit L-04).
    event FrozenRootGracePeriodUpdated(uint256 oldPeriod, uint256 newPeriod);

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    constructor(address admin_, address groth16Verifier_) {
        _initOrchardVerifier(admin_, groth16Verifier_);
    }

    /// @notice Initialize the note state machine: set the admin + verifier and seed the empty
    ///         Merkle tree (root pushed to history + recorded as a valid anchor). Runs exactly
    ///         once — from the constructor (standalone `new PERC20`) or from `PERC20.initialize`
    ///         (EIP-1167 clone). Reverts on re-entry via the `_initialized` guard, which also
    ///         locks the cloned implementation contract against direct (re-)initialization.
    function _initOrchardVerifier(address admin_, address groth16Verifier_) internal {
        if (_initialized) revert AlreadyInitialized();
        _initialized = true;
        admin = admin_;
        groth16Verifier = IActionGroth16Verifier(groth16Verifier_);
        maxActions = 10;
        _tree.init();
        _pushHistoricalRoot(_tree.root);
        _allRootsEver[_tree.root] = true;
    }

    /// @inheritdoc IEndpointCore
    function cmxRoot() external view returns (bytes32) {
        return _tree.root;
    }

    /// @dev Virtual getter; `PERC20` exposes this via `IPERC20.cmxFrozenRoot()`.
    function cmxFrozenRoot() public view virtual returns (uint256) {
        return _frozenRoot;
    }

    function _setFrozenRoot(uint256 frozenRoot_) internal returns (uint256 old) {
        old = _frozenRoot;
        // Audit L-04: remember the previous root + when it was replaced, for the grace window.
        _prevFrozenRoot = old;
        _frozenRootUpdatedAt = block.timestamp;
        _frozenRoot = frozenRoot_;
    }

    /// @notice Set the grace window during which the immediately-previous frozen root is also
    ///         accepted (audit L-04). Default 0 = strict. Capped at 1 day. Admin-only.
    function setFrozenRootGracePeriod(uint256 period) external onlyAdmin {
        require(period <= 1 days, "grace too long");
        emit FrozenRootGracePeriodUpdated(frozenRootGracePeriod, period);
        frozenRootGracePeriod = period;
    }

    function setGroth16Verifier(address groth16Verifier_) external onlyAdmin {
        if (groth16Verifier_ == address(0)) revert ZeroAddress();
        emit Groth16VerifierUpdated(address(groth16Verifier), groth16Verifier_);
        groth16Verifier = IActionGroth16Verifier(groth16Verifier_);
    }

    /// @notice Begin a two-step admin transfer. The new admin only takes effect after
    ///         it calls `acceptAdmin`, preventing accidental hand-off to a wrong/zero
    ///         address that would brick all privileged operations.
    function transferAdmin(address next) external onlyAdmin {
        if (next == address(0)) revert ZeroAddress();
        pendingAdmin = next;
        emit AdminTransferStarted(admin, next);
    }

    /// @notice Complete a two-step admin transfer. Callable only by the pending admin.
    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert NotPendingAdmin();
        emit AdminUpdated(admin, pendingAdmin);
        admin = pendingAdmin;
        pendingAdmin = address(0);
    }

    function setMaxActions(uint256 limit) external onlyAdmin {
        // Audit L-03: cap lowered 50 → 16 so a large bundle (pairing + 32 Poseidon inserts +
        // 2 Schnorr verifies per action) cannot be configured to grief / exceed block gas.
        require(limit >= 1 && limit <= 16, "maxActions out of range");
        emit MaxActionsUpdated(maxActions, limit);
        maxActions = limit;
    }

    /// @notice Number of roots currently retained in the ring buffer
    ///         (`min(total roots ever pushed, HISTORICAL_ROOT_WINDOW)`).
    function historicalRootsLength() external view returns (uint256) {
        return _rootsPushed < HISTORICAL_ROOT_WINDOW ? _rootsPushed : HISTORICAL_ROOT_WINDOW;
    }

    /// @notice Returns the i-th retained root, ordered oldest (`i = 0`) → newest.
    function historicalRootAt(uint256 i) external view returns (bytes32) {
        uint256 len = _rootsPushed < HISTORICAL_ROOT_WINDOW ? _rootsPushed : HISTORICAL_ROOT_WINDOW;
        require(i < len, "IMT: root index out of range");
        uint256 absolute = _rootsPushed - len + i;
        return _historicalRing[absolute % HISTORICAL_ROOT_WINDOW];
    }

    /// @inheritdoc IEndpointCore
    function isValidAnchor(bytes32 root) external view returns (bool) {
        return _allRootsEver[root];
    }

    /// @notice Number of note commitments inserted into the Merkle tree.
    ///         Derived from the tree's leaf counter, so it needs no extra storage.
    function treeSize() external view returns (uint256) {
        return _tree.nextIndex;
    }

    /// @notice Whether a nullifier has been consumed (note spent). Read-only accessor
    ///         over the private spent-set; wallets/indexers use it to detect spends
    ///         without trusting an off-chain source. Storage stays encapsulated.
    function isSpent(bytes32 nullifier) external view returns (bool) {
        return _isSpent[nullifier];
    }

    /// @dev O(1) ring-buffer push (overwrites the oldest slot once full).
    function _pushHistoricalRoot(bytes32 root) internal {
        _historicalRing[_rootsPushed % HISTORICAL_ROOT_WINDOW] = root;
        _rootsPushed += 1;
    }

    function _insertAndPushRoot(bytes32 cmx) internal {
        bytes32 newRoot = _tree.insert(uint256(cmx));
        _allRootsEver[newRoot] = true;
        _pushHistoricalRoot(newRoot);
    }

    function _executeBundle(
        BundleAction[] memory actions,
        uint256 valueBalance,
        uint256 amount,
        bytes32 recipientMeta,
        address executor,
        uint256[3] memory bindingSig
    ) internal {
        if (address(groth16Verifier) == address(0)) revert VerifierNotSet();

        (
            uint256[] memory cvXs,
            uint256[] memory cvYs,
            bytes32[] memory nullifiers,
            bytes32[] memory commitments
        ) = _verifyBundle(actions, executor);

        uint256 n = commitments.length;

        // Verify value conservation (binding signature) BEFORE mutating ANY state. `_verifyBundle`
        // is now `view` (audit L-05): it no longer marks nullifiers spent, so a bad binding
        // signature reverts before the spent-set / tree / events are touched.
        bytes32 sighash = BindingSignature.buildSighash(
            block.chainid,
            address(this),
            nullifiers,
            commitments,
            valueBalance,
            recipientMeta,
            executor
        );
        if (!BindingSignature.verify(cvXs, cvYs, valueBalance, sighash,
                bindingSig[0], bindingSig[1], bindingSig[2]))
            revert BadBindingSig();

        // Audit L-05: consume nullifiers only AFTER value conservation is verified. This loop
        // also rejects intra-bundle duplicate nullifiers (the second check-and-set reverts).
        for (uint256 i = 0; i < n; i++) {
            bytes32 nf = nullifiers[i];
            if (_isSpent[nf]) revert NullifierSpent();
            _isSpent[nf] = true;
        }

        for (uint256 i = 0; i < n; i++) {
            bytes32 cmx = actions[i].cmx;
            if (cmxExists[cmx]) revert DuplicateCommitment();
            cmxExists[cmx] = true;

            uint256 pos = _tree.nextIndex;
            _insertAndPushRoot(cmx);
            emit NoteAdded(
                cmx,
                actions[i].encCiphertext,
                actions[i].outCiphertext,
                actions[i].epk,
                actions[i].nfOld,
                bytes32(actions[i].pubFields[1])
            );
            emit NoteConfirmed(cmx, _tree.root, pos);
        }

        emit BundleExecuted(valueBalance, amount, recipientMeta);
    }

    function _verifyAction(BundleAction memory a) private view {
        // `ActionPubHash` reduces every field mod FIELD_MODULUS before hashing, and the
        // snarkjs verifier only range-checks the resulting single `pub_hash`. Without the
        // guard below an attacker could submit `nf + FIELD_MODULUS` (same `pub_hash`, same
        // proof) yet a different `isSpent` key — double-spending the same note. Reject any
        // non-canonical public field up front.
        for (uint256 i = 0; i < 8; i++) {
            if (a.pubFields[i] >= FIELD_MODULUS) revert PubFieldOutOfRange();
        }
        // Audit L-04: require the current frozen root, or — within the opt-in grace window —
        // the immediately-previous root, so a mid-flight setFrozenRoot does not strand proofs.
        uint256 fr = cmxFrozenRoot();
        if (a.pubFields[7] != fr) {
            if (
                frozenRootGracePeriod == 0 ||
                a.pubFields[7] != _prevFrozenRoot ||
                block.timestamp > _frozenRootUpdatedAt + frozenRootGracePeriod
            ) revert BadFrozenRoot();
        }
        // Solidity abi-encodes memory args into calldata for the external call —
        // the interface keeps `calldata` for gas efficiency on the implementation side.
        if (!groth16Verifier.verifyAction(a.proof, a.pubFields)) revert InvalidProof();
    }

    function _verifyProofsAndSigs(
        BundleAction[] memory actions,
        address executor,
        uint256[] memory cvXs,
        uint256[] memory cvYs,
        bytes32[] memory nullifiers,
        bytes32[] memory commitments
    ) private view {
        uint256 n = actions.length;

        for (uint256 i = 0; i < n; i++) {
            BundleAction memory a = actions[i];
            _verifyAction(a);

            uint256[8] memory pub = a.pubFields;
            // Reject the degenerate zero commitment (collides with the empty-leaf sentinel).
            if (a.cmx == bytes32(0)) revert ZeroCommitment();
            // Reject the degenerate zero nullifier. `_executeBundle` uses `nfOld` as the spent-set
            // key, so a zero nullifier (e.g. a mint dummy input naively set to 0) would let the
            // first such action poison `_isSpent[0]` and brick every later zero-nullifier action.
            // Real (dummy or spend) nullifiers are unique non-zero field elements, so this only
            // rejects malformed input.
            if (a.nfOld == bytes32(0)) revert ZeroNullifier();
            if (bytes32(pub[6]) != a.cmx) revert InvalidProof();

            if (!_allRootsEver[a.anchor]) revert BadAnchor();
            if (bytes32(pub[0]) != a.anchor) revert BadAnchor();
            if (bytes32(pub[3]) != a.nfOld) revert NullifierSpent();

            if (a.encCiphertext.length != 580) revert BadEncLen();

            bytes32 saHash = SpendAuthSignature.buildSighash(
                block.chainid,
                address(this),
                a.nfOld,
                a.cmx,
                a.epk,
                a.encCiphertext,
                a.outCiphertext,
                executor
            );
            if (!SpendAuthSignature.verify(
                pub[4], pub[5], saHash,
                a.spendAuthSig[0], a.spendAuthSig[1], a.spendAuthSig[2]
            )) revert BadSpendAuthSig();

            nullifiers[i] = a.nfOld;
            commitments[i] = a.cmx;
            cvXs[i] = pub[1];
            cvYs[i] = pub[2];
        }
    }

    /// @dev Audit L-05: now `view` — it verifies proofs/signatures and collects per-action
    ///      values but performs NO state writes. Nullifiers are consumed by the caller
    ///      (`_executeBundle`) only after the binding signature is verified. Cross-bundle and
    ///      intra-bundle double-spends are both caught by that later check-and-set loop.
    function _verifyBundle(
        BundleAction[] memory actions,
        address executor
    ) internal view returns (
        uint256[] memory cvXs,
        uint256[] memory cvYs,
        bytes32[] memory nullifiers,
        bytes32[] memory commitments
    ) {
        uint256 n = actions.length;
        require(n > 0, "empty bundle");
        require(n <= maxActions, "bundle exceeds maxActions");
        cvXs = new uint256[](n);
        cvYs = new uint256[](n);
        nullifiers = new bytes32[](n);
        commitments = new bytes32[](n);

        _verifyProofsAndSigs(actions, executor, cvXs, cvYs, nullifiers, commitments);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {OrchardVerifier} from "../orchardverifier/OrchardVerifier.sol";
import {IEndpointCore} from "../interfaces/IEndpointCore.sol";
import {IPERC20} from "../interfaces/IPERC20.sol";

/// @title PERC20
/// @notice Reference implementation of the pERC20 standard (privacy-native fungible token).
///   Wraps the OrchardVerifier note state machine with ERC-20-like metadata + public totalSupply,
///   and exposes mint/burn/transfer over IPERC20.PrivacyCall.
contract PERC20 is OrchardVerifier, IPERC20 {
    string private _name;
    string private _symbol;
    uint8 private _decimals;
    /// @notice Token issuer / compliance officer. Storage (not `immutable`) so that EIP-1167
    ///         clones — which never run the constructor — can set it per-instance in `initialize`.
    address public issuer;

    uint256 private _totalSupply;

    error NotIssuer();
    error AmountVbMismatch();
    error BurnSignBitSet();
    error SupplyUnderflow();
    error AmountTooLarge();
    /// @notice A bundle bound to a specific `executor` was submitted by a different `msg.sender`.
    error UnauthorizedExecutor();
error ZeroIssuer();
error ZeroVerifier();

    modifier onlyIssuer() {
        if (msg.sender != issuer) revert NotIssuer();
        _;
    }

    /// @param issuer_ Token issuer; also acts as the per-asset compliance officer
    ///                (admin) — same address holds `mint`, `setFrozenRoot`, and
    ///                `setGroth16Verifier` authority. Use `transferAdmin`/`acceptAdmin`
    ///                to split later.
    constructor(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        address issuer_,
        address groth16Verifier_
    ) OrchardVerifier(issuer_, groth16Verifier_) {
        // OrchardVerifier's constructor already ran `_initOrchardVerifier` (tree seed +
        // `_initialized` guard); set the PERC20 metadata to finish a standalone deploy.
        _initPerc20Metadata(name_, symbol_, decimals_, issuer_, groth16Verifier_);
    }

    /// @notice Initialize an EIP-1167 clone (the equivalent of the constructor for the
    ///         factory/clone deploy path, which never runs the constructor). Seeds the
    ///         OrchardVerifier state machine and the PERC20 metadata. One-shot: the
    ///         `_initialized` guard reverts on any second call (and locks the implementation,
    ///         whose constructor already set the guard). `PERC20Factory` clones and calls this
    ///         atomically in one transaction, so there is no initialization front-running window.
    function initialize(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        address issuer_,
        address groth16Verifier_
    ) external {
        _initOrchardVerifier(issuer_, groth16Verifier_); // guarded — reverts if already initialized
        _initPerc20Metadata(name_, symbol_, decimals_, issuer_, groth16Verifier_);
    }

    function _initPerc20Metadata(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        address issuer_,
        address groth16Verifier_
    ) internal {
        if (issuer_ == address(0)) revert ZeroIssuer();
        if (groth16Verifier_ == address(0)) revert ZeroVerifier();
        _name = name_;
        _symbol = symbol_;
        _decimals = decimals_;
        issuer = issuer_;
        emit Perc20Created(address(this), issuer_, name_, symbol_, decimals_);
    }

    function name() external view returns (string memory) {
        return _name;
    }

    function symbol() external view returns (string memory) {
        return _symbol;
    }

    function decimals() external view returns (uint8) {
        return _decimals;
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    /// @inheritdoc IPERC20
    function cmxFrozenRoot() public view override(IPERC20, OrchardVerifier) returns (uint256) {
        return super.cmxFrozenRoot();
    }

    /// @inheritdoc IPERC20
    /// @dev Restricted to `onlyAdmin`.
    function setFrozenRoot(uint256 newRoot) external override onlyAdmin {
        uint256 old = _setFrozenRoot(newRoot);
        emit FrozenRootUpdated(old, newRoot);
    }

    /// @inheritdoc IPERC20
    /// @dev Per IPERC20: this standard intentionally does NOT emit the ERC-20 `Transfer`
    ///   event. Per-note observability is provided by `NoteAdded`/`NoteConfirmed`
    ///   (see IEndpointCore). Returns `true` on success to match ERC-20 calling conventions.
    /// @param call Privacy bundle payload:
    ///   - `call.actions` must be `abi.encode(IEndpointCore.BundleAction[])`.
    ///   - for transfer, actions are regular spend/output actions (`valueBalance = 0`).
    ///   - `call.bindingSig` is verified by `_executeBundle` against this contract + chain id.
    function transfer(PrivacyCall calldata call) external returns (bool) {
        // Permissionless transfer: executor = address(0) (anyone may submit).
        return _transfer(address(0), call);
    }

    /// @inheritdoc IPERC20
    /// @notice Executor-gated transfer. When `executor != address(0)`, the bundle is bound
    ///   (in both the binding and spend-auth sighashes) to that submitter, and only that
    ///   address may call this function. Used by an atomic-swap coordinator so a single swap
    ///   leg cannot be replayed or front-run on its own. `executor == address(0)` behaves
    ///   exactly like `transfer(call)`.
    function transfer(address executor, PrivacyCall calldata call) external returns (bool) {
        if (executor != address(0) && msg.sender != executor) revert UnauthorizedExecutor();
        return _transfer(executor, call);
    }

    function _transfer(address executor, PrivacyCall calldata call) internal returns (bool) {
        // Decode the private action bundle provided by caller/wallet.
        IEndpointCore.BundleAction[] memory actions =
            abi.decode(call.actions, (IEndpointCore.BundleAction[]));
        // Transfer is value-neutral at the public layer: valueBalance = 0, amount = 0.
        _executeBundle(actions, 0, 0, bytes32(0), executor, call.bindingSig);
        return true;
    }

    /// @inheritdoc IPERC20
    /// @param call Privacy bundle payload:
    ///   - `call.actions` must be `abi.encode(IEndpointCore.BundleAction[])`.
    ///   - for mint, actions are output-only; each consumes a DUMMY input note whose nullifier
    ///     (`nfOld`) MUST be a unique, non-zero field element (a zero nullifier is rejected
    ///     on-chain, since the spent-set is keyed by `nfOld`).
    ///   - `call.bindingSig` must bind to `valueBalance = amount | (1 << 255)`.
    function mint(uint256 amount, PrivacyCall calldata call) external onlyIssuer {
        // Keep public amount within subgroup order so declared amount matches scalar semantics.
        if (amount >= SUBGROUP_ORDER) revert AmountTooLarge();
        // Mint is encoded as negative value-balance (bit255 = 1) with low 255 bits = amount.
        uint256 vb = amount | (1 << 255);
        _requireAmountMatchesVb(amount, vb);
        // Decode proof bundle and execute note-state transition with binding-signature checks.
        IEndpointCore.BundleAction[] memory actions =
            abi.decode(call.actions, (IEndpointCore.BundleAction[]));
        _executeBundle(actions, vb, amount, bytes32(0), address(0), call.bindingSig);
        // Public supply increases only after successful bundle verification/execution.
        _totalSupply += amount;
        emit Mint(issuer, amount);
    }

    /// @inheritdoc IPERC20
    /// @param call Privacy bundle payload:
    ///   - `call.actions` must be `abi.encode(IEndpointCore.BundleAction[])`.
    ///   - burn consumes existing notes and binds `valueBalance = amount`.
    ///   - `call.bindingSig` is validated in `_executeBundle` before any state mutation.
    function burn(uint256 amount, PrivacyCall calldata call) external {
        // Burn uses a non-negative public amount; sign bit must stay unset.
        if (amount >= (1 << 255)) revert BurnSignBitSet();
        // Keep the declared amount inside the prime subgroup range to avoid mod-l mismatch.
        if (amount >= SUBGROUP_ORDER) revert AmountTooLarge();
        _requireAmountMatchesVb(amount, amount);
        // Decode the proof bundle from IPERC20.PrivacyCall.
        IEndpointCore.BundleAction[] memory actions =
            abi.decode(call.actions, (IEndpointCore.BundleAction[]));
        // Verify proofs/signatures and apply note-state transitions first; this reverts atomically on failure.
        _executeBundle(actions, amount, amount, bytes32(0), address(0), call.bindingSig);
        // Only after bundle success, update public supply with an explicit underflow guard.
        if (_totalSupply < amount) revert SupplyUnderflow();
        _totalSupply -= amount;
        emit Burn(amount);
    }

    function _requireAmountMatchesVb(uint256 amount, uint256 valueBalance) internal pure {
        if ((valueBalance & ((1 << 255) - 1)) != amount) revert AmountVbMismatch();
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PERC20} from "./PERC20.sol";
import {Clones} from "../proxy/Clones.sol";
import {IActionGroth16Verifier} from "../interfaces/IActionGroth16Verifier.sol";

/// @title PERC20Factory
/// @notice Optional recommended deployer for new `PERC20` instances, using EIP-1167 minimal
///         proxies (clones).
///
/// @dev Why clones: a factory that `new`s `PERC20` from an external function would embed
///      `PERC20`'s ~24 KB creation code into the factory's own RUNTIME bytecode, pushing it past
///      the EIP-170 24,576-byte limit (this is what the previous `new PERC20` factory hit). Here
///      the full `PERC20` is deployed exactly once as an `implementation` in the FACTORY's
///      CONSTRUCTOR (so its creation code is part of the factory's initcode, bounded by EIP-3860,
///      not its runtime), and every asset is a ~45-byte clone that `DELEGATECALL`s into it. The
///      factory's runtime is therefore tiny.
///
///      Each clone is an independent `PERC20`: its own storage (note tree, nullifier set,
///      supply, metadata, per-asset `cmxFrozenRoot`), sharing only the immutable `groth16Verifier`
///      by reference. `createPerc20` clones and `initialize`s atomically in one transaction, so
///      there is no initialization front-running window. Standalone `new PERC20(...)` deployments
///      remain conformant and are unaffected.
///
///      Factory deployment is RECOMMENDED but not required by the pERC20 standard. Genesis minting
///      is intentionally NOT performed here: a binding signature embeds the deployed contract's
///      address (anti-cross-contract replay), unknowable before deployment.
///
///      Indexers: the one-time `implementation()` address also emits `Perc20Created` (with
///      `issuer == address(this)`) when this factory is constructed; it is a locked template, not a
///      usable asset, and MUST be skipped (filter on `factory.implementation()`).
contract PERC20Factory {
    /// @notice Shared Groth16 action verifier every deployed asset references.
    IActionGroth16Verifier public immutable groth16Verifier;

    /// @notice The locked `PERC20` template that all assets are EIP-1167 clones of.
    address public immutable implementation;

    /// @notice Emitted for each asset deployed through this factory (in addition to the asset's
    ///         own `IPERC20.Perc20Created`), so the factory is a single discoverable entry point.
    event Perc20Deployed(address indexed pool, address indexed issuer);

    constructor(address groth16Verifier_) {
        groth16Verifier = IActionGroth16Verifier(groth16Verifier_);
        // Deploy the implementation ONCE here in the constructor (kept out of factory runtime).
        // It is fully initialized (issuer = this factory) and therefore locked: its
        // `_initialized` guard makes `initialize(...)` revert, so it can never be hijacked.
        implementation = address(
            new PERC20("pERC20-implementation", "pIMPL", 0, address(this), groth16Verifier_)
        );
    }

    /// @notice Deploy a new pERC20 asset (EIP-1167 clone) with the caller as issuer / compliance
    ///         officer. Address is non-deterministic (`CREATE`); use `createPerc20Deterministic`
    ///         for a predictable address.
    /// @dev Audit I-03 — metadata is NOT authenticated: `name`/`symbol` are caller-chosen and
    ///      anyone may deploy a look-alike. Asset identity is the contract ADDRESS (binding
    ///      sighashes embed `address(this)`); wallets/indexers MUST key on address + issuer.
    /// @return pool Address of the deployed `PERC20` clone.
    function createPerc20(
        string calldata name,
        string calldata symbol,
        uint8 decimals
    ) external returns (address pool) {
        pool = Clones.clone(implementation);
        PERC20(pool).initialize(name, symbol, decimals, msg.sender, address(groth16Verifier));
        emit Perc20Deployed(pool, msg.sender);
    }

    /// @notice Deploy a new pERC20 asset at a deterministic (`CREATE2`) address derived from
    ///         `salt` and the caller; see `predictPerc20Address`. Reverts if that address is taken.
    /// @return pool Address of the deployed `PERC20` clone.
    function createPerc20Deterministic(
        string calldata name,
        string calldata symbol,
        uint8 decimals,
        bytes32 salt
    ) external returns (address pool) {
        // Bind the salt to the caller so distinct issuers can't collide on each other's addresses.
        pool = Clones.cloneDeterministic(implementation, keccak256(abi.encode(msg.sender, salt)));
        PERC20(pool).initialize(name, symbol, decimals, msg.sender, address(groth16Verifier));
        emit Perc20Deployed(pool, msg.sender);
    }

    /// @notice Predict the address `createPerc20Deterministic(_, _, _, salt)` from `issuer` yields.
    function predictPerc20Address(address issuer, bytes32 salt) external view returns (address) {
        return Clones.predictDeterministicAddress(
            implementation, keccak256(abi.encode(issuer, salt)), address(this)
        );
    }
}

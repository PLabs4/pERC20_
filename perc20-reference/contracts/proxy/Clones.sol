// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Clones — EIP-1167 minimal proxy deployment
/// @notice Minimal in-repo port of OpenZeppelin's `Clones` (the project vendors no
///         external Solidity deps). Deploys gas-cheap, fixed-bytecode proxies that
///         `DELEGATECALL` to a single `implementation`. Used by `PERC20Factory` so the
///         factory's *runtime* code never embeds `PERC20`'s ~24 KB creation code (which
///         would exceed the EIP-170 limit); the implementation is deployed once and every
///         asset is a 45-byte clone of it.
/// @dev Clones are initialized via an explicit `initialize(...)` call (they do not run the
///      implementation's constructor), which `PERC20Factory` performs atomically in the same
///      transaction as the clone, leaving no front-running window.
library Clones {
    error CloneCreationFailed();

    /// @notice Deploy a minimal proxy of `implementation` via `CREATE`.
    function clone(address implementation) internal returns (address instance) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(ptr, 0x14), shl(0x60, implementation))
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            instance := create(0, ptr, 0x37)
        }
        if (instance == address(0)) revert CloneCreationFailed();
    }

    /// @notice Deploy a minimal proxy of `implementation` via `CREATE2` for a deterministic
    ///         address (see `predictDeterministicAddress`).
    function cloneDeterministic(address implementation, bytes32 salt)
        internal
        returns (address instance)
    {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(ptr, 0x14), shl(0x60, implementation))
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            instance := create2(0, ptr, 0x37, salt)
        }
        if (instance == address(0)) revert CloneCreationFailed();
    }

    /// @notice Compute the address a `cloneDeterministic(implementation, salt)` from `deployer`
    ///         would produce, without deploying.
    function predictDeterministicAddress(address implementation, bytes32 salt, address deployer)
        internal
        pure
        returns (address predicted)
    {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(ptr, 0x14), shl(0x60, implementation))
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf3ff00000000000000000000000000000000)
            mstore(add(ptr, 0x38), shl(0x60, deployer))
            mstore(add(ptr, 0x4c), salt)
            mstore(add(ptr, 0x6c), keccak256(ptr, 0x37))
            predicted := and(keccak256(add(ptr, 0x37), 0x55), 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }
}

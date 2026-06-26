// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IPERC20
/// @notice pERC20 privacy fungible token standard (p = privacy).
interface IPERC20 {
    struct PrivacyCall {
        bytes actions;              // abi.encode(IEndpointCore.BundleAction[])
        uint256[3] bindingSig;
    }

    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
    function issuer() external view returns (address);

    /// @notice Current compliance frozen SMT root. Every action's `pubFields[7]` MUST
    ///         equal this value at proof time. Updated via `setFrozenRoot` by admin.
    function cmxFrozenRoot() external view returns (uint256);

    /// @notice Update the compliance frozen root after rebuilding the off-chain blacklist SMT.
    /// @dev    Restricted to `admin`.
    function setFrozenRoot(uint256 newRoot) external;

    /// @notice Private note→note transfer. Returns true on success (ERC-20 convention).
    function transfer(PrivacyCall calldata call) external returns (bool);
    /// @notice Executor-gated transfer. When `executor != address(0)`, the bundle's signatures
    ///   are bound to that submitter and only that address may submit it (used by atomic-swap
    ///   coordinators). `executor == address(0)` is identical to `transfer(call)`.
    function transfer(address executor, PrivacyCall calldata call) external returns (bool);
    function mint(uint256 amount, PrivacyCall calldata call) external;
    function burn(uint256 amount, PrivacyCall calldata call) external;

    // ── Events ──
    //
    // This standard intentionally does NOT emit ERC-20's `Transfer(from,to,value)`:
    //   - from/to are always hidden notes, and value is private for transfers, so a
    //     `Transfer` event would carry no meaningful (and no non-misleading) data.
    //   - Per-note observability for ALL operations (mint/burn/transfer) is provided by
    //     `NoteAdded` / `NoteConfirmed` (see IEndpointCore).
    //   - Supply-changing operations additionally emit `Mint` / `Burn` (public amount only).
    event Mint(address indexed issuer, uint256 amount);
    event Burn(uint256 amount);
    event FrozenRootUpdated(uint256 oldRoot, uint256 newRoot);
    /// @dev MUST be emitted once at asset deployment (typically in the constructor).
    ///      Factory deployment is RECOMMENDED but not required; standalone deployments
    ///      are conformant when this event is emitted from the asset contract.
    event Perc20Created(
        address indexed pool,
        address indexed issuer,
        string name,
        string symbol,
        uint8 decimals
    );
}

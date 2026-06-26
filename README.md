# pERC20

**p**rivacy-native fungible token standard for the EVM.

pERC20 borrows the familiar semantics of [ERC-20](https://eips.ethereum.org/EIPS/eip-20) — `name`, `symbol`, `decimals`, `totalSupply`, mint, transfer, and burn — but implements them on top of an **Orchard-style ZK-UTXO** note model. Balances and transfer amounts are private by default; only aggregate supply and mint/burn amounts are public.

This repository publishes the **reference asset contract** (`PERC20.sol`) from the pERC20 reference implementation. The full codebase (Groth16 verifier, Merkle tree, crypto libraries, factory, tests, and EIP draft) lives in the main PERC20 development repository.

## Why pERC20

| Goal | Approach |
| --- | --- |
| Privacy by default | Assets exist as encrypted notes from issuance; no public-to-shielded hop |
| UTXO-level privacy | No on-chain account balances; anonymity sets form from homogeneous notes |
| Verifiable honesty | Public `totalSupply` prevents invisible inflation |
| Built-in compliance | Each asset binds to a `cmxFrozenRoot`; blacklisted commitments cannot be spent (enforced in-circuit) |
| EVM-native | Standard interfaces for wallets, indexers, relayers, and issuers |

pERC20 is **not** binary-compatible with ERC-20: there is no `balanceOf`, `approve`, or `transferFrom`. Holders discover notes via viewing keys; relayers submit zero-knowledge proofs on their behalf.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  IPERC20 (product layer)                                │
│  name · symbol · decimals · totalSupply · issuer        │
│  cmxFrozenRoot · setFrozenRoot                          │
│  mint · burn · transfer(PrivacyCall)                    │
└──────────────────────────┬──────────────────────────────┘
                           │ inherits
┌──────────────────────────▼──────────────────────────────┐
│  OrchardVerifier / IEndpointCore (implementation layer) │
│  Groth16 verification · commitment tree · nullifier set │
│  cmxRoot · isValidAnchor · NoteAdded / NoteConfirmed     │
└─────────────────────────────────────────────────────────┘
```

### `PERC20.sol` (this repo)

`PERC20` is the **asset-facing** contract. It wraps the Orchard note state machine with:

- ERC-20-like metadata and public `totalSupply` accounting
- Issuer-gated `mint`, holder `burn`, and private `transfer`
- Compliance root management via `setFrozenRoot` / `cmxFrozenRoot`
- Constructor emission of `Perc20Created` for indexer discovery

All value-changing paths go through `_executeBundle` (internal). There is **no public `bundle()`** entry point — supply invariants cannot be bypassed at the ABI level.

### Key interfaces

| Interface | Role |
| --- | --- |
| **`IPERC20`** | Token API: metadata, supply, compliance root, `PrivacyCall` operations |
| **`IEndpointCore`** | Note state machine observability: `cmxRoot`, `isValidAnchor`, events |
| **`IActionGroth16Verifier`** | Groth16 proof verification hook |

### `PrivacyCall`

Every `mint`, `burn`, and `transfer` accepts a `PrivacyCall`:

```solidity
struct PrivacyCall {
    bytes      actions;     // abi.encode(IEndpointCore.BundleAction[])
    uint256[3] bindingSig;  // Baby JubJub Schnorr binding signature
}
```

Each `BundleAction` carries a Groth16 proof, public fields, spend-auth signature, output commitment (`cmx`), and encrypted note payloads. See the EIP draft in the main repository for the full `BundleAction` layout.

## Operations

| Method | Who | Public `amount` | Value balance encoding |
| --- | --- | --- | --- |
| `transfer(call)` | anyone | hidden | `0` |
| `mint(amount, call)` | issuer | `amount` | `amount \| (1 << 255)` |
| `burn(amount, call)` | holder | `amount` | `amount` |

Mint uses a circuit-constrained dummy input note (`v = 0`) and shares the same anchor / nullifier / spend-auth verification path as transfer and burn.

## Compliance (`cmxFrozenRoot`)

The compliance blacklist is a sparse Merkle tree of **note commitments (`cmx`)**, rooted at `cmxFrozenRoot`. Because spends expose **nullifiers (`nf`)**, not commitments, on-chain membership checks would break privacy. Non-membership is therefore proved **inside the Groth16 circuit**; the chain stores only the SMT root and binds `pubFields[7]` to `cmxFrozenRoot()` at verification time.

Admin updates the root off-chain (rebuild blacklist SMT → `setFrozenRoot(newRoot)`). Initial root `0` means an empty blacklist (default allow).

## Deployment

Standalone deployment (conformant):

```solidity
PERC20 token = new PERC20(
    "My Token",
    "pMTK",
    18,
    issuerAddress,
    groth16VerifierAddress
);
// Emits Perc20Created from the constructor
```

A factory (`PERC20Factory`) is **recommended** but not required by the standard — useful when many assets share one Groth16 verifying key.

**Genesis mint** requires two steps: deploy the contract, then call `mint` with a binding signature that includes the deployed contract address (anti cross-contract replay).

## Chain observability

| View / event | Purpose |
| --- | --- |
| `cmxRoot()` | Latest commitment-tree root; compare against locally rebuilt tree |
| `isValidAnchor(root)` | Preflight check that a proof anchor is valid before submitting a tx |
| `cmxFrozenRoot()` | Current compliance SMT root for proof construction |
| `NoteAdded` / `NoteConfirmed` | Per-note indexing (wallets scan via IVK/OVK) |
| `Mint` / `Burn` | Public supply changes |
| `Perc20Created` | New asset registration |

## Files in this repository

```
contracts/ptoken/PERC20.sol   ← minimal reference asset contract (root)
perc20-reference/             ← full contract stack + audit reports (snapshot)
docs/                         ← PDF audit reports (beta rounds)
```

The root `PERC20.sol` imports `OrchardVerifier`, `IPERC20`, and `IEndpointCore` from the full reference implementation. It does **not** compile in isolation; use [`perc20-reference/`](./perc20-reference/) for the complete on-chain stack, or the [PERC20](https://github.com/PERC20Labs/PERC20) development repository for build, test, and deployment.

## Status

Draft standard — intended for Ethereum Magicians discussion and eventual EIP submission. Not audited for production mainnet deployment.

## License

MIT — see [LICENSE](./LICENSE).

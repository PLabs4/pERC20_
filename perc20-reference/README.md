# pERC20 Reference Snapshot

Self-contained snapshot of the **pERC20** (privacy-native fungible token) reference contracts and security audit reports, synced from the main [PERC20](https://github.com/PERC20Labs/PERC20) development repository.

**Source commit:** [`75d63e7`](https://github.com/PERC20Labs/PERC20/commit/75d63e7fe219912949e971037bee92d4e0134cbd) (2026-06-26)

This folder is separate from the minimal root-level `contracts/ptoken/PERC20.sol` publication. It includes the full on-chain stack needed to understand, review, and build against the standard.

## Contracts

```
contracts/
├── ptoken/
│   ├── PERC20.sol          ← asset-facing pERC20 implementation
│   └── PERC20Factory.sol   ← EIP-1167 clone factory (recommended deploy path)
├── orchardverifier/        ← note state machine (Groth16, Merkle tree, nullifiers)
├── crypto/                 ← Baby JubJub, Poseidon, signatures, Merkle helpers
├── interfaces/
│   ├── IPERC20.sol
│   ├── IEndpointCore.sol
│   └── IActionGroth16Verifier.sol
└── proxy/
    └── Clones.sol
```

Build and test against the full repository: [PERC20Labs/PERC20](https://github.com/PERC20Labs/PERC20).

## Audit Reports

| File | Scope |
| --- | --- |
| [audit-contracts-perc20-1.md](./docs/audit/audit-contracts-perc20-1.md) | Full pERC20 contract stack (`PERC20` + `OrchardVerifier` + crypto libraries) |
| [audit-3-circuits-and-contracts.md](./docs/audit/audit-3-circuits-and-contracts.md) | Round 3 — circuits + contracts cross-layer review |
| [Audit-PERC20.md](./docs/audit/Audit-PERC20.md) | Issuer-minted `PERC20.sol` focused audit (2026-06-24) |
| [audit-perc20-sol.md](./docs/audit/audit-perc20-sol.md) | Single-contract audit — Chinese (2026-06-03) |
| [audit-perc20-sol-ai-audit.md](./docs/audit/audit-perc20-sol-ai-audit.md) | Single-contract audit — English (2026-06-03) |

PDF audit reports (beta rounds) remain in the repository root [`docs/`](../docs/) directory.

## License

MIT — see [LICENSE](../LICENSE).

# Smart Contract Security Audit — `PERC20` (Issuer-Minted Privacy Token)

**Scope (this report):** `contracts/ptoken/PERC20.sol` and its direct dependency surface (`OrchardVerifier`, the Baby JubJub signature libraries, `IPERC20`/`IEndpointCore`).
**Scenario:** Issuer-minted privacy-native fungible token — public `totalSupply` + ERC-20-style metadata, balances held as Orchard-model ZK-UTXO notes.
**Question answered:** Can an unprivileged attacker forge, counterfeit, double-spend, or illegally mint / transfer / burn the token?
**Date:** 2026-06-24

---

## 1. Executive Summary

`PERC20` extends `OrchardVerifier` (the note state machine: Groth16 proof verification, Poseidon Merkle commitment tree, nullifier set, Baby JubJub binding + spend-auth signatures) with supply accounting and the `mint` / `burn` / `transfer` entry points of `IPERC20`.

**Headline result.** No vulnerability was found that lets an *unprivileged* attacker forge, counterfeit, double-spend, or illegally mint / transfer / burn. Value integrity is enforced by a layered design: canonical-field checks on all Groth16 public inputs, single-spend (`_isSpent`) and commitment-uniqueness (`cmxExists`) guards, value conservation via the binding signature, spend authority via the spend-auth signature, and `chainId` / `address(this)`-bound sighashes that defeat replay.

**Where the real risk is: privilege, not the protocol.** The dominant exposure is centralization. Each asset's `admin` (= `issuer` at deploy) can hot-swap the Groth16 verifier (`setGroth16Verifier`) with **no timelock and no immutability**; a malicious or key-compromised admin can install a verifier that accepts any proof, and thereby counterfeit notes and break value conservation. Per the engagement, this admin trust is **accepted** for this scenario, but it remains the most important assumption and is recorded here as such.

### Findings summary

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| H-01 | Admin can hot-swap the Groth16 verifier with no timelock / immutability | **High** | Accepted (trust assumption) |
| M-01 | Concentrated, un-timelocked admin powers (verifier, frozen root) | **Medium** | Accepted (trust assumption) |
| L-01 | `setGroth16Verifier` / `setFrozenRoot` can grief liveness (freeze withdrawals / invalidate in-flight proofs) | **Low** | Accepted (mitigated by L-04 grace window) |
| I-01 | `mint` dummy-input nullifier must be a unique non-zero field element | Informational | **Resolved** (on-chain `ZeroNullifier` guard + corrected NatSpec) |
| I-02 | Free-standing `error ZeroIssuer/ZeroVerifier` indentation / placement | Informational | Open (cosmetic) |
| I-03 | Token metadata (`name`/`symbol`) not authenticated at deploy | Informational | Documented (asset identity = address) |

---

## 2. Audited Files

| File | Role |
|------|------|
| `contracts/ptoken/PERC20.sol` | Metadata, `totalSupply`, `mint`/`burn`/`transfer`, frozen-root setter |
| `contracts/orchardverifier/OrchardVerifier.sol` | Proof verification + note state machine (tree, nullifiers, roots, sig checks) |
| `contracts/crypto/signature/BindingSignature.sol` | Value-conservation Schnorr |
| `contracts/crypto/signature/SpendAuthSignature.sol` | Per-action spend-authorization Schnorr |
| `contracts/interfaces/{IPERC20,IEndpointCore}.sol` | Structs, events, layout |

**Relied upon, not re-derived:** `Groth16PairingVerifier.sol` (snarkjs-generated VK), `PoseidonT3.sol`, and the soundness of `action.circom`. These are inherent ZK-system trust roots.

---

## 3. Severity Classification

- **Critical** — direct loss of funds / unauthorized supply, exploitable by any user.
- **High** — loss of funds or integrity under a realistic (possibly privileged) actor.
- **Medium** — conditional / partial impact; defense-in-depth gaps.
- **Low** — limited impact, hard to trigger, or non-financial.
- **Informational** — documentation / hygiene / latent assumptions.

---

## 4. Attack Surface

A caller submits `IPERC20.PrivacyCall { bytes actions, uint256[3] bindingSig }`. `actions` decodes to `BundleAction[]`; each carries `cmx`, `nfOld`, `anchor`, ciphertexts, `proof`, `pubFields[8]`, `spendAuthSig`. Entry points:

- `mint(amount, call)` — `onlyIssuer`; `valueBalance = amount | (1<<255)`.
- `burn(amount, call)` — permissionless; `valueBalance = amount`; underflow-guarded supply.
- `transfer(call)` / `transfer(executor, call)` — `valueBalance = 0`.

All funnel into `OrchardVerifier._executeBundle`, which per action enforces (before any state write):

1. all 8 `pubFields < FIELD_MODULUS` (canonical — blocks `nf + p` aliasing double-spend);
2. `pubFields[7] == cmxFrozenRoot()` (compliance), with the L-04 grace window;
3. `groth16Verifier.verifyAction(proof, pubFields)`;
4. `cmx != 0`, `nfOld != 0` (see I-01), `pubFields[6] == cmx`;
5. `anchor ∈ _allRootsEver`, `pubFields[0] == anchor`, `pubFields[3] == nfOld`;
6. spend-auth Schnorr over `(nfOld, cmx, epk, encCiphertext, outCiphertext, executor)` under `rk = (pubFields[4], pubFields[5])`;
7. binding Schnorr over all nullifiers + commitments + `valueBalance` + `recipientMeta` + `executor` + `chainId` + `address(this)`.

Only after the binding signature verifies are nullifiers consumed into `_isSpent`, commitments inserted (rejecting duplicates), root updated, and events emitted.

**Why each forgery class fails for an unprivileged attacker:**

- **Illegal mint / counterfeit.** `mint` is `onlyIssuer`. A `transfer` (`vb=0`) cannot create value: the binding signature forces `Σcv = (Σrcv)·G_RANDOM`, and the circuit ties each `cv` to `(v_old − v_new)`.
- **Double-spend.** Canonical nullifier + `_isSpent` + `pubFields[3]==nfOld` + canonical-field check (no `nf+p` alias) + intra-bundle duplicate rejection.
- **Spending another's note.** Requires the victim's nullifier secret *and* a spend-auth signature under `rk`.
- **Replay (cross-chain / cross-contract).** Both sighashes bind `chainId` and `address(this)`; nullifiers single-use.
- **Over-burn.** Value conservation forces spent notes to net `+amount`; `_totalSupply` underflow-guarded.

---

## 5. Findings

### [H-01] Admin can hot-swap the Groth16 verifier — **High** — Accepted

`OrchardVerifier.setGroth16Verifier` is `onlyAdmin` with only a zero-address check and no timelock / immutability:

```solidity
function setGroth16Verifier(address groth16Verifier_) external onlyAdmin {
    if (groth16Verifier_ == address(0)) revert ZeroAddress();
    groth16Verifier = IActionGroth16Verifier(groth16Verifier_);
}
```

A malicious or key-compromised admin can install a verifier returning `true` for any proof, then mint counterfeit notes that break value conservation. For `PERC20` the admin is also the `issuer` (already trusted to mint), so the marginal additional power is "forge other users' note transitions". **Accepted** for this scenario per engagement scope.

**Recommendation (optional):** timelock / governance / multisig on `setGroth16Verifier`, or make the verifier immutable once the circuit is final.

### [M-01] Concentrated, un-timelocked admin powers — **Medium** — Accepted

A single `admin` key holds `setGroth16Verifier`, `setFrozenRoot`, `setFrozenRootGracePeriod`, and `setMaxActions`. Two-step `transferAdmin` / `acceptAdmin` mitigates accidental hand-off, but a single-key compromise is high-impact. **Accepted.**

### [L-01] Admin liveness griefing — **Low** — Accepted

`setFrozenRoot` can be set so that no in-flight proof satisfies `pubFields[7] == cmxFrozenRoot()`, freezing transfers/burns. The L-04 grace window (`setFrozenRootGracePeriod`, capped at 1 day) lets in-flight proofs against the previous root settle, bounding the disruption. **Accepted** as a compliance-control trade-off.

### [I-01] `mint` dummy-input nullifier must be unique & non-zero — Informational — **Resolved**

`_executeBundle` keys the spent-set on `nfOld`. A literal zero dummy nullifier would poison `_isSpent[0]` and brick every later zero-nullifier action. The implementation now rejects `nfOld == 0` on-chain (`ZeroNullifier`) and the `mint` NatSpec documents the requirement. Not externally exploitable (no valid proof exists for a poisoned key), fixed as defense-in-depth.

### [I-02] Error-declaration formatting — Informational — Open

`error ZeroIssuer();` / `error ZeroVerifier();` are declared at column 0 (outside the indentation of the surrounding error block). Cosmetic only.

### [I-03] Metadata not authenticated at deploy — Informational — Documented

`name` / `symbol` are caller-supplied; asset identity is the contract address (binding sighashes embed `address(this)`). A look-alike deployment is an unrelated token. Standard ZK-asset trust boundary.

---

## 6. Conclusion

For the issuer-minted scenario, `PERC20`'s value-integrity guarantees against unprivileged attackers are sound. Residual risk is concentrated in the `admin`/`issuer` trust assumptions (H-01, M-01), which are **accepted** for this engagement. The one defense-in-depth gap found during review (zero nullifier, I-01) has been remediated.

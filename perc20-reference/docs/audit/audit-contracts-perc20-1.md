# Smart Contract Security Audit — pERC20 (`PERC20` + `OrchardVerifier` + crypto libraries)

**Report style:** modeled on the Nethermind *NM-0131 Worldcoin* report format.
**Scope:** the on-chain pERC20 reference implementation under `contracts/`.
**Question answered:** can the pERC20 privacy token be **maliciously forged, created, minted, transferred, or burned** by an attacker?

---

## 1. Executive Summary

pERC20 is a privacy-native fungible token: ERC-20-style public metadata + `totalSupply`, with balances held as Orchard-model ZK-UTXO notes verified by Groth16. `PERC20` adds supply accounting and `mint`/`burn`/`transfer` on top of `OrchardVerifier`, the note state machine that verifies each action's proof, maintains the Poseidon Merkle commitment tree + nullifier set, and checks the Baby JubJub binding / spend-auth signatures.

**Headline result.** We found **no vulnerability that lets an *unprivileged* attacker forge, counterfeit, double-spend, or illegally mint / transfer / burn** the token. Value integrity is enforced by a layered design: a now-audited circuit, a contract that pins every Groth16 public field to externally-meaningful state, single-spend (`_isSpent`) and commitment-uniqueness (`cmxExists`) guards, value conservation via the binding signature, spend authority via the spend-auth signature, and `chainId`/`address`-bound sighashes that defeat replay. The single-public-input design (`ActionPubHash`) was verified **byte-identical** to the circuit's `PubHashAction`.

**Where the real risk is: privilege, not the protocol.** The dominant exposure is **centralization**. Each asset's `admin` can hot-swap the Groth16 verifier (`setGroth16Verifier`) with **no timelock and no immutability**; a malicious or key-compromised admin can install a verifier that accepts any proof and thereby **counterfeit notes / break value conservation / drain the shielded pool** (**H-01**). The admin role is also broadly powered (verifier, frozen root, action cap) so a single-key compromise is catastrophic (**M-01**). These are trust assumptions, not exploits available to a regular user.

**Update to the prior report.** The previous audit's **Critical C-01** ("on-chain integrity is wholly delegated to an *unsound* circuit") was correct *at that time*. The circuit has since been audited and remediated across rounds 0–3 (under-constraints, range checks, subgroup checks, identity exclusion, scaffold cleanup) and cross-checked against the contract in round 4. **C-01 is therefore no longer a Critical finding** — the delegation now targets a sound, independently-audited circuit. The residual "the contract trusts the verifier + circuit + crypto libraries" is inherent to any ZK system and is addressed by the recommendations below (immutable/timelocked verifier, library review, MPC ceremony).

### Findings summary

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| H-01 | Admin can hot-swap the Groth16 verifier with no timelock / immutability → counterfeit & drain | **High** | Open |
| M-01 | Concentrated, un-timelocked admin powers (verifier, frozen root, maxActions) | **Medium** | Open |
| L-01 | Public EC points (`cv_net`, `rk`) consumed without on-chain on-curve/subgroup checks (now backstopped by circuit soundness) | **Low** (was Medium) | **Resolved** |
| L-02 | Schnorr malleability: `s` not range-checked; `R` only on-curve, not subgroup-checked | **Low** | **Resolved** |
| L-03 | `maxActions` up to 50 → large-bundle gas / proof-cost griefing | **Low** | **Resolved** |
| L-04 | Frozen-root update invalidates in-flight proofs (liveness) | **Low** | **Resolved** |
| L-05 | Nullifier set written before the binding-signature check (defense-in-depth) | **Low** | **Resolved** |
| I-01 | Note ciphertext not proven in-circuit → recipient non-receipt risk | Informational | **Resolved** (documented) |
| I-02 | NUMS generators assumed prime-order without a recorded on-chain/offline check | Informational | **Resolved** |
| I-03 | Token metadata (`name`/`symbol`) not authenticated at `create` | Informational | **Resolved** (documented) |
| I-04 | `pointNeg` non-canonical for `x = 0`; trusted Poseidon / empty-subtree constants | Informational | **Resolved** |
| (resolved) | C-01 (prior) "delegated to an unsound circuit" — circuit since audited & fixed | — | Resolved by circuit rounds 0–4 |
| (resolved) | L-03 (prior) "frozen SMT keyed on low 32 bits of cmx" — replaced by full-value IMT | — | Resolved (IMT migration) |

---

## 2. Audited Files

| File | LoC | Role |
|------|----:|------|
| `contracts/orchardverifier/OrchardVerifier.sol` | 331 | Proof verification + note state machine (tree, nullifiers, roots, sig checks) |
| `contracts/ptoken/PERC20.sol` | 143 | Metadata, `totalSupply`, `mint`/`burn`/`transfer`, frozen-root setter |
| `contracts/ptoken/PERC20Factory.sol` | 50 | Optional deployer (`createPerc20`) |
| `contracts/orchardverifier/ActionGroth16Verifier.sol` | 52 | Decode proof, recompute `pub_hash`, delegate to pairing verifier |
| `contracts/crypto/hash/ActionPubHash.sol` | 56 | On-chain `pub_hash` sponge (must match circuit) |
| `contracts/crypto/signature/BindingSignature.sol` | 152 | Value-conservation Schnorr (mint/burn/transfer balance) |
| `contracts/crypto/signature/SpendAuthSignature.sol` | 99 | Per-action spend-authorization Schnorr |
| `contracts/crypto/merkle/IncrementalMerkleTree.sol` | 115 | Depth-32 Poseidon frontier tree |
| `contracts/crypto/curve/BabyJubJub.sol` | 238 | Twisted-Edwards EC ops used by the signatures |
| `contracts/orchardverifier/Groth16ProofCodec.sol` | 24 | `abi.(en/de)code` of `(pA,pB,pC)` |
| `contracts/interfaces/{IEndpointCore,IPERC20,IActionGroth16Verifier}.sol` | — | Structs, events, layout |

**Relied upon, not re-derived:** `Groth16PairingVerifier.sol` (snarkjs-generated VK, trusted as generated) and `PoseidonT3.sol` (auto-generated permutation). These are exercised by the no-mock e2e suite but a dedicated review is recommended (see Disclaimer).

---

## 3. Severity Classification

- **Critical** — directly leads to loss of funds / unauthorized supply, exploitable by any user.
- **High** — loss of funds or protocol integrity under a realistic (possibly privileged) actor.
- **Medium** — conditional or partial impact; defense-in-depth gaps that become exploitable when combined.
- **Low** — limited impact, hard-to-trigger, or non-financial.
- **Informational** — documentation / hygiene / latent assumptions, no direct impact.

---

## 4. System Overview & the Forgery/Mint/Transfer/Burn Attack Surface

A user submits an `IPERC20.PrivacyCall { bytes actions, uint256[3] bindingSig }`. `actions` decodes to `BundleAction[]`; each action carries `cmx`, `nfOld`, `anchor`, ciphertexts, `proof`, `pubFields[8]`, `spendAuthSig`. The entry points are `mint(amount, call)` (onlyIssuer), `burn(amount, call)`, `transfer(call)`; all funnel into the internal `_executeBundle` (there is deliberately no public `bundle()`).

Per action, `OrchardVerifier` enforces, **before** any state write:

1. all 8 `pubFields < FIELD_MODULUS` (canonical — blocks `nf + p` aliasing double-spends);
2. `pubFields[7] == cmxFrozenRoot()` (compliance);
3. `groth16Verifier.verifyAction(proof, pubFields)` with `pub_hash` recomputed on-chain via `ActionPubHash` (verified identical to the circuit);
4. `cmx != 0`, `pubFields[6] == cmx`;
5. `anchor ∈ _allRootsEver`, `pubFields[0] == anchor`;
6. `pubFields[3] == nfOld` (the proof's nullifier matches the action field);
7. spend-auth Schnorr over a sighash binding `(nfOld, cmx, epk, encCiphertext, outCiphertext)` to `rk = (pubFields[4], pubFields[5])`;
8. binding Schnorr: `Σ cv == valueBalance·G_VALUE + (Σ rcv)·G_RANDOM`, sighash bound to all nullifiers + commitments + `valueBalance` + `chainId` + `address(this)`.

After the binding signature verifies (L-05), `_executeBundle` consumes each `nfOld` into `_isSpent` (reverts on reuse, intra- and inter-bundle), then inserts each `cmx` (rejecting duplicates via `cmxExists`), updates the root, and emits `NoteAdded`/`NoteConfirmed`. Verification itself (steps 1–8) performs no state writes. Supply moves only on success: `mint` `_totalSupply += amount` (vb `= amount | (1<<255)`); `burn` `_totalSupply -= amount` (underflow-guarded, vb `= amount`); `transfer` vb `= 0`.

**Why each forgery class fails for an unprivileged attacker:**

- **Counterfeit / illegal mint.** `mint` is `onlyIssuer`. A `transfer` (`vb=0`) cannot create value: the binding signature forces `Σcv = (Σrcv)·G_RANDOM`, and the circuit ties each `cv` to `(v_old − v_new)`, so a single spend→output forces `v_new = v_old`. The soft-Merkle (`v_old=0`) path carries zero value, so a "dummy" input cannot conjure value — any non-zero output must be funded by a real, in-tree, owned input.
- **Double-spend.** Deterministic canonical nullifier (circuit) + `_isSpent` + `pubFields[3]==nfOld` + canonical-field check (no `nf+p` alias).
- **Spending another user's note.** Requires the victim's note nullifier (secret, derived from the victim's `nk`) *and* a spend-auth signature over `rk` (requires the authority key). Neither is available to an attacker.
- **Replay / cross-contract / cross-chain.** Both sighashes bind `chainId` and `address(this)`; nullifiers are single-use.
- **Forged `create`.** `createPerc20` sets `issuer = msg.sender`; asset identity is the contract address, and binding sighashes embed `address(this)`, so a fake deployment is just an unrelated token (see I-03).
- **Over-burn.** Value conservation forces spent notes to net `+amount`; `_totalSupply` underflow-guarded.

---

## 5. Findings

### [H-01] Admin can hot-swap the Groth16 verifier with no timelock or immutability — **High** — Open

**Description.** `OrchardVerifier.setGroth16Verifier(address)` is `onlyAdmin` and takes effect immediately, with no timelock, no two-step, and no immutability. `admin` starts as the issuer but can be reassigned via `transferAdmin`/`acceptAdmin`.

**Impact.** A malicious or key-compromised admin can install a verifier whose `verifyAction` returns `true` for any input. Although the binding and spend-auth signatures are checked by the *contract* (not the verifier), an attacker who controls the action's `cv_net`/`rk` can produce valid signatures for values of their choosing once the proof no longer constrains them. Concretely, they can craft a `transfer` whose fake proof decouples the committed note value from `cv_net`: emit a note committing to value `V` while the binding signature sees `vb = 0`. The note is later spendable for `V` real units — **counterfeit / unauthorized supply**, breaking the invariant `totalSupply ≈ Σ note values` and enabling drain of any value-backing. This is the single most serious on-chain exposure and converts a key compromise into total loss for that asset's holders.

**Recommendation.** Make the verifier **immutable** (set once at construction; rotate only by deploying a new asset), or gate `setGroth16Verifier` behind a **timelock** (e.g. 48–72h) plus an on-chain event, and ideally a multisig admin (M-01). Document the verifier address as part of the asset's trust assumptions so wallets can monitor rotations.

### [M-01] Concentrated, un-timelocked admin powers — **Medium** — Open

**Description.** A single `admin` controls `setGroth16Verifier` (H-01), `setFrozenRoot` (compliance censorship / un-censorship), and `setMaxActions`. `admin` and `issuer` may diverge after `transferAdmin`. There is no timelock on any of these except the two-step on the admin handover itself.

**Impact.** Single-key compromise is catastrophic (via H-01) and additionally allows compliance manipulation (freeze/unfreeze arbitrary notes by changing the root) and griefing (`maxActions`). The `issuer` separately holds unlimited `mint` — inherent to a "compliant issuer" token, but worth stating: **supply integrity is only as trustworthy as the issuer**.

**Recommendation.** Use a multisig (and/or timelock) for `admin`; separate `admin` from `issuer`; consider per-power roles (a dedicated compliance role for `setFrozenRoot`). Publish the governance model in the standard.

### [L-01] Public EC points (`cv_net`, `rk`) consumed without on-chain on-curve / subgroup checks — **Low** (was Medium) — **Resolved**

**Description.** `cv_net = (pubFields[1], pubFields[2])` enters `BindingSignature.verify` (summed via `pointAdd`) and `rk = (pubFields[4], pubFields[5])` enters `SpendAuthSignature.verify` (`scalarMul`), with no on-chain `isOnCurve`/subgroup check — only the canonical range check (`< FIELD_MODULUS`). The points are *proof-attested*: the circuit computes `cv = [magnitude]·G_VALUE + [rcv]·G_RANDOM` and `rk = ak + [α]·G_SPEND_AUTH`, both subgroup points, and binds them into `pub_hash`.

**Impact.** Safe **iff** the circuit is sound and the generators are prime-order. With the circuit now audited (rounds 0–3) and the matched-set verified, this is no longer Medium; it is a residual defense-in-depth gap that would re-open if the verifier were swapped (H-01) or the circuit changed. (Note: `BindingSignature`/`SpendAuthSignature` *do* check the attacker-supplied `R` with `isOnCurve`, which is the genuinely-unconstrained input.)

**Recommendation.** Add cheap `isOnCurve` (and ideally subgroup) checks on `cv_net` and `rk` for defense-in-depth, so on-chain integrity does not depend solely on circuit soundness.

### [L-02] Schnorr signature malleability — `s` unbounded, `R` only on-curve — **Low** — **Resolved**

**Description.** Both signature libraries reduce `s` via `scalar % SUBGROUP_ORDER` inside `scalarMul` but never reject `s ≥ ℓ`, so `s` and `s + ℓ` are both accepted (signature malleability). `R` is checked `isOnCurve` but not subgroup-membership (the Schnorr equation self-corrects: `s·G ∈ subgroup` forces a valid `R` into the subgroup, so non-subgroup `R` simply fails).

**Impact.** Low. Replay is independently prevented by nullifiers + bundle-bound sighashes; malleable signatures are not used as unique identifiers. The concern is hygiene and any future code that might treat a signature as canonical.

**Recommendation.** Require `sigS < SUBGROUP_ORDER`; optionally add an explicit subgroup check on `R`.

### [L-03] `maxActions` up to 50 → large-bundle gas / proof griefing — **Low** — **Resolved**

**Description.** `setMaxActions` allows up to 50 actions per bundle; each action runs a pairing check + 32 Poseidon insertions + two Schnorr verifications.

**Impact.** Large bundles can be expensive; an admin could raise the cap to grief, and large legitimate bundles risk hitting block gas limits. Low.

**Recommendation.** Keep the cap modest (the default 10 is reasonable); document gas expectations.

### [L-04] Frozen-root update invalidates in-flight proofs (liveness) — **Low** — **Resolved**

**Description.** Every action must satisfy `pubFields[7] == cmxFrozenRoot()` at execution time. A `setFrozenRoot` between proof generation and submission causes the action to revert (`BadFrozenRoot`).

**Impact.** Liveness only — no funds at risk; users simply re-prove against the new root. (The prior report's companion concern — "frozen SMT keyed on the low 32 bits of `cmx`" — is **resolved**: the design moved to an Indexed Merkle Tree over full `cmx` values, so distinct commitments never collide regardless of depth; see circuit round-0 Issue E.)

**Recommendation.** Consider a short grace window accepting the previous root, or emit `FrozenRootUpdated` prominently (already emitted) so relayers re-prove promptly.

### [L-05] Nullifier set written before the binding-signature check — **Low** (defense-in-depth) — **Resolved**

**Description.** `_verifyBundle` sets `_isSpent[nf] = true` for every action *before* `_executeBundle` verifies the binding signature, although the surrounding comment states value conservation is checked "before mutating any state." Because the whole call is atomic, a failing binding signature reverts the writes — **not exploitable**.

**Recommendation.** Move the `_isSpent` check-and-set after the binding-signature verification (or correct the comment), so the "no mutation before value conservation" invariant holds literally and survives future refactors. (Tracked as round-4 Issue E-1.)

### [I-01] Note ciphertext not proven in-circuit — Informational — **Resolved** (documented)

The circuit does not prove `encCiphertext` correctly encrypts the note committed by `cmx` (as in Zcash). It is bound to the action by the spend-auth signature (no in-flight swap), but a **malicious sender** can emit an undecryptable note — the recipient cannot spend it (non-receipt). This is **not** counterfeit/theft (equivalent to non-payment, detected by the recipient). Document that "received" means "successfully trial-decrypted", never "a `NoteAdded` exists."

### [I-02] NUMS generators assumed prime-order without recorded verification — Informational — **Resolved**

`G_VALUE / G_RANDOM / G_SPEND_AUTH` (and the circuit's `G_NOTE / H_NOTE / G_NULLIFIER`) are trusted to lie in the Baby JubJub prime-order subgroup. This assumption is load-bearing for both the circuit's value commitment and the on-chain binding/spend-auth signatures. Add a one-time offline assertion (`on-curve ∧ [ℓ]G = O ∧ G ≠ O`) for all generators and record it / pin it in CI. (Ties to circuit round-2 Suggestion 9 / round-4 Suggestion 11.)

### [I-03] Token metadata not authenticated at `create` — Informational — **Resolved** (documented)

`createPerc20` (and standalone `new PERC20`) accept arbitrary `name`/`symbol`; anyone can deploy a "USDC"-named pERC20. Asset identity is the contract **address** (and binding sighashes embed it), so this is harmless to protocol integrity but can mislead users. Wallets/indexers MUST key on address and SHOULD surface issuer + deployment provenance, not name.

### [I-04] Minor: `pointNeg(0, y)` non-canonical; trusted hash constants — Informational — **Resolved**

`pointNeg(x,y) = (Fr - x, y)` yields the non-canonical `Fr` when `x = 0` (e.g. negating the identity for a `vb = 0` transfer); downstream `pointAdd` uses `mulmod`, which reduces it, so the result is correct, but the intermediate is non-canonical. Separately, `IncrementalMerkleTree._empty(l)` and `PoseidonT3` constants are trusted (generated from the Rust spec); add an on-chain/CI differential test against the circuit's Poseidon and empty-subtree vectors.

---

## 5a. Remediation Applied (this round) — L-01…L-05, I-01…I-04

All Low and Informational findings were remediated in-contract and re-verified (`forge test`: **70/70 pass**, including the 20 no-mock E2E real-proof cases for mint/transfer/burn and the new generator test):

| ID | Fix |
|----|-----|
| **L-01** | `BindingSignature.verify` now `isOnCurve`-checks every `cv_net`; `SpendAuthSignature.verify` `isOnCurve`-checks `rk` — before any EC arithmetic. On-chain soundness for these points no longer depends solely on circuit soundness. |
| **L-02** | Both signature libraries now reject `sigS >= SUBGROUP_ORDER` (closes the `s` / `s+ℓ` malleability). |
| **L-03** | `setMaxActions` upper bound lowered **50 → 16**. |
| **L-04** | Added an **opt-in** frozen-root grace window: `_setFrozenRoot` records the previous root + timestamp; `setFrozenRootGracePeriod(period)` (admin, ≤ 1 day, default **0 = strict**) lets the previous root be accepted within the window, so a mid-flight `setFrozenRoot` no longer strands in-flight proofs. Default keeps strict compliance (no behaviour change unless opted in). |
| **L-05** | `_verifyBundle` is now `view` and performs **no** state writes; nullifiers are consumed by `_executeBundle` **after** the binding signature verifies. The "no state mutation before value conservation" invariant now holds literally (verified by `test_failed_binding_leaves_state_clean`). |
| **I-01** | Documented the trust boundary in `IEndpointCore.NoteAdded`: a "received note" = "successfully trial-decrypted", never merely "a `NoteAdded` event exists". |
| **I-02** | Verified off-chain that all three generators are on-curve, prime-order (`[ℓ]G = O`), and ≠ identity; recorded in `BabyJubJub.sol` and asserted on-curve by `test/Generators.t.sol`. |
| **I-03** | Documented in `PERC20Factory.createPerc20`: metadata is caller-chosen and unauthenticated; identity is the contract address — wallets/indexers MUST key on address + issuer. |
| **I-04** | `pointNeg` is now canonical for `x = 0` (returns `0`, not `Fr`). |

> Note: the storage-layout change for L-04 was placed at the **end** of `OrchardVerifier` storage to preserve the existing slot layout (the no-mock E2E harness injects anchors via `vm.store` against fixed slots). **H-01** and **M-01** (centralization) are governance/deployment changes and remain Open by design.

---

## 6. Positive Observations

- **No public `bundle()`** — the single execution entry is the internal `_executeBundle`, removing a large misuse surface.
- **Canonical public-field guard** (`pubFields[i] < FIELD_MODULUS`) closes the `nf + p` aliasing double-spend (circuit H-1) — a subtle and correctly-handled cross-layer pitfall.
- **Tight field binding**: `pubFields[3]==nfOld`, `pubFields[6]==cmx`, `pubFields[0]==anchor∈_allRootsEver`, `pubFields[7]==frozenRoot`; `cmx != 0`; `cmxExists` rejects duplicate leaves.
- **Value & authority**: binding signature enforces `Σcv == vb·G_VALUE + …`; spend-auth signature binds the ciphertexts and proves authority over `rk`.
- **Replay resistance**: both sighashes bind `chainId` + `address(this)`; nullifiers single-use intra- and inter-bundle.
- **Anchor safety**: validity goes through the permanent `_allRootsEver` set, not the bounded ring buffer; the ring is view-only.
- **Supply guards**: `mint` `onlyIssuer`; `amount < SUBGROUP_ORDER`; `_requireAmountMatchesVb`; `burn` underflow-guarded; `transfer` `vb=0`.
- **Two-step admin transfer** prevents accidental hand-off; **immutable `issuer`**.
- **Matched-set verified**: `ActionPubHash.hash` is byte-identical to the circuit's `PubHashAction` (init, absorption order, capacity, domain, return).
- **Reconstruction-friendly events**: `NoteAdded`/`NoteConfirmed` let any party rebuild and self-verify the tree against on-chain roots (the indexer is not a trust anchor).

---

## 7. Conclusion

For an **unprivileged attacker**, we found **no path to forge, counterfeit, double-spend, or illegally mint / transfer / burn** pERC20: the audited circuit, the contract's public-field bindings, the single-spend and uniqueness guards, the binding and spend-auth signatures, and the `chainId`/`address`-bound sighashes form a sound whole, and the single-public-input `pub_hash` is matched exactly on-chain.

The material risk is **centralization**: an asset's `admin` can hot-swap the Groth16 verifier with no timelock (**H-01**) and holds concentrated, un-timelocked powers (**M-01**); a compromised admin key can counterfeit and drain. The remaining findings are Low/Informational defense-in-depth and hygiene items. The prior Critical (C-01) is **no longer applicable** because the circuit has been independently audited and fixed.

**Priority recommendations before mainnet:**
1. Make the Groth16 verifier **immutable or timelocked**, and place `admin` behind a **multisig/timelock** (H-01, M-01).
2. Add on-chain `isOnCurve`/subgroup checks on `cv_net`/`rk` and `sigS < ℓ` (L-01, L-02).
3. Record the **prime-order generator** verification and a **matched-set CI** test (I-02; circuit Suggestions 4/5/9).
4. Commission a **dedicated review of the signature + Poseidon libraries** and a **formal Groth16 MPC ceremony** (circuit Suggestion 6).

---

## 8. Disclaimer

This review covers the Solidity contracts listed in §2 at their current state. `Groth16PairingVerifier` (snarkjs VK) and `PoseidonT3` (generated permutation) are trusted, not re-derived; the Baby JubJub EC and Schnorr libraries were read for obvious correctness but not formally verified. Findings about cross-layer soundness rely on the companion circuit audits (`docs/audit-circuits-action-{0,1,2-en,3-en}.md`). The end-to-end no-mock test suite (real Groth16 proofs for mint/transfer/burn verifying on-chain) provides strong evidence of correctness but is not a substitute for a formal verification of the cryptographic libraries or a trusted-setup ceremony. An audit is not a guarantee of bug-freedom.

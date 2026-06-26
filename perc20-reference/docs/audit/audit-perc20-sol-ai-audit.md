# PERC20 Single-Contract Security Audit Report (AI Audit)

> **Audit target:** `contracts/ptoken/PERC20.sol`
>
> **Objective:** Assess security of the core pERC20 (privacy-native fungible token) issuance implementation
>
> **Audit model:** AI-assisted static review (English translation of [audit-perc20-sol.md](./audit-perc20-sol.md); original review: Codex 5.3)
>
> **Audit date:** 2026-06-03
>
> **Method:** Manual static review focused on the single contract, with necessary checks against direct inheritance semantics
>
> **Remediation status:** 2026-06-03 (constructor zero-address checks merged)

**Severity scale:** Critical / High / Medium / Low / Informational

---

## 1. Executive Summary

`PERC20.sol` has a clear core role: expose `mint` / `burn` / `transfer` and maintain a public `totalSupply`. Proof verification and the note state machine are handled by inherited layers. For the question “can an external attacker bypass authorization or forge state directly?” this review did **not** find an immediately exploitable critical flaw.

As a **standard-grade privacy asset issuance contract**, one class of material risk and one governance recommendation remain:

1. **Governance and issuance risk (High):** Issuance authority is a single point with no supply cap; key compromise enables unbounded inflation.
2. **Initialization robustness (Medium/Low, remediated):** Missing non-zero checks on critical constructor addresses were fixed.

---

## 2. Scope

- **Primary file:** `contracts/ptoken/PERC20.sol`
- **Related semantics reviewed:** `contracts/orchardverifier/OrchardVerifier.sol`, `contracts/interfaces/IPERC20.sol`

> **Note:** This report focuses on single-contract behavior and standardization fitness. It does **not** cover the Groth16 circuit repository.

---

## 3. Findings

### H-01 (High): Single-point issuance with no cap — key compromise enables unlimited minting

**Description**

`mint` is gated only by `onlyIssuer`. The implementation does not define a `mint cap`, rate limiting, or timelock. At the standard layer this is a **strong trust model**: if the issuer key is leaked or abused, inflation can continue without bound.

**Impact**

- The asset can be inflated without limit; the economic trust model fails quickly.
- Users of a “standard contract” may incorrectly equate **technical safety** with **economic safety**.

**Recommendations**

- Run `issuer` behind a multisig (minimum bar).
- Optional standard extensions: global cap, phased cap, timelock on mint authority.
- Disclose issuer trust assumptions explicitly in the standard documentation.

---

### M-01 (Medium, fixed): Constructor did not require `issuer_ != address(0)`

**Description**

**Historical issue:** The constructor assigned `issuer = issuer_` without a non-zero check.

**Impact**

- If misconfigured to the zero address, `mint` is permanently unusable (`onlyIssuer` never satisfied).
- Where admin and issuance are coupled, the deployment can become unrecoverable or expensive to recover.

**Recommendations**

- **Fixed:** Added `error ZeroIssuer();` and a non-zero check in the constructor.

---

### L-01 (Low, fixed): Constructor did not require `groth16Verifier_ != address(0)`

**Description**

**Historical issue:** The constructor allowed a zero-address verifier parameter.

**Impact**

- The contract may be unusable immediately after deployment until an admin fixes configuration.
- Increases operational risk during the launch window.

**Recommendations**

- **Fixed:** Added `error ZeroVerifier();` and a non-zero check in the constructor.

---

## 4. Positive Observations

- `mint` and `burn` both require `amount < SUBGROUP_ORDER`, avoiding mismatch between declared amount and the binding scalar modulo the subgroup order.
- `burn` enforces sign-bit and supply underflow checks; public ledger semantics are clear.
- `transfer` does not modify `_totalSupply`; supply changes are cleanly separated by operation type.

---

## 5. Conclusion

With the current implementation, `PERC20.sol` core flows are sound and zero-address initialization risks are remediated. If promoted as a **privacy asset issuance standard template**, the remaining material risk is concentrated in the **issuance governance model** (single issuer, no supply cap).

**Recommended actions:**

1. Deploy issuance authority behind a multisig and state centralized trust boundaries clearly in the standard text.
2. Optionally add supply caps, phased limits, or timelocks on mint governance.

---

## 6. Remediation Record

The following were added in `PERC20.sol`:

- `error ZeroIssuer();`
- `error ZeroVerifier();`

Constructor guards:

- `if (issuer_ == address(0)) revert ZeroIssuer();`
- `if (groth16Verifier_ == address(0)) revert ZeroVerifier();`

Tests added:

- `test_constructor_zero_issuer_reverts`
- `test_constructor_zero_verifier_reverts`

These changes do not alter the external interface semantics and materially reduce deployment misconfiguration risk.

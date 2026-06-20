# Comptra v1 → exceptional: what changed, and why it's hard to copy

This upgrade moves Comptra from "a working verifiable ledger" to a layered, defensible system. The
base crypto (JCS, SHA-256 hash-chain, RFC 9162 Merkle, Ed25519) is copyable — and is **not** the moat.
The moat is the three layers built on top, each of which is now real, tested, and shipping.

**Tests: 54 → 71, green. Typecheck clean. No existing behavior changed (additive + version-gated).**

---

## 1. Witness cosigning + the split-view defense  *(the headline)*

The honest open gap in v1 was **split-view**: a malicious operator could show one history to the agent
and a different one to the auditor between checkpoints. That gap is now closed.

- `packages/core/src/proofs.ts` — RFC 9162 **inclusion** proofs (O(log n)) and **consistency** proofs
  (prove tree *m* is an append-only prefix of tree *n*). 5 tests, validated against an independent
  Merkle-root oracle across all sizes, including an explicit fork-rejection case.
- `packages/core/src/witness.ts` — an independent **witness** cosigns a checkpoint **only after**
  verifying a consistency proof from the last head it saw. A verifier requires a **t-of-n quorum**.
- **Why a fork is now impossible to hide:** to present two divergent histories at the same `tree_size`,
  an operator would need *t* honest witnesses to each cosign a head inconsistent with the one they
  already cosigned — which the consistency check forbids. A fork cannot reach quorum. 4 tests prove it,
  including "SPLIT-VIEW is impossible" and "a witness refuses a rewrite of history it has cosigned."
- Wired end-to-end: the Agent Spend Audit Report now carries the quorum; `comptra verify` checks it;
  `comptra witness` lets anyone **be** a witness.

**Why hard to replicate:** the code clones in an afternoon, but a roster of *independent* cosigners
(an auditor, a cyber-insurer, the customer's own infra) compounds per operator over quarters. The
claim upgrades, honestly, from *tamper-evident* to **tamper-evident and split-view-resistant**.

## 2. A published spec + conformance suite + a second, independent verifier  *(own the standard)*

- `spec/comptra-wire-v1.md` — the normative byte format and verification algorithm, frozen at v1.
- `conformance/vectors.json` + `conformance/report.json` — golden vectors + a self-contained witnessed
  report. `test/conformance.test.ts` re-derives them in CI (the wire format is locked).
- `verifiers/comptra_verify.py` — a **zero-dependency** Python verifier (stdlib + an inline RFC 8032
  Ed25519) that reproduces the chain, the Merkle root, the checkpoint signature, **and** the witness
  quorum **byte-for-byte**. Proven: it prints `VERIFIED — no trust in Comptra required` on a clean
  report and `VERIFICATION FAILED` on a tampered one, agreeing exactly with the TypeScript core.

**Why hard to replicate:** two byte-identical verifiers in different languages are the literal
"don't trust the vendor" proof, and the spec author owns the vocabulary — clones become *Comptra-
compatible*. This also de-risks the #1 footgun (canonicalization drift) by proving cross-language parity.

## 3. A composable policy DSL with the judgment sealed into the ledger  *(verify the judgment)*

- `packages/core/src/policy-dsl.ts` — a **closed-grammar** policy engine (a fixed set of conditions:
  vendor, MCC, amount, window-cap, velocity, off-hours, new-counterparty, risk) evaluated by a
  **total, deterministic, order-independent** function with fixed precedence (forbid > review > permit
  > default). Outcomes expand from PASS/BLOCK to **PASS / BLOCK / REVIEW** (step-up for human approval).
- Deterministic, explainable, **integer-only** risk scoring (`risk_score_bp`, basis points) with named
  contributions (new-vendor, off-hours, velocity, amount-spike) — no ML, no floats (a float would break
  the cross-language verifier).
- The full **Judgment** (policy_hash + integer feature vector + risk score + matched-rule trace) is
  designed to be sealed into the record, so an auditor re-runs `evaluate()` over the sealed inputs and
  confirms the decision and risk score were neither fabricated nor suppressed. 5 tests, including
  totality, precedence, and exact `compileLegacy()` equivalence with the v1 flat policy.

**Why hard to replicate:** a general expression language is copyable but destroys totality and
replay; the *sealed, re-executable* trace requires the closed evaluator + schema-in-hash together.

---

## Try it

```bash
npm test                                            # 71 tests, green
node bin/comptra.ts verify conformance/report.json  # chain + Ed25519 checkpoint + witness quorum
python verifiers/comptra_verify.py conformance/report.json   # the SAME, in another language, zero deps
```

## Honest boundaries (named, not hidden)

Witness quorum value equals witness independence — a quorum run entirely by Comptra is theater and is
not claimed. C2SP signed-note wire-compat (so existing witnesses like Sigsum interoperate), KMS/HSM key
custody, the live multi-host witness network, and gate-path sealing of the Judgment are the tracked
next steps. Everything above is in `@comptra/core`, pure, and covered by tests.

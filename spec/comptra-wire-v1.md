# Comptra Wire Format & Verification — v1 (normative)

**Status:** stable · **Version:** `v1` (frozen; never breaks) · **Audience:** anyone building an independent verifier.

This document specifies the exact bytes of a Comptra **Agent Spend Audit Report** and the algorithm to
verify it **without trusting Comptra**. Two independent implementations ship from this spec and agree
byte-for-byte: the TypeScript core (`@comptra/core`) and a zero-dependency Python verifier
(`verifiers/comptra_verify.py`). A conformance corpus (`conformance/`) pins every value below.

The verb is deliberate: a Comptra ledger is **tamper-evident and split-view-resistant**, not
"tamper-proof". Section 6 states precisely what that buys and what it assumes.

Keywords MUST / SHOULD / MAY per RFC 2119.

---

## 1. Canonicalization (RFC 8785 JCS)

Every hashed or signed structure is serialized with a restricted RFC 8785 JCS profile:

- Only these value types occur: object, array, string, **integer**, boolean, null.
- Numbers MUST be IEEE-754 **safe integers** and are emitted as their shortest decimal (`String(n)`).
  Money is integer **minor units**; a float anywhere in a hashed structure is a protocol violation
  (it would break cross-language verification). No fractions, no exponents.
- Object member names are sorted by **UTF-16 code unit** (for the all-ASCII key set used here this is
  identical to code-point order).
- Strings use mandatory-only escapes (`\"` `\\` `\b` `\t` `\n` `\f` `\r`, and `\u00xx` for other
  control chars); every other character is emitted as literal UTF-8.
- Object members whose value is JS `undefined` are omitted; `null` is kept.

Reference: `packages/core/src/canon.ts` (TS) and `canon()` in `verifiers/comptra_verify.py` (Python).
`JCS(x)` below means the UTF-8 bytes of this serialization.

## 2. The hash chain (spine)

Each `LedgerRecord` carries `prev_hash` and `record_hash`. With `GENESIS = "0"×64`:

```
record_hash = SHA-256( utf8(prev_hash)  ||  JCS(record_without_record_hash) )
```

`prev_hash` is **inside** the hash input, so any later edit, insert, delete, or reorder fractures the
chain. A verifier walks the records, recomputing each `record_hash`, and MUST report the exact
**first** `seq` at which `seq` is out of order, `prev_hash` fails to link, or `record_hash` mismatches.

## 3. Merkle tree (RFC 9162) and proofs

Domain-separated Merkle Tree Hash, split at the **largest power of two strictly less than n**:

```
MTH({})        = SHA-256("")
MTH({d0})      = d0
MTH(D[0:n])    = SHA-256( 0x01 || MTH(D[0:k]) || MTH(D[k:n] )),  k = 2^⌊log2(n-1)⌋
leaf(record)   = SHA-256( 0x00 || JCS(record) )
```

- **Inclusion proof** (§2.1.3 of RFC 9162): O(log n) audit path proving a record is in a tree of a
  given size/root.
- **Consistency proof** (§2.1.4): proves the tree of size `m` is an append-only **prefix** of the tree
  of size `n`. This is the primitive the witness layer is built on.

Reference: `packages/core/src/merkle.ts`, `packages/core/src/proofs.ts`.

## 4. Signed checkpoint

A checkpoint binds a `(tenant_id, chain_key, tree_size, root_hash)` to the operator's Ed25519 key:

```
body      = the Checkpoint object MINUS { signature, cosignatures }
signature = base64( Ed25519_sign( operator_sk, JCS(body) ) )
```

The operator signature covers neither `signature` nor `cosignatures`. A retained checkpoint defeats a
whole-history rewrite the hash chain alone cannot (an operator with DB write access can recompute a
self-consistent forged chain, but cannot forge a signature over a root you already hold).

## 5. Witness cosignatures (the split-view defense)

A **witness** is an independent party (ideally across distinct trust domains, e.g. Comptra + the
customer + a neutral operator) holding only its own Ed25519 key and the last `(tree_size, root_hash)`
it cosigned for a given origin. On a new checkpoint it MUST verify, in one atomic step:

1. the operator's checkpoint signature (§4);
2. `tree_size` does not regress;
3. an RFC 9162 **consistency proof** from its last cosigned head to the new head (§3).

Only then does it emit a cosignature over the witness statement:

```
statement = JCS({ kind:"comptra.witness.cosig.v1", tenant_id, chain_key, tree_size, root_hash, witness_id })
cosignature.signature = base64( Ed25519_sign( witness_sk, statement ) )
```

A verifier requires a **t-of-n quorum** of valid cosignatures from a published registry, counting each
witness once. **Why this closes split-view:** to show two divergent histories at the same `tree_size`,
an operator would need t honest witnesses to each cosign a head inconsistent with the one they already
cosigned — which step (3) makes impossible. A fork therefore cannot reach quorum.

> Independence is load-bearing. A quorum of witnesses all run by Comptra provides **zero** split-view
> protection and MUST NOT be claimed as such. Quorum value is exactly the independence of its members.

Reference: `packages/core/src/witness.ts`; run `comptra witness <request.json>` to be a witness.

## 6. Threat model (what v1 proves, and what it assumes)

Given the auditor retains **one** checkpoint and the witness public keys:

- **Tamper-evident:** any edit/insert/delete/reorder fractures the chain at an exact `seq`. ✔ unconditional
- **No silent history rewrite:** defeated by the retained signed checkpoint. ✔ assumes the operator
  cannot forge Ed25519.
- **Split-view-resistant:** a fork cannot reach a t-of-n witness quorum. ✔ assumes **≥1 witness is
  honest and reachable**, and that witnesses span independent trust domains.

Out of scope for v1 (named, not hidden): preventing a *policy-allowed* bad payment; moving money
(Comptra is not a rail); and proving a payment that never reached the gate (reconcile against the
issuer). KMS/HSM key custody and C2SP signed-note wire-compat are tracked for v1.x.

## 7. Verifying a report

```
comptra verify <audit-report.json>            # TypeScript, ships in @comptra/core
python verifiers/comptra_verify.py <report>   # independent, zero-dependency, reproduces every byte
```

A conforming verifier MUST: re-derive the chain (§2), recompute the Merkle root and check it equals the
checkpoint `root_hash` (§3), verify the operator signature (§4), and verify the witness quorum (§5);
and MUST fail closed on any mismatch. The conformance corpus (`conformance/vectors.json`,
`conformance/report.json`) is the acceptance test; `test/conformance.test.ts` gates it in CI.

---

*v1 is frozen. Extensions arrive as new optional fields or a `v2`; the bytes above never change.*

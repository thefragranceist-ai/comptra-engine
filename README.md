# Comptra

**Cap what every AI agent can spend, on top of any rail — and prove every decision in a tamper-evident ledger.**

Comptra is a neutral, rail-agnostic **spend-control gate** plus a cryptographically **verifiable audit ledger** for AI agents. It sits on top of any issuer (Stripe Issuing, Lithic, x402/stablecoin) and:

1. **Gates every transaction** against a per-agent policy (per-call cap, daily/monthly cap, vendor allow/deny, MCC allow, token-bucket rate limit, instant freeze) — decided in-memory in well under a millisecond, on the authorization path.
2. **Seals every decision** (PASS *and* BLOCK) into an append-only, hash-chained ledger. Each record's hash is `SHA-256(prev_hash ‖ JCS(record))`, anchored by **RFC 9162 Merkle checkpoints** that are **Ed25519-signed**. Any later edit, insert, delete or reorder fractures the chain at an exact, locatable record.
3. **Exports the Agent Spend Audit Report** — a self-contained file an auditor re-verifies with a standalone CLI, *without trusting Comptra's servers*. That report is the artifact that unblocks the enterprise security review: *"how does your AI spend money?"*

Comptra is **not a bank and not a rail**. It never touches interchange; it prices per governed agent + ledger event.

---

## Quickstart

```bash
npm install
npm test          # 54 tests: JCS, hash-chain + destructive tamper, policy table + latency,
                  #            gate concurrency, Merkle/checkpoints, API, SDK, rails
npm run demo      # a no-server walkthrough: gate, seal, tamper -> fracture, audit report
npm run dev       # boots the API + dashboard on http://localhost:8787 (prints a seeded API key)
```

Then open **http://localhost:8787** for the register console, or hit the gate directly:

```bash
curl -s localhost:8787/v1/gate \
  -H "Authorization: Bearer cmp_test_…" -H "Content-Type: application/json" \
  -d '{"agent_id":"agent_4a9f1c","vendor":{"name":"openai"},"amount_minor":420000}'
# -> {"decision":"PASS","reason_code":"PASS","ledger_seq":0,"record_hash":"…"}
```

Verify a downloaded report independently (no server, no trust):

```bash
npm run comptra -- verify ./comptra-agent-spend-audit.json
# ✓ chain intact  N records  root …
# ✓ checkpoint  tree_size N  Ed25519-signed root … verified
```

## The 4-line SDK drop-in

```ts
import { Comptra } from 'comptra';
const comptra = new Comptra({ apiKey: process.env.COMPTRA_KEY });          // failMode 'closed' by default
const d = await comptra.gate({ agentId, vendor: { name: 'openai' }, amountMinor: 4200 });
if (!d.allowed) return refuse(d.reason);   // a BLOCK is a normal outcome — gate() never throws on a denial
```

`gate()` returns a discriminated union (`{ allowed: true, … } | { allowed: false, reason, … }`) and throws **only** on transport/auth/validation/rate-limit (`ComptraAuthError`, `ComptraUnavailableError`, …). `failMode: 'closed'` means an unreachable Comptra throws rather than silently allowing spend.

## API surface

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/gate` | the hot path. A **BLOCK is HTTP 200** (a normal business outcome), never a 4xx. `Idempotency-Key` header dedupes retries with no second ledger row. |
| `POST` / `DELETE` | `/v1/policies/:agentId/freeze` | instant kill-switch |
| `POST` | `/v1/policies` | set an agent policy |
| `GET` | `/v1/ledger?agent_id=` | read the sealed records |
| `GET` | `/v1/ledger/verify?agent_id=` | re-derive the chain server-side |
| `POST` | `/v1/report` | the self-contained, signed Agent Spend Audit Report |
| `POST` | `/v1/keys` | mint a scoped API key (`admin` \| `gate:decide` \| `ledger:read`) |

Errors are RFC 9457 `application/problem+json`. The tenant is resolved from the API key and forced onto every read/write — never trusted from the body.

## Architecture

A TypeScript npm-workspaces monorepo. The crypto is **real** and the verifiable core is a pure, dependency-free library — the load-bearing, exhaustively-tested artifact, with thin transport around it.

```
packages/
  schema/   zod schemas -> inferred types; the single wire contract
  core/     PURE, no I/O: canon (RFC 8785 JCS) · hash (WebCrypto SHA-256 + Ed25519) ·
            chain (hash-chain + O(n) verifier, localizes the fracture) ·
            merkle (RFC 9162 domain-separated) + signed checkpoints ·
            policy (sub-ms decide) · gate (per-chain serialized, idempotent) · stores (DI seams)
  sdk/      the `comptra` client: discriminated-union gate(), auto-idempotency, local verify
apps/
  api/      Hono app (Node entry + Cloudflare worker entry) + file-backed stores + rail adapters
  dashboard/ static "register console" (served by the API on one port)
bin/comptra.ts  the standalone auditor CLI (verify / keygen)
```

WebCrypto-only (not `node:crypto`) so the same bytes are produced on Node and on Cloudflare Workers. All money is **integer minor units** (no float drift); timestamps are RFC3339 UTC.

## Security & threat model (honest)

- **What it defends:** any post-hoc edit, insert, delete or reorder of sealed records is mathematically detectable and localized to the exact `seq` — *given the auditor retains the Ed25519-signed checkpoints*. A bare hash chain only proves internal consistency; the signed Merkle checkpoints are what make the claim meaningful against an operator who has database write access.
- **What it does NOT yet defend:** an operator **split-view** (showing different histories to different parties). That requires external **witnesses / cosigning**; the checkpoint format is deliberately detached-signable so witness cosignatures slot in as an extra field. This is on the roadmap and stated in every report rather than glossed over.
- **Key custody:** the Ed25519 signing key sits behind a `Signer` interface. In production it belongs **outside** the ledger database trust domain (KMS/HSM). The file-key here is the local-dev impl.
- **Fail-closed:** the gate fails closed and is kept trivially simple so it rarely fails. The rail's own timeout fallback (e.g. Stripe's ~2s window) must be configured to **decline** — a shared-responsibility boundary, documented, not silently assumed.

## Rail neutrality

One `RailAdapter` interface, `SimulatedRail` as the default (drives every test, needs no credentials). `StripeIssuingTestRail` is a fixture-tested, env-gated sketch of the real-time `issuing_authorization.request` path (test mode only). `X402Rail` sketches a stablecoin/HTTP-402 rail. Adding a rail is ~30 lines and zero changes to the engine or ledger.

## Deployment

The same Hono app runs on Node today and is one credential away from an edge deploy.

- **Local / any Node host:** `npm run dev`, or the provided `Dockerfile`. State persists to `./data` (append-only JSONL ledger + JSON control plane).
- **Cloudflare Workers:** `apps/api/src/worker.ts` exports `default { fetch }`. Swap the in-memory stores for D1 / Durable Object stores behind the same `LedgerStore`/`CounterStore` interfaces (the Durable Object's single-threaded-per-object model makes hash-chain serialization free). See `.env.example`.
- **Turso/libSQL:** set `TURSO_URL` / `TURSO_TOKEN` and implement the libSQL `LedgerStore` (interface ready).

## What's in this MVP (and what's deliberately out)

**In:** the pure verifiable core (policy + chain + Merkle + signed checkpoints + verifier + report) with destructive tamper tests; the Hono gate API with key auth, tenant isolation, idempotency, RFC 9457 errors; the `comptra` SDK; the standalone verifier CLI; the register-console dashboard; the audit-report export; one-command local boot; fully-offline tests; deploy-ready entries.

**Out (and why):** live money movement / processor approval / a legal entity (no credentials — `SimulatedRail` is the default so runnability is never blocked); witness/cosigning network (split-view defense, designed-for, deferred); KMS/HSM custody (interface stub); multi-node distributed rate limiting (interface ready, in-memory for now); billing/metering; SOC 2.

---

*Comptra — the ledger every agent answers to.*

import { z } from 'zod';

/**
 * @comptra/schema — the single wire contract.
 * Every type that crosses a boundary (API, SDK, ledger, dashboard, CLI) is defined here once.
 */

// ---- reason codes (closed, versioned enum) ----
export const REASON_CODES = [
  'PASS',
  'FROZEN',
  'VENDOR_NOT_ALLOWED',
  'PER_CALL_CAP',
  'RATE_LIMIT',
  'DAILY_CAP',
  'MONTHLY_CAP',
] as const;
export const ReasonCode = z.enum(REASON_CODES);
export type ReasonCode = z.infer<typeof ReasonCode>;

// ---- vendor ----
export const Vendor = z.object({
  name: z.string().min(1),
  mcc: z.string().default('0000'),
  country: z.string().default('US'),
});
export type Vendor = z.infer<typeof Vendor>;

// ---- gate request (what an agent attempts) ----
export const GateRequest = z.object({
  agent_id: z.string().min(1),
  end_customer_id: z.string().min(1).default('-'),
  vendor: Vendor,
  amount_minor: z.number().int().nonnegative(), // integer minor units, never float
  currency: z.string().length(3).default('USD'),
  mandate_ref: z.string().nullable().default(null),
  idempotency_key: z.string().optional(),
});
export type GateRequest = z.infer<typeof GateRequest>;

// ---- policy (the rules the gate enforces) ----
export const RateLimit = z.object({
  capacity: z.number().int().positive(),
  refill_per_sec: z.number().nonnegative(),
});
export const Policy = z.object({
  frozen: z.boolean().default(false),
  vendor_allowlist: z.array(z.string()).default([]),
  vendor_denylist: z.array(z.string()).default([]),
  mcc_allowlist: z.array(z.string()).default([]),
  per_call_cap_minor: z.number().int().nonnegative().nullable().default(null),
  daily_cap_minor: z.number().int().nonnegative().nullable().default(null),
  monthly_cap_minor: z.number().int().nonnegative().nullable().default(null),
  rate_limit: RateLimit.nullable().default(null),
  currency: z.string().length(3).default('USD'),
});
export type Policy = z.infer<typeof Policy>;

// ---- gate decision (pure engine output, before it is sealed into the ledger) ----
export const GateDecision = z.object({
  decision: z.enum(['PASS', 'BLOCK']),
  reason_code: ReasonCode,
  approved_amount_minor: z.number().int().nullable(),
  limit: z.number().int().nullable().optional(),
  observed: z.number().int().nullable().optional(),
});
export type GateDecision = z.infer<typeof GateDecision>;

// ---- ledger record (the load-bearing schema; EVERY field is inside the hash) ----
export const LedgerRecord = z.object({
  v: z.literal(1),
  seq: z.number().int().nonnegative(),
  tenant_id: z.string(),
  chain_key: z.string(),
  agent_id: z.string(),
  end_customer_id: z.string(),
  decision: z.enum(['PASS', 'BLOCK']),
  reason_code: ReasonCode,
  vendor: Vendor,
  amount_minor: z.number().int(),
  approved_amount_minor: z.number().int().nullable(),
  currency: z.string(),
  mandate_ref: z.string().nullable(),
  idempotency_key: z.string(),
  rail: z.string(),
  ts: z.string(), // RFC3339 UTC
  prev_hash: z.string().length(64),
  record_hash: z.string().length(64),
});
export type LedgerRecord = z.infer<typeof LedgerRecord>;

// ---- signed checkpoint (anchors the chain against operator rewrite) ----
export const Checkpoint = z.object({
  v: z.literal(1),
  tenant_id: z.string(),
  chain_key: z.string(),
  tree_size: z.number().int().nonnegative(),
  root_hash: z.string().length(64),
  prev_checkpoint_hash: z.string().length(64),
  ts: z.string(),
  key_id: z.string(),
  signature: z.string(), // base64 Ed25519 over JCS(checkpoint - signature)
});
export type Checkpoint = z.infer<typeof Checkpoint>;

// ---- audit report (self-contained, independently checkable) ----
export const AuditReport = z.object({
  report: z.literal('comptra-agent-spend-audit'),
  version: z.literal(1),
  generated_at: z.string(),
  tenant_id: z.string(),
  scope: z.object({
    agent_id: z.string().nullable(),
    end_customer_id: z.string().nullable(),
    from_ts: z.string().nullable(),
    to_ts: z.string().nullable(),
  }),
  summary: z.object({
    records: z.number().int(),
    sealed: z.number().int(),
    blocked: z.number().int(),
    verified: z.boolean(),
    root_hash: z.string().nullable(),
  }),
  policy: Policy.partial().optional(),
  records: z.array(LedgerRecord),
  checkpoints: z.array(Checkpoint),
  public_key: z.string(), // hex raw Ed25519
  key_provenance: z.string(),
  canonicalization_spec: z.string(),
  hashing_spec: z.string(),
  merkle_spec: z.string(),
  threat_model: z.string(),
  standalone_verifier: z.string(),
});
export type AuditReport = z.infer<typeof AuditReport>;

// ---- SDK gate result (discriminated union; a BLOCK is a normal outcome, never an error) ----
export type GateAllowed = { allowed: true; decisionId: string; ledgerSeq: number; recordHash: string };
export type GateBlocked = {
  allowed: false;
  reason: ReasonCode;
  decisionId: string;
  ledgerSeq: number;
  limit?: number | null;
  observed?: number | null;
};
export type GateResult = GateAllowed | GateBlocked;

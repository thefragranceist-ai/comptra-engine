import type { GateRequest, Policy } from '@comptra/schema';
import { canonicalize } from './canon.ts';
import { sha256Hex } from './hash.ts';

/**
 * Composable policy DSL + deterministic, explainable risk scoring — the "verify the JUDGMENT"
 * layer. A general expression language is copyable and destroys totality; this is a CLOSED grammar
 * (a fixed set of conditions) evaluated by a total, side-effect-free, order-independent function with
 * fixed effect precedence (forbid > review > permit > default). The full Judgment — the policy_hash,
 * an integer-only feature vector, an integer risk score in basis points, and the matched-rule trace —
 * is sealed into the ledger record, so an auditor re-runs evaluate() over the sealed inputs and
 * confirms the decision and risk score were neither fabricated nor suppressed.
 *
 * Everything that can enter the hash is an INTEGER (basis points, minor units) — a float would break
 * the cross-language verifier (verifiers/comptra_verify.py).
 */

export type Condition =
  | { t: 'vendor_in'; names: string[] }
  | { t: 'vendor_not_in'; names: string[] }
  | { t: 'mcc_not_in'; mccs: string[] }
  | { t: 'amount_gt'; minor: number }
  | { t: 'window_cap'; window: 'daily' | 'monthly'; minor: number } // would-exceed
  | { t: 'velocity_gt'; count: number }
  | { t: 'off_hours'; open_utc: number; close_utc: number }
  | { t: 'new_counterparty' }
  | { t: 'risk_gt_bp'; bp: number }
  | { t: 'always' };

export type Effect = 'forbid' | 'review' | 'permit';
export type Rule = { id: string; effect: Effect; reason: string; when: Condition[] };
export type PolicyV2 = { v: 2; default: 'permit' | 'deny'; rules: Rule[] };

export type Features = {
  amount_minor: number;
  daily_would_minor: number;
  monthly_would_minor: number;
  velocity_count: number;
  hour_utc: number;
  vendor_seen: 0 | 1;
  risk_score_bp: number;
  risk_factors: string[]; // named, human-readable contributions (NOT hashed-sensitive; integers above are)
};

export type EvalContext = {
  daily_spent_minor: number;
  monthly_spent_minor: number;
  recent_count: number; // attempts already in the current velocity window, from prior sealed records
  vendor_seen: boolean; // has this (agent, vendor) appeared before in the chain
  now_ms: number;
};

export type Judgment = {
  decision: 'PASS' | 'BLOCK' | 'REVIEW';
  reason: string;
  risk_score_bp: number;
  features: Omit<Features, 'risk_factors'>;
  risk_factors: string[];
  trace: { rule_id: string; effect: Effect; matched: boolean }[];
  policy_hash: string;
};

const clampBp = (n: number) => Math.max(0, Math.min(10000, Math.trunc(n)));

/** Deterministic, integer-only risk score with named contributions. No ML, no floats, fully replayable. */
export function riskScore(req: GateRequest, ctx: EvalContext, f: { hour_utc: number; velocity_count: number }): { bp: number; factors: string[] } {
  let bp = 0;
  const factors: string[] = [];
  if (!ctx.vendor_seen) { bp += 2500; factors.push('new_vendor(+2500)'); }
  if (f.hour_utc < 6 || f.hour_utc >= 22) { bp += 1500; factors.push('off_hours(+1500)'); }
  if (f.velocity_count > 10) { const v = Math.min(3000, (f.velocity_count - 10) * 200); bp += v; factors.push(`velocity(+${v})`); }
  // amount spike vs the chain's running daily baseline (integer ratio, no float)
  const seen = ctx.recent_count;
  const baseline = seen > 0 ? Math.trunc(ctx.daily_spent_minor / seen) : 0;
  if (baseline > 0 && req.amount_minor >= baseline * 5) { bp += 1800; factors.push('amount_spike(+1800)'); }
  return { bp: clampBp(bp), factors };
}

export function extractFeatures(req: GateRequest, ctx: EvalContext): Features {
  const hour_utc = new Date(ctx.now_ms).getUTCHours();
  const velocity_count = ctx.recent_count;
  const r = riskScore(req, ctx, { hour_utc, velocity_count });
  return {
    amount_minor: req.amount_minor,
    daily_would_minor: ctx.daily_spent_minor + req.amount_minor,
    monthly_would_minor: ctx.monthly_spent_minor + req.amount_minor,
    velocity_count,
    hour_utc,
    vendor_seen: ctx.vendor_seen ? 1 : 0,
    risk_score_bp: r.bp,
    risk_factors: r.factors,
  };
}

function condMatch(c: Condition, req: GateRequest, f: Features): boolean {
  const vn = req.vendor.name.toLowerCase();
  switch (c.t) {
    case 'always': return true;
    case 'vendor_in': return c.names.some((n) => n.toLowerCase() === vn);
    case 'vendor_not_in': return c.names.length > 0 && !c.names.some((n) => n.toLowerCase() === vn);
    case 'mcc_not_in': return c.mccs.length > 0 && !c.mccs.includes(req.vendor.mcc);
    case 'amount_gt': return req.amount_minor > c.minor;
    case 'window_cap': return (c.window === 'daily' ? f.daily_would_minor : f.monthly_would_minor) > c.minor;
    case 'velocity_gt': return f.velocity_count > c.count;
    case 'off_hours': return f.hour_utc < c.open_utc || f.hour_utc >= c.close_utc;
    case 'new_counterparty': return f.vendor_seen === 0;
    case 'risk_gt_bp': return f.risk_score_bp > c.bp;
  }
}

const EFFECT_RANK: Record<Effect, number> = { forbid: 3, review: 2, permit: 1 };

/** Total, deterministic, order-independent. forbid > review > permit > default. */
export async function evaluate(req: GateRequest, policy: PolicyV2, ctx: EvalContext): Promise<Judgment> {
  const f = extractFeatures(req, ctx);
  const policy_hash = await policyHash(policy);
  const rules = [...policy.rules].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const trace: Judgment['trace'] = [];
  let winner: Rule | null = null;
  for (const r of rules) {
    const matched = r.when.length > 0 && r.when.every((c) => condMatch(c, req, f));
    trace.push({ rule_id: r.id, effect: r.effect, matched });
    if (matched && (!winner || EFFECT_RANK[r.effect] > EFFECT_RANK[winner.effect])) winner = r;
  }
  let decision: Judgment['decision']; let reason: string;
  if (winner && winner.effect === 'forbid') { decision = 'BLOCK'; reason = winner.reason; }
  else if (winner && winner.effect === 'review') { decision = 'REVIEW'; reason = winner.reason; }
  else if (winner && winner.effect === 'permit') { decision = 'PASS'; reason = winner.reason; }
  else { decision = policy.default === 'deny' ? 'BLOCK' : 'PASS'; reason = policy.default === 'deny' ? 'DEFAULT_DENY' : 'PASS'; }

  const { risk_factors, ...feat } = f;
  return { decision, reason, risk_score_bp: f.risk_score_bp, features: feat, risk_factors, trace, policy_hash };
}

// policy_hash binds WHICH ruleset evaluated, inside the record hash, so an auditor can confirm the
// exact ruleset that produced a decision (JCS over the policy, then SHA-256).
export async function policyHash(policy: PolicyV2): Promise<string> {
  return sha256Hex(new TextEncoder().encode(canonicalize(policy)));
}

/** Backward-compat: the flat v1 Policy is sugar over the DSL. Emits forbid rules in v1 evaluation order. */
export function compileLegacy(p: Policy): PolicyV2 {
  const rules: Rule[] = [];
  if (p.frozen) rules.push({ id: '00-frozen', effect: 'forbid', reason: 'FROZEN', when: [{ t: 'always' }] });
  if (p.vendor_denylist.length) rules.push({ id: '10-vendor-deny', effect: 'forbid', reason: 'VENDOR_NOT_ALLOWED', when: [{ t: 'vendor_in', names: p.vendor_denylist }] });
  if (p.vendor_allowlist.length) rules.push({ id: '11-vendor-allow', effect: 'forbid', reason: 'VENDOR_NOT_ALLOWED', when: [{ t: 'vendor_not_in', names: p.vendor_allowlist }] });
  if (p.mcc_allowlist.length) rules.push({ id: '12-mcc-allow', effect: 'forbid', reason: 'VENDOR_NOT_ALLOWED', when: [{ t: 'mcc_not_in', mccs: p.mcc_allowlist }] });
  if (p.per_call_cap_minor != null) rules.push({ id: '20-per-call', effect: 'forbid', reason: 'PER_CALL_CAP', when: [{ t: 'amount_gt', minor: p.per_call_cap_minor }] });
  if (p.daily_cap_minor != null) rules.push({ id: '30-daily', effect: 'forbid', reason: 'DAILY_CAP', when: [{ t: 'window_cap', window: 'daily', minor: p.daily_cap_minor }] });
  if (p.monthly_cap_minor != null) rules.push({ id: '31-monthly', effect: 'forbid', reason: 'MONTHLY_CAP', when: [{ t: 'window_cap', window: 'monthly', minor: p.monthly_cap_minor }] });
  return { v: 2, default: 'permit', rules };
}

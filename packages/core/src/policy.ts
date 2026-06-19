import type { GateRequest, GateDecision, Policy, ReasonCode } from '@comptra/schema';

/**
 * PolicyEngine — a PURE, synchronous decision. Zero network, zero disk, no Date.now (clock injected).
 * This is on the authorization hot path, so it must be trivially fast and trivially auditable.
 *
 * Fixed, deterministic evaluation order:
 *   1. freeze            -> FROZEN
 *   2. vendor deny/allow -> VENDOR_NOT_ALLOWED   (deny wins; allowlist is a whitelist; MCC allowlist)
 *   3. per-call cap      -> PER_CALL_CAP
 *   4. token-bucket rate -> RATE_LIMIT
 *   5. daily cap         -> DAILY_CAP
 *   6. monthly cap       -> MONTHLY_CAP
 *   else                 -> PASS
 *
 * All money is integer minor units. All counter math lives here (single tested source of truth);
 * the caller just persists the returned `counters`.
 */

export type Counters = {
  day_key: string; // 'YYYY-MM-DD' UTC
  month_key: string; // 'YYYY-MM' UTC
  daily_spent_minor: number;
  monthly_spent_minor: number;
  tokens: number; // current token-bucket level (float ok; it's not hashed)
  last_refill_ms: number;
};

export function emptyCounters(nowMs: number, capacity = 0): Counters {
  return {
    day_key: utcDay(nowMs),
    month_key: utcMonth(nowMs),
    daily_spent_minor: 0,
    monthly_spent_minor: 0,
    tokens: capacity,
    last_refill_ms: nowMs,
  };
}

export function utcDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}
export function utcMonth(ms: number): string {
  return new Date(ms).toISOString().slice(0, 7);
}

export type DecideResult = { decision: GateDecision; counters: Counters };

export function decide(req: GateRequest, policy: Policy, counters: Counters, nowMs: number): DecideResult {
  const c: Counters = { ...counters };

  // roll rolling windows (UTC)
  const dayKey = utcDay(nowMs);
  const monthKey = utcMonth(nowMs);
  if (c.day_key !== dayKey) { c.day_key = dayKey; c.daily_spent_minor = 0; }
  if (c.month_key !== monthKey) { c.month_key = monthKey; c.monthly_spent_minor = 0; }

  // refill token bucket
  if (policy.rate_limit) {
    const elapsedSec = Math.max(0, (nowMs - c.last_refill_ms) / 1000);
    c.tokens = Math.min(policy.rate_limit.capacity, c.tokens + elapsedSec * policy.rate_limit.refill_per_sec);
    c.last_refill_ms = nowMs;
  }

  const block = (reason_code: ReasonCode, limit: number | null = null, observed: number | null = null): DecideResult => ({
    decision: { decision: 'BLOCK', reason_code, approved_amount_minor: null, limit, observed },
    counters: c,
  });

  if (policy.frozen) return block('FROZEN');

  const vn = req.vendor.name.toLowerCase();
  if (policy.vendor_denylist.some((d) => d.toLowerCase() === vn)) return block('VENDOR_NOT_ALLOWED');
  if (policy.vendor_allowlist.length > 0 && !policy.vendor_allowlist.some((a) => a.toLowerCase() === vn)) {
    return block('VENDOR_NOT_ALLOWED');
  }
  if (policy.mcc_allowlist.length > 0 && !policy.mcc_allowlist.includes(req.vendor.mcc)) {
    return block('VENDOR_NOT_ALLOWED');
  }

  if (policy.per_call_cap_minor != null && req.amount_minor > policy.per_call_cap_minor) {
    return block('PER_CALL_CAP', policy.per_call_cap_minor, req.amount_minor);
  }

  if (policy.rate_limit && c.tokens < 1) {
    return block('RATE_LIMIT', policy.rate_limit.capacity, 0);
  }

  if (policy.daily_cap_minor != null && c.daily_spent_minor + req.amount_minor > policy.daily_cap_minor) {
    return block('DAILY_CAP', policy.daily_cap_minor, c.daily_spent_minor + req.amount_minor);
  }

  if (policy.monthly_cap_minor != null && c.monthly_spent_minor + req.amount_minor > policy.monthly_cap_minor) {
    return block('MONTHLY_CAP', policy.monthly_cap_minor, c.monthly_spent_minor + req.amount_minor);
  }

  // PASS — consume budget + one token
  if (policy.rate_limit) c.tokens -= 1;
  c.daily_spent_minor += req.amount_minor;
  c.monthly_spent_minor += req.amount_minor;
  return {
    decision: { decision: 'PASS', reason_code: 'PASS', approved_amount_minor: req.amount_minor, limit: null, observed: null },
    counters: c,
  };
}

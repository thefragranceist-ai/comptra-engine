import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decide, emptyCounters } from '@comptra/core';
import { Policy, GateRequest } from '@comptra/schema';

const NOW = Date.parse('2026-06-19T12:00:00.000Z');
const pol = (p: Record<string, unknown> = {}) => Policy.parse(p);
const req = (amount: number, vendor = 'openai', mcc = '0000') =>
  GateRequest.parse({ agent_id: 'a', vendor: { name: vendor, mcc }, amount_minor: amount });

test('S6: PASS within all limits returns approved amount', () => {
  const r = decide(req(4200), pol({ per_call_cap_minor: 5000, daily_cap_minor: 25000 }), emptyCounters(NOW), NOW);
  assert.equal(r.decision.reason_code, 'PASS');
  assert.equal(r.decision.approved_amount_minor, 4200);
});

test('S6: FROZEN beats every other rule', () => {
  const r = decide(req(1), pol({ frozen: true, per_call_cap_minor: 1_000_000 }), emptyCounters(NOW), NOW);
  assert.equal(r.decision.reason_code, 'FROZEN');
});

test('S6: VENDOR_NOT_ALLOWED via denylist (deny wins)', () => {
  const r = decide(req(1, 'sketchy'), pol({ vendor_denylist: ['sketchy'], vendor_allowlist: ['sketchy'] }), emptyCounters(NOW), NOW);
  assert.equal(r.decision.reason_code, 'VENDOR_NOT_ALLOWED');
});

test('S6: VENDOR_NOT_ALLOWED via allowlist miss', () => {
  const r = decide(req(1, 'aws'), pol({ vendor_allowlist: ['openai', 'anthropic'] }), emptyCounters(NOW), NOW);
  assert.equal(r.decision.reason_code, 'VENDOR_NOT_ALLOWED');
});

test('S6: VENDOR_NOT_ALLOWED via MCC allowlist miss', () => {
  const r = decide(req(1, 'openai', '7995'), pol({ mcc_allowlist: ['0000', '5734'] }), emptyCounters(NOW), NOW);
  assert.equal(r.decision.reason_code, 'VENDOR_NOT_ALLOWED');
});

test('S6: PER_CALL_CAP reports limit + observed', () => {
  const r = decide(req(6000), pol({ per_call_cap_minor: 5000 }), emptyCounters(NOW), NOW);
  assert.equal(r.decision.reason_code, 'PER_CALL_CAP');
  assert.equal(r.decision.limit, 5000);
  assert.equal(r.decision.observed, 6000);
});

test('S6: DAILY_CAP when the day total would exceed', () => {
  const c = { ...emptyCounters(NOW), daily_spent_minor: 24000 };
  const r = decide(req(2000), pol({ daily_cap_minor: 25000 }), c, NOW);
  assert.equal(r.decision.reason_code, 'DAILY_CAP');
});

test('S6: MONTHLY_CAP when the month total would exceed', () => {
  const c = { ...emptyCounters(NOW), monthly_spent_minor: 99000 };
  const r = decide(req(2000), pol({ monthly_cap_minor: 100000 }), c, NOW);
  assert.equal(r.decision.reason_code, 'MONTHLY_CAP');
});

test('S6: RATE_LIMIT when the token bucket is empty', () => {
  const c = { ...emptyCounters(NOW, 5), tokens: 0 };
  const r = decide(req(1), pol({ rate_limit: { capacity: 5, refill_per_sec: 0 } }), c, NOW);
  assert.equal(r.decision.reason_code, 'RATE_LIMIT');
});

test('S6: the token bucket refills over elapsed time', () => {
  const c = { ...emptyCounters(NOW, 5), tokens: 0, last_refill_ms: NOW - 2000 };
  const r = decide(req(1), pol({ rate_limit: { capacity: 5, refill_per_sec: 1 } }), c, NOW);
  assert.equal(r.decision.reason_code, 'PASS');
});

test('S6: a PASS consumes daily + monthly budget and one token', () => {
  const c = emptyCounters(NOW, 5);
  const r = decide(req(1000), pol({ rate_limit: { capacity: 5, refill_per_sec: 0 }, daily_cap_minor: 25000 }), c, NOW);
  assert.equal(r.decision.reason_code, 'PASS');
  assert.equal(r.counters.daily_spent_minor, 1000);
  assert.equal(r.counters.monthly_spent_minor, 1000);
  assert.equal(r.counters.tokens, 4);
});

test('S6: a UTC day rollover resets the daily counter', () => {
  const c = { ...emptyCounters(NOW), day_key: '2026-06-18', daily_spent_minor: 24000 };
  const r = decide(req(2000), pol({ daily_cap_minor: 25000 }), c, NOW);
  assert.equal(r.decision.reason_code, 'PASS');
  assert.equal(r.counters.daily_spent_minor, 2000);
});

test('S6: latency — 20k decisions average well under 1ms (hot-path budget)', () => {
  const p = pol({ per_call_cap_minor: 5000, daily_cap_minor: 1_000_000_000, rate_limit: { capacity: 1e9, refill_per_sec: 0 } });
  let c = emptyCounters(NOW, 1e9);
  const t0 = performance.now();
  for (let i = 0; i < 20000; i++) {
    const r = decide(req(100), p, c, NOW);
    c = r.counters;
  }
  const perCall = (performance.now() - t0) / 20000;
  assert.ok(perCall < 1, `decide() averaged ${perCall.toFixed(4)}ms, expected < 1ms`);
});

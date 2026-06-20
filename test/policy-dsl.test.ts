import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GateRequest, Policy } from '@comptra/schema';
import { decide, emptyCounters } from '../packages/core/src/policy.ts';
import { evaluate, compileLegacy, extractFeatures, type PolicyV2, type EvalContext, type Condition } from '../packages/core/src/policy-dsl.ts';

const req = (over: Partial<GateRequest> = {}) =>
  GateRequest.parse({ agent_id: 'a', vendor: { name: 'openai', mcc: '7372' }, amount_minor: 5000, ...over });
const NOON = Date.UTC(2026, 5, 20, 12, 0, 0);
const ctx = (over: Partial<EvalContext> = {}): EvalContext =>
  ({ daily_spent_minor: 0, monthly_spent_minor: 0, recent_count: 0, vendor_seen: true, now_ms: NOON, ...over });

test('evaluate is deterministic and total over the closed grammar', async () => {
  const allConds: Condition[] = [
    { t: 'always' }, { t: 'vendor_in', names: ['openai'] }, { t: 'vendor_not_in', names: ['aws'] },
    { t: 'mcc_not_in', mccs: ['1234'] }, { t: 'amount_gt', minor: 1 }, { t: 'window_cap', window: 'daily', minor: 1 },
    { t: 'velocity_gt', count: 0 }, { t: 'off_hours', open_utc: 6, close_utc: 22 }, { t: 'new_counterparty' }, { t: 'risk_gt_bp', bp: 0 },
  ];
  const pol: PolicyV2 = { v: 2, default: 'permit', rules: allConds.map((c, i) => ({ id: 'r' + i, effect: 'review', reason: 'R', when: [c] })) };
  const a = await evaluate(req(), pol, ctx());
  const b = await evaluate(req(), pol, ctx());
  assert.deepEqual(a, b, 'same inputs -> identical judgment');
  assert.ok(['PASS', 'BLOCK', 'REVIEW'].includes(a.decision));
});

test('effect precedence is forbid > review > permit > default, regardless of rule order', async () => {
  const rules = [
    { id: 'z-permit', effect: 'permit' as const, reason: 'ok', when: [{ t: 'always' } as Condition] },
    { id: 'a-review', effect: 'review' as const, reason: 'look', when: [{ t: 'always' } as Condition] },
    { id: 'm-forbid', effect: 'forbid' as const, reason: 'STOP', when: [{ t: 'amount_gt', minor: 1000 } as Condition] },
  ];
  const pol: PolicyV2 = { v: 2, default: 'permit', rules };
  assert.equal((await evaluate(req({ amount_minor: 5000 }), pol, ctx())).decision, 'BLOCK'); // forbid wins
  assert.equal((await evaluate(req({ amount_minor: 500 }), pol, ctx())).decision, 'REVIEW'); // review beats permit
  const noReview: PolicyV2 = { v: 2, default: 'permit', rules: [rules[0]] };
  assert.equal((await evaluate(req(), noReview, ctx())).decision, 'PASS');
});

test('compileLegacy: the flat v1 Policy is exact sugar over the DSL for the static checks', async () => {
  const cases: Array<[Partial<Policy>, Partial<GateRequest>, 'PASS' | 'BLOCK', string]> = [
    [{ frozen: true }, {}, 'BLOCK', 'FROZEN'],
    [{ vendor_denylist: ['openai'] }, {}, 'BLOCK', 'VENDOR_NOT_ALLOWED'],
    [{ vendor_allowlist: ['aws'] }, { vendor: { name: 'openai', mcc: '0000', country: 'US' } }, 'BLOCK', 'VENDOR_NOT_ALLOWED'],
    [{ per_call_cap_minor: 1000 }, { amount_minor: 5000 }, 'BLOCK', 'PER_CALL_CAP'],
    [{ per_call_cap_minor: 100000 }, { amount_minor: 5000 }, 'PASS', 'PASS'],
  ];
  for (const [pol, r, want, reason] of cases) {
    const p = Policy.parse(pol);
    const legacy = decide(req(r), p, emptyCounters(NOON), NOON).decision;
    const j = await evaluate(req(r), compileLegacy(p), ctx());
    assert.equal(j.decision === 'REVIEW' ? 'BLOCK' : j.decision, want, JSON.stringify(pol));
    assert.equal(j.reason, reason);
    assert.equal(legacy.decision, want === 'BLOCK' ? 'BLOCK' : 'PASS', 'matches legacy decide()');
  }
});

test('window caps use the integer feature vector and would-exceed semantics', async () => {
  const p = Policy.parse({ daily_cap_minor: 10000 });
  const pol = compileLegacy(p);
  assert.equal((await evaluate(req({ amount_minor: 3000 }), pol, ctx({ daily_spent_minor: 6000 }))).decision, 'PASS');  // 9000 <= 10000
  assert.equal((await evaluate(req({ amount_minor: 5000 }), pol, ctx({ daily_spent_minor: 6000 }))).decision, 'BLOCK'); // 11000 > 10000
});

test('risk score is a clamped, deterministic integer with named factors; routes to REVIEW', async () => {
  const f = extractFeatures(req({ amount_minor: 9999 }), ctx({ vendor_seen: false, now_ms: Date.UTC(2026, 5, 20, 3, 0, 0), recent_count: 15, daily_spent_minor: 1500 }));
  assert.equal(Number.isInteger(f.risk_score_bp), true);
  assert.ok(f.risk_score_bp >= 0 && f.risk_score_bp <= 10000);
  assert.ok(f.risk_factors.includes('new_vendor(+2500)') && f.risk_factors.includes('off_hours(+1500)'));
  // a risk gate routes high-risk spend to human review instead of silently passing
  const pol: PolicyV2 = { v: 2, default: 'permit', rules: [
    { id: 'permit-all', effect: 'permit', reason: 'ok', when: [{ t: 'always' }] },
    { id: 'risk-review', effect: 'review', reason: 'STEP_UP_REQUIRED', when: [{ t: 'risk_gt_bp', bp: 3000 }] },
  ] };
  const hi = await evaluate(req({ amount_minor: 9999 }), pol, ctx({ vendor_seen: false, now_ms: Date.UTC(2026, 5, 20, 3, 0, 0) }));
  assert.equal(hi.decision, 'REVIEW');
  assert.match(hi.policy_hash, /^[0-9a-f]{64}$/);
  for (const v of Object.values(hi.features)) assert.equal(Number.isInteger(v), true, 'every sealed feature is an integer');
});

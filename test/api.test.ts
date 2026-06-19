import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp, mintKey, keyHash, type Stores, type KeyLookup } from '../apps/api/src/app.ts';
import type { ApiKeyRecord } from '../apps/api/src/store-file.ts';
import { MemLedgerStore, MemCounterStore, MemPolicyStore, MemIdempotencyStore, verifyChain } from '@comptra/core';
import { Policy } from '@comptra/schema';

class MemKeys implements KeyLookup {
  private m = new Map<string, ApiKeyRecord>();
  byHash(h: string) { return this.m.get(h) ?? null; }
  put(h: string, r: ApiKeyRecord) { this.m.set(h, r); }
}

async function harness() {
  const keys = new MemKeys();
  const policies = new MemPolicyStore();
  const stores: Stores = { ledger: new MemLedgerStore(), counters: new MemCounterStore(), policies, idem: new MemIdempotencyStore(), keys };
  const adminRaw = mintKey('test');
  keys.put(await keyHash(adminRaw), { tenant_id: 't_demo', role: 'admin', env: 'test', prefix: adminRaw.slice(0, 13), created_at: '2026-06-19T12:00:00.000Z' });
  await policies.set('t_demo', 'agent_4a9f1c', '-', Policy.parse({ vendor_allowlist: ['openai'], per_call_cap_minor: 500000, daily_cap_minor: 2500000 }));
  const app = createApp(stores, { rail: 'simulated', now: () => Date.parse('2026-06-19T12:00:00.000Z') });
  const H = { Authorization: `Bearer ${adminRaw}`, 'Content-Type': 'application/json' };
  return { app, H, stores };
}
const gate = (app: any, H: any, body: object, extra: object = {}) =>
  app.request('/v1/gate', { method: 'POST', headers: { ...H, ...extra }, body: JSON.stringify(body) });

test('S9: rejects requests with no API key (401 problem+json)', async () => {
  const { app } = await harness();
  const res = await app.request('/v1/gate', { method: 'POST', body: '{}' });
  assert.equal(res.status, 401);
  assert.match(res.headers.get('content-type') ?? '', /application\/problem\+json/);
});

test('S9: a within-policy gate returns 200 PASS and seals seq 0', async () => {
  const { app, H } = await harness();
  const res = await gate(app, H, { agent_id: 'agent_4a9f1c', vendor: { name: 'openai' }, amount_minor: 420000 });
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.equal(j.decision, 'PASS');
  assert.equal(j.ledger_seq, 0);
  assert.match(j.record_hash, /^[0-9a-f]{64}$/);
  assert.match(j.decision_id, /^dec_/);
});

test('S9: an over-cap gate returns 200 BLOCK (not a 4xx)', async () => {
  const { app, H } = await harness();
  const res = await gate(app, H, { agent_id: 'agent_4a9f1c', vendor: { name: 'openai' }, amount_minor: 600000 });
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.equal(j.decision, 'BLOCK');
  assert.equal(j.reason_code, 'PER_CALL_CAP');
  assert.equal(j.limit, 500000);
});

test('S9: a disallowed vendor blocks', async () => {
  const { app, H } = await harness();
  const j = await (await gate(app, H, { agent_id: 'agent_4a9f1c', vendor: { name: 'casino' }, amount_minor: 100 })).json();
  assert.equal(j.reason_code, 'VENDOR_NOT_ALLOWED');
});

test('S9: Idempotency-Key header replays without a second ledger row', async () => {
  const { app, H, stores } = await harness();
  const a = await (await gate(app, H, { agent_id: 'agent_4a9f1c', vendor: { name: 'openai' }, amount_minor: 1000 }, { 'Idempotency-Key': 'k1' })).json();
  const b = await (await gate(app, H, { agent_id: 'agent_4a9f1c', vendor: { name: 'openai' }, amount_minor: 1000 }, { 'Idempotency-Key': 'k1' })).json();
  assert.equal(b.replayed, true);
  assert.equal(a.record_hash, b.record_hash);
  assert.equal((await stores.ledger.readChain('t_demo|agent_4a9f1c|-')).length, 1);
});

test('S9: malformed body -> 422 validation problem', async () => {
  const { app, H } = await harness();
  const res = await gate(app, H, { vendor: { name: 'openai' } }); // missing agent_id
  assert.equal(res.status, 422);
});

test('S9: freeze endpoint then a gate returns FROZEN', async () => {
  const { app, H } = await harness();
  await app.request('/v1/policies/agent_4a9f1c/freeze', { method: 'POST', headers: H });
  const j = await (await gate(app, H, { agent_id: 'agent_4a9f1c', vendor: { name: 'openai' }, amount_minor: 1 })).json();
  assert.equal(j.reason_code, 'FROZEN');
});

test('S9: /v1/ledger/verify returns ok over real gated traffic', async () => {
  const { app, H } = await harness();
  for (const amt of [1000, 2000, 600000, 3000]) await gate(app, H, { agent_id: 'agent_4a9f1c', vendor: { name: 'openai' }, amount_minor: amt });
  const v = await (await app.request('/v1/ledger/verify?agent_id=agent_4a9f1c', { headers: H })).json();
  assert.equal(v.ok, true);
  assert.equal(v.size, 4);
});

test('S9: /v1/report is a self-contained, verified audit report', async () => {
  const { app, H } = await harness();
  await gate(app, H, { agent_id: 'agent_4a9f1c', vendor: { name: 'openai' }, amount_minor: 1000 });
  const r = await (await app.request('/v1/report', { method: 'POST', headers: H, body: JSON.stringify({ agent_id: 'agent_4a9f1c' }) })).json();
  assert.equal(r.report, 'comptra-agent-spend-audit');
  assert.equal(r.summary.verified, true);
  assert.equal(r.records.length, 1);
  assert.ok(r.threat_model.length > 50);
  // the report must be independently re-verifiable from its own records
  const v = await verifyChain(r.records);
  assert.equal(v.ok, true);
});

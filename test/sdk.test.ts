import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Comptra, ComptraAuthError } from 'comptra';
import { createApp, mintKey, keyHash, type Stores, type KeyLookup } from '../apps/api/src/app.ts';
import type { ApiKeyRecord } from '../apps/api/src/store-file.ts';
import { MemLedgerStore, MemCounterStore, MemPolicyStore, MemIdempotencyStore } from '@comptra/core';
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
  const raw = mintKey('test');
  keys.put(await keyHash(raw), { tenant_id: 't', role: 'admin', env: 'test', prefix: raw.slice(0, 13), created_at: 'x' });
  await policies.set('t', 'agent_4a9f1c', '-', Policy.parse({ vendor_allowlist: ['openai'], per_call_cap_minor: 500000, daily_cap_minor: 2500000 }));
  const app = createApp(stores, { now: () => Date.parse('2026-06-19T12:00:00.000Z') });
  const fetchImpl = ((input: any, init: any) => { const u = new URL(input); return app.request(u.pathname + u.search, init); }) as unknown as typeof fetch;
  return { raw, fetchImpl };
}

test('SDK: gate() PASS returns allowed:true with a record hash', async () => {
  const { raw, fetchImpl } = await harness();
  const c = new Comptra({ apiKey: raw, baseUrl: 'http://comptra.test', fetchImpl });
  const d = await c.gate({ agentId: 'agent_4a9f1c', vendor: { name: 'openai' }, amountMinor: 420000 });
  assert.equal(d.allowed, true);
  if (d.allowed) assert.match(d.recordHash, /^[0-9a-f]{64}$/);
});

test('SDK: gate() BLOCK returns allowed:false and NEVER throws', async () => {
  const { raw, fetchImpl } = await harness();
  const c = new Comptra({ apiKey: raw, baseUrl: 'http://comptra.test', fetchImpl });
  const d = await c.gate({ agentId: 'agent_4a9f1c', vendor: { name: 'openai' }, amountMinor: 600000 });
  assert.equal(d.allowed, false);
  if (!d.allowed) {
    assert.equal(d.reason, 'PER_CALL_CAP');
    assert.equal(d.limit, 500000);
  }
});

test('SDK: a bad API key throws ComptraAuthError', async () => {
  const { fetchImpl } = await harness();
  const c = new Comptra({ apiKey: 'cmp_test_' + '0'.repeat(36), baseUrl: 'http://comptra.test', fetchImpl });
  await assert.rejects(() => c.gate({ agentId: 'a', vendor: { name: 'openai' }, amountMinor: 1 }), ComptraAuthError);
});

test('SDK: report() then local ledger.verify() recomputes trust client-side', async () => {
  const { raw, fetchImpl } = await harness();
  const c = new Comptra({ apiKey: raw, baseUrl: 'http://comptra.test', fetchImpl });
  await c.gate({ agentId: 'agent_4a9f1c', vendor: { name: 'openai' }, amountMinor: 1000 });
  const report = await c.report({ agentId: 'agent_4a9f1c' });
  const v = await c.ledger.verify(report);
  assert.equal(v.ok, true);
});

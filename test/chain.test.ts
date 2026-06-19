import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sealRecord, verifyChain, GENESIS_HASH } from '@comptra/core';
import type { RecordDraft } from '@comptra/core';
import type { LedgerRecord } from '@comptra/schema';

function draft(seq: number, amount: number, decision: 'PASS' | 'BLOCK' = 'PASS'): RecordDraft {
  return {
    tenant_id: 't_demo',
    chain_key: 't_demo|agent_4a9f1c|-',
    agent_id: 'agent_4a9f1c',
    end_customer_id: '-',
    decision,
    reason_code: decision === 'PASS' ? 'PASS' : 'PER_CALL_CAP',
    vendor: { name: 'openai', mcc: '0000', country: 'US' },
    amount_minor: amount,
    approved_amount_minor: decision === 'PASS' ? amount : null,
    currency: 'USD',
    mandate_ref: null,
    idempotency_key: 'idem-' + seq,
    rail: 'simulated',
    ts: '2026-06-19T12:00:0' + (seq % 10) + '.000Z',
  };
}

async function buildChain(n: number): Promise<LedgerRecord[]> {
  const recs: LedgerRecord[] = [];
  let prev = GENESIS_HASH;
  for (let i = 0; i < n; i++) {
    const r = await sealRecord(prev, i, draft(i, (i + 1) * 1000, i % 4 === 3 ? 'BLOCK' : 'PASS'));
    recs.push(r);
    prev = r.record_hash;
  }
  return recs;
}

test('S3: an honest chain verifies intact', async () => {
  const c = await buildChain(8);
  const v = await verifyChain(c);
  assert.equal(v.ok, true);
  if (v.ok) assert.equal(v.size, 8);
});

test('S3: flipping a past amount fractures at that exact seq', async () => {
  const c = await buildChain(8);
  c[2] = { ...c[2], amount_minor: 9_999_999 }; // forge the value, keep the old stored hash
  const v = await verifyChain(c);
  assert.equal(v.ok, false);
  if (!v.ok) {
    assert.equal(v.fractureSeq, 2);
    assert.match(v.reason, /record_hash mismatch/);
  }
});

test('S3: deleting a record fractures at the next link', async () => {
  const c = await buildChain(8);
  c.splice(3, 1); // remove seq 3; seq 4 now sits where seq 3 was
  const v = await verifyChain(c);
  assert.equal(v.ok, false);
  if (!v.ok) assert.equal(v.fractureSeq, 4);
});

test('S3: reordering two records fractures', async () => {
  const c = await buildChain(8);
  [c[2], c[3]] = [c[3], c[2]];
  const v = await verifyChain(c);
  assert.equal(v.ok, false);
});

test('S3: forging a record_hash by hand (no key) is caught', async () => {
  const c = await buildChain(8);
  c[5] = { ...c[5], record_hash: 'f'.repeat(64) };
  const v = await verifyChain(c);
  assert.equal(v.ok, false);
  if (!v.ok) assert.equal(v.fractureSeq, 5);
});

test('S3: re-canonicalization is order-insensitive (honest re-serialization still verifies)', async () => {
  const c = await buildChain(5);
  // simulate an auditor whose JSON arrived with shuffled keys — verify must still pass
  const reshuffled = c.map((r) => {
    const entries = Object.entries(r).sort(() => 0.5 - ((r.seq * 7) % 1)); // deterministic-ish shuffle
    return Object.fromEntries(entries) as LedgerRecord;
  });
  const v = await verifyChain(reshuffled);
  assert.equal(v.ok, true);
});
